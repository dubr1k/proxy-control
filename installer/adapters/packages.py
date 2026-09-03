from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from installer.model import HostMode, InstallerConfig
from installer.planner import Action, AuditFacts, Evidence

if TYPE_CHECKING:
    from installer.audit import CommandRunner


DEFAULT_PACKAGES = (
    "ca-certificates",
    "certbot",
    "curl",
    "docker-ce",
    "docker-ce-cli",
    "docker-compose-plugin",
    "nginx-full",
    "openssl",
    "python3",
)
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
_VERSION = re.compile(r"[^\t\r\n\x00]{1,256}\Z")
_QUERY_FORMAT = "${Package}\t${db:Status-Abbrev}\t${Version}\\n"


class PackageError(RuntimeError):
    """Package ownership cannot be established without risking foreign state."""


class PackagesAdapter:
    """Install exact missing packages and own only those package selections."""

    name = "packages"
    requires = frozenset()

    def __init__(
        self,
        *,
        runner: CommandRunner | object | None = None,
        packages: Sequence[str] = DEFAULT_PACKAGES,
    ) -> None:
        if runner is None:
            from installer.audit import CommandRunner

            runner = CommandRunner()
        normalized = tuple(sorted(set(packages)))
        if not normalized or any(
            not isinstance(package, str) or _PACKAGE.fullmatch(package) is None
            for package in normalized
        ):
            raise ValueError("packages must be exact Debian package names")
        self.runner = runner
        self.packages = normalized

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if config.host_mode is not HostMode.FRESH:
            return ()
        if getattr(facts, "hard_stops", ()):
            raise PackageError("host audit contains blocking findings")
        return (
            Action(
                id="packages.host",
                adapter=self.name,
                owner="proxy-control:packages",
                mutations=tuple(f"package={package}" for package in self.packages),
                preconditions=(
                    "supported package manager and package status are observed",
                ),
                verification=("every exact requested package is installed",),
                inverse=("purge only exact packages installed by this action",),
                credentials_required=False,
            ),
        )

    def prepare(self, action: Action) -> Mapping[str, object]:
        packages = _action_packages(action)
        self._assert_selected(packages)
        statuses = self._statuses(packages)
        return {
            "installer_added": {},
            "owner": action.owner,
            "ownership": {},
            "preexisting": {
                package: version
                for package, version in statuses.items()
                if version is not None
            },
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        packages = _action_packages(action)
        preexisting, recorded_added = _checkpoint_packages(checkpoint, packages)
        current = self._statuses(packages)
        _assert_preexisting_unchanged(preexisting, current)
        _assert_added_unchanged(recorded_added, current)
        missing = tuple(package for package in packages if current[package] is None)
        if missing:
            self._run_checked(
                (
                    "apt-get",
                    "install",
                    "--yes",
                    "--no-install-recommends",
                    "--no-upgrade",
                    *missing,
                ),
                "package installation failed",
            )
        observed = self._statuses(packages)
        if any(observed[package] is None for package in packages):
            raise PackageError("requested package is not installed")
        _assert_preexisting_unchanged(preexisting, observed)
        installer_added = {
            package: observed[package]
            for package in packages
            if package not in preexisting
        }
        if any(not isinstance(version, str) for version in installer_added.values()):
            raise PackageError("requested package status is invalid")
        return {
            "installer_added": installer_added,
            "owner": action.owner,
            "ownership": {},
            "preexisting": preexisting,
        }

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.apply(action, checkpoint)

    def verify(self, action: Action) -> Evidence:
        packages = _action_packages(action)
        try:
            self._assert_selected(packages)
            current = self._statuses(packages)
            success = all(current[package] is not None for package in packages)
        except PackageError:
            success = False
        return Evidence(
            action_id=action.id,
            success=success,
            observations=(
                "exact package set is installed"
                if success
                else "exact package set is incomplete or invalid",
            ),
            details={"packages": packages},
        )

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        del purge_data
        if rollback_target not in {"rolled_back", "uninstalled"}:
            raise ValueError("invalid rollback target")
        packages = _action_packages(action)
        preexisting, installer_added = _checkpoint_packages(checkpoint, packages)
        current = self._statuses(packages)
        _assert_preexisting_unchanged(preexisting, current)
        _assert_added_unchanged(installer_added, current, allow_absent=True)
        present_owned = tuple(
            package
            for package in packages
            if package in installer_added and current[package] is not None
        )
        if present_owned:
            self._run_checked(
                ("apt-get", "purge", "--yes", *present_owned),
                "package rollback failed",
            )
        after = self._statuses(packages)
        _assert_preexisting_unchanged(preexisting, after)
        if any(after[package] is not None for package in installer_added):
            raise PackageError("installer-owned package remains installed")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("installer-owned packages were removed",),
            details={"removed": tuple(sorted(installer_added))},
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        packages = _action_packages(action)
        preexisting, installer_added = _checkpoint_packages(checkpoint, packages)
        current = self._statuses(packages)
        _assert_preexisting_unchanged(preexisting, current)
        recovered = dict(installer_added)
        for package in packages:
            if package not in preexisting and current[package] is not None:
                recovered[package] = current[package]
        recovered_checkpoint = {
            "installer_added": recovered,
            "owner": action.owner,
            "ownership": {},
            "preexisting": preexisting,
        }
        return self.rollback(
            action,
            recovered_checkpoint,
            purge_data=purge_data,
            rollback_target=rollback_target,
        )

    def _assert_selected(self, packages: tuple[str, ...]) -> None:
        if packages != self.packages:
            raise PackageError("package action does not match this adapter")

    def _statuses(self, packages: tuple[str, ...]) -> dict[str, str | None]:
        return {package: self._status(package) for package in packages}

    def _status(self, package: str) -> str | None:
        result = self.runner.run(
            ("dpkg-query", "--show", f"--showformat={_QUERY_FORMAT}", package)
        )
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise PackageError("package status query failed")
        lines = result.stdout.splitlines()
        if len(lines) != 1:
            raise PackageError("package status response is malformed")
        fields = lines[0].split("\t")
        if (
            len(fields) != 3
            or fields[0] != package
            or fields[1] != "ii "
            or _VERSION.fullmatch(fields[2]) is None
        ):
            raise PackageError("package status response is malformed")
        return fields[2]

    def _run_checked(self, argv: tuple[str, ...], message: str) -> None:
        result = self.runner.run(argv)
        if result.returncode != 0:
            raise PackageError(message)


def _action_packages(action: Action) -> tuple[str, ...]:
    if action.adapter != "packages" or action.id != "packages.host":
        raise PackageError("package action is invalid")
    packages: list[str] = []
    for mutation in action.mutations:
        key, separator, value = mutation.partition("=")
        if separator != "=" or key != "package" or _PACKAGE.fullmatch(value) is None:
            raise PackageError("package action is invalid")
        packages.append(value)
    normalized = tuple(sorted(set(packages)))
    if tuple(packages) != normalized:
        raise PackageError("package action is invalid")
    return normalized


def _checkpoint_packages(
    checkpoint: Mapping[str, object],
    packages: tuple[str, ...],
) -> tuple[dict[str, str], dict[str, str]]:
    if set(checkpoint) != {"installer_added", "owner", "ownership", "preexisting"}:
        raise PackageError("package checkpoint is invalid")
    if checkpoint["owner"] != "proxy-control:packages" or checkpoint["ownership"] != {}:
        raise PackageError("package checkpoint is invalid")
    preexisting = _version_mapping(checkpoint["preexisting"], packages)
    installer_added = _version_mapping(checkpoint["installer_added"], packages)
    if set(preexisting) & set(installer_added):
        raise PackageError("package checkpoint is invalid")
    return preexisting, installer_added


def _version_mapping(value: object, packages: tuple[str, ...]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise PackageError("package checkpoint is invalid")
    parsed: dict[str, str] = {}
    for package, version in value.items():
        if (
            not isinstance(package, str)
            or package not in packages
            or not isinstance(version, str)
            or _VERSION.fullmatch(version) is None
        ):
            raise PackageError("package checkpoint is invalid")
        parsed[package] = version
    return dict(sorted(parsed.items()))


def _assert_preexisting_unchanged(
    expected: Mapping[str, str],
    current: Mapping[str, str | None],
) -> None:
    if any(current[package] != version for package, version in expected.items()):
        raise PackageError("pre-existing package status changed")


def _assert_added_unchanged(
    expected: Mapping[str, str],
    current: Mapping[str, str | None],
    *,
    allow_absent: bool = False,
) -> None:
    for package, version in expected.items():
        observed = current[package]
        if allow_absent and observed is None:
            continue
        if observed != version:
            raise PackageError("installer-owned package version drift")


__all__ = ["DEFAULT_PACKAGES", "PackageError", "PackagesAdapter"]
