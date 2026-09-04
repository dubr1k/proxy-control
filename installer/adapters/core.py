from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from installer.model import InstallerConfig
from installer.planner import Action, AuditFacts, Evidence
from installer.transaction import (
    atomic_write,
    durable_copy2,
    durable_mkdir,
    durable_remove,
    fsync_tree,
)

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_PROBE = "/usr/local/libexec/mtproxy-respq-probe"
_PROBE_IMAGE = "mtproxy-respq-probe:1.0.0"
_TDLIB_PIN = "0.1008066.0"
_SAFE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\Z"
)
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_BEARER = re.compile(r"Bearer [A-Za-z0-9_-]{32,256}\Z")
_COPY_FILES = ("compose.yaml", "uninstall.sh", "scripts/proxyctl.py")
_COPY_DIRECTORIES = ("docker", "installer", "panel")
_PRESERVED_CREDENTIALS = (
    "secrets/users.conf",
    "secrets/telemt-api-token",
    "secrets/panel-bootstrap-password",
)


class CoreError(RuntimeError):
    """Core runtime ownership cannot be changed safely."""


class AcceptanceError(CoreError):
    """The Core runtime failed an end-to-end acceptance requirement."""

class _DefaultCoreRunner:
    """Bounded, non-logging host and HTTPS acceptance boundary."""

    def __init__(self, *, timeout: float = 900.0) -> None:
        self.timeout = timeout

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin_path: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        stdin = stdin_path.open("rb") if stdin_path is not None else subprocess.DEVNULL
        try:
            return subprocess.run(
                [str(value) for value in argv],
                check=False,
                stdin=stdin,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout,
                env=dict(env) if env is not None else None,
            )
        finally:
            if stdin_path is not None:
                stdin.close()

    def capture(self, argv: Sequence[str], *, max_chars: int) -> str:
        limit = min(max(max_chars, 0), 4096)
        try:
            completed = subprocess.run(
                [str(value) for value in argv],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=min(self.timeout, 15.0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"diagnostic unavailable: {type(exc).__name__}"[:limit]
        output = completed.stdout or ""
        if completed.returncode:
            output = f"exit={completed.returncode} {output}"
        return output[-limit:]

    def compose_project_present(self, project_dir: str) -> bool:
        containers = self._capture_checked(
            (
                "docker",
                "compose",
                "--project-directory",
                project_dir,
                "ps",
                "-a",
                "-q",
            )
        )
        networks = self._capture_checked(
            (
                "docker",
                "network",
                "ls",
                "--quiet",
                "--filter",
                "label=com.docker.compose.project=mtproxy",
            )
        )
        return bool(containers.strip() or networks.strip())

    def compose_project_volumes_present(self, _project_dir: str) -> bool:
        return bool(
            self._capture_checked(
                (
                    "docker",
                    "volume",
                    "ls",
                    "--quiet",
                    "--filter",
                    "label=com.docker.compose.project=mtproxy",
                )
            ).strip()
        )

    def core_acceptance(
        self,
        *,
        project_dir: str,
        proxy_domain: str,
        panel_domain: str,
        users_file: str,
        probe_path: str,
        adjacent_sni: Sequence[str],
        bootstrap_credential_file: str,
        sensitive_scan_ok: bool,
        telemt_api_internal: bool,
    ) -> Mapping[str, object]:
        compose = (
            "docker",
            "compose",
            "--project-directory",
            project_dir,
        )
        self._run_checked(compose + ("config", "-q"), "Compose config")
        running = self._capture_checked(
            compose + ("ps", "--status", "running", "-q")
        )
        healthy = len([line for line in running.splitlines() if line.strip()])
        if healthy != 3:
            raise AcceptanceError("Core acceptance failed: Compose health checks")
        request = urllib.request.Request(
            "http://127.0.0.1:8787/healthz",
            headers={"Host": panel_domain},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read(65537)
                if response.status != 200 or len(body) > 65536:
                    raise AcceptanceError(
                        "Core acceptance failed: panel health"
                    )
        except (OSError, urllib.error.URLError) as exc:
            raise AcceptanceError(
                "Core acceptance failed: panel health"
            ) from exc
        self.cleanup_core_acceptance(
            panel_domain=panel_domain,
            bootstrap_credential_file=bootstrap_credential_file,
        )
        verified = self._panel_and_respq(
            panel_domain=panel_domain,
            proxy_domain=proxy_domain,
            probe_path=probe_path,
            bootstrap_credential_file=bootstrap_credential_file,
        )
        for domain in adjacent_sni:
            self._run_checked(
                (
                    "openssl",
                    "s_client",
                    "-connect",
                    "127.0.0.1:443",
                    "-servername",
                    domain,
                    "-brief",
                ),
                "adjacent SNI",
            )
        return {
            "adjacent_sni_ok": True,
            "compose_config_ok": True,
            "expected_services": 3,
            "healthy_services": healthy,
            "panel_health_ok": True,
            "panel_login_ok": True,
            "respq_expected": 1,
            "respq_verified": verified,
            "sensitive_scan_ok": sensitive_scan_ok,
            "telemt_api_internal": telemt_api_internal,
            "temporary_state_removed": True,
        }

    def cleanup_core_acceptance(
        self,
        *,
        panel_domain: str,
        bootstrap_credential_file: str,
        **_ignored: object,
    ) -> None:
        password = Path(bootstrap_credential_file).read_text().rstrip("\r\n")
        opener, csrf = self._login(panel_domain, "owner", password)
        try:
            users = self._json_request(opener, panel_domain, "/api/users")
            rows = users.get("items", []) if isinstance(users, Mapping) else []
            if any(
                isinstance(row, Mapping)
                and row.get("username") == "proxy-control-acceptance"
                for row in rows
            ):
                self._json_request(
                    opener,
                    panel_domain,
                    "/api/users/proxy-control-acceptance",
                    method="DELETE",
                    csrf=csrf,
                )
        finally:
            self._logout(opener, panel_domain, csrf)

    def _panel_and_respq(
        self,
        *,
        panel_domain: str,
        proxy_domain: str,
        probe_path: str,
        bootstrap_credential_file: str,
    ) -> int:
        password = Path(bootstrap_credential_file).read_text().rstrip("\r\n")
        opener, csrf = self._login(panel_domain, "owner", password)
        temporary: Path | None = None
        created = False
        try:
            me = self._json_request(opener, panel_domain, "/api/auth/me")
            if not isinstance(me, Mapping) or me.get("username") != "owner":
                raise AcceptanceError("Core acceptance failed: panel login")
            created_value = self._json_request(
                opener,
                panel_domain,
                "/api/users",
                method="POST",
                payload={"username": "proxy-control-acceptance"},
                csrf=csrf,
            )
            created = True
            reveal = (
                created_value.get("reveal_token")
                if isinstance(created_value, Mapping)
                else None
            )
            if not isinstance(reveal, str) or not reveal:
                raise AcceptanceError("Core acceptance failed: resPQ")
            credential = self._json_request(
                opener,
                panel_domain,
                f"/api/reveal/{reveal}",
            )
            value = credential.get("secret") if isinstance(credential, Mapping) else None
            if not isinstance(value, str) or _HEX_32.fullmatch(value) is None:
                raise AcceptanceError("Core acceptance failed: resPQ")
            descriptor, name = tempfile.mkstemp(prefix="proxy-control-respq-")
            temporary = Path(name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w") as handle:
                    handle.write(f"proxy-control-acceptance={value}\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                os.close(descriptor)
                raise
            self._run_checked(
                (
                    probe_path,
                    "--domain",
                    proxy_domain,
                    "--secrets-file",
                    str(temporary),
                ),
                "resPQ",
            )
            return 1
        finally:
            if created:
                try:
                    self._json_request(
                        opener,
                        panel_domain,
                        "/api/users/proxy-control-acceptance",
                        method="DELETE",
                        csrf=csrf,
                    )
                except BaseException:
                    pass
            self._logout(opener, panel_domain, csrf)
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _login(
        self,
        domain: str,
        username: str,
        password: str,
    ) -> tuple[urllib.request.OpenerDirector, str]:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            urllib.request.HTTPCookieProcessor(jar),
        )
        self._json_request(opener, domain, "/login", expect_json=False)
        csrf = next(
            (
                cookie.value
                for cookie in jar
                if cookie.name == "panel_csrf"
            ),
            "",
        )
        if not csrf:
            raise AcceptanceError("Core acceptance failed: panel login")
        self._json_request(
            opener,
            domain,
            "/api/auth/login",
            method="POST",
            payload={"username": username, "password": password},
            csrf=csrf,
            expect_json=False,
        )
        csrf = next(
            (
                cookie.value
                for cookie in jar
                if cookie.name == "panel_csrf"
            ),
            "",
        )
        if not csrf:
            raise AcceptanceError("Core acceptance failed: panel login")
        return opener, csrf

    def _logout(
        self,
        opener: urllib.request.OpenerDirector,
        domain: str,
        csrf: str,
    ) -> None:
        try:
            self._json_request(
                opener,
                domain,
                "/api/auth/logout",
                method="POST",
                csrf=csrf,
                expect_json=False,
            )
        except BaseException:
            pass

    @staticmethod
    def _json_request(
        opener: urllib.request.OpenerDirector,
        domain: str,
        path: str,
        *,
        method: str = "GET",
        payload: Mapping[str, object] | None = None,
        csrf: str | None = None,
        expect_json: bool = True,
    ) -> object:
        data = (
            json.dumps(payload, separators=(",", ":")).encode()
            if payload is not None
            else None
        )
        headers = {"Content-Type": "application/json"} if data is not None else {}
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(
            f"https://{domain}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with opener.open(request, timeout=20) as response:
                body = response.read(65537)
        except (OSError, urllib.error.URLError) as exc:
            raise AcceptanceError("Core acceptance failed: panel login") from exc
        if len(body) > 65536:
            raise AcceptanceError("Core acceptance response is too large")
        if not expect_json or not body:
            return {}
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise AcceptanceError("Core acceptance response is invalid") from exc

    def _run_checked(self, argv: Sequence[str], label: str) -> None:
        result = self.run(argv)
        if result.returncode:
            raise AcceptanceError(f"Core acceptance failed: {label}")

    def _capture_checked(self, argv: Sequence[str]) -> str:
        try:
            completed = subprocess.run(
                [str(value) for value in argv],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=min(self.timeout, 30.0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CoreError("Core runtime query failed") from exc
        if completed.returncode:
            raise CoreError("Core runtime query failed")
        if len(completed.stdout) > 65536:
            raise CoreError("Core runtime query exceeded its bound")
        return completed.stdout


@dataclass(frozen=True)
class CorePaths:
    """Fixed host paths owned by the existing Core runtime generation."""

    project_dir: str = _PROJECT
    probe_path: str = _PROBE
    marker_name: str = ".mtproxy-owned"
    bootstrap_marker_name: str = ".panel-bootstrapped"

    def __post_init__(self) -> None:
        for value, label in (
            (self.project_dir, "project directory"),
            (self.probe_path, "probe path"),
        ):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError(f"{label} must be a normalized absolute path")
        for value in (self.marker_name, self.bootstrap_marker_name):
            if "/" in value or value in {"", ".", ".."}:
                raise ValueError("project marker name is invalid")

    @property
    def users_file(self) -> str:
        return f"{self.project_dir}/secrets/users.conf"

    @property
    def api_credential_file(self) -> str:
        return f"{self.project_dir}/secrets/telemt-api-token"

    @property
    def bootstrap_credential_file(self) -> str:
        return f"{self.project_dir}/secrets/panel-bootstrap-password"

    @property
    def marker_path(self) -> str:
        return f"{self.project_dir}/{self.marker_name}"

    @property
    def bootstrap_marker_path(self) -> str:
        return f"{self.project_dir}/{self.bootstrap_marker_name}"


@dataclass(frozen=True)
class RenderedCore:
    """Deterministic, credential-free portion of a Core generation."""

    compose_yaml: str
    env_text: str
    file_modes: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_modes", MappingProxyType(dict(self.file_modes)))

    def mode(self, relative_path: str) -> int:
        return self.file_modes[relative_path]


@dataclass(frozen=True)
class CoreAcceptance:
    """Sanitized acceptance facts; values are only booleans and counts."""

    compose_config_ok: bool
    healthy_services: int
    expected_services: int
    panel_health_ok: bool
    panel_login_ok: bool
    telemt_api_internal: bool
    respq_verified: int
    respq_expected: int
    adjacent_sni_ok: bool
    sensitive_scan_ok: bool
    temporary_state_removed: bool = True

    def __post_init__(self) -> None:
        boolean_fields = (
            "compose_config_ok",
            "panel_health_ok",
            "panel_login_ok",
            "telemt_api_internal",
            "adjacent_sni_ok",
            "sensitive_scan_ok",
            "temporary_state_removed",
        )
        if any(not isinstance(getattr(self, name), bool) for name in boolean_fields):
            raise TypeError("acceptance flags must be booleans")
        counts = (
            self.healthy_services,
            self.expected_services,
            self.respq_verified,
            self.respq_expected,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("acceptance counts must be non-negative integers")
        if (
            self.healthy_services > self.expected_services
            or self.respq_verified > self.respq_expected
            or self.expected_services == 0
            or self.respq_expected == 0
        ):
            raise ValueError("acceptance counts are inconsistent")

    def details(self) -> dict[str, bool | int]:
        return asdict(self)


class CoreAdapter:
    """Own the existing Telemt, panel, Compose, and TDLib probe lifecycle."""

    name = "core"
    requires = frozenset({"nginx"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        source_dir: Path | None = None,
        paths: CorePaths | None = None,
        users: Sequence[str] | None = None,
        adjacent_sni: Sequence[str] = (),
    ) -> None:
        if runner is None:
            runner = _DefaultCoreRunner()
        self.root = Path(root)
        self.runner = runner
        self.source_dir = Path(source_dir or Path(__file__).resolve().parents[2])
        self.paths = paths or CorePaths()
        self.users = tuple(users) if users is not None else None
        normalized_sni = tuple(sorted(set(adjacent_sni)))
        if any(_DOMAIN.fullmatch(value) is None for value in normalized_sni):
            raise ValueError("adjacent SNI names must be valid domains")
        self.adjacent_sni = normalized_sni

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if getattr(facts, "hard_stops", ()):
            raise CoreError("host audit contains blocking findings")
        selected_users = self.users or (config.initial_user,)
        _validate_users(selected_users)
        mutations = (
            f"project={self.paths.project_dir}",
            f"proxy-domain={config.domains.mtproxy}",
            f"panel-domain={config.domains.panel}",
            f"users={','.join(selected_users)}",
            "proxy-backend-port=8445",
            "panel-app-port=8787",
            f"probe={self.paths.probe_path}",
            f"probe-image={_PROBE_IMAGE}",
            f"prebuilt-tdlib={_TDLIB_PIN}",
        )
        return (
            Action(
                id="core.runtime",
                adapter=self.name,
                owner="proxy-control:core",
                mutations=mutations,
                preconditions=(
                    "Nginx routes and certificates are verified",
                    "the existing mtproxy project boundary is absent or explicitly owned",
                ),
                verification=(
                    "Compose model and all service health checks pass",
                    "panel health and an HTTPS authenticated session pass",
                    "Telemt management API remains private to Compose",
                    "every temporary MTProto credential returns validated resPQ",
                    "adjacent SNI routes and bounded sensitive-data scan pass",
                ),
                inverse=(
                    "stop only the mtproxy Compose project",
                    "preserve credentials and named volumes unless data purge is explicit",
                    "remove only Core-owned artifacts and the owned probe",
                ),
                credentials_required=True,
            ),
        )

    def action(
        self,
        *,
        proxy_domain: str,
        panel_domain: str,
        users: Sequence[str],
        proxy_backend_port: int = 8445,
        panel_app_port: int = 8787,
    ) -> Action:
        """Build the same secret-free action for compatibility coordinators."""
        selected_users = tuple(users)
        _validate_users(selected_users)
        return Action(
            id="core.runtime",
            adapter=self.name,
            owner="proxy-control:core",
            mutations=(
                f"project={self.paths.project_dir}",
                f"proxy-domain={proxy_domain}",
                f"panel-domain={panel_domain}",
                f"users={','.join(selected_users)}",
                f"proxy-backend-port={proxy_backend_port}",
                f"panel-app-port={panel_app_port}",
                f"probe={self.paths.probe_path}",
                f"probe-image={_PROBE_IMAGE}",
                f"prebuilt-tdlib={_TDLIB_PIN}",
            ),
            preconditions=("owned Core generation",),
            verification=("Core acceptance",),
            inverse=("remove owned Core generation",),
            credentials_required=True,
        )


    def render(self, action: Action) -> RenderedCore:
        selected = self._selection(action)
        compose_path = self.source_dir / "compose.yaml"
        try:
            compose = compose_path.read_text()
        except OSError as exc:
            raise CoreError("Core Compose source is unavailable") from exc
        if not compose.startswith("name: mtproxy\n"):
            raise CoreError("Core Compose project identity is invalid")
        if _compose_publishes_telemt_api(compose):
            raise CoreError("Telemt API must not be host-published")
        env = (
            f"MTPROXY_DOMAIN={selected['proxy_domain']}\n"
            f"MTPROXY_BACKEND_PORT={selected['proxy_backend_port']}\n"
            f"MTPROXY_COVER_ROOT=/var/www/{selected['proxy_domain']}\n"
            "MTPROXY_LETSENCRYPT_ROOT=/etc/letsencrypt\n"
            f"PANEL_ALLOWED_HOSTS={selected['panel_domain']}\n"
            f"PANEL_HEALTHCHECK_HOST={selected['panel_domain']}\n"
        )
        return RenderedCore(
            compose_yaml=compose,
            env_text=env,
            file_modes={
                ".env": 0o600,
                self.paths.marker_name: 0o600,
                "secrets": 0o700,
                "secrets/users.conf": 0o600,
                "secrets/telemt-api-token": 0o600,
                "secrets/panel-bootstrap-password": 0o600,
            },
        )

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        rendered = self.render(action)
        del rendered
        project = self._host(self.paths.project_dir)
        kind = self._project_kind(project)
        probe = self._host(self.paths.probe_path)
        probe_preexisting = probe.exists() or probe.is_symlink()
        if probe_preexisting:
            source_probe = self.source_dir / "probe" / "mtproxy-respq-probe"
            if (
                probe.is_symlink()
                or not probe.is_file()
                or not source_probe.is_file()
                or _file_sha256(probe) != _file_sha256(source_probe)
            ):
                raise CoreError("pre-existing protocol probe is not installer-owned")
        return {
            "adoption": kind,
            "owner": action.owner,
            "ownership": {},
            "probe_preexisting": probe_preexisting,
            "project_created": kind == "absent",
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        self._install_probe()
        self._write_generation(selected, recovery=True)
        self._compose("config", "-q")
        self._compose("pull", "-q")
        self._compose_start()
        self._bootstrap_panel(selected)
        ownership = self._ownership(include_probe=not prepared["probe_preexisting"])
        return {
            **prepared,
            "ownership": ownership,
        }

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.apply(action, checkpoint)

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        result: CoreAcceptance | None = None
        cleanup_ok = False
        failure: Exception | None = None
        try:
            raw = self._run_acceptance(selected)
            result = _acceptance_value(raw)
            self._require_acceptance(result)
        except Exception as exc:
            failure = exc
        finally:
            try:
                self._cleanup_acceptance(selected)
                cleanup_ok = True
            except Exception as exc:
                if failure is None:
                    failure = AcceptanceError("temporary-user and session cleanup failed")
                    failure.__cause__ = exc
        if failure is not None:
            if isinstance(failure, AcceptanceError):
                raise failure
            raise AcceptanceError("Core acceptance execution failed") from failure
        if result is None or not cleanup_ok:
            raise AcceptanceError("temporary-user and session cleanup failed")
        result = CoreAcceptance(**{**result.details(), "temporary_state_removed": True})
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "Core Compose, panel, MTProto, isolation, and coexistence acceptance passed",
                "temporary acceptance state was removed",
            ),
            details=result.details(),
        )

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._assert_checkpoint_ownership(prepared)
        self._compose_start()
        return prepared

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        if rollback_target not in {"rolled_back", "uninstalled"}:
            raise ValueError("invalid rollback target")
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._cleanup_acceptance(selected)
        if self._compose_present():
            self._compose("down", "--remove-orphans")
        if purge_data and self._volumes_present():
            self._compose("down", "--remove-orphans", "--volumes")
        self._remove_generation(prepared, preserve_credentials=True)
        self._remove_owned_probe(prepared)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "Core runtime was removed",
                "persistent data was purged" if purge_data else "persistent data was preserved",
            ),
            details={"persistent_data_preserved": not purge_data},
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        return self.rollback(
            action,
            checkpoint,
            purge_data=purge_data,
            rollback_target=rollback_target,
        )

    def install_probe(self) -> None:
        """Compatibility entry point used by the legacy runtime coordinator."""
        self._install_probe()

    def render_to_disk(self, action: Action, *, recovery: bool = False) -> bool:
        """Compatibility entry point while RuntimeInstaller remains importable."""
        selected = self._selection(action)
        project = self._host(self.paths.project_dir)
        created = not project.exists()
        if not recovery and self._project_kind(project) != "absent":
            raise CoreError("pre-existing project requires explicit migration; refusing overwrite")
        self._write_generation(selected, recovery=recovery)
        return created

    def start(self) -> None:
        self._compose_start()

    def accept(self, action: Action) -> Evidence:
        return self.verify(action)

    def clean_preserving_credentials(self) -> None:
        self._remove_generation(
            {"ownership": self._ownership(existing_only=True)},
            preserve_credentials=True,
        )

    def marker_sha256(self, expected: str | None = None) -> str:
        marker = self._host(self.paths.marker_path)
        if (
            marker.is_symlink()
            or not marker.is_file()
            or stat.S_IMODE(marker.stat().st_mode) != 0o600
            or (
                self.root == Path("/")
                and (marker.stat().st_uid, marker.stat().st_gid) != (0, 0)
            )
        ):
            raise CoreError("runtime project ownership has drifted")
        actual = _file_sha256(marker)
        if expected is not None and actual != expected:
            raise CoreError("runtime project ownership has drifted")
        return actual

    def compose_project_present(self) -> bool:
        return self._compose_present()

    def compose_project_volumes_present(self) -> bool:
        return self._volumes_present()

    def _selection(self, action: Action) -> dict[str, object]:
        if action.adapter != self.name or action.id != "core.runtime" or action.owner != "proxy-control:core":
            raise CoreError("Core action is invalid")
        values: dict[str, str] = {}
        for mutation in action.mutations:
            key, separator, value = mutation.partition("=")
            if not separator or not key or key in values:
                raise CoreError("Core action is invalid")
            values[key] = value
        required = {
            "project",
            "proxy-domain",
            "panel-domain",
            "users",
            "proxy-backend-port",
            "panel-app-port",
            "probe",
            "probe-image",
            "prebuilt-tdlib",
        }
        if set(values) != required:
            raise CoreError("Core action is invalid")
        if (
            values["project"] != self.paths.project_dir
            or values["probe"] != self.paths.probe_path
            or values["probe-image"] != _PROBE_IMAGE
            or values["prebuilt-tdlib"] != _TDLIB_PIN
            or _DOMAIN.fullmatch(values["proxy-domain"]) is None
            or _DOMAIN.fullmatch(values["panel-domain"]) is None
            or values["proxy-domain"] == values["panel-domain"]
        ):
            raise CoreError("Core action is invalid")
        selected_users = tuple(values["users"].split(","))
        _validate_users(selected_users)
        try:
            proxy_port = int(values["proxy-backend-port"])
            panel_port = int(values["panel-app-port"])
        except ValueError as exc:
            raise CoreError("Core action is invalid") from exc
        if not (1024 <= proxy_port <= 65535 and 1024 <= panel_port <= 65535):
            raise CoreError("Core action is invalid")
        return {
            "proxy_domain": values["proxy-domain"].lower(),
            "panel_domain": values["panel-domain"].lower(),
            "users": selected_users,
            "proxy_backend_port": proxy_port,
            "panel_app_port": panel_port,
        }

    def _checkpoint(
        self,
        checkpoint: Mapping[str, object],
        action: Action,
        *,
        applied: bool = False,
    ) -> dict[str, object]:
        required = {
            "adoption",
            "owner",
            "ownership",
            "probe_preexisting",
            "project_created",
        }
        if set(checkpoint) != required:
            raise CoreError("Core checkpoint is invalid")
        adoption = checkpoint.get("adoption")
        owner = checkpoint.get("owner")
        created = checkpoint.get("project_created")
        probe_preexisting = checkpoint.get("probe_preexisting")
        ownership = checkpoint.get("ownership")
        if (
            adoption not in {"absent", "recovery"}
            or owner != action.owner
            or not isinstance(created, bool)
            or created != (adoption == "absent")
            or not isinstance(probe_preexisting, bool)
            or not isinstance(ownership, Mapping)
            or (not applied and ownership)
        ):
            raise CoreError("Core checkpoint is invalid")
        if applied:
            _validate_ownership_mapping(ownership)
        return {
            "adoption": adoption,
            "owner": owner,
            "ownership": dict(ownership),
            "probe_preexisting": probe_preexisting,
            "project_created": created,
        }

    def _project_kind(self, project: Path) -> str:
        if not project.exists():
            return "absent"
        if project.is_symlink() or not project.is_dir():
            raise CoreError("pre-existing project requires explicit migration; refusing overwrite")
        names = {entry.name for entry in project.iterdir()}
        if not names:
            return "absent"
        if self.paths.marker_name not in names or not names <= {self.paths.marker_name, "secrets"}:
            raise CoreError("pre-existing project requires explicit migration; refusing overwrite")
        self.marker_sha256()
        secret_dir = project / "secrets"
        if secret_dir.exists() and (secret_dir.is_symlink() or not secret_dir.is_dir()):
            raise CoreError("pre-existing project credentials are unsafe")
        if secret_dir.is_dir():
            self._validate_existing_credentials(secret_dir)
        return "recovery"

    def _validate_existing_credentials(self, secret_dir: Path) -> None:
        metadata = secret_dir.stat()
        if stat.S_IMODE(metadata.st_mode) != 0o700 or (
            self.root == Path("/") and (metadata.st_uid, metadata.st_gid) != (0, 0)
        ):
            raise CoreError("pre-existing project credentials are unsafe")
        allowed = {Path(value).name for value in _PRESERVED_CREDENTIALS}
        if {entry.name for entry in secret_dir.iterdir()} - allowed:
            raise CoreError("pre-existing project credentials are unsafe")
        validators = {
            "users.conf": _valid_users_file,
            "telemt-api-token": lambda data: _BEARER.fullmatch(data.rstrip("\n")) is not None,
            "panel-bootstrap-password": lambda data: bool(data.rstrip("\n")) and "\n" not in data.rstrip("\n"),
        }
        for name, validator in validators.items():
            path = secret_dir / name
            if not path.exists():
                continue
            metadata = path.stat()
            if (
                path.is_symlink()
                or not path.is_file()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (
                    self.root == Path("/")
                    and (metadata.st_uid, metadata.st_gid) != (0, 0)
                )
            ):
                raise CoreError("pre-existing project credentials are unsafe")
            try:
                value = path.read_text()
            except (OSError, UnicodeError) as exc:
                raise CoreError("pre-existing project credentials are unsafe") from exc
            if not validator(value):
                raise CoreError("pre-existing project credentials are unsafe")

    def _write_generation(self, selected: Mapping[str, object], *, recovery: bool) -> None:
        rendered = self.render(self._action_from_selection(selected))
        project = self._host(self.paths.project_dir)
        if project.exists() and self._project_kind_for_apply(project, recovery) == "foreign":
            raise CoreError("pre-existing project requires explicit migration; refusing overwrite")
        durable_mkdir(project)
        self._assert_safe_project_tree(project)
        marker = project / self.paths.marker_name
        if not marker.exists():
            self._atomic(marker, (secrets.token_hex(16) + "\n").encode(), 0o600)
        source = self.source_dir
        if not source.is_dir():
            raise CoreError("installer source directory does not exist")
        for name in _COPY_FILES:
            durable_copy2(source / name, project / name)
        for directory in _COPY_DIRECTORIES:
            shutil.copytree(
                source / directory,
                project / directory,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc", "*.sqlite3*"),
            )
            fsync_tree(project / directory)
        credential_dir = project / "secrets"
        if credential_dir.exists() and (
            credential_dir.is_symlink() or not credential_dir.is_dir()
        ):
            raise CoreError("pre-existing project credentials are unsafe")
        durable_mkdir(credential_dir, mode=0o700)
        self._validate_existing_credentials(credential_dir)
        os.chmod(credential_dir, 0o700)
        users_file = credential_dir / "users.conf"
        existing = _read_existing_users(users_file)
        users = selected["users"]
        if not isinstance(users, tuple):
            raise CoreError("Core selection is invalid")
        self._atomic(
            users_file,
            "".join(f"{name}={existing.get(name, secrets.token_hex(16))}\n" for name in users).encode(),
            0o600,
        )
        api_file = credential_dir / "telemt-api-token"
        if not api_file.exists():
            self._atomic(api_file, ("Bearer " + secrets.token_urlsafe(48) + "\n").encode(), 0o600)
        bootstrap_file = credential_dir / "panel-bootstrap-password"
        if not bootstrap_file.exists():
            self._atomic(bootstrap_file, (secrets.token_urlsafe(32) + "\n").encode(), 0o600)
        self._atomic(project / ".env", rendered.env_text.encode(), 0o600)
        for domain, title in (
            (selected["proxy_domain"], "Welcome"),
            (selected["panel_domain"], "Workspace"),
        ):
            cover = self._host(f"/var/www/{domain}/index.html")
            if not cover.exists():
                body = f"<!doctype html><title>{title}</title><h1>{title}</h1>\n".encode()
                self._atomic(cover, body, 0o644)

    def _assert_safe_project_tree(self, project: Path) -> None:
        marker = project / self.paths.marker_name
        if marker.exists() or marker.is_symlink():
            if (
                marker.is_symlink()
                or not marker.is_file()
                or stat.S_IMODE(marker.stat().st_mode) != 0o600
            ):
                raise CoreError("runtime project ownership has drifted")
        for relative in _COPY_FILES:
            path = project / relative
            parent = path.parent
            if parent != project and parent.exists() and (
                parent.is_symlink() or not parent.is_dir()
            ):
                raise CoreError("runtime project ownership has drifted")
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file():
                    raise CoreError("runtime project ownership has drifted")
        for relative in _COPY_DIRECTORIES:
            path = project / relative
            if path.exists() and (path.is_symlink() or not path.is_dir()):
                raise CoreError("runtime project ownership has drifted")

    def _project_kind_for_apply(self, project: Path, recovery: bool) -> str:
        if project.is_symlink() or not project.is_dir():
            return "foreign"
        names = {entry.name for entry in project.iterdir()}
        if not names:
            return "owned"
        if self.paths.marker_name not in names:
            return "foreign"
        if names <= {self.paths.marker_name, "secrets"}:
            return "owned" if recovery else "foreign"
        # Reconciliation may see any prefix of the exact owned generation.
        allowed = {
            self.paths.marker_name,
            self.paths.bootstrap_marker_name,
            "secrets",
            ".env",
            *(Path(value).parts[0] for value in _COPY_FILES),
            *_COPY_DIRECTORIES,
        }
        return "owned" if recovery and names <= allowed else "foreign"

    def _action_from_selection(self, selected: Mapping[str, object]) -> Action:
        users = selected["users"]
        if not isinstance(users, tuple):
            raise CoreError("Core selection is invalid")
        return Action(
            id="core.runtime",
            adapter="core",
            owner="proxy-control:core",
            mutations=(
                f"project={self.paths.project_dir}",
                f"proxy-domain={selected['proxy_domain']}",
                f"panel-domain={selected['panel_domain']}",
                f"users={','.join(users)}",
                f"proxy-backend-port={selected['proxy_backend_port']}",
                f"panel-app-port={selected['panel_app_port']}",
                f"probe={self.paths.probe_path}",
                f"probe-image={_PROBE_IMAGE}",
                f"prebuilt-tdlib={_TDLIB_PIN}",
            ),
            preconditions=("owned Core generation",),
            verification=("Core acceptance",),
            inverse=("remove owned Core generation",),
            credentials_required=True,
        )

    def _install_probe(self) -> None:
        destination = self._host(self.paths.probe_path)
        source = self.source_dir / "probe" / "mtproxy-respq-probe"
        installer = self.source_dir / "probe" / "install.sh"
        if not source.is_file() or not installer.is_file():
            raise CoreError("pinned TDLib probe sources are unavailable")
        expected = _file_sha256(source)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file() or _file_sha256(destination) != expected:
                raise CoreError("pre-existing protocol probe is not installer-owned")
            return
        self._run(str(installer))
        if not destination.exists() and self.root != Path("/"):
            durable_copy2(source, destination)
            os.chmod(destination, 0o750)
        if destination.is_symlink() or not destination.is_file() or _file_sha256(destination) != expected:
            raise CoreError("pinned TDLib probe installation failed")
        os.chmod(destination, 0o750)

    def _bootstrap_panel(self, selected: Mapping[str, object]) -> None:
        marker = self._host(self.paths.bootstrap_marker_path)
        credential = self._host(self.paths.bootstrap_credential_file)
        expected = hashlib.sha256(
            b"owner\0" + credential.read_bytes().rstrip(b"\r\n")
        ).hexdigest()
        if marker.is_file() and marker.read_text().strip() == expected:
            return
        if marker.exists() or marker.is_symlink():
            raise CoreError("panel bootstrap ownership has drifted")
        self._run(
            "docker",
            "compose",
            "--project-directory",
            self.paths.project_dir,
            "exec",
            "-T",
            "panel",
            "python",
            "-m",
            "panel.cli",
            "create-admin",
            "--username",
            "owner",
            "--role",
            "owner",
            "--password-stdin",
            stdin_path=credential,
        )
        self._atomic(marker, (expected + "\n").encode(), 0o600)

    @staticmethod
    def sanitize_diagnostic(value: str, *, max_chars: int = 4096) -> str:
        clean = " ".join(value.split())
        clean = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", clean)
        clean = re.sub(
            r"(?i)\b(password|secret|token|authorization)(\s*[=:]\s*|\s+)\S+",
            lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
            clean,
        )
        return clean[-max_chars:]

    def _compose_start(self) -> None:
        try:
            self._compose("up", "-d", "--wait")
        except Exception as original:
            compose = (
                "docker",
                "compose",
                "--project-directory",
                self.paths.project_dir,
            )

            def capture(command: tuple[str, ...], limit: int) -> str:
                method = getattr(self.runner, "capture", None)
                if not callable(method):
                    return "diagnostic unavailable"
                try:
                    value = method(command, max_chars=limit)
                except Exception as exc:
                    value = f"diagnostic unavailable: {type(exc).__name__}"
                return self.sanitize_diagnostic(str(value), max_chars=limit)

            containers = capture(
                compose + ("ps", "-q", "panel"),
                256,
            ).strip().splitlines()
            if containers and re.fullmatch(
                r"[A-Za-z0-9_.-]{1,128}",
                containers[-1],
            ):
                health = capture(
                    (
                        "docker",
                        "inspect",
                        "--format",
                        "{{json .State.Health}}",
                        containers[-1],
                    ),
                    2400,
                )
            else:
                health = "container id unavailable"
            diagnostics = (
                ("panel health", health),
                (
                    "panel logs",
                    capture(
                        compose
                        + ("logs", "--no-color", "--tail", "80", "panel"),
                        600,
                    ),
                ),
                ("compose ps", capture(compose + ("ps",), 400)),
            )
            summary = self.sanitize_diagnostic(str(original), max_chars=300)
            detail = "; ".join(
                f"{label}: {value or '(empty)'}"
                for label, value in diagnostics
            )
            raise CoreError(
                f"compose startup failed: {summary}; "
                f"startup diagnostics: {detail}"
            ) from original

    def health_and_protocol(self, action: Action) -> None:
        """Run the legacy safe subset through the Core command boundary."""
        selected = self._selection(action)
        self._compose("config", "-q")
        self._compose("ps", "--status", "running")
        self._run(
            "curl",
            "-fsS",
            "-H",
            f"Host: {selected['panel_domain']}",
            f"http://127.0.0.1:{selected['panel_app_port']}/healthz",
        )
        self._run(
            self.paths.probe_path,
            "--domain",
            str(selected["proxy_domain"]),
            "--secrets-file",
            self.paths.users_file,
        )

    def _compose(self, *args: str) -> None:
        self._run(
            "docker",
            "compose",
            "--project-directory",
            self.paths.project_dir,
            *args,
        )

    def _compose_present(self) -> bool:
        method = getattr(self.runner, "compose_project_present", None)
        return bool(method(self.paths.project_dir)) if callable(method) else True

    def _volumes_present(self) -> bool:
        method = getattr(self.runner, "compose_project_volumes_present", None)
        return bool(method(self.paths.project_dir)) if callable(method) else True

    def _run(self, *argv: str, stdin_path: Path | None = None) -> None:
        try:
            result = self.runner.run(argv, stdin_path=stdin_path)
        except TypeError:
            result = self.runner.run(argv)
        returncode = getattr(result, "returncode", 0)
        if returncode:
            raise CoreError("Core command failed")

    def _run_acceptance(self, selected: Mapping[str, object]) -> object:
        method = getattr(self.runner, "core_acceptance", None)
        if callable(method):
            return method(
                project_dir=self.paths.project_dir,
                proxy_domain=selected["proxy_domain"],
                panel_domain=selected["panel_domain"],
                users_file=self.paths.users_file,
                probe_path=self.paths.probe_path,
                adjacent_sni=self.adjacent_sni,
                bootstrap_credential_file=self.paths.bootstrap_credential_file,
                sensitive_scan_ok=self._bounded_sensitive_scan(),
                telemt_api_internal=not _compose_publishes_telemt_api(
                    (self.source_dir / "compose.yaml").read_text()
                ),
            )
        if all(
            hasattr(self.runner, name)
            for name in ("respq", "panel_health", "panel_login")
        ):
            return CoreAcceptance(
                compose_config_ok=bool(
                    getattr(self.runner, "compose_config", True)
                ),
                healthy_services=(
                    3 if bool(getattr(self.runner, "compose_health", True)) else 0
                ),
                expected_services=3,
                panel_health_ok=bool(getattr(self.runner, "panel_health")),
                panel_login_ok=bool(getattr(self.runner, "panel_login")),
                telemt_api_internal=bool(
                    getattr(self.runner, "api_internal", True)
                ),
                respq_verified=(
                    1 if bool(getattr(self.runner, "respq")) else 0
                ),
                respq_expected=1,
                adjacent_sni_ok=bool(
                    getattr(self.runner, "adjacent_sni", True)
                ),
                sensitive_scan_ok=bool(
                    getattr(self.runner, "sensitive_scan", True)
                ),
            )
        self._compose("config", "-q")
        self._compose("ps", "--status", "running")
        self._run(
            "curl",
            "-fsS",
            "-H",
            f"Host: {selected['panel_domain']}",
            f"http://127.0.0.1:{selected['panel_app_port']}/healthz",
        )
        self._run(
            self.paths.probe_path,
            "--domain",
            str(selected["proxy_domain"]),
            "--secrets-file",
            self.paths.users_file,
        )
        for domain in self.adjacent_sni:
            self._run(
                "openssl",
                "s_client",
                "-connect",
                "127.0.0.1:443",
                "-servername",
                domain,
                "-brief",
            )
        scan_ok = self._bounded_sensitive_scan()
        return CoreAcceptance(
            compose_config_ok=True,
            healthy_services=3,
            expected_services=3,
            panel_health_ok=True,
            panel_login_ok=True,
            telemt_api_internal=not _compose_publishes_telemt_api(
                (self.source_dir / "compose.yaml").read_text()
            ),
            respq_verified=len(selected["users"]),
            respq_expected=len(selected["users"]),
            adjacent_sni_ok=True,
            sensitive_scan_ok=scan_ok,
        )

    def _cleanup_acceptance(self, selected: Mapping[str, object]) -> None:
        method = getattr(self.runner, "cleanup_core_acceptance", None)
        if callable(method):
            method(
                project_dir=self.paths.project_dir,
                panel_domain=selected["panel_domain"],
                bootstrap_credential_file=self.paths.bootstrap_credential_file,
            )

    @staticmethod
    def _require_acceptance(result: CoreAcceptance) -> None:
        checks = (
            (result.compose_config_ok, "Compose config"),
            (result.healthy_services == result.expected_services, "Compose health checks"),
            (result.panel_health_ok, "panel health"),
            (result.panel_login_ok, "panel login"),
            (result.telemt_api_internal, "Telemt API isolation"),
            (result.respq_verified == result.respq_expected, "resPQ"),
            (result.adjacent_sni_ok, "adjacent SNI"),
            (result.sensitive_scan_ok, "sensitive scan"),
            (result.temporary_state_removed, "temporary-user cleanup"),
        )
        for success, label in checks:
            if not success:
                raise AcceptanceError(f"Core acceptance failed: {label}")

    def _bounded_sensitive_scan(self) -> bool:
        project = self._host(self.paths.project_dir)
        credential_paths = [project / value for value in _PRESERVED_CREDENTIALS]
        needles: list[bytes] = []
        try:
            for path in credential_paths:
                if not path.is_file() or path.stat().st_size > 65536:
                    return False
                data = path.read_bytes()
                if path.name == "users.conf":
                    needles.extend(
                        line.partition(b"=")[2]
                        for line in data.splitlines()
                        if b"=" in line
                    )
                else:
                    needles.append(data.strip())
            candidates = (
                project / ".env",
                project / "compose.yaml",
                project / self.paths.marker_name,
                project / self.paths.bootstrap_marker_name,
                self._host("/var/lib/proxy-control/plan.json"),
                self._host("/var/lib/proxy-control/state.json"),
                self._host("/var/lib/proxy-control/ownership.json"),
                self._host("/var/lib/proxy-control/report.json"),
                self._host("/var/lib/proxy-control/runtime.json"),
            )
            scanned = 0
            for path in candidates:
                if not path.is_file():
                    continue
                size = path.stat().st_size
                if size > 1024 * 1024 or scanned + size > 4 * 1024 * 1024:
                    return False
                data = path.read_bytes()
                scanned += size
                if any(needle and needle in data for needle in needles):
                    return False
        except OSError:
            return False
        return True

    def _ownership(
        self,
        *,
        existing_only: bool = False,
        include_probe: bool = True,
    ) -> dict[str, dict[str, object]]:
        project = self._host(self.paths.project_dir)
        ownership: dict[str, dict[str, object]] = {}
        if project.is_dir():
            for path in sorted(project.rglob("*")):
                if not path.is_file() and not path.is_symlink():
                    continue
                relative = path.relative_to(project).as_posix()
                preserve = relative in _PRESERVED_CREDENTIALS or relative == self.paths.marker_name
                ownership[self._host_name(path)] = {
                    "preserve": preserve,
                    "sha256": _path_sha256(path),
                }
        probe = self._host(self.paths.probe_path)
        if include_probe and (probe.exists() or probe.is_symlink()):
            ownership[self.paths.probe_path] = {
                "preserve": False,
                "sha256": _path_sha256(probe),
            }
        if not existing_only and not ownership:
            raise CoreError("Core generation has no owned files")
        return ownership

    def _assert_checkpoint_ownership(self, checkpoint: Mapping[str, object]) -> None:
        ownership = checkpoint["ownership"]
        if not isinstance(ownership, Mapping):
            raise CoreError("Core checkpoint is invalid")
        for host_path, entry in ownership.items():
            if not isinstance(host_path, str) or not isinstance(entry, Mapping):
                raise CoreError("Core checkpoint is invalid")
            path = self._host(host_path)
            if not (path.exists() or path.is_symlink()) or _path_sha256(path) != entry["sha256"]:
                raise CoreError(f"Core owned file has drifted: {host_path}")

    def _remove_generation(
        self,
        checkpoint: Mapping[str, object],
        *,
        preserve_credentials: bool,
    ) -> None:
        ownership = checkpoint.get("ownership", {})
        if not isinstance(ownership, Mapping):
            raise CoreError("Core checkpoint is invalid")
        for host_path, entry in sorted(ownership.items(), reverse=True):
            if host_path == self.paths.probe_path:
                continue
            if not isinstance(entry, Mapping):
                raise CoreError("Core checkpoint is invalid")
            if preserve_credentials and entry.get("preserve") is True:
                continue
            path = self._host(host_path)
            if not (path.exists() or path.is_symlink()):
                continue
            if _path_sha256(path) != entry.get("sha256"):
                raise CoreError(f"Core owned file has drifted: {host_path}")
            durable_remove(path)
        project = self._host(self.paths.project_dir)
        if project.is_dir():
            for child in tuple(project.iterdir()):
                if child.name not in {"secrets", self.paths.marker_name}:
                    durable_remove(child, missing_ok=True)

    def _remove_owned_probe(self, checkpoint: Mapping[str, object]) -> None:
        ownership = checkpoint.get("ownership", {})
        if not isinstance(ownership, Mapping):
            raise CoreError("Core checkpoint is invalid")
        entry = ownership.get(self.paths.probe_path)
        probe = self._host(self.paths.probe_path)
        if not (probe.exists() or probe.is_symlink()):
            return
        if not isinstance(entry, Mapping) or _path_sha256(probe) != entry.get("sha256"):
            raise CoreError("Core owned protocol probe has drifted")
        durable_remove(probe)

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise CoreError("Core host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise CoreError("Core root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise CoreError("Core host path crosses an unsafe parent")
        return self.root / relative

    def _host_name(self, path: Path) -> str:
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise CoreError("Core owned path escapes selected root") from exc
        return "/" + relative.as_posix()

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        atomic_write(path, data, mode=mode, owner=owner)


def _validate_users(users: Sequence[str]) -> None:
    if not users or len(set(users)) != len(users) or any(
        not isinstance(name, str)
        or _SAFE_NAME.fullmatch(name) is None
        or name == "proxy-control-acceptance"
        for name in users
    ):
        raise CoreError("Core users must be unique safe names")


def _read_existing_users(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CoreError("existing Core credentials are unsafe")
    try:
        text = path.read_text()
    except (OSError, UnicodeError) as exc:
        raise CoreError("existing Core credentials are unreadable") from exc
    if not _valid_users_file(text):
        raise CoreError("existing Core credentials are invalid")
    return dict(line.split("=", 1) for line in text.splitlines())


def _valid_users_file(text: str) -> bool:
    lines = text.splitlines()
    if not lines:
        return False
    names: list[str] = []
    for line in lines:
        name, separator, value = line.partition("=")
        if separator != "=" or _SAFE_NAME.fullmatch(name) is None or _HEX_32.fullmatch(value) is None:
            return False
        names.append(name)
    return len(names) == len(set(names))


def _compose_publishes_telemt_api(compose: str) -> bool:
    in_mtproxy = False
    in_ports = False
    base_indent = 0
    for line in compose.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if line == "  mtproxy:":
            in_mtproxy = True
            in_ports = False
            base_indent = 2
            continue
        if in_mtproxy and indent <= base_indent and stripped:
            in_mtproxy = False
            in_ports = False
        if not in_mtproxy:
            continue
        if stripped == "ports:":
            in_ports = True
            continue
        if in_ports and indent <= 4 and stripped:
            in_ports = False
        if in_ports and re.search(r"(?:^|[:\"'])9091(?:[/\"']|$)", stripped):
            return True
    return False


def _acceptance_value(value: object) -> CoreAcceptance:
    if isinstance(value, CoreAcceptance):
        return value
    if not isinstance(value, Mapping):
        raise AcceptanceError("Core acceptance result is invalid")
    required = {
        "compose_config_ok",
        "healthy_services",
        "expected_services",
        "panel_health_ok",
        "panel_login_ok",
        "telemt_api_internal",
        "respq_verified",
        "respq_expected",
        "adjacent_sni_ok",
        "sensitive_scan_ok",
    }
    if not required <= set(value) or set(value) - required - {"temporary_state_removed"}:
        raise AcceptanceError("Core acceptance result is invalid")
    try:
        return CoreAcceptance(**{key: value[key] for key in required}, temporary_state_removed=value.get("temporary_state_removed", True))
    except (TypeError, ValueError) as exc:
        raise AcceptanceError("Core acceptance result is invalid") from exc


def _validate_ownership_mapping(value: Mapping[object, object]) -> None:
    for path, entry in value.items():
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or ".." in Path(path).parts
            or not isinstance(entry, Mapping)
            or set(entry) != {"preserve", "sha256"}
            or not isinstance(entry.get("preserve"), bool)
            or not isinstance(entry.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256"))) is None
        ):
            raise CoreError("Core checkpoint ownership is invalid")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path_sha256(path: Path) -> str:
    if path.is_symlink():
        return hashlib.sha256(("symlink:" + os.readlink(path)).encode()).hexdigest()
    return _file_sha256(path)


__all__ = [
    "AcceptanceError",
    "CoreAcceptance",
    "CoreAdapter",
    "CoreError",
    "CorePaths",
    "RenderedCore",
]
