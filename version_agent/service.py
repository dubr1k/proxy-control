from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit

from .artifacts import ArtifactError, extract_member
from .catalog import CatalogEntry, CatalogError, entry_from_dict, load_catalog, sha256_bytes
from .upstream import ALLOWED_HOSTS, Fetcher, UpstreamError
from .upstream import check_all as _check_all
from .upstream import fetch_https, open_allowed


class UpdateError(RuntimeError):
    """An approved update failed."""

    state = "update_failed"


class RolledBackError(UpdateError):
    """An update failed, but the previous generation was verified."""

    state = "rolled_back"


class RollbackFailedError(UpdateError):
    """An update failed and the previous generation could not be verified."""

    state = "rollback_failed"


class ConflictError(UpdateError):
    """The runtime changed since the panel read its current revision."""

Runner = Callable[..., str]
Downloader = Callable[[str], bytes]

_ALL_COMPONENTS = ("telemt", "naive", "mita", "xray")
_BASE_COMPONENTS = ("telemt", "naive", "mita")


def _run(command: list[str], *, env=None, cwd=None, timeout=None) -> str:
    merged_env = None
    if env is not None:
        merged_env = os.environ.copy()
        merged_env.update(env)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=merged_env,
        text=True,
        capture_output=True,
        timeout=timeout or 120,
        check=True,
    )
    return result.stdout.strip()


def _download(url: str, *, maximum=256 * 1024 * 1024) -> bytes:
    source = urlsplit(url)
    # A catalog artifact may only redirect within its own host. A release asset of an
    # upstream host (github.com → objects.githubusercontent.com) may move within the
    # fixed upstream allowlist and nowhere else; every hop is checked, not just the last.
    allowed = frozenset({source.hostname} if source.hostname else set())
    if source.hostname in ALLOWED_HOSTS:
        allowed = allowed | ALLOWED_HOSTS
    try:
        response = open_allowed(url, allowed=allowed, timeout=120)
    except HTTPError as exc:
        if exc.reason == "redirect left the allowed hosts":
            raise UpdateError("artifact redirect left the catalog host") from exc
        raise UpdateError(f"artifact download failed: HTTP {exc.code}") from exc
    except UpstreamError as exc:
        raise UpdateError(str(exc)) from exc
    with response:
        final = urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname not in allowed:
            raise UpdateError("artifact redirect left the catalog host")
        content = bytearray()
        while True:
            chunk = response.read(min(1024 * 1024, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum:
                raise UpdateError("artifact is too large")
        return bytes(content)


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {"schema": 2, "components": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError("version state is unreadable") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema", 1) not in (1, 2)
        or not isinstance(value.get("components", {}), dict)
        or not isinstance(value.get("upstream", {}), dict)
    ):
        raise UpdateError("version state is invalid")
    return value


class VersionAgent:
    """Apply only artifacts from a root-owned catalog or the cached upstream check, and verify each restart."""

    UPSTREAM_MIN_INTERVAL = 60

    def __init__(
        self,
        *,
        catalog_path: Path,
        state_path: Path,
        compose_dir: Path | None = None,
        compose_files: tuple[str, ...] = (),
        binary_paths: dict[str, Path] | None = None,
        service_names: dict[str, str] | None = None,
        checkers: dict[str, Path | str] | None = None,
        caddyfiles: dict[str, Path] | None = None,
        version_pins: dict[str, Path] | None = None,
        consumer_overlays: dict[str, tuple[Path, str, str]] | None = None,
        telemt_container: str = "proxy-control-mtproxy",
        downloader: Downloader | None = None,
        runner: Runner | None = None,
        health_timeout: float = 60,
        fetcher: Fetcher | None = None,
        upstream_enabled: bool = True,
        router_enabled: bool = False,
        clock: Callable[[], float] = time.time,
        xray_bin_dir: Path = Path("/usr/local/lib/proxy-control/xray-router"),
        xray_overlay: Path = Path("/opt/mtproxy-shared443/.env.xray-router"),
        xray_container: str = "proxy-control-xray-router",
        caddy_build_dir: Path = Path("/var/lib/proxy-control/version-agent/caddy-build"),
        caddy_image: str = "proxy-control/caddy-naive:agent",
    ):
        self.catalog_path = catalog_path
        self.state_path = state_path
        self.compose_dir = compose_dir
        self.compose_files = compose_files
        self.binary_paths = binary_paths or {}
        self.service_names = service_names or {}
        self.checkers = checkers or {}
        self.caddyfiles = caddyfiles or {}
        self.version_pins = version_pins or {}
        # component → (env overlay, key that pins the host binary by digest, Compose service)
        self.consumer_overlays = consumer_overlays or {}
        self.telemt_container = telemt_container
        self.downloader = downloader or _download
        self.runner = runner or _run
        self.health_timeout = health_timeout
        self.fetcher = fetcher
        self.upstream_enabled = upstream_enabled
        self.router_enabled = router_enabled
        self.clock = clock
        self.xray_bin_dir = xray_bin_dir
        self.xray_overlay = xray_overlay
        self.xray_container = xray_container
        self.caddy_build_dir = caddy_build_dir
        self.caddy_image = caddy_image
        self.check_all = _check_all
        self.lock_path = state_path.with_suffix(state_path.suffix + ".lock")

    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def _state(self) -> dict:
        return _load_state(self.state_path)

    def _save_state(self, state: dict) -> None:
        state["schema"] = 2
        _atomic_write(self.state_path, json.dumps(state, indent=2, sort_keys=True).encode())

    # ------------------------------------------------------------------
    # listing and the upstream check
    # ------------------------------------------------------------------

    def _components(self) -> tuple[str, ...]:
        return _ALL_COMPONENTS if self.router_enabled else _BASE_COMPONENTS

    @staticmethod
    def _component_state(state: dict, component: str) -> dict:
        current = state.get("components", {}).get(component, {})
        return current if isinstance(current, dict) else {}

    def _current_versions(self, state: dict) -> dict[str, str | None]:
        return {c: self._component_state(state, c).get("version") for c in self._components()}

    @staticmethod
    def _cached_probe(state: dict, component: str) -> dict:
        probe = state.get("upstream", {}).get("components", {}).get(component, {})
        return probe if isinstance(probe, dict) else {}

    def list_versions(self) -> dict:
        catalog = load_catalog(self.catalog_path)
        state = self._state()
        cached = state.get("upstream", {})
        checked_at = cached.get("checked_at")
        components = {}
        for component in self._components():
            current = self._component_state(state, component)
            entries = [entry.public() for entry in catalog.components.get(component, ())]
            seen = {entry["version"] for entry in entries}
            probe = self._cached_probe(state, component) if self.upstream_enabled else {}
            for candidate in probe.get("candidates", []):
                if isinstance(candidate, dict) and candidate.get("version") not in seen:
                    entries.append(dict(candidate))
                    seen.add(candidate["version"])
            components[component] = {
                "current": current.get("version"),
                "status": current.get("status", "ready"),
                "available": entries,
                "upstream": {
                    "checked_at": checked_at if self.upstream_enabled else None,
                    "latest": probe.get("latest"),
                    "installable": bool(probe.get("installable", False)),
                    "reason": probe.get("reason"),
                    "last_error": probe.get("last_error"),
                },
            }
        return {
            "enabled": True,
            "upstream_enabled": self.upstream_enabled,
            "checked_at": checked_at if self.upstream_enabled else None,
            "components": components,
        }

    def check_upstream(self, force: bool = False) -> dict:
        if not self.upstream_enabled:
            raise UpdateError("upstream check is disabled on this host")
        with self._locked():
            state = self._state()
            cached = state.get("upstream", {})
            now = int(self.clock())
            last = cached.get("checked_at")
            if (
                not force
                and isinstance(last, int)
                and 0 <= now - last < self.UPSTREAM_MIN_INTERVAL
            ):
                return self.list_versions()
            probes = self.check_all(
                self._current_versions(state),
                fetcher=self.fetcher or fetch_https,
                router_enabled=self.router_enabled,
            )
            previous_probes = cached.get("components", {})
            for component, probe in list(probes.items()):
                # A source that failed keeps its previous candidates; the error rides alongside.
                if probe.get("last_error") and isinstance(previous_probes.get(component), dict):
                    probes[component] = {**previous_probes[component], "last_error": probe["last_error"]}
            state["upstream"] = {"checked_at": now, "components": probes}
            self._save_state(state)
        return self.list_versions()

    def _resolve(self, component: str, version: str, state: dict) -> CatalogEntry:
        catalog = load_catalog(self.catalog_path)
        try:
            return catalog.entry(component, version)
        except CatalogError:
            pass
        if self.upstream_enabled:
            for candidate in self._cached_probe(state, component).get("candidates", []):
                if isinstance(candidate, dict) and candidate.get("version") == version:
                    raw = {k: v for k, v in candidate.items() if k not in ("tag", "published_at")}
                    entry = entry_from_dict(component, raw)
                    if entry.source != "upstream":
                        raise CatalogError("cached upstream candidate is malformed")
                    return entry
        raise CatalogError(f"version is not approved for {component}")

    # ------------------------------------------------------------------
    # update
    # ------------------------------------------------------------------

    def update(self, component: str, version: str, expected_current: str | None = None) -> dict:
        if component not in self._components():
            raise CatalogError("unsupported component")
        with self._locked():
            state = self._state()
            entry = self._resolve(component, version, state)
            current_data = self._component_state(state, component)
            state.setdefault("components", {})
            current = current_data.get("version")
            if current_data.get("status") == "rollback_failed":
                raise RollbackFailedError(
                    f"{component} has an unverified rollback; operator recovery is required"
                )
            if expected_current is not None and current != expected_current:
                raise ConflictError("runtime version changed; reload the versions page")
            if current == version:
                return {"component": component, "version": version, "changed": False}
            installed_sha256 = entry.sha256
            runtime_version = entry.runtime_version
            members: dict[str, str] | None = None
            try:
                if component == "telemt":
                    self._update_telemt(entry)
                elif component == "xray":
                    members = self._update_xray(entry, current)
                elif entry.kind == "build":
                    # Built on the host: the pin is whatever the fresh build reports,
                    # not something the catalog could know in advance.
                    payload, runtime_version = self._build_caddy(entry)
                    installed_sha256 = self._update_binary(
                        component, entry, payload=payload, runtime_version=runtime_version
                    )
                else:
                    installed_sha256 = self._update_binary(component, entry)
            except RollbackFailedError:
                failed = dict(current_data)
                failed["status"] = "rollback_failed"
                failed["failed_at"] = int(time.time())
                state["components"][component] = failed
                try:
                    self._save_state(state)
                except Exception as state_exc:
                    raise RollbackFailedError(
                        f"{component} rollback failed and the failure state could not be persisted"
                    ) from state_exc
                raise
            except UpdateError:
                raise
            except Exception as exc:
                raise UpdateError(f"{component} update failed") from exc
            state["components"][component] = {
                "version": version,
                "kind": entry.kind,
                "source": entry.source,
                "image": entry.image,
                "url": entry.url,
                "sha256": installed_sha256,
                "archive": entry.archive,
                "runtime_version": runtime_version,
                "updated_at": int(time.time()),
            }
            if members is not None:
                state["components"][component]["members"] = members
            if entry.build is not None:
                state["components"][component]["build"] = dict(entry.build)
            self._save_state(state)
            return {"component": component, "version": version, "changed": True}

    # ------------------------------------------------------------------
    # xray (the router's pinned bin-dir: xray, geoip.dat, geosite.dat)
    # ------------------------------------------------------------------

    XRAY_MODES = {"xray": 0o755, "geoip.dat": 0o644, "geosite.dat": 0o644}
    XRAY_KEYS = {
        "xray": "XRAY_ROUTER_XRAY_SHA256",
        "geoip.dat": "XRAY_ROUTER_GEOIP_SHA256",
        "geosite.dat": "XRAY_ROUTER_GEOSITE_SHA256",
    }

    def _xray_status(self) -> dict:
        """The manager's `/v1/status`, read over its own socket from inside the container."""
        output = self.runner(
            ["docker", "exec", self.xray_container, "python", "-m", "xray_router_manager.healthcheck", "--status"],
            timeout=30,
        )
        try:
            value = json.loads(output)
        except ValueError as exc:
            raise UpdateError("xray-router status is not JSON") from exc
        if not isinstance(value, dict):
            raise UpdateError("xray-router status is not an object")
        return value

    def _assert_xray_running(self, expected_version: str | None) -> None:
        status = self._xray_status()
        if status.get("phase") != "idle":
            raise UpdateError(f"xray-router is not idle: {status.get('phase') or 'unknown'}")
        reported = str(status.get("xray_version") or "")
        words = reported.split()
        running = words[1] if len(words) >= 2 and words[0] == "Xray" else ""
        if expected_version is not None and running != expected_version:
            raise UpdateError(f"xray-router runs {running or 'unknown'}, expected {expected_version}")

    def _update_xray(self, entry: CatalogEntry, previous_version: str | None) -> dict[str, str]:
        if (
            entry.kind != "binary"
            or not entry.url
            or not entry.sha256
            or not entry.archive
            or set(entry.archive.get("members", {})) != set(self.XRAY_MODES)
        ):
            raise UpdateError("xray entry must name the archive members")
        if self.xray_bin_dir.is_symlink() or not self.xray_bin_dir.is_dir():
            raise UpdateError("xray-router binary directory is missing")
        payload = self.downloader(entry.url)
        if sha256_bytes(payload) != entry.sha256:
            raise UpdateError("xray artifact SHA-256 mismatch")
        try:
            members = {
                name: extract_member(payload, entry.archive, path)
                for name, path in entry.archive["members"].items()
            }
        except ArtifactError as exc:
            raise UpdateError(f"xray archive: {exc}") from exc
        digests = {name: sha256_bytes(data) for name, data in members.items()}
        backup_dir = self.state_path.parent / "backups" / "xray.previous"
        backup_dir.mkdir(parents=True, exist_ok=True)
        existed: dict[str, bool] = {}
        for name in members:
            path = self.xray_bin_dir / name
            if path.is_symlink():
                raise UpdateError(f"refusing to replace symlink {path}")
            existed[name] = path.exists()
            if existed[name]:
                shutil.copyfile(path, backup_dir / name)
                os.chmod(backup_dir / name, self.XRAY_MODES[name])
        previous_overlay = self.xray_overlay.read_bytes() if self.xray_overlay.exists() else None
        try:
            for name, data in members.items():
                _atomic_write(self.xray_bin_dir / name, data, self.XRAY_MODES[name])
            self._fsync_directory(self.xray_bin_dir)
            for name, digest in digests.items():
                self._rewrite_env_line(self.xray_overlay, self.XRAY_KEYS[name], digest)
            self._compose_up("xray-router")
            self._assert_xray_running(entry.version)
        except Exception as exc:
            try:
                for name in members:
                    if existed[name]:
                        os.replace(backup_dir / name, self.xray_bin_dir / name)
                        os.chmod(self.xray_bin_dir / name, self.XRAY_MODES[name])
                    else:
                        (self.xray_bin_dir / name).unlink(missing_ok=True)
                self._fsync_directory(self.xray_bin_dir)
                self._restore_file(self.xray_overlay, previous_overlay, 0o600)
                self._compose_up("xray-router")
                self._assert_xray_running(previous_version)
            except Exception as rollback_exc:
                raise RollbackFailedError(
                    "xray update failed; restored generation could not be verified"
                ) from rollback_exc
            raise RolledBackError(
                "xray update failed; previous generation was restored and verified"
            ) from exc
        return digests

    def _fetch_binary(self, component: str, entry: CatalogEntry) -> bytes:
        """Download the catalog artifact, verify it, and unpack the named member if any."""
        payload = self.downloader(entry.url)
        if sha256_bytes(payload) != entry.sha256:
            raise UpdateError(f"{component} artifact SHA-256 mismatch")
        if entry.archive:
            member = entry.archive.get("member")
            if not member:
                raise UpdateError(f"{component} archive entry must name a single member")
            try:
                payload = extract_member(payload, entry.archive, member)
            except ArtifactError as exc:
                raise UpdateError(f"{component} archive: {exc}") from exc
        return payload

    def _update_binary(
        self,
        component: str,
        entry: CatalogEntry,
        *,
        payload: bytes | None = None,
        runtime_version: str | None = None,
    ) -> str:
        """Install `payload` (or the downloaded catalog artifact) as the component's binary; returns its SHA-256."""
        runtime_version = runtime_version or entry.runtime_version
        if payload is None and (entry.kind != "binary" or not entry.url or not entry.sha256):
            raise UpdateError("binary catalog entry is incomplete")
        if payload is not None and entry.kind not in ("binary", "build"):
            raise UpdateError("binary catalog entry is incomplete")
        target = self.binary_paths.get(component)
        service = self.service_names.get(component)
        if target is None or service is None:
            raise UpdateError(f"{component} runtime is not configured")
        if target.is_symlink():
            raise UpdateError(f"refusing to replace symlink {target}")
        if component in self.version_pins and not runtime_version:
            raise UpdateError(
                f"{component} catalog entry must set runtime_version to keep the startup check in sync"
            )
        consumer = self.consumer_overlays.get(component)
        if payload is None:
            payload = self._fetch_binary(component, entry)
        installed_sha256 = sha256_bytes(payload)
        target.parent.mkdir(parents=True, exist_ok=True)
        backup_dir = self.state_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / f"{component}.previous"
        existed = target.exists()
        previous_sha256 = self._sha256_file(target) if existed else None
        if existed:
            shutil.copyfile(target, backup)
            os.chmod(backup, target.stat().st_mode & 0o777)
        stage = target.with_name(f".{target.name}.proxy-control-new")
        pin = self.version_pins.get(component)
        previous_pin = pin.read_text().strip() if pin and pin.exists() else None
        previous_overlay: bytes | None = None
        overlay_touched = False
        try:
            _atomic_write(stage, payload, 0o755)
            self._run_binary_config_checks(component, stage, runtime_version)
            os.replace(stage, target)
            self._fsync_directory(target.parent)
            self._assert_binary_generation(target, installed_sha256)
            # Replacing the binary needs a restart: a reload re-reads the config
            # but keeps the running process, so the old build would stay live
            # while state.json already claimed the new version.
            self._write_pin(component, runtime_version)
            self._assert_pin(component, runtime_version)
            if consumer:
                # The consumer container pins the binary by digest through its env
                # overlay; it follows the new build before anything restarts.
                overlay_path, key, _service = consumer
                previous_overlay = self._rewrite_env_line(overlay_path, key, installed_sha256)
                overlay_touched = True
            self._restart_service_and_slots(service)
            if consumer:
                self._compose_up(consumer[2])
        except Exception as exc:
            try:
                if existed:
                    os.replace(backup, target)
                else:
                    target.unlink(missing_ok=True)
                self._fsync_directory(target.parent)
                self._restore_pin(component, previous_pin)
                self._assert_pin(component, previous_pin)
                if existed:
                    self._assert_binary_generation(target, previous_sha256)
                    self._run_binary_config_checks(component, target, previous_pin)
                if consumer and overlay_touched:
                    self._restore_file(consumer[0], previous_overlay, 0o600)
                self._restart_service_and_slots(service)
                if consumer:
                    self._compose_up(consumer[2])
            except Exception as rollback_exc:
                raise RollbackFailedError(
                    f"{component} update failed; restored generation could not be verified"
                ) from rollback_exc
            raise RolledBackError(
                f"{component} update failed; previous generation was restored and verified"
            ) from exc
        finally:
            stage.unlink(missing_ok=True)
        return installed_sha256

    def _build_caddy(self, entry: CatalogEntry) -> tuple[bytes, str]:
        """Build Caddy with the pinned forward-proxy commit from a digest-pinned builder image.

        Mirrors `docker/Dockerfile.caddy-naive` and the installer's extraction, so a build
        through the agent and a clean install produce the same kind of binary. Nothing on
        the host changes until the build succeeded and reported the expected version.
        """
        build = entry.build
        if not build:
            raise UpdateError("naive build entry is incomplete")
        self.caddy_build_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.caddy_build_dir, 0o700)
        dockerfile = self.caddy_build_dir / "Dockerfile"
        _atomic_write(
            dockerfile,
            (
                f"# Generated by proxy-control version-agent; do not edit manually.\n"
                f"FROM {build['builder_image']} AS builder\n"
                f"RUN xcaddy build v{build['caddy_version']} \\\n"
                f"    --with github.com/caddyserver/forwardproxy@caddy2="
                f"github.com/klzgrad/forwardproxy@{build['forwardproxy_commit']}\n"
                "FROM scratch\n"
                "COPY --from=builder /usr/bin/caddy /caddy\n"
            ).encode(),
            0o600,
        )
        self.runner(
            ["docker", "build", "-f", str(dockerfile), "-t", self.caddy_image, str(self.caddy_build_dir)],
            timeout=900,
        )
        container = self.runner(
            ["docker", "create", "--entrypoint", "/caddy", self.caddy_image, "version"], timeout=60
        ).strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise UpdateError("caddy build produced no container")
        extracted = self.caddy_build_dir / "caddy"
        try:
            self.runner(["docker", "cp", f"{container}:/caddy", str(extracted)], timeout=120)
        finally:
            self.runner(["docker", "rm", container], timeout=60)
        try:
            payload = extracted.read_bytes()
            os.chmod(extracted, 0o755)
            lines = self.runner([str(extracted), "version"], timeout=30).strip().splitlines()
        finally:
            extracted.unlink(missing_ok=True)
        runtime_version = lines[0].strip() if lines else ""
        if not runtime_version.startswith(f"v{build['caddy_version']} "):
            raise UpdateError(
                f"built Caddy reports {runtime_version or 'nothing'}, expected v{build['caddy_version']}"
            )
        return payload, runtime_version

    def _run_binary_config_checks(
        self, component: str, binary: Path, runtime_version: str | None
    ) -> None:
        checker = self.checkers.get(component)
        if checker:
            checker_env = {"CADDY_BIN": str(binary)}
            if runtime_version:
                checker_env["EXPECTED_CADDY_VERSION"] = runtime_version
            self.runner([str(checker)], env=checker_env)
        if component == "naive":
            caddyfile = self.caddyfiles.get(component)
            if caddyfile:
                self.runner(
                    [
                        str(binary),
                        "adapt",
                        "--adapter",
                        "caddyfile",
                        "--validate",
                        "--config",
                        str(caddyfile),
                    ]
                )

    def _assert_binary_generation(self, target: Path, expected_sha256: str | None) -> None:
        if expected_sha256 is None or not target.is_file():
            raise UpdateError("binary generation is missing")
        if self._sha256_file(target) != expected_sha256:
            raise UpdateError("binary generation readback did not match")

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _write_pin(self, component: str, runtime_version: str | None) -> None:
        """Keep the unit's startup check on the version the agent just installed.

        The check runs from ExecStartPre without the agent's environment, so a
        stale pin would refuse the new build on the next restart or reboot.
        """
        pin = self.version_pins.get(component)
        if pin is None or not runtime_version:
            return
        _atomic_write(pin, (runtime_version + "\n").encode(), 0o644)

    def _restore_pin(self, component: str, previous: str | None) -> None:
        pin = self.version_pins.get(component)
        if pin is None:
            return
        if previous is None:
            pin.unlink(missing_ok=True)
        else:
            _atomic_write(pin, (previous + "\n").encode(), 0o644)

    def _assert_pin(self, component: str, expected: str | None) -> None:
        pin = self.version_pins.get(component)
        if pin is None:
            return
        actual = pin.read_text().strip() if pin.exists() else None
        if actual != expected:
            raise UpdateError(f"{component} runtime pin readback did not match")

    @staticmethod
    def _rewrite_env_line(path: Path, key: str, value: str) -> bytes | None:
        """Set `key=value` in an env overlay in place, keeping the other lines; returns the previous bytes."""
        previous = path.read_bytes() if path.exists() else None
        lines = (previous or b"").decode("utf-8").splitlines()
        replaced = False
        result = []
        for line in lines:
            if line.startswith(key + "="):
                if not replaced:
                    result.append(f"{key}={value}")
                    replaced = True
                continue
            result.append(line)
        if not replaced:
            result.append(f"{key}={value}")
        mode = (path.stat().st_mode & 0o777) if previous is not None else 0o600
        _atomic_write(path, ("\n".join(result) + "\n").encode("utf-8"), mode)
        return previous

    @staticmethod
    def _restore_file(path: Path, previous: bytes | None, mode: int) -> None:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, previous, mode)

    def _slot_units(self, service: str) -> list[str]:
        """Instances `<service>@<n>` that are loaded (Mieru lanes), so they restart with the binary."""
        listed = self.runner(
            ["systemctl", "list-units", "--plain", "--no-legend", f"{service}@*.service"], timeout=30
        )
        units = []
        for line in listed.splitlines():
            name = line.split()[0] if line.split() else ""
            if name.startswith(f"{service}@") and name.endswith(".service"):
                units.append(name.removesuffix(".service"))
        return units

    def _restart_service_and_slots(self, service: str) -> None:
        self.runner(["systemctl", "restart", service], timeout=120)
        self.runner(["systemctl", "is-active", service], timeout=30)
        for unit in self._slot_units(service):
            self.runner(["systemctl", "restart", unit], timeout=120)
            self.runner(["systemctl", "is-active", unit], timeout=30)

    def _env_files(self) -> list[Path]:
        """The project env plus every protocol overlay present, in the installer's order."""
        if self.compose_dir is None:
            return []
        files = [self.compose_dir / ".env"]
        for sibling in ("naive", "mieru", "xray-router"):
            overlay = self.compose_dir / f".env.{sibling}"
            if overlay.is_file():
                files.append(overlay)
        return files

    def _compose_up(self, service: str) -> None:
        """Recreate one Compose service with the overlays it was installed with and wait for health."""
        override = self.compose_dir / "version-overrides" / "compose.versions.yaml" if self.compose_dir else None
        command = self._compose_command(
            "up", "-d", "--wait", service,
            include_override=bool(override and override.exists()),
            env_files=True,
        )
        self.runner(command, cwd=self.compose_dir, timeout=300)

    def _compose_command(
        self, *args: str, include_override: bool = True, env_files: bool = False
    ) -> list[str]:
        if self.compose_dir is None or not self.compose_files:
            raise UpdateError("Compose deployment is not configured")
        command = ["docker", "compose", "--project-name", "mtproxy"]
        if env_files:
            for env_file in self._env_files():
                command.extend(["--env-file", str(env_file)])
        for compose_file in self.compose_files:
            path = Path(compose_file)
            if path.is_absolute() or ".." in path.parts:
                raise UpdateError("invalid Compose file path")
            command.extend(["-f", str(self.compose_dir / path)])
        if include_override:
            command.extend(["-f", str(self.compose_dir / "version-overrides" / "compose.versions.yaml")])
        command.extend(args)
        return command

    def _update_telemt(self, entry: CatalogEntry) -> None:
        if entry.kind != "image" or not entry.image:
            raise UpdateError("Telemt catalog entry is incomplete")
        override = self.compose_dir / "version-overrides" / "compose.versions.yaml" if self.compose_dir else None
        if override is None:
            raise UpdateError("Telemt Compose deployment is not configured")
        previous = override.read_bytes() if override.exists() else None
        previous_image = self._inspect_telemt_image()
        content = (
            "# Generated by proxy-control version-agent; do not edit manually.\n"
            "services:\n"
            "  mtproxy:\n"
            f"    image: {entry.image}\n"
        ).encode()
        # Every Compose call carries the protocol overlays (`.env.naive`, `.env.mieru`,
        # `.env.xray-router`): the model includes their files, whose required variables
        # live only there — without them Compose refuses before touching anything (found
        # live on ams-test in v0.11).
        try:
            _atomic_write(override, content, 0o640)
            self.runner(
                self._compose_command("pull", "mtproxy", env_files=True), cwd=self.compose_dir, timeout=900
            )
            self.runner(
                self._compose_command("up", "-d", "--no-deps", "mtproxy", env_files=True),
                cwd=self.compose_dir,
                timeout=300,
            )
            self._verify_telemt_generation(entry.image)
        except Exception as exc:
            try:
                if previous is None:
                    override.unlink(missing_ok=True)
                    command = self._compose_command(
                        "up", "-d", "--no-deps", "mtproxy", include_override=False, env_files=True
                    )
                else:
                    _atomic_write(override, previous, 0o640)
                    command = self._compose_command("up", "-d", "--no-deps", "mtproxy", env_files=True)
                self.runner(command, cwd=self.compose_dir, timeout=300)
                self._verify_telemt_generation(previous_image)
            except Exception as rollback_exc:
                raise RollbackFailedError(
                    "Telemt update failed; restored generation could not be verified"
                ) from rollback_exc
            raise RolledBackError(
                "Telemt update failed; previous generation was restored and verified"
            ) from exc

    def _inspect_telemt_image(self) -> str:
        image = self.runner(
            ["docker", "inspect", "--format", "{{.Config.Image}}", self.telemt_container],
            timeout=30,
        ).strip()
        if not image:
            raise UpdateError("Telemt image readback was empty")
        return image

    def _verify_telemt_generation(self, expected_image: str) -> None:
        actual_image = self._inspect_telemt_image()
        if actual_image != expected_image:
            raise UpdateError("Telemt image readback did not match the selected generation")
        deadline = time.monotonic() + self.health_timeout
        status = ""
        while True:
            status = self.runner(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", self.telemt_container],
                timeout=30,
            ).strip()
            if status == "healthy":
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(1, remaining))
        raise UpdateError(f"Telemt health did not become healthy: {status or 'unknown'}")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _consumer_overlays(value: str) -> dict[str, tuple[Path, str, str]]:
    """Parse `component=<overlay path>:<env key>:<compose service>[,…]`."""
    result: dict[str, tuple[Path, str, str]] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        component, spec = part.split("=", 1)
        pieces = spec.rsplit(":", 2)
        if len(pieces) != 3 or not all(pieces):
            raise ValueError(f"invalid consumer overlay for {component}: expected path:key:service")
        result[component.strip()] = (Path(pieces[0]), pieces[1], pieces[2])
    return result


def _flag(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in ("on", "1", "true", "yes")


def agent_from_env() -> VersionAgent:
    def paths(prefix: str, default: str) -> dict[str, Path]:
        value = os.getenv(prefix, default)
        return {key: Path(item) for key, item in (part.split("=", 1) for part in value.split(",") if "=" in part)}

    compose_files = tuple(filter(None, os.getenv("PROXY_CONTROL_COMPOSE_FILES", "compose.yaml").split(":")))
    state_path = Path(os.getenv("PROXY_CONTROL_VERSION_STATE", "/var/lib/proxy-control/version-agent/state.json"))
    # buildx keeps its state under $DOCKER_CONFIG; the unit's ProtectHome leaves /root
    # read-only, so a build from the agent needs a writable config dir of its own.
    os.environ.setdefault("DOCKER_CONFIG", str(state_path.parent / "docker"))
    return VersionAgent(
        catalog_path=Path(os.getenv("PROXY_CONTROL_VERSION_CATALOG", "/etc/proxy-control/versions.json")),
        state_path=state_path,
        compose_dir=Path(os.getenv("PROXY_CONTROL_COMPOSE_DIR", "/opt/mtproxy-shared443")),
        compose_files=compose_files,
        binary_paths=paths("PROXY_CONTROL_BINARY_PATHS", "naive=/usr/local/bin/caddy,mita=/usr/bin/mita"),
        service_names={key: value for key, value in (part.split("=", 1) for part in os.getenv("PROXY_CONTROL_SERVICE_NAMES", "naive=caddy-naive,mita=mita").split(",") if "=" in part)},
        checkers=paths("PROXY_CONTROL_CHECKERS", "naive=/usr/local/libexec/check-naive-caddy-build"),
        caddyfiles=paths("PROXY_CONTROL_CADDYFILES", "naive=/var/lib/naive-manager/Caddyfile"),
        version_pins=paths("PROXY_CONTROL_VERSION_PINS", "naive=/etc/proxy-control/caddy-naive.pin"),
        consumer_overlays=_consumer_overlays(
            os.getenv(
                "PROXY_CONTROL_CONSUMER_OVERLAYS",
                "mita=/opt/mtproxy-shared443/.env.mieru:MIERU_MITA_SHA256:mieru-manager",
            )
        ),
        telemt_container=os.getenv("PROXY_CONTROL_TELEMT_CONTAINER", "proxy-control-mtproxy"),
        health_timeout=float(os.getenv("PROXY_CONTROL_VERSION_HEALTH_TIMEOUT", "60")),
        upstream_enabled=os.getenv("PROXY_CONTROL_UPSTREAM_CHECK", "on").strip().lower() != "off",
        router_enabled=_flag("PROXY_CONTROL_XRAY_ROUTER", "off"),
        xray_bin_dir=Path(os.getenv("PROXY_CONTROL_XRAY_BIN_DIR", "/usr/local/lib/proxy-control/xray-router")),
        xray_overlay=Path(os.getenv("PROXY_CONTROL_XRAY_OVERLAY", "/opt/mtproxy-shared443/.env.xray-router")),
        xray_container=os.getenv("PROXY_CONTROL_XRAY_CONTAINER", "proxy-control-xray-router"),
        caddy_build_dir=Path(
            os.getenv("PROXY_CONTROL_CADDY_BUILD_DIR", "/var/lib/proxy-control/version-agent/caddy-build")
        ),
    )
