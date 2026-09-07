"""Installer-owned official Cloudflare WARP in loopback proxy mode."""
from __future__ import annotations

import ipaddress
import hashlib
import os
import re
import stat
import secrets
import time
from pathlib import Path

from installer.model import InstallerConfig
from installer.planner import Action, AuditFacts, Evidence
from installer.transaction import atomic_write, durable_mkdir, durable_remove

VERSION = "2026.7.1377.0"
PACKAGE_URL = f"https://pkg.cloudflareclient.com/pool/noble/main/c/cloudflare-warp/cloudflare-warp_{VERSION}_amd64.deb"
PACKAGE_SHA256 = "a73429701c47ee9dc3c8307a0ead67054530787239bd71a12e7f93acdbe96f65"
KEY_SHA256 = "0f37fc298c98e88ee3c0ee68c95b69f1dba9eb477abe3167e13982105911264d"
KEY_PATH = "usr/share/keyrings/proxy-control-warp.asc"
REPO_PATH = "etc/apt/sources.list.d/proxy-control-warp.list"
REPO = b"deb [arch=amd64 signed-by=/usr/share/keyrings/proxy-control-warp.asc] https://pkg.cloudflareclient.com/ noble main\n"
TRACE = "https://www.cloudflare.com/cdn-cgi/trace"


class WarpError(RuntimeError):
    """WARP ownership or actual tunneled egress could not be verified."""


class WarpAdapter:
    name = "warp"
    requires = frozenset({"packages"})

    def __init__(self, *, root: Path = Path("/"), runner=None):
        self.root = Path(root)
        if runner is None:
            from installer.audit import CommandRunner
            runner = CommandRunner(timeout=900.0)
        self.runner = runner

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if not config.three_xui.warp:
            return ()
        if getattr(facts, "hard_stops", ()):
            raise WarpError("host audit contains blocking findings")
        return (Action(
            id="warp.runtime", adapter=self.name, owner="proxy-control:warp",
            mutations=(f"port={config.three_xui.warp_port}",),
            preconditions=("no foreign WARP package, registration or listener exists",),
            verification=("official WARP proxy returns a distinct tunneled external IP",),
            inverse=("remove only the installer-owned WARP package and registration",),
            credentials_required=False,
        ),)

    def _path(self, relative):
        path = self.root / relative
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise WarpError("WARP path crosses a symlink")
        return path

    def _version(self):
        result = self.runner.run(("dpkg-query", "-W", "-f=${Version}", "cloudflare-warp"))
        return result.stdout.strip() if result.returncode == 0 else None

    def _package_state(self):
        return self._run("dpkg-query", "-W", "-f=${db:Status-Status}", "cloudflare-warp").strip()

    def _port(self, action):
        if action.id != "warp.runtime" or action.owner != "proxy-control:warp":
            raise WarpError("invalid WARP action")
        values = dict(item.split("=", 1) for item in action.mutations)
        port = int(values["port"])
        if not 1024 <= port <= 65535:
            raise WarpError("invalid WARP port")
        return port

    def prepare(self, action):
        self._port(action)
        if self._version() is not None or any(self._path(p).exists() for p in (
            "var/lib/cloudflare-warp", KEY_PATH, REPO_PATH, "var/lib/proxy-control/warp"
        )):
            raise WarpError("foreign WARP installation or state requires explicit migration")
        return {"owner": action.owner, "marker": secrets.token_hex(16), "ownership": {}}

    def _pending_owner(self, checkpoint):
        nonce = checkpoint.get("marker")
        if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
            raise WarpError("invalid WARP ownership checkpoint")
        return self._path(f"var/lib/proxy-control/warp/.owner.{nonce}.tmp")

    def _check_unclaimed_stage(self, checkpoint):
        pending = self._pending_owner(checkpoint)
        if pending.parent.exists():
            if any(p != pending for p in pending.parent.iterdir()):
                raise WarpError("foreign WARP staging state appeared after planning")
            if pending.exists():
                info = pending.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                    raise WarpError("WARP pending owner is unsafe")
                if info.st_size > 32 or not checkpoint["marker"].encode().startswith(pending.read_bytes()):
                    raise WarpError("WARP pending owner drifted")
        return pending

    def _write_owner(self, marker, checkpoint):
        pending = self._check_unclaimed_stage(checkpoint)
        durable_mkdir(marker.parent, mode=0o700)
        fd = os.open(pending, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+b") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise WarpError("WARP pending owner is unsafe")
            if info.st_size > 32 or not checkpoint["marker"].encode().startswith(handle.read(33)):
                raise WarpError("WARP pending owner drifted")
            handle.seek(0)
            handle.write(checkpoint["marker"].encode())
            handle.truncate()
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        os.replace(pending, marker)
        from installer.transaction import fsync_directory
        fsync_directory(marker.parent)

    def _assert_owned(self, checkpoint):
        self._pending_owner(checkpoint)
        marker = self._path("var/lib/proxy-control/warp/owner")
        if marker.exists() and marker.read_text() != checkpoint.get("marker"):
            raise WarpError("WARP ownership drifted")
        return marker

    def _run(self, *argv):
        result = self.runner.run(tuple(argv))
        if result.returncode:
            raise WarpError(f"WARP command failed: {argv[0]} {argv[1] if len(argv)>1 else ''}")
        return result.stdout

    def _cli(self, deadline, *args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WarpError("WARP readiness deadline expired")
        from installer.audit import AuditError
        import subprocess
        try:
            return self.runner.run(("warp-cli", "--accept-tos", *args), timeout=min(5.0, remaining))
        except AuditError:
            return subprocess.CompletedProcess(args, 124, "", "")

    def _prepare_package(self):
        import tempfile
        # Every download gets a new private directory; never follow or truncate
        # a predictable leftover file, including a single-link symlink target.
        stage = Path(tempfile.mkdtemp(prefix="download-", dir=self._path("var/lib/proxy-control/warp")))
        key = stage / "key.asc"
        self._run("curl", "--fail", "--location", "--proto", "=https", "--max-time", "180", "--output", str(key), "https://pkg.cloudflareclient.com/pubkey.gpg")
        if hashlib.sha256(key.read_bytes()).hexdigest() != KEY_SHA256:
            raise WarpError("official Cloudflare signing key digest mismatch")
        atomic_write(self._path(KEY_PATH), key.read_bytes(), mode=0o644)
        atomic_write(self._path(REPO_PATH), REPO, mode=0o644)
        self._run("apt-get", "update")
        package = stage / "cloudflare-warp.deb"
        self._run("curl", "--fail", "--location", "--proto", "=https", "--max-time", "300", "--output", str(package), PACKAGE_URL)
        if hashlib.sha256(package.read_bytes()).hexdigest() != PACKAGE_SHA256:
            raise WarpError("official WARP package digest mismatch")
        return package

    def apply(self, action, checkpoint):
        port = self._port(action)
        marker = self._assert_owned(checkpoint)
        for relative, digest in ((KEY_PATH, KEY_SHA256), (REPO_PATH, hashlib.sha256(REPO).hexdigest())):
            path = self._path(relative)
            if path.exists() and (not marker.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                raise WarpError("WARP repository ownership drifted")
            if f"/{relative}" in checkpoint.get("ownership", {}) and not path.exists():
                raise WarpError("WARP repository ownership is missing")
        if not marker.exists():
            if self._version() is not None or any(self._path(p).exists() for p in ("var/lib/cloudflare-warp", KEY_PATH, REPO_PATH)):
                raise WarpError("foreign WARP package or state appeared after planning")
            self._check_unclaimed_stage(checkpoint)
            if self._listeners(port):
                raise WarpError("WARP proxy port is occupied")
            self._write_owner(marker, checkpoint)
        current = self._version()
        if current is None:
            package = self._prepare_package()
            self._run("apt-get", "install", "--yes", "--no-install-recommends", str(package))
        elif current != VERSION:
            raise WarpError("WARP package version drifted")
        if self._version() != VERSION:
            raise WarpError("WARP installation did not produce the pinned package")
        state = self._package_state()
        if state in {"unpacked", "half-configured"}:
            # Never configure unrelated packages with dpkg --configure -a.
            self._run("dpkg", "--configure", "cloudflare-warp")
        if self._package_state() != "installed":
            raise WarpError("WARP package is not fully configured")
        self._run("systemctl", "enable", "--now", "warp-svc")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            registration = self._cli(deadline, "registration", "show")
            if registration.returncode == 0:
                break
            if self._cli(deadline, "registration", "new").returncode == 0:
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        else:
            raise WarpError("WARP registration readiness deadline expired")
        for command in (("mode", "proxy"), ("proxy", "port", str(port)), ("connect",)):
            if self._cli(deadline, *command).returncode:
                raise WarpError("WARP proxy configuration failed")
        while time.monotonic() < deadline:
            status = self._cli(deadline, "status")
            if status.returncode == 0 and "Status update: Connected" in status.stdout.splitlines():
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        else:
            raise WarpError("WARP did not connect within 90 seconds")
        ownership = {"/var/lib/proxy-control/warp/owner": hashlib.sha256(checkpoint["marker"].encode()).hexdigest()}
        for relative, digest in ((KEY_PATH, KEY_SHA256), (REPO_PATH, hashlib.sha256(REPO).hexdigest())):
            if self._path(relative).exists():
                ownership[f"/{relative}"] = digest
        return {**checkpoint, "ownership": ownership}

    reconcile_apply = apply
    repair = apply

    def _listeners(self, port):
        rows = []
        for line in self._run("ss", "-H", "-ltnp").splitlines():
            fields = line.split()
            if len(fields) < 5:
                raise WarpError("cannot parse host listeners")
            address, _, value = fields[3].rpartition(":")
            if value == str(port):
                rows.append((address.strip("[]"), line))
        return rows

    def _assert_listener(self, port):
        rows = self._listeners(port)
        if not rows or not any(address == "127.0.0.1" for address, _ in rows):
            raise WarpError("WARP loopback listener is absent")
        if any(address not in {"127.0.0.1", "::1"} or '("warp-svc",pid=' not in row for address, row in rows):
            raise WarpError("WARP listener is public or foreign")

    def verify(self, action):
        port = self._port(action)
        if self._version() != VERSION or self._package_state() != "installed":
            raise WarpError("WARP package is not fully installed at the pinned version")
        for check, expected in (("is-active", "active"), ("is-enabled", "enabled")):
            if self._run("systemctl", check, "warp-svc").strip() != expected:
                raise WarpError("WARP service is not active and enabled")
        self._assert_listener(port)
        direct = self._run("curl", "--fail", "--silent", "--show-error", "--noproxy", "*", "--max-time", "30", TRACE)
        proxied = self._run("curl", "--fail", "--silent", "--show-error", "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{port}", "--max-time", "30", TRACE)
        self.validate_egress(direct, proxied)
        return Evidence(action_id=action.id, success=True,
            observations=("official WARP has distinct tunneled egress",),
            details={"port": port, "distinct_egress": True})

    def rollback(self, action, checkpoint, *, purge_data=False, rollback_target="rolled_back"):
        self._port(action)
        marker = self._assert_owned(checkpoint)
        owned_paths = []
        for relative, digest in ((KEY_PATH, KEY_SHA256), (REPO_PATH, hashlib.sha256(REPO).hexdigest())):
            path = self._path(relative)
            if path.exists():
                if not marker.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise WarpError("WARP repository ownership drifted")
                owned_paths.append(path)
        state = self._path("var/lib/cloudflare-warp")
        if not marker.exists():
            if state.exists() or self._version() is not None:
                raise WarpError("WARP state exists without ownership marker")
            pending = self._check_unclaimed_stage(checkpoint)
            durable_remove(pending, missing_ok=True)
        if marker.exists():
            current = self._version()
            if current not in (None, VERSION):
                raise WarpError("foreign WARP package version prevents rollback")
            if current is not None:
                stopped = self.runner.run(("systemctl", "disable", "--now", "warp-svc"))
                if stopped.returncode:
                    # A partial purge can remove the unit before postrm finishes.
                    # Do not swallow permission, bus, or genuine stop failures.
                    status = self._run("systemctl", "show", "warp-svc", "--property=LoadState,ActiveState")
                    properties = dict(line.split("=", 1) for line in status.splitlines() if "=" in line)
                    if properties != {"LoadState": "not-found", "ActiveState": "inactive"}:
                        raise WarpError("WARP service could not be safely stopped")
                self._run("apt-get", "purge", "--yes", "cloudflare-warp")
            if self._version() is not None:
                raise WarpError("WARP package remains after rollback")
            for path in owned_paths:
                durable_remove(path)
            durable_remove(state, missing_ok=True)
            # Keep proof of ownership until every other artifact is durable-gone.
            for child in marker.parent.iterdir():
                if child != marker:
                    durable_remove(child)
            from installer import transaction as tx
            for relative in (KEY_PATH, REPO_PATH, "var/lib/cloudflare-warp"):
                parent = self._path(relative).parent
                if parent.exists():
                    tx.fsync_directory(parent)
            durable_remove(marker)
        if self._version() is not None:
            raise WarpError("WARP package remains after rollback")
        if marker.parent.exists():
            # Also finishes a crash after owner unlink but before directory removal.
            if any(marker.parent.iterdir()):
                raise WarpError("WARP cleanup left unexpected state")
            durable_remove(marker.parent)
        return Evidence(action_id=action.id, success=True, observations=("owned WARP removed",), details={})

    reconcile_rollback = rollback

    @staticmethod
    def validate_egress(direct: str, proxied: str) -> bool:
        def parse(text):
            return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        a, b = parse(direct), parse(proxied)
        try:
            ips = ipaddress.ip_address(a["ip"]), ipaddress.ip_address(b["ip"])
        except (KeyError, ValueError) as exc:
            raise WarpError("egress trace did not contain valid IP addresses") from exc
        if ips[0] == ips[1] or b.get("warp") not in {"on", "plus"}:
            raise WarpError("WARP did not provide a distinct tunneled egress")
        return True
