#!/usr/bin/env python3
"""Fleet v2 end to end on the lab host (v0.3 spec §10 «Тестирование», §11 acceptance).

Runs as root on the host that carries the installed node panel. It starts a second,
in-process «central» panel from the source tree under test, links the node to it over
HTTPS with a scoped `node-sync` key, and drives the whole operator flow through the
public API only — every claim below is a status code, a byte a real client received, or
a row the node's own API reports:

   1. central up: database, master key, owner, uvicorn on 127.0.0.1;
   2. node key: a `node-sync` API key on the node, the node is unmastered;
   3. fingerprint + test + link (`tls_verify=pin`): `online` within 10 s, `node.up`;
   4. import: every runtime user the node has becomes the central's, untouched;
   5. grants: a client with MTProxy + NaiveProxy + Mieru on the node, `enabled` within
      30 s; the subscription feeds carry traffic through sing-box (naive) and mihomo
      (mieru, TCP + UDP), the MTProxy secret passes the TDLib resPQ probe;
   6. disable → the runtime refuses each client; rotate → the old credential fails, the
      new one works; delete → the account is gone and the grant is purged;
   7. offline convergence: a grant issued while the node's panel is stopped is applied
      once it is back;
   8. restart mid-apply: twenty grants, the node's panel restarted a second later,
      convergence without duplicates;
   9. key revoke: the link goes `offline` with `node.down`; a new key relinks it;
  10. cleanup + unlink: the node ends exactly as found — users, ownership, master, keys;
  11. central down (`--cleanup` also removes its directory).

Nothing here prints a key, a password, a token or a link. The report is a JSON object
of booleans, counts and short details; the exit code is non-zero when a check failed.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
# The same pinned cores subscription-acceptance was proven with on the stand (v0.2 Task 19A).
SINGBOX_IMAGE = "ghcr.io/sagernet/sing-box@sha256:4bed9332a0013fef72c31200a84e8fc0ed91a5ab2fe373a69f0acbbbbfbef3c5"
MIHOMO_IMAGE = "metacubex/mihomo@sha256:baf38d282b785d7037337676714a69e3fdd1f2d9bf748dfd25fce681a624ea74"
PROTOCOLS = ("mtproxy", "naive", "mieru")
# The node's own listing per protocol (owner session), the way the node UI sees it.
NODE_LISTS = {"mtproxy": "/api/users", "naive": "/api/naive/users", "mieru": "/api/mieru/users"}
CLIENT_NAME = "fleet-probe"
KEY_NAME_PREFIX = "fleet-lab-"
# The Naive and Mieru managers tombstone every deleted username for good (accounting
# history stays attributable), so a run never reuses a runtime username: each one carries
# the run's own suffix, and residue of an earlier run is recognised by this shape.
RUN_USERNAME = re.compile(r"^fleet-(probe|offline|bulk)(-[0-9a-f]{6})?(-[0-9]{2})?$")
# Deadlines from the brief (online 10 s, enabled 30 s) and for the steps that restart
# the node's panel container, which has to boot before it can report anything.
ONLINE_SECONDS = 10
ENABLED_SECONDS = 30
RESTART_SECONDS = 240
POLL = 1.0
_SECRET_SHAPES = (
    re.compile(r"tg://proxy\?"), re.compile(r"secret=[0-9a-fA-F]"), re.compile(r"pc_[0-9a-f]{8}_[A-Za-z0-9_-]{20,}"),
    re.compile(r"naive\+https://"), re.compile(r"mierus://"), re.compile(r"/s/[A-Za-z0-9_-]{43,}"),
    re.compile(r"\b[0-9a-f]{32}\b"),
)


def _load_sibling(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# `Panel`'s cookie/CSRF handling, `fetch`, `check`-style reporting and the real cores
# (`core_checks`) come from the subscription acceptance; this script adds the fleet flow.
_subscription = _load_sibling("subscription-acceptance")
Check = _subscription.Check
core_checks = _subscription.core_checks
fetch = _subscription.fetch


# --- arguments -------------------------------------------------------------------------

def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--node-url", required=True, help="the installed node panel, e.g. https://panel.lab.test")
    parser.add_argument("--node-password-file", required=True, type=Path,
                        help="the node owner's password: the installer's secrets/panel-bootstrap-password (one line), "
                             "the wizard's install.credentials (TOML) or a credentials/handoff.json")
    parser.add_argument("--node-username", default="owner", help="overridden by panel_username in a TOML file")
    parser.add_argument("--node-container", default="proxy-control-panel", help="the node panel's Docker container")
    parser.add_argument("--central-dir", required=True, type=Path, help="state of the in-process central panel")
    parser.add_argument("--central-host", default="127.0.0.1")
    parser.add_argument("--central-port", type=int, default=8791)
    parser.add_argument("--python", default=sys.executable, help="interpreter that starts the central (uvicorn, FastAPI)")
    parser.add_argument("--source", type=Path, default=REPO_ROOT, help="tree whose `panel` package the central imports")
    parser.add_argument("--output", required=True, type=Path, help="directory for report.json, feeds and the central log")
    parser.add_argument("--singbox-image", default=SINGBOX_IMAGE, help="pinned sing-box image for naive; empty skips")
    parser.add_argument("--mihomo-image", default=MIHOMO_IMAGE, help="pinned mihomo image for mieru; empty skips")
    parser.add_argument("--mtproxy-probe", default="/usr/local/libexec/mtproxy-respq-probe",
                        help="the installer's TDLib resPQ probe; empty skips the MTProxy client check")
    parser.add_argument("--mtproxy-domain", default="proxy.lab.test", help="the node's MTProxy (Fake-TLS) domain")
    parser.add_argument("--client-ca-file", default=None, type=Path,
                        help="CA the node session and the client cores trust in addition to / instead of the system "
                             "store (the lab's own CA); unset = WebPKI")
    parser.add_argument("--heartbeat-seconds", type=int, default=3, help="PANEL_FLEET_HEARTBEAT_SECONDS of the central")
    parser.add_argument("--bulk-grants", type=int, default=20, help="grants issued before the restart in step 8")
    parser.add_argument("--allow-private-address", action="store_true", help="the node URL is a private/lab address")
    parser.add_argument("--cleanup", action="store_true", help="remove --central-dir at the end")
    args = parser.parse_args(argv)
    args.source = Path(args.source).resolve()
    # Docker bind mounts (the cores read their config from here) need an absolute path.
    args.output = Path(args.output).resolve()
    args.central_dir = Path(args.central_dir).resolve()
    return args


def read_node_credentials(path: Path, default_username: str) -> tuple[str, str]:
    """(username, password) from whatever the installation left behind: a one-line
    bootstrap password, the wizard's TOML, or the root-only JSON handoff."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        raise Check(f"{path} holds no password")
    if stripped.startswith("{"):
        document = json.loads(stripped)
        credentials = document.get("credentials") if isinstance(document, dict) else None
        if not isinstance(credentials, dict):
            raise Check(f"{path} is not a credentials handoff")
        for label, value in credentials.items():
            if "password" in label and isinstance(value, str) and value:
                return default_username, value
        raise Check(f"{path} names no panel password")
    if "=" in stripped and re.search(r"^\s*panel_password\s*=", text, re.MULTILINE):
        document = tomllib.loads(text)
        password = document.get("panel_password")
        if not isinstance(password, str) or not password:
            raise Check(f"{path} names no panel password")
        username = document.get("panel_username")
        return (username if isinstance(username, str) and username else default_username), password
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise Check(f"{path} is neither a one-line password nor a credentials file")
    return default_username, lines[0].rstrip("\r\n")


def mtproxy_secret(link: str) -> str:
    """The 32-hex Telemt secret inside a `tg://proxy` link: a Fake-TLS one is `ee` + secret +
    hex(domain); a bare secret is taken as it is (the probe adds the Fake-TLS framing)."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
    value = (query.get("secret") or [""])[0]
    if value.startswith("ee") and re.fullmatch(r"[0-9a-fA-F]{32}", value[2:34]) and len(value) > 34:
        return value[2:34].lower()
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return value.lower()
    raise Check("the MTProxy link does not carry a Telemt secret")


def describe_artifact(value: str) -> dict:
    """What a client would receive, without the credential: host, port and the shape of
    the secret — enough to tell a Fake-TLS link from a bare one, and the right port from
    a default one."""
    parts = urllib.parse.urlsplit(value)
    query = urllib.parse.parse_qs(parts.query)
    if parts.scheme == "tg":
        secret = (query.get("secret") or [""])[0]
        return {"scheme": "tg", "server": (query.get("server") or [""])[0], "port": (query.get("port") or [""])[0],
                "secret_length": len(secret), "fake_tls": secret.startswith("ee") and len(secret) > 34}
    described = {"scheme": parts.scheme, "host": parts.hostname or "", "port": parts.port,
                 "username": parts.username or "", "password_length": len(parts.password or "")}
    if parts.scheme == "mierus":
        described["port"] = (query.get("port") or [""])[0]
        described["protocol"] = (query.get("protocol") or [""])[0]
    return described


def central_environment(args: argparse.Namespace) -> dict[str, str]:
    """The central manages the node's runtimes, never its own: every local manager is
    disabled or pointed at nothing, so the process needs only the source tree."""
    central = Path(args.central_dir)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(args.source),
        "PYTHONUNBUFFERED": "1",
        "PANEL_DATABASE": str(central / "panel.sqlite3"),
        "PANEL_MASTER_KEY_FILE": str(central / "master-key"),
        "PANEL_ALLOWED_HOSTS": f"{args.central_host},localhost",
        "PANEL_COOKIE_SECURE": "false",
        "NAIVE_ENABLED": "false",
        "MIERU_ENABLED": "false",
        "PANEL_FLEET_HEARTBEAT_SECONDS": str(args.heartbeat_seconds),
        "PANEL_SUBSCRIPTION_URL": f"http://{args.central_host}:{args.central_port}",
        "PANEL_VERSION_FILE": str(args.source / "VERSION"),
        # Nothing listens here; the Telemt client is created lazily and only fails per request.
        "TELEMT_API_URL": "http://127.0.0.1:1",
        "TELEMT_API_TOKEN": "unused",
        "NAIVE_MANAGER_SOCKET": str(central / "no-naive.sock"),
        "MIERU_MANAGER_SOCKET": str(central / "no-mieru.sock"),
        "VERSION_AGENT_SOCKET": str(central / "no-version-agent.sock"),
    }


def assert_secret_free(document) -> None:
    """The report may name lengths, counts and prefixes — never a credential shape."""
    def walk(value, path):
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        elif isinstance(value, str):
            for shape in _SECRET_SHAPES:
                if shape.search(value):
                    raise Check(f"report would carry a secret-shaped value at {path}")

    walk(document, "report")


def redact(value):
    """Details are error texts from panels, cores and probes: anything shaped like a
    credential in them is blanked before the report is written."""
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        for shape in _SECRET_SHAPES:
            value = shape.sub("[REDACTED]", value)
        return value
    return value


def leaf_fingerprint(host: str, port: int, *, timeout: float = 5.0) -> str:
    """SHA-256 of the certificate the node presents, chain unverified — what pin mode pins."""
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


# --- the two panels --------------------------------------------------------------------

class Panel:
    """Cookie session (CSRF header on writes) or Bearer key against one panel base URL."""

    def __init__(self, base_url: str, *, bearer: str | None = None, timeout: float = 30.0,
                 ca_file: Path | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer, self.timeout, self.ca_file = bearer, timeout, ca_file
        self.jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context()
        if ca_file is not None:
            # The lab's own CA next to the system store: the node's certificate chains to it,
            # and the host's trust store is not this script's to rely on.
            context.load_verify_locations(cafile=str(ca_file))
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def with_bearer(self, token: str) -> Panel:
        return Panel(self.base_url, bearer=token, timeout=self.timeout, ca_file=self.ca_file)

    def _csrf(self) -> str:
        return next((c.value for c in self.jar if c.name == "panel_csrf"), "")

    def request(self, path: str, *, method: str = "GET", payload=None, headers: dict | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        sent = {"Content-Type": "application/json"} if data is not None else {}
        if self.bearer:
            sent["Authorization"] = f"Bearer {self.bearer}"
        elif method != "GET":
            sent["X-CSRF-Token"] = self._csrf()
        sent.update(headers or {})
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=sent, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def json(self, path: str, *, method: str = "GET", payload=None, expect=(200, 201)):
        status, _, body = self.request(path, method=method, payload=payload)
        if status not in expect:
            detail = ""
            with contextlib.suppress(ValueError):
                detail = json.loads(body).get("detail", "") if body else ""
            raise Check(f"{method} {self.base_url}{path} -> {status} {str(detail)[:200]}")
        return json.loads(body) if body else {}

    def login(self, username: str, password: str) -> None:
        status, _, _ = self.request("/login")
        if status != 200 or not self._csrf():
            raise Check(f"{self.base_url}/login did not set the CSRF cookie ({status})")
        self.json("/api/auth/login", method="POST", payload={"username": username, "password": password},
                  expect=(200, 204))
        me = self.json("/api/auth/me")
        if me.get("username") != username:
            raise Check(f"login on {self.base_url} did not yield the {username} session")


# --- host-side collaborators (all replaceable by fakes) --------------------------------

class CentralProcess:
    """One uvicorn serving `panel.app:create_app` from `--source`, detached in its own session."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.directory = Path(args.central_dir)
        self.log = self.directory / "central.log"
        self.pid_file = self.directory / "central.pid"
        self.process: subprocess.Popen | None = None

    def _cli(self, *argv: str, stdin: str | None = None) -> None:
        completed = subprocess.run(
            [self.args.python, "-m", "panel.cli", "--database", str(self.directory / "panel.sqlite3"), *argv],
            cwd=self.args.source, env=central_environment(self.args), input=stdin, text=True,
            capture_output=True, timeout=120, check=False,
        )
        if completed.returncode != 0:
            raise Check(f"panel.cli {argv[0]} failed: {completed.stderr.strip()[-400:]}")

    def _stop_stale(self) -> None:
        if not self.pid_file.exists():
            return
        with contextlib.suppress(ValueError, OSError):
            _terminate(int(self.pid_file.read_text().strip()))
        self.pid_file.unlink(missing_ok=True)

    def start(self, owner_password: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        self._stop_stale()
        for name in ("panel.sqlite3", "panel.sqlite3-wal", "panel.sqlite3-shm", "master-key", "central.log"):
            (self.directory / name).unlink(missing_ok=True)
        self._cli("master-key-init", "--path", str(self.directory / "master-key"))
        self._cli("create-admin", "--username", "owner", "--role", "owner", "--password-stdin",
                  stdin=owner_password + "\n")
        with self.log.open("ab") as log:
            self.process = subprocess.Popen(
                # `--no-access-log` as in panel/entrypoint.sh: `/s/{token}` and `/api/reveal/{token}`
                # are bearer credentials, and an access line would be a copy of them.
                [self.args.python, "-m", "uvicorn", "panel.app:create_app", "--factory",
                 "--host", self.args.central_host, "--port", str(self.args.central_port), "--log-level", "info",
                 "--no-access-log"],
                cwd=self.args.source, env=central_environment(self.args), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
        self.pid_file.write_text(f"{self.process.pid}\n")

    def stop(self) -> None:
        if self.process is not None:
            _terminate(self.process.pid, self.process)
            self.pid_file.unlink(missing_ok=True)

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def collect_log(self, destination: Path) -> str:
        """Copy the central's log next to the report; returns its text for the token scan."""
        if not self.log.exists():
            return ""
        shutil.copyfile(self.log, destination)
        return self.log.read_text(errors="replace")


def _terminate(pid: int, process: subprocess.Popen | None = None, grace: float = 10.0) -> None:
    """SIGTERM the process (never a pattern: a `pkill -f` over SSH kills the session too)."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if process is not None:
            if process.poll() is not None:
                return
        else:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
        time.sleep(0.2)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    if process is not None:
        process.wait(timeout=5)


class Docker:
    def _run(self, *argv: str) -> None:
        completed = subprocess.run(["docker", *argv], capture_output=True, text=True, timeout=180, check=False)
        if completed.returncode != 0:
            raise Check(f"docker {' '.join(argv)} failed: {completed.stderr.strip()[-300:]}")

    def stop(self, name: str) -> None:
        self._run("stop", name)

    def start(self, name: str) -> None:
        self._run("start", name)

    def restart(self, name: str) -> None:
        self._run("restart", name)


class Probes:
    """The real clients: sing-box and mihomo loaded from the feeds in a directory, and the
    installer's TDLib resPQ probe with one secret."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.enabled = bool(args.singbox_image or args.mihomo_image or args.mtproxy_probe)

    def cores(self, feeds_dir: Path) -> dict:
        if not (self.args.singbox_image or self.args.mihomo_image):
            return {}
        return core_checks(feeds_dir, singbox_image=self.args.singbox_image, mihomo_image=self.args.mihomo_image,
                           ca_file=self.args.client_ca_file)

    def mtproxy(self, secret: str) -> tuple[bool, str]:
        if not self.args.mtproxy_probe:
            return True, "skipped"
        descriptor, name = tempfile.mkstemp(prefix="fleet-respq-")
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(f"{CLIENT_NAME}={secret}\n")
            completed = subprocess.run(
                [self.args.mtproxy_probe, "--domain", self.args.mtproxy_domain, "--secrets-file", name],
                capture_output=True, text=True, timeout=180, check=False,
            )
        finally:
            os.unlink(name)
        detail = (completed.stdout + completed.stderr).strip()[-300:]
        return completed.returncode == 0, re.sub(r"[0-9a-fA-F]{32,}", "[REDACTED]", detail)


# --- the scenario ----------------------------------------------------------------------

class Scenario:
    def __init__(self, args, *, node: Panel, central: Panel, process, docker, probes, clock=time,
                 fingerprint=leaf_fingerprint, fetch=fetch) -> None:
        self.args, self.node, self.central = args, node, central
        self.process, self.docker, self.probes, self.clock = process, docker, probes, clock
        self.fingerprint, self.fetch = fingerprint, fetch
        self.output = Path(args.output)
        self.report: dict = {"checks": {}, "details": {}, "counts": {}, "cleanup": []}
        self.node_bearer: Panel | None = None
        self.node_id: str | None = None
        self.key_ids: list[int] = []
        self.client_id: str | None = None
        self.initial_users: dict[str, list[str]] = {}
        self.usernames: set[str] = set()
        self.subscription_url: str | None = None
        self.started = None
        self.run_id = secrets.token_hex(3)
        self.probe_user = f"fleet-probe-{self.run_id}"

    # --- reporting ---

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        self.report["checks"][name] = bool(condition)
        if not condition:
            self.report["details"][name] = str(detail)[:600]
        return bool(condition)

    def wait(self, predicate, seconds: float, what: str):
        """Poll `predicate` until it returns a truthy value or `seconds` pass; returns
        (value, elapsed). A predicate raising `Check` (a panel that is down) keeps polling."""
        deadline = self.clock.monotonic() + seconds
        started = self.clock.monotonic()
        last = None
        while True:
            try:
                last = predicate()
            except (Check, urllib.error.URLError, OSError, ValueError) as exc:
                last = None
                self.report["details"].setdefault(f"wait:{what}", str(exc)[:200])
            if last:
                return last, round(self.clock.monotonic() - started, 1)
            if self.clock.monotonic() >= deadline:
                return None, round(self.clock.monotonic() - started, 1)
            self.clock.sleep(POLL)

    # --- node views ---

    def node_users(self) -> dict[str, list[str]]:
        return {protocol: sorted(item["username"] for item in self.node.json(path)["items"])
                for protocol, path in NODE_LISTS.items()}

    def node_enabled(self, protocol: str, username: str):
        for item in self.node.json(NODE_LISTS[protocol])["items"]:
            if item["username"] == username:
                return item.get("enabled") is not False
        return None

    def node_delete_user(self, protocol: str, username: str) -> int:
        """Remove one runtime user through the node's own API (only names this script made)."""
        payload = None
        if protocol == "mieru":
            # mita is optimistic: a write names the service revision it was decided on.
            revision = (self.node.json(NODE_LISTS["mieru"]).get("service") or {}).get("revision")
            payload = {"expected_revision": str(revision)}
        status, _, _ = self.node.request(f"{NODE_LISTS[protocol]}/{username}", method="DELETE", payload=payload)
        return status

    def node_inventory(self) -> dict[str, list[dict]]:
        return self.node_bearer.json("/api/fleet/v2/inventory")["protocols"]

    def node_identity(self) -> dict:
        return self.node_bearer.json("/api/fleet/v2/identity")

    def node_view(self) -> dict:
        return self.central.json(f"/api/nodes/{self.node_id}")

    def link_status(self) -> str:
        return self.node_view()["link"]["status"]

    def converged(self) -> bool:
        link = self.node_view()["link"]
        return (link["status"] == "online" and not link["config_dirty"]
                and link["acknowledged_generation"] == link["desired_generation"])

    def grants(self) -> list[dict]:
        return self.central.json(f"/api/clients/{self.client_id}")["grants"]

    def grants_in(self, states: tuple[str, ...], names: set[str] | None = None) -> bool:
        rows = [g for g in self.grants() if names is None or g["runtime_username"] in names]
        return bool(rows) and all(g["observed_state"] in states for g in rows)

    def events(self, name: str) -> int:
        items = self.central.json("/api/events?limit=500")["items"]
        return sum(1 for item in items if item["name"] == name)

    # --- steps ---

    def step_01_central_up(self) -> None:
        password = secrets.token_urlsafe(24)  # memory only; never written anywhere
        self.process.start(password)
        ready, elapsed = self.wait(lambda: self.central.request("/healthz")[0] == 200, 60, "central healthz")
        if not self.check("s01_central_started", bool(ready), f"no /healthz after {elapsed}s"):
            raise Check("the central did not start; see central.log")
        self.central.login("owner", password)
        self.check("s01_central_owner_login", self.central.json("/api/auth/me").get("username") == "owner")

    def step_02_node_key(self) -> None:
        username, password = read_node_credentials(self.args.node_password_file, self.args.node_username)
        self.node.login(username, password)
        me = self.node.json("/api/auth/me")
        self.check("s02_node_login", me.get("username") == username and me.get("role") == "owner", json.dumps(me)[:120])
        self._remove_residue()
        self.initial_users = self.node_users()
        self.report["counts"]["node_users_initial"] = {p: len(v) for p, v in self.initial_users.items()}
        created = self.node.json("/api/keys", method="POST",
                                 payload={"name": f"{KEY_NAME_PREFIX}{secrets.token_hex(3)}", "scope": "node-sync",
                                          "expires_at": None})
        plaintext = created["plaintext"]
        self.key_ids.append(created["key"]["id"])
        self.report["counts"]["node_key_length"] = len(plaintext)
        self.check("s02_node_key_created", plaintext.startswith("pc_") and created["key"]["scope"] == "node-sync")
        self.node_bearer = self.node.with_bearer(plaintext)
        identity = self.node_identity()
        self.report["node_guid_length"] = len(identity.get("guid") or "")
        if identity.get("master_guid"):
            # Residue of an interrupted run: the node's owner releases it (spec §5.2).
            self.node.json("/api/nodes/local/unlink", method="POST")
            self.report["cleanup"].append("stale master released on the node")
            identity = self.node_identity()
        self.check("s02_node_unmastered_initially", identity.get("master_guid") is None and identity.get("api_version") == 2)
        self._key_plaintext = plaintext

    def _remove_residue(self) -> None:
        """A previous run that died leaves its accounts and keys behind; only names this
        script itself creates are ever touched."""
        removed = []
        for protocol, path in NODE_LISTS.items():
            for item in self.node.json(path)["items"]:
                if RUN_USERNAME.match(item["username"]):
                    removed.append(f"{protocol}:{item['username']}:{self.node_delete_user(protocol, item['username'])}")
        for key in self.node.json("/api/keys")["items"]:
            if str(key.get("name", "")).startswith(KEY_NAME_PREFIX):
                self.node.json(f"/api/keys/{key['id']}", method="DELETE")
                removed.append(f"key:{key['id']}")
        if removed:
            self.report["cleanup"].append(f"stale residue removed: {' '.join(removed)}")

    def step_03_link(self) -> None:
        parts = urllib.parse.urlsplit(self.args.node_url)
        expected = self.fingerprint(parts.hostname, parts.port or 443)
        digest = self.central.json("/api/nodes/fingerprint", method="POST", payload={"url": self.args.node_url})["sha256"]
        self.check("s03_fingerprint_matches_leaf", digest == expected, f"{digest[:12]} != {expected[:12]}")
        common = {"url": self.args.node_url, "tls_verify": "pin", "pinned_sha256": digest,
                  "allow_private_address": self.args.allow_private_address}
        probe = self.central.json("/api/nodes/test", method="POST", payload={**common, "api_key": self._key_plaintext})
        guid = self.node_identity()["guid"]
        self.check("s03_test_reports_node_identity", probe["identity"].get("guid") == guid
                   and probe["identity"].get("api_version") == 2, json.dumps(probe.get("identity", {}))[:200])
        status, _, body = self.central.request("/api/nodes/test", method="POST",
                                               payload={**common, "api_key": "pc_00000000_" + "x" * 43})
        self.check("s03_test_refuses_bad_key", status == 409, f"{status} {body[:120]!r}")
        linked = self.central.json("/api/nodes/link", method="POST",
                                   payload={**common, "display_name": "lab node", "api_key": self._key_plaintext})
        self.node_id = linked["node_id"]
        self.check("s03_link_created", self.node_id == guid)
        online, elapsed = self.wait(lambda: self.link_status() == "online", ONLINE_SECONDS, "link online")
        self.check("s03_link_online", bool(online), f"status {self.link_status()} after {elapsed}s: "
                   f"{self.node_view()['link'].get('last_error')}")
        self.report["counts"]["link_online_seconds"] = elapsed
        self.check("s03_node_up_event", self.events("node.up") >= 1)

    def step_04_import(self) -> None:
        table = self.central.json(f"/api/nodes/{self.node_id}/inventory")["protocols"]
        candidates = [{"protocol": protocol, "runtime_username": row["runtime_username"], "client": "new"}
                      for protocol, rows in table.items() for row in rows
                      if row.get("linked_grant_id") is None and row.get("ownership") == "local"]
        self.report["counts"]["import_candidates"] = {p: sum(1 for c in candidates if c["protocol"] == p) for p in PROTOCOLS}
        self.check("s04_import_candidates_present", bool(candidates), "the node runs no user to import")
        if not candidates:
            return
        result = self.central.json(f"/api/nodes/{self.node_id}/import", method="POST", payload={"resources": candidates})
        self.report["counts"]["imported"] = len(result.get("imported", []))
        self.report["counts"]["imported_without_credential"] = len(result.get("without_credential", []))
        self.check("s04_import_accepted", len(result.get("imported", [])) == len(candidates), json.dumps(result)[:300])
        wanted = {(c["protocol"], c["runtime_username"]) for c in candidates}

        def adopted():
            owned = {(p, r["runtime_username"]) for p, rows in self.node_inventory().items()
                     for r in rows if r.get("ownership") == "central"}
            return wanted <= owned

        done, elapsed = self.wait(adopted, ENABLED_SECONDS, "import adopted")
        self.check("s04_imported_marked_central", bool(done), f"not all central-owned after {elapsed}s")
        after = self.node_users()
        self.check("s04_node_users_unchanged_after_import", after == self.initial_users,
                   json.dumps({"before": self.initial_users, "after": after})[:400])
        generations = self.central.json(f"/api/nodes/{self.node_id}/generations")
        observed = generations.get("observed") or {}
        self.check("s04_import_generation_converged", observed.get("reconcile_state") == "converged"
                   and observed.get("applied_generation") == (generations.get("desired") or {}).get("generation"),
                   json.dumps({k: observed.get(k) for k in ("reconcile_state", "applied_generation")}))
        self.check("s04_node_mastered_after_first_generation", bool(self.node_identity().get("master_guid")))

    def step_05_grants(self) -> None:
        client = self.central.json("/api/clients", method="POST", payload={"display_name": CLIENT_NAME})
        self.client_id = client["id"]
        user = self.probe_user
        self.usernames.add(user)
        operation = self.central.json(f"/api/clients/{self.client_id}/grants", method="POST", payload={"grants": [
            {"protocol": "mtproxy", "node_id": self.node_id, "runtime_username": user, "options": {}},
            {"protocol": "naive", "node_id": self.node_id, "runtime_username": user, "options": {}},
            {"protocol": "mieru", "node_id": self.node_id, "runtime_username": user, "options": {"quotas": []}},
        ]})
        self.check("s05_grants_pending_remote", operation.get("status") == "pending_remote", str(operation.get("status")))
        done, elapsed = self.wait(lambda: self.grants_in(("enabled",)), ENABLED_SECONDS, "grants enabled")
        self.report["counts"]["grants_enabled_seconds"] = elapsed
        self.check("s05_grants_enabled", bool(done),
                   f"{[(g['protocol'], g['observed_state']) for g in self.grants()]} after {elapsed}s")
        status = self.central.json(f"/api/operations/{operation['operation_id']}")["status"]
        self.check("s05_operation_succeeded", status == "succeeded", status)
        present = {p: self.node_enabled(p, user) for p in PROTOCOLS}
        self.check("s05_node_runtime_has_probe_users", all(present[p] is True for p in PROTOCOLS), json.dumps(present))
        owned = {(p, r["runtime_username"]) for p, rows in self.node_inventory().items()
                 for r in rows if r.get("ownership") == "central"}
        self.check("s05_probe_users_owned_by_central", all((p, user) in owned for p in PROTOCOLS))
        refused, headers, body = self.node.request(f"/api/naive/users/{user}/disable", method="POST", payload={})
        self.check("s05_node_refuses_central_owned_mutation",
                   refused == 409 and headers.get("X-Reason") == "managed_by_central", f"{refused} {body[:120]!r}")
        self.operation_id = operation["operation_id"]
        self.credentials = self._bundle_credentials("s05")
        self.check("s05_bundle_has_three_artifacts", set(self.credentials) == set(PROTOCOLS), str(sorted(self.credentials)))
        shapes = self.report.setdefault("artifacts", {})["s05"]
        mtproxy = shapes.get("mtproxy") or {}
        self.check("s05_mtproxy_link_is_fake_tls", mtproxy.get("fake_tls") is True, json.dumps(mtproxy))
        self.check("s05_mtproxy_link_names_the_proxy_domain", mtproxy.get("server") == self.args.mtproxy_domain,
                   json.dumps(mtproxy))
        self.subscription_url = self._subscription_url()
        feeds = self._fetch_feeds(self.output / "s05-feeds")
        self.check("s05_subscription_has_every_protocol", feeds == {"tg": 1, "naive": 1, "mieru": 1}, json.dumps(feeds))
        self._client_checks("s05", self.output / "s05-feeds", self.credentials.get("mtproxy"), expect_live=True)

    def _bundle_credentials(self, label: str) -> dict[str, str]:
        """Per protocol, the client-side value of the grant: the MTProxy secret out of the
        link; for naive and mieru the whole artifact (kept in memory for equality only)."""
        token = self.central.json(f"/api/operations/{self.operation_id}/bundle", method="POST")["reveal_token"]
        bundle = self.central.json(f"/api/reveal/{token}")
        values: dict[str, str] = {}
        shapes: dict[str, dict] = {}
        for grant in bundle.get("grants", []):
            artifact = (grant.get("artifacts") or [{}])[0].get("value", "")
            shapes[grant["protocol"]] = describe_artifact(artifact)
            values[grant["protocol"]] = mtproxy_secret(artifact) if grant["protocol"] == "mtproxy" else artifact
        self.report.setdefault("artifacts", {})[label] = shapes
        return values

    def _subscription_url(self) -> str:
        overview = self.central.json(f"/api/clients/{self.client_id}/subscription")
        if overview.get("subscription"):
            self.central.json(f"/api/clients/{self.client_id}/subscription/revoke", method="POST")
        token = self.central.json(f"/api/clients/{self.client_id}/subscription", method="POST")["reveal_token"]
        return self.central.json(f"/api/reveal/{token}")["url"]

    def _fetch_feeds(self, directory: Path) -> dict[str, int]:
        """Render the client's subscription into `directory` the way the cores read it."""
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o755)
        status, _, raw = self.fetch(self.subscription_url)
        if status != 200:
            raise Check(f"subscription raw -> {status}")
        for name, query in (("singbox-official", "?format=singbox&client=singbox"), ("clash", "?format=clash")):
            status, _, rendered = self.fetch(f"{self.subscription_url}{query}")
            if status != 200:
                raise Check(f"subscription {name} -> {status}")
            (directory / f"subscription.{name}").write_bytes(rendered)
            (directory / f"subscription.{name}").chmod(0o644)
        lines = raw.decode().splitlines()
        return {"tg": sum(line.startswith("tg://proxy?") for line in lines),
                "naive": sum(line.startswith("naive+https://") for line in lines),
                "mieru": sum(line.startswith("mierus://") for line in lines)}

    def _client_checks(self, prefix: str, feeds_dir: Path, secret: str | None, *, expect_live: bool) -> None:
        """Real clients against the node: the feeds in `feeds_dir` through sing-box and
        mihomo, `secret` through the resPQ probe. `expect_live` says whether they must pass."""
        if not self.probes.enabled:
            return
        result = self.probes.cores(feeds_dir)
        self.report.setdefault("cores", {})[prefix] = {k: v for k, v in result.items() if isinstance(v, (bool, list))}
        for name in ("singbox_check", "mihomo_check"):
            if name in result:
                self.check(f"{prefix}_core_{name}", result[name] is True, str(result.get(f"{name}_detail", ""))[:300])
        naive = result.get("singbox_naive_traffic")
        mieru = result.get("mihomo_mieru_tcp")
        udp = result.get("mihomo_mieru_udp")
        if naive is not None:
            self.check(f"{prefix}_naive_{'works' if expect_live else 'refused'}", naive is expect_live,
                       str(result.get("singbox_naive_traffic_detail", ""))[:300])
        if mieru is not None:
            self.check(f"{prefix}_mieru_tcp_{'works' if expect_live else 'refused'}", mieru is expect_live,
                       str(result.get("mihomo_mieru_tcp_detail", ""))[:300])
            if expect_live and udp is not None:
                self.check(f"{prefix}_mieru_udp_works", udp is True)
        if secret and self.args.mtproxy_probe:
            ok, detail = self.probes.mtproxy(secret)
            self.check(f"{prefix}_mtproxy_{'works' if expect_live else 'refused'}", ok is expect_live, detail)

    def _grant_ids(self, username: str) -> dict[str, str]:
        return {g["protocol"]: g["id"] for g in self.grants() if g["runtime_username"] == username}

    def step_06_disable_rotate_delete(self) -> None:
        user = self.probe_user
        ids = self._grant_ids(user)
        for grant_id in ids.values():
            self.central.json(f"/api/clients/grants/{grant_id}/disable", method="POST")
        done, elapsed = self.wait(lambda: self.grants_in(("disabled",), {user}), ENABLED_SECONDS, "grants disabled")
        self.check("s06_disable_observed", bool(done), f"after {elapsed}s")
        states = {p: self.node_enabled(p, user) for p in PROTOCOLS}
        self.check("s06_disable_seen_on_node", all(states[p] is False for p in PROTOCOLS), json.dumps(states))
        # The feeds rendered before the disable still name the accounts: the runtime must refuse them.
        self._client_checks("s06_disabled", self.output / "s05-feeds", self.credentials.get("mtproxy"), expect_live=False)
        for grant_id in ids.values():
            self.central.json(f"/api/clients/grants/{grant_id}/enable", method="POST")
        done, elapsed = self.wait(lambda: self.grants_in(("enabled",), {user}), ENABLED_SECONDS, "grants re-enabled")
        self.check("s06_reenable_observed", bool(done), f"after {elapsed}s")
        before = {g["protocol"]: g["secret_ref"]["version"] for g in self.grants() if g["runtime_username"] == user}
        for grant_id in ids.values():
            self.central.json(f"/api/clients/grants/{grant_id}/rotate", method="POST")
        done, elapsed = self.wait(lambda: self.grants_in(("enabled",), {user}) and self.converged(),
                                  ENABLED_SECONDS, "rotate converged")
        self.check("s06_rotate_converged", bool(done), f"after {elapsed}s")
        after = {g["protocol"]: g["secret_ref"]["version"] for g in self.grants() if g["runtime_username"] == user}
        self.check("s06_rotate_new_versions", all(after[p] == before[p] + 1 for p in PROTOCOLS), json.dumps(after))
        rotated = self._bundle_credentials("s06_rotated")
        self.check("s06_rotate_changed_every_credential",
                   all(rotated.get(p) and rotated[p] != self.credentials.get(p) for p in PROTOCOLS))
        # Old feeds (pre-rotation credentials) must fail; the freshly rendered ones must work.
        self._client_checks("s06_rotated_old", self.output / "s05-feeds", self.credentials.get("mtproxy"), expect_live=False)
        feeds = self._fetch_feeds(self.output / "s06-feeds")
        self.check("s06_subscription_still_complete", feeds == {"tg": 1, "naive": 1, "mieru": 1}, json.dumps(feeds))
        self._client_checks("s06_rotated_new", self.output / "s06-feeds", rotated.get("mtproxy"), expect_live=True)
        self.credentials = rotated
        for grant_id in ids.values():
            self.central.json(f"/api/clients/grants/{grant_id}/delete", method="POST")
        # The client view hides a grant the moment it is `deleted`; the purge itself happens
        # when the node acknowledges the generation that carried the deletion.
        done, elapsed = self.wait(lambda: self.converged() and not any(g["runtime_username"] == user for g in self.grants()),
                                  ENABLED_SECONDS, "deletion converged")
        self.check("s06_delete_purged", bool(done), f"after {elapsed}s: {[(g['protocol'], g['observed_state']) for g in self.grants()]}")
        gone = {p: self.node_enabled(p, user) for p in PROTOCOLS}
        self.check("s06_deleted_gone_from_node", all(v is None for v in gone.values()), json.dumps(gone))

    def step_07_offline_convergence(self) -> None:
        self.docker.stop(self.args.node_container)
        offline, elapsed = self.wait(lambda: self.link_status() == "offline", ENABLED_SECONDS, "link offline")
        self.check("s07_offline_detected", bool(offline), f"after {elapsed}s")
        downs = self.events("node.down")
        self.check("s07_node_down_event", downs >= 1)
        username = f"fleet-offline-{self.run_id}"
        self.usernames.add(username)
        operation = self.central.json(f"/api/clients/{self.client_id}/grants", method="POST", payload={"grants": [
            {"protocol": "naive", "node_id": self.node_id, "runtime_username": username, "options": {}}]})
        self.check("s07_offline_grant_pending", operation.get("status") == "pending_remote"
                   and self.grants_in(("pending",), {username}), str(operation.get("status")))
        self.docker.start(self.args.node_container)
        online, elapsed = self.wait(lambda: self.link_status() == "online", RESTART_SECONDS, "link online again")
        self.check("s07_online_after_start", bool(online), f"after {elapsed}s")
        done, elapsed = self.wait(lambda: self.grants_in(("enabled",), {username}), RESTART_SECONDS, "offline grant enabled")
        self.report["counts"]["offline_convergence_seconds"] = elapsed
        self.check("s07_offline_grant_converged", bool(done) and self.node_enabled("naive", username) is True,
                   f"after {elapsed}s: {[(g['runtime_username'], g['observed_state']) for g in self.grants()]}")

    def step_08_restart_mid_apply(self) -> None:
        total = self.args.bulk_grants
        names = [f"fleet-bulk-{self.run_id}-{i:02d}" for i in range(1, total + 1)]
        self.usernames.update(names)
        options = {"mtproxy": {}, "naive": {}, "mieru": {"quotas": []}}
        requests = [{"protocol": PROTOCOLS[i % 3], "node_id": self.node_id, "runtime_username": name,
                     "options": options[PROTOCOLS[i % 3]]} for i, name in enumerate(names)]
        operations = []
        for start in range(0, total, 8):  # GrantsCreate allows at most 8 grants per request
            operation = self.central.json(f"/api/clients/{self.client_id}/grants", method="POST",
                                          payload={"grants": requests[start:start + 8]})
            operations.append(operation["operation_id"])
        self.check("s08_bulk_created", len({g["runtime_username"] for g in self.grants()} & set(names)) == total)
        self.clock.sleep(1)
        self.docker.restart(self.args.node_container)
        done, elapsed = self.wait(lambda: self.grants_in(("enabled",), set(names)) and self.converged(),
                                  RESTART_SECONDS, "bulk converged")
        self.report["counts"]["bulk_convergence_seconds"] = elapsed
        self.check("s08_bulk_converged", bool(done),
                   f"after {elapsed}s: {sorted((g['observed_state'] for g in self.grants()))[:5]}")
        statuses = [self.central.json(f"/api/operations/{op}")["status"] for op in operations]
        self.check("s08_operations_succeeded", all(s == "succeeded" for s in statuses), json.dumps(statuses))
        listed = self.node_users()
        duplicates = {p: [u for u in set(v) if v.count(u) > 1] for p, v in listed.items()}
        expected = {p: sorted(set(self.initial_users[p]) | {n for i, n in enumerate(names) if PROTOCOLS[i % 3] == p}
                              | ({f"fleet-offline-{self.run_id}"} if p == "naive" else set()))
                    for p in PROTOCOLS}
        self.check("s08_no_duplicates_on_node", all(not d for d in duplicates.values()) and listed == expected,
                   json.dumps({"duplicates": duplicates, "extra": {p: sorted(set(listed[p]) - set(expected[p])) for p in PROTOCOLS},
                               "missing": {p: sorted(set(expected[p]) - set(listed[p])) for p in PROTOCOLS}})[:500])
        grants = self.grants()
        keys = [(g["protocol"], g["runtime_username"]) for g in grants]
        self.check("s08_no_duplicates_on_central", len(keys) == len(set(keys)) and len(grants) == total + 1, str(len(grants)))
        observed = (self.central.json(f"/api/nodes/{self.node_id}/generations").get("observed") or {})
        failed = [r for r in observed.get("resources", []) if r.get("state") in ("failed", "drifted")]
        self.check("s08_no_failed_resources", not failed, json.dumps(failed)[:400])

    def step_09_key_revoke(self) -> None:
        old_key = self.key_ids[-1]
        self.node.json(f"/api/keys/{old_key}/enabled", method="POST", payload={"enabled": False})
        offline, elapsed = self.wait(lambda: self.link_status() == "offline", ENABLED_SECONDS, "revoked key offline")
        self.check("s09_revoked_key_offline", bool(offline), f"after {elapsed}s: {self.node_view()['link'].get('last_error')}")
        self.check("s09_node_down_event", self.events("node.down") >= 2)
        created = self.node.json("/api/keys", method="POST",
                                 payload={"name": f"{KEY_NAME_PREFIX}{secrets.token_hex(3)}", "scope": "node-sync",
                                          "expires_at": None})
        self.key_ids.append(created["key"]["id"])
        self.node_bearer = self.node.with_bearer(created["plaintext"])
        self.central.json(f"/api/nodes/{self.node_id}/link", method="POST", payload={"api_key": created["plaintext"]})
        online, elapsed = self.wait(lambda: self.link_status() == "online", ENABLED_SECONDS, "relinked online")
        self.check("s09_relinked_online", bool(online), f"after {elapsed}s")
        self.node.json(f"/api/keys/{old_key}", method="DELETE")
        self.key_ids.remove(old_key)

    def step_10_cleanup_unlink(self) -> None:
        for grant in self.grants():
            self.central.json(f"/api/clients/grants/{grant['id']}/delete", method="POST")
        done, elapsed = self.wait(lambda: self.converged() and not self.grants(), RESTART_SECONDS, "all deletions converged")
        self.report["counts"]["final_purge_seconds"] = elapsed
        self.check("s10_all_grants_purged", bool(done), f"after {elapsed}s: {len(self.grants())} left, "
                   f"link {json.dumps({k: self.node_view()['link'].get(k) for k in ('status', 'desired_generation', 'acknowledged_generation', 'config_dirty')})}")
        listed = self.node_users()
        leftovers = {p: sorted(set(listed[p]) & self.usernames) for p in PROTOCOLS}
        self.check("s10_node_runtime_clean", not any(leftovers.values()), json.dumps(leftovers))
        status, _, body = self.central.request(f"/api/clients/{self.client_id}/state", method="POST",
                                               payload={"state": "archived"})
        self.check("s10_client_archived", status == 200, f"{status} {body[:120]!r}")
        unlinked = self.central.json(f"/api/nodes/{self.node_id}", method="DELETE")
        self.check("s10_unlinked", unlinked.get("ok") is True)
        self.check("s10_central_forgot_node",
                   all(item["node_id"] != self.node_id for item in self.central.json("/api/nodes")["items"]))
        identity = self.node_identity()
        self.check("s10_node_master_cleared", identity.get("master_guid") is None, str(identity.get("master_guid"))[:12])
        owned = [(p, r["runtime_username"]) for p, rows in self.node_inventory().items() for r in rows
                 if r.get("ownership") != "local"]
        self.check("s10_imported_local_again", not owned, json.dumps(owned)[:300])
        final = self.node_users()
        self.check("s10_node_users_equal_initial", final == self.initial_users,
                   json.dumps({"initial": self.initial_users, "final": final})[:500])
        self._revoke_keys()
        names = [k["name"] for k in self.node.json("/api/keys")["items"] if str(k["name"]).startswith(KEY_NAME_PREFIX)]
        self.check("s10_lab_keys_removed", not names, str(names))

    def _revoke_keys(self) -> None:
        for key_id in list(self.key_ids):
            status, _, _ = self.node.request(f"/api/keys/{key_id}", method="DELETE")
            if status in (200, 404):
                self.key_ids.remove(key_id)

    def step_11_central_down(self) -> None:
        self.process.stop()
        self.check("s11_central_stopped", self.process.is_running() is False)
        text = self.process.collect_log(self.output / "central.log") or ""
        # The lab central runs like production (`--no-access-log`): no subscription token,
        # reveal token or API key may have reached its log.
        leaked = [shape.pattern for shape in _SECRET_SHAPES if shape.search(text)]
        self.check("s11_central_log_free_of_secrets", not leaked, str(leaked))
        self.check("s11_central_log_free_of_tracebacks", "Traceback" not in text and "fleet: tick failed" not in text,
                   " | ".join(line for line in text.splitlines() if "Error" in line or "fleet:" in line)[-400:])

    # --- orchestration ---

    STEPS = ("step_01_central_up", "step_02_node_key", "step_03_link", "step_04_import", "step_05_grants",
             "step_06_disable_rotate_delete", "step_07_offline_convergence", "step_08_restart_mid_apply",
             "step_09_key_revoke", "step_10_cleanup_unlink")

    def run(self) -> bool:
        self.output.mkdir(parents=True, exist_ok=True)
        self.started = self.clock.monotonic()
        failure: str | None = None
        try:
            for name in self.STEPS:
                started = self.clock.monotonic()
                try:
                    getattr(self, name)()
                finally:
                    self.report.setdefault("durations", {})[name] = round(self.clock.monotonic() - started, 1)
        except Check as exc:
            failure = str(exc)
            self.report["aborted"] = failure
        except Exception as exc:  # noqa: BLE001 — the report must still say where it died
            failure = f"{type(exc).__name__}: {exc}"
            self.report["aborted"] = failure
        finally:
            self._restore_node()
            with contextlib.suppress(Exception):
                self.step_11_central_down()
            self._remove_feeds()
            self._write_report(failure)
        return self.report["ok"]

    def _restore_node(self) -> None:
        """Best effort after a failure: the node must end as it was found (ruling 6)."""
        if self.report["checks"].get("s10_node_users_equal_initial"):
            return
        notes = self.report["cleanup"]
        with contextlib.suppress(Exception):
            if self.client_id and self.node_id:
                for grant in self.grants():
                    with contextlib.suppress(Exception):
                        self.central.json(f"/api/clients/grants/{grant['id']}/delete", method="POST")
                done, _ = self.wait(lambda: self.converged() and not self.grants(), 120, "cleanup purge")
                notes.append(f"grants purged after failure: {bool(done)}")
        with contextlib.suppress(Exception):
            if self.node_id:
                status, _, _ = self.central.request(f"/api/nodes/{self.node_id}", method="DELETE")
                notes.append(f"unlink after failure: {status}")
        with contextlib.suppress(Exception):
            if self.node_bearer and self.node_identity().get("master_guid"):
                self.node.json("/api/nodes/local/unlink", method="POST")
                notes.append("node released its master after failure")
        with contextlib.suppress(Exception):
            if self.initial_users:
                for protocol in PROTOCOLS:
                    for username in set(self.node_users()[protocol]) - set(self.initial_users[protocol]):
                        if username in self.usernames:
                            notes.append(f"removed {protocol}:{username}: {self.node_delete_user(protocol, username)}")
        with contextlib.suppress(Exception):
            self._revoke_keys()

    def _remove_feeds(self) -> None:
        """The rendered feeds carry the (now deleted) credentials; they do not outlive the run."""
        for directory in self.output.glob("s0*-feeds"):
            shutil.rmtree(directory, ignore_errors=True)

    def _write_report(self, failure: str | None) -> None:
        checks = self.report["checks"]
        failed = sorted(name for name, value in checks.items() if value is False)
        self.report["failed"] = failed
        self.report["ok"] = not failed and failure is None
        self.report["elapsed_seconds"] = round(self.clock.monotonic() - self.started, 1)
        self.report = redact(self.report)
        assert_secret_free(self.report)
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")


def main(argv=None) -> int:
    args = parse_args(argv)
    if not Path(args.python).exists():
        print(f"FAILED: interpreter {args.python} is missing", file=sys.stderr)
        return 2
    if not (args.source / "panel" / "app.py").exists():
        print(f"FAILED: {args.source} has no panel package", file=sys.stderr)
        return 2
    central_url = f"http://{args.central_host}:{args.central_port}"
    scenario = Scenario(args, node=Panel(args.node_url, ca_file=args.client_ca_file), central=Panel(central_url),
                        process=CentralProcess(args), docker=Docker(), probes=Probes(args))
    ok = scenario.run()
    if args.cleanup:
        shutil.rmtree(args.central_dir, ignore_errors=True)
    print(json.dumps(scenario.report, indent=2, sort_keys=True))
    if not ok:
        print(f"FAILED: {scenario.report.get('aborted') or ', '.join(scenario.report['failed'])}", file=sys.stderr)
        return 1
    print("FLEET_ACCEPTANCE_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
