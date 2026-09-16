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
import base64
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
    # The Xray-router ingress credential (v0.5): `user:password` as URL userinfo, or as the
    # line the secret files and mita's `socks5Authentication` carry.
    re.compile(r"socks5://[^\s\"'/@]+:[^\s\"'/@]+@"), re.compile(r"\b(?:naive|mieru)-[0-9a-f]{8}:[A-Za-z0-9._~-]{16,}"),
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
    # Routing (v0.4, spec §11): the scenarios routing-01…10 run after the grants, against a
    # SOCKS5 stub this script starts as the node's «WARP» (the managers must already point
    # at it: NAIVE_EGRESS_WARP / MIERU_EGRESS_WARP = socks5://<--stub-listen>).
    parser.add_argument("--routing", action="store_true", help="run the v0.4 routing scenarios")
    parser.add_argument("--stub-listen", default="127.0.0.1:45000", help="where the SOCKS5 stub listens")
    parser.add_argument("--caddyfile", type=Path, default=Path("/var/lib/naive-manager/Caddyfile"),
                        help="the node's NaiveProxy Caddyfile on the host (digest before/after)")
    parser.add_argument("--routing-allowed", default="https://api.ipify.org", help="a target every policy lets through")
    parser.add_argument("--routing-blocked-host", default="example.com", help="the host the block-domain rule names")
    parser.add_argument("--routing-cidr-target", default="https://1.1.1.1/cdn-cgi/trace",
                        help="a literal-IP target inside --routing-cidr")
    parser.add_argument("--routing-cidr", default="1.1.1.0/24", help="the network the block-cidr rule names")
    # The Xray-router (v0.5, spec §13): the scenarios router-01…14 run after the routing ones
    # on a node installed with `[egress] router = true`; they need --routing (the stub).
    parser.add_argument("--router", action="store_true", help="run the v0.5 Xray-router scenarios (needs --routing)")
    parser.add_argument("--router-container", default="proxy-control-xray-router", help="the node's router container")
    parser.add_argument("--router-secrets-dir", type=Path, default=Path("/opt/mtproxy-shared443/secrets"),
                        help="where the installer keeps the ingress credentials (read as root)")
    parser.add_argument("--router-rotate", type=Path, default=Path("/usr/local/libexec/rotate-xray-router-ingress"),
                        help="the credential rotation script the installer put on the host")
    parser.add_argument("--router-geoip-target", default="https://1.1.1.1/cdn-cgi/trace",
                        help="a literal-IP target inside geoip:cloudflare")
    parser.add_argument("--router-geosite-host", default="doubleclick.net", help="a host inside geosite:category-ads-all")
    parser.add_argument("--router-control", default="https://example.com/",
                        help="a target outside geoip:cloudflare and geosite:category-ads-all")
    parser.add_argument("--router-plain-target", default="http://example.com/", help="a port-80 target the port rule refuses")
    parser.add_argument("--routing-other", default="https://www.cloudflare.com/cdn-cgi/trace",
                        help="a target outside the selective rule, expected through the stub")
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
            # A 422 detail echoes the request (a login password, a reveal path with its
            # token): the message is redacted here, before it can reach a log or a report.
            raise Check(f"{method} {self.base_url}{redact(path)} -> {status} {redact(str(detail))[:200]}")
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


# --- routing (v0.4) collaborators ---------------------------------------------------------

class Stub:
    """`scripts/lab/socks5-stub.py` as the node's «WARP»: started here, on the host loopback,
    logging every CONNECT target so «went through the egress» is a fact, not an IP guess."""

    def __init__(self, listen: str, log: Path) -> None:
        self.listen, self.log = listen, log
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.process = subprocess.Popen(
            [sys.executable, str(HERE / "socks5-stub.py"), "--listen", self.listen, "--log", str(self.log)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
        host, _, port = self.listen.rpartition(":")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host or "127.0.0.1", int(port)), timeout=1):
                    return
            except OSError:
                time.sleep(0.2)
        raise Check(f"socks5 stub did not listen on {self.listen}")

    def stop(self) -> None:
        if self.process is not None:
            _terminate(self.process.pid, self.process)
            self.process = None

    def lines(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def hosts_since(self, mark: int) -> list[str]:
        return [line.split("\t")[1] for line in self.lines()[mark:] if line.count("\t") >= 2]


class Host:
    """Digests of what routing must not touch (nginx, nftables) and of what it does (the
    Caddyfile, mita's config) — read on the node's host, where this script runs."""

    def __init__(self, caddyfile: Path) -> None:
        self.caddyfile = caddyfile

    @staticmethod
    def _run(*argv: str) -> tuple[int, str]:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        return completed.returncode, completed.stdout

    def caddyfile_sha256(self) -> str:
        return hashlib.sha256(self.caddyfile.read_bytes()).hexdigest()

    def caddyfile_text(self) -> str:
        return self.caddyfile.read_text()

    def nginx_sha256(self) -> str:
        completed = subprocess.run(["nginx", "-T"], capture_output=True, text=True, timeout=60, check=False)
        return hashlib.sha256((completed.stdout + completed.stderr).encode()).hexdigest()

    def nft_sha256(self) -> str:
        # The ruleset, not its traffic: `counter` rules print live packet/byte counts.
        text = re.sub(r"packets \d+ bytes \d+", "packets N bytes N", self._run("nft", "list", "ruleset")[1])
        return hashlib.sha256(text.encode()).hexdigest()

    def mita_egress(self) -> dict | None:
        code, out = self._run("mita", "describe", "config")
        if code != 0:
            raise Check(f"mita describe config -> {code}")
        return json.loads(out).get("egress")

    # --- the Xray-router (v0.5) ---

    def router_status(self, container: str) -> dict:
        """The manager's `/v1/status`, the way the installer's verify reads it."""
        code, out = self._run("docker", "exec", container, "python", "-m", "xray_router_manager.healthcheck", "--status")
        if code != 0:
            raise Check(f"router status -> {code}")
        return json.loads(out)

    def router_kill_xray(self, container: str) -> bool:
        """SIGKILL the child `xray` inside the container (the manager's identity owns it)."""
        script = ("import os,signal,sys\n"
                  "for entry in os.listdir('/proc'):\n"
                  "    if not entry.isdigit(): continue\n"
                  "    try: argv = open(f'/proc/{entry}/cmdline','rb').read().split(b'\\0')\n"
                  "    except OSError: continue\n"
                  "    if argv and argv[0].endswith(b'/xray'):\n"
                  "        os.kill(int(entry), signal.SIGKILL); print(entry); sys.exit(0)\n"
                  "sys.exit(1)\n")
        code, _ = self._run("docker", "exec", container, "python", "-c", script)
        return code == 0

    def docker_logs(self, container: str) -> str:
        return self._run("docker", "logs", "--tail", "400", container)[1]

    @staticmethod
    def secret_line(path: Path) -> str:
        return path.read_text().strip()

    @staticmethod
    def xui_fingerprint() -> str:
        """What a foreign 3x-ui on the host looks like: presence, size and mtime of its files."""
        parts = []
        for name in ("/usr/local/x-ui/x-ui", "/etc/x-ui/x-ui.db", "/usr/local/x-ui"):
            try:
                info = os.stat(name)
                parts.append(f"{name}:{info.st_size}:{int(info.st_mtime)}")
            except OSError:
                parts.append(f"{name}:absent")
        return "|".join(parts)


class RoutingProbes:
    """The clients of the routing scenarios: curl as NaiveProxy's HTTPS-proxy client with
    the probe grant's credential (the spike's proven path), and one mihomo container
    speaking Mieru — both on the host, targets chosen by the scenario."""

    MIHOMO_PORT = 18089

    def __init__(self, args: argparse.Namespace, work: Path) -> None:
        self.args, self.work = args, work
        self.naive_artifact: str | None = None
        self.mihomo_up = False

    @staticmethod
    def _run(*argv: str, timeout: int = 40) -> tuple[int, str]:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return completed.returncode, (completed.stdout + completed.stderr)[-400:]

    def naive(self, target: str) -> tuple[bool, str]:
        parts = urllib.parse.urlsplit(self.naive_artifact.replace("naive+https://", "https://", 1))
        auth = f"{urllib.parse.unquote(parts.username)}:{urllib.parse.unquote(parts.password)}"
        token = base64.b64encode(auth.encode()).decode()
        argv = ["curl", "--silent", "--show-error", "--max-time", "25", "--output", "/dev/null", "--write-out", "%{http_code}",
                "--proxy", f"https://{parts.hostname}:{parts.port or 443}", "--proxy-header", f"Proxy-Authorization: Basic {token}"]
        if self.args.client_ca_file:
            argv += ["--proxy-cacert", str(self.args.client_ca_file)]
        code, out = self._run(*argv, target)
        return code == 0 and out.endswith("200"), redact(f"curl {code} {out}")

    def mieru_start(self, share_url: str) -> None:
        if not self.args.mihomo_image:
            return
        parts = urllib.parse.urlsplit(share_url)
        pairs = urllib.parse.parse_qsl(parts.query)
        ports = [int(value) for key, value in pairs if key == "port"]
        protocols = [value for key, value in pairs if key == "protocol"]
        tcp = next((port for port, protocol in zip(ports, protocols) if protocol == "TCP"), ports[0])
        config = (f"mixed-port: {self.MIHOMO_PORT}\nbind-address: '127.0.0.1'\nallow-lan: false\nmode: rule\n"
                  f"log-level: warning\nproxies:\n  - name: lab\n    type: mieru\n    server: {parts.hostname}\n"
                  f"    port: {tcp}\n    transport: TCP\n    username: {urllib.parse.unquote(parts.username)}\n"
                  f"    password: {urllib.parse.unquote(parts.password)}\n    udp: true\n"
                  "proxy-groups: []\nrules:\n  - MATCH,lab\n")
        self.work.mkdir(parents=True, exist_ok=True)
        self.work.chmod(0o755)
        (self.work / "mihomo.yaml").write_text(config)
        (self.work / "mihomo.yaml").chmod(0o644)
        self._run("docker", "rm", "-f", "pc-routing-mihomo")
        code, out = self._run("docker", "run", "-d", "--name", "pc-routing-mihomo", "--network", "host", "-v",
                              f"{self.work}:/cfg", self.args.mihomo_image, "-d", "/cfg", "-f", "/cfg/mihomo.yaml", timeout=180)
        if code != 0:
            raise Check(f"mihomo did not start: {out}")
        time.sleep(4)
        self.mihomo_up = True

    def mieru(self, target: str) -> tuple[bool, str]:
        if not self.mihomo_up:
            return True, "skipped"
        code, out = self._run("curl", "--silent", "--show-error", "--max-time", "25", "--output", "/dev/null",
                              "--write-out", "%{http_code}", "--proxy", f"socks5h://127.0.0.1:{self.MIHOMO_PORT}", target)
        return code == 0 and out.endswith("200"), f"curl {code} {out}"

    def stop(self) -> None:
        if self.mihomo_up:
            self._run("docker", "rm", "-f", "pc-routing-mihomo")
            self.mihomo_up = False
        with contextlib.suppress(OSError):
            (self.work / "mihomo.yaml").unlink()


# --- the scenario ----------------------------------------------------------------------

class Scenario:
    def __init__(self, args, *, node: Panel, central: Panel, process, docker, probes, clock=time,
                 fingerprint=leaf_fingerprint, fetch=fetch, stub=None, host=None, routing_probes=None) -> None:
        self.args, self.node, self.central = args, node, central
        self.process, self.docker, self.probes, self.clock = process, docker, probes, clock
        self.fingerprint, self.fetch = fingerprint, fetch
        # Routing (v0.4): the stub, the host digests and the routing clients; None unless --routing.
        self.stub, self.host, self.routing_probes = stub, host, routing_probes
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

    def steps(self) -> tuple[str, ...]:
        """The routing scenarios (v0.4) sit right after the grants: they need the probe user's
        credentials and must be over before disable/rotate/delete take them away."""
        if not self.args.routing:
            return self.STEPS
        index = self.STEPS.index("step_05_grants") + 1
        extra = ("step_05r_routing", "step_05x_router") if self.args.router else ("step_05r_routing",)
        return (*self.STEPS[:index], *extra, *self.STEPS[index:])

    def run(self) -> bool:
        self.output.mkdir(parents=True, exist_ok=True)
        self.started = self.clock.monotonic()
        failure: str | None = None
        try:
            for name in self.steps():
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
            self._restore_routing()
            self._restore_node()
            with contextlib.suppress(Exception):
                self.step_11_central_down()
            self._remove_feeds()
            self._write_report(failure)
        return self.report["ok"]

    # --- routing (v0.4, spec §11: routing-01 … routing-10) ---

    def _policy_path(self, protocol: str) -> str:
        return f"/api/routing/policies/{self.node_id}/{protocol}"

    def _policy(self, protocol: str) -> dict | None:
        status, _, body = self.central.request(self._policy_path(protocol))
        return json.loads(body) if status == 200 else None

    def _put_policy(self, protocol: str, *, default: str = "direct", rules: list[dict] | None = None,
                    fallback: str = "fail_closed", backend: str | None = None) -> dict:
        current = self._policy(protocol)
        body = {"default_action": default, "default_egress": "warp" if default == "egress" else None, "fallback": fallback,
                "rules": rules or [], "expected_revision": current["revision"] if current else None}
        if backend:
            body["backend"] = backend
        return self.central.json(self._policy_path(protocol), method="PUT", payload=body)

    def _apply_policy(self, protocol: str, *, expect=(200,)) -> tuple[int, dict]:
        policy = self._policy(protocol)
        status, _, body = self.central.request(f"{self._policy_path(protocol)}/apply", method="POST",
                                               payload={"expected_revision": policy["revision"]})
        parsed = json.loads(body) if body else {}
        if status not in expect:
            raise Check(f"apply {protocol} -> {status} {redact(json.dumps(parsed))[:300]}")
        return status, parsed

    def _wait_applied(self, protocol: str, revision: int, seconds: float = 90) -> tuple[dict | None, float]:
        """Until the node's report moved the policy to `applied` at `revision` (pusher, heartbeat)."""
        def settled():
            policy = self._policy(protocol)
            if policy and policy["state"] == "applied" and policy["applied_revision"] == revision:
                return policy
            return policy if policy and policy["state"] == "failed" else None  # a refusal settles it too
        policy, elapsed = self.wait(settled, seconds, f"{protocol} policy applied")
        return (policy if policy and policy["state"] == "applied" else None), elapsed

    def _apply_and_wait(self, label: str, protocol: str, *, default: str = "direct", rules: list[dict] | None = None,
                        fallback: str = "fail_closed", backend: str | None = None) -> dict | None:
        policy = self._put_policy(protocol, default=default, rules=rules, fallback=fallback, backend=backend)
        preview = self.central.json(f"{self._policy_path(protocol)}/preview", method="POST")
        if not self.check(f"{label}_{protocol}_preview_supported", preview.get("status") == "supported",
                          json.dumps(preview.get("reasons"))[:300]):
            return None
        self._apply_policy(protocol)
        applied, elapsed = self._wait_applied(protocol, policy["revision"])
        self.report["counts"][f"{label}_{protocol}_applied_seconds"] = elapsed
        self.check(f"{label}_{protocol}_applied", bool(applied), f"not applied after {elapsed}s: {self._policy(protocol)}")
        return applied

    def _probe(self, protocol: str, target: str) -> tuple[bool, str]:
        return self.routing_probes.naive(target) if protocol == "naive" else self.routing_probes.mieru(target)

    def _targets(self) -> dict[str, dict]:
        return {item["protocol"]: item for item in self.central.json("/api/routing/targets")["items"]
                if item["node_id"] == self.node_id}

    def step_05r_routing(self) -> None:
        args = self.args
        allowed, other = args.routing_allowed, args.routing_other
        blocked = f"https://{args.routing_blocked_host}/"
        self.stub.start()
        self.routing_probes.naive_artifact = self.credentials.get("naive")
        self.routing_probes.mieru_start(self.credentials.get("mieru", ""))
        protocols = [p for p in ("naive", "mieru") if p == "naive" or self.routing_probes.mihomo_up]
        baseline = {"caddyfile": self.host.caddyfile_sha256(), "nginx": self.host.nginx_sha256(),
                    "nft": self.host.nft_sha256(), "mita": self.host.mita_egress()}
        self.report["routing_initial_mita_egress"] = baseline["mita"] is None

        # routing-01: targets — naive/mieru with egress.v1 and a reachable warp, mtproxy out of scope,
        # the node's own screen says the central holds the pen.
        def warp_reachable():
            table = self._targets()
            ready = all(table.get(p, {}).get("providers", {}).get("warp", {}).get("reachable") is True for p in protocols)
            return table if ready else None

        targets, elapsed = self.wait(warp_reachable, 30, "warp reachable in targets")
        targets = targets or self._targets()
        for protocol in protocols:
            item = targets.get(protocol, {})
            self.check(f"r01_{protocol}_target", item.get("egress_v1") is True and item.get("backend") == f"{protocol}_native"
                       and item.get("providers", {}).get("warp", {}).get("reachable") is True and not item.get("reason"),
                       json.dumps(item)[:300])
        self.check("r01_mtproxy_out_of_scope", targets.get("mtproxy", {}).get("reason") == "protocol_out_of_scope")
        local = {item["protocol"]: item for item in self.node.json("/api/routing/targets")["items"] if item["node_id"] == "local"}
        self.check("r01_node_local_managed_by_central", local.get("naive", {}).get("reason") == "managed_by_central",
                   json.dumps(local.get("naive"))[:200])
        self.check("r01_targets_secret_free", "socks5://" not in json.dumps(targets))

        # routing-02/03: whole service through warp — the stub sees the CONNECT target.
        for protocol in protocols:
            if self._apply_and_wait("r02" if protocol == "naive" else "r03", protocol, default="egress") is None:
                continue
            mark = len(self.stub.lines())
            ok, detail = self._probe(protocol, allowed)
            hosts = self.stub.hosts_since(mark)
            label = "r02" if protocol == "naive" else "r03"
            self.check(f"{label}_{protocol}_whole_warp_works", ok, detail)
            self.check(f"{label}_{protocol}_stub_saw_target", any(h == urllib.parse.urlsplit(allowed).hostname for h in hosts),
                       str(hosts[-3:]))
        self.check("r02_naive_caddyfile_has_upstream", "upstream socks5://" in self.host.caddyfile_text())

        # routing-04: block by domain (default direct) — the target is refused, the rest goes.
        for protocol in protocols:
            rule = {"action": "block", "match": {"domains": [args.routing_blocked_host, f"*.{args.routing_blocked_host}"]}}
            if self._apply_and_wait("r04", protocol, rules=[rule]) is None:
                continue
            refused, detail = self._probe(protocol, blocked)
            self.check(f"r04_{protocol}_blocked_domain_refused", not refused, detail)
            ok, detail = self._probe(protocol, allowed)
            self.check(f"r04_{protocol}_other_target_works", ok, detail)
        cover = self.node_identity()["protocols"]["naive"]["public_host"]
        code, out = RoutingProbes._run("curl", "--silent", "--max-time", "20", "--output", "/dev/null", "--write-out", "%{http_code}",
                                       *(["--cacert", str(args.client_ca_file)] if args.client_ca_file else []), f"https://{cover}/")
        self.check("r04_naive_cover_site_alive", code == 0 and out.endswith("200"), f"curl {code} {out}")

        # routing-05: block by CIDR — a literal-IP target inside the network is refused.
        for protocol in protocols:
            rule = {"action": "block", "match": {"cidrs": [args.routing_cidr]}}
            if self._apply_and_wait("r05", protocol, rules=[rule]) is None:
                continue
            refused, detail = self._probe(protocol, args.routing_cidr_target)
            self.check(f"r05_{protocol}_blocked_cidr_refused", not refused, detail)
            ok, detail = self._probe(protocol, allowed)
            self.check(f"r05_{protocol}_other_target_works", ok, detail)

        # routing-06: selective — mieru sends one domain direct and the rest through warp;
        # naive cannot, and the preview says so instead of applying something else.
        selective = [{"action": "direct", "match": {"domains": [urllib.parse.urlsplit(allowed).hostname]}}]
        naive_policy = self._put_policy("naive", default="egress", rules=selective)
        preview = self.central.json(f"{self._policy_path('naive')}/preview", method="POST")
        self.check("r06_naive_selective_unsupported", preview.get("status") == "unsupported"
                   and any(r.get("code") == "backend_capability_missing" and r.get("rule_id") for r in preview.get("reasons", [])),
                   json.dumps(preview.get("reasons"))[:300])
        status, refused = self._apply_policy("naive", expect=(422,))
        self.check("r06_naive_selective_apply_is_422", status == 422 and refused.get("code") == "unsupported", json.dumps(refused)[:200])
        self.check("r06_naive_policy_still_applied_at_previous_revision",
                   (p := self._policy("naive")) is not None and p["applied_revision"] == naive_policy["revision"] - 1, str(self._policy("naive")))
        if "mieru" in protocols and self._apply_and_wait("r06", "mieru", default="egress", rules=selective) is not None:
            mark = len(self.stub.lines())
            ok, detail = self._probe("mieru", allowed)
            direct_hosts = self.stub.hosts_since(mark)
            self.check("r06_mieru_direct_exception_works", ok, detail)
            self.check("r06_mieru_direct_exception_bypasses_stub", urllib.parse.urlsplit(allowed).hostname not in direct_hosts,
                       str(direct_hosts))
            mark = len(self.stub.lines())
            ok, detail = self._probe("mieru", other)
            self.check("r06_mieru_other_target_through_stub", ok and urllib.parse.urlsplit(other).hostname in self.stub.hosts_since(mark),
                       f"{detail} {self.stub.hosts_since(mark)[-3:]}")

        # routing-07: rollback — the manager's previous entry comes back byte for byte.
        for protocol in protocols:
            before = self._apply_and_wait("r07a", protocol, rules=[{"action": "block", "match": {"cidrs": [args.routing_cidr]}}])
            if before is None:
                continue
            snapshot = self.host.caddyfile_sha256() if protocol == "naive" else json.dumps(self.host.mita_egress(), sort_keys=True)
            after = self._apply_and_wait("r07b", protocol, default="egress")
            if after is None:
                continue
            self.central.json(f"{self._policy_path(protocol)}/rollback", method="POST", payload={"expected_revision": after["revision"]})
            rolled, elapsed = self._wait_applied(protocol, before["revision"])
            self.check(f"r07_{protocol}_rolled_back", bool(rolled), f"after {elapsed}s: {self._policy(protocol)}")
            restored = self.host.caddyfile_sha256() if protocol == "naive" else json.dumps(self.host.mita_egress(), sort_keys=True)
            self.check(f"r07_{protocol}_config_restored_exactly", restored == snapshot, f"{snapshot[:16]} != {restored[:16]}")
            ok, detail = self._probe(protocol, allowed)
            self.check(f"r07_{protocol}_still_serving", ok, detail)

        # routing-08: the provider is down — fail-closed, nothing on the node changes.
        self.stub.stop()
        down, elapsed = self.wait(lambda: self._targets().get("naive", {}).get("providers", {}).get("warp", {}).get("reachable") is False,
                                  60, "warp unreachable in targets")
        self.check("r08_targets_report_warp_unreachable", bool(down), f"after {elapsed}s")
        snapshot = self.host.caddyfile_sha256()
        self._put_policy("naive", default="egress")
        status, refused = self._apply_policy("naive", expect=(409, 422))
        codes = {refused.get("code")} | {r.get("code") for r in (refused.get("compiled") or {}).get("reasons", [])}
        self.check("r08_apply_refused_fail_closed", bool(codes & {"provider_unreachable", "egress_unreachable"}),
                   f"{status} {json.dumps(refused)[:300]}")
        self.check("r08_caddyfile_unchanged", self.host.caddyfile_sha256() == snapshot)
        self.check("r08_policy_not_applied", (p := self._policy("naive")) is not None and p["applied_current"] is False, str(p))
        self.stub.start()
        up, elapsed = self.wait(lambda: self._targets().get("naive", {}).get("providers", {}).get("warp", {}).get("reachable") is True,
                                60, "warp reachable again")
        self.check("r08_targets_report_warp_back", bool(up), f"after {elapsed}s")

        # routing-09: the capability handshake is covered by unit tests (a v0.3 node is not
        # on this stand); the real capability is what routing-01 read.
        self.report["routing_09_legacy_capability"] = "unit-tested (panel/tests/test_routing_fleet.py)"

        # routing-10: what routing never touches. Then the reset: direct, no rules, applied
        # and the policies gone — the node keeps only the managers' journal.
        self.check("r10_nginx_untouched", self.host.nginx_sha256() == baseline["nginx"])
        self.check("r10_nft_untouched", self.host.nft_sha256() == baseline["nft"])
        for protocol in protocols:
            self._apply_and_wait("r11", protocol)
            status, _, body = self.central.request(self._policy_path(protocol), method="DELETE")
            self.check(f"r11_{protocol}_policy_deleted", status == 204, f"{status} {body[:200]!r}")
            ok, detail = self._probe(protocol, allowed)
            self.check(f"r11_{protocol}_direct_again", ok, detail)
        # The reset is «direct, no rules», not the installer's seed byte for byte: the seed may
        # carry the provider with a DIRECT rule, the reset removes the section. Both are direct.
        final_mita = self.host.mita_egress()
        self.check("r11_mita_egress_direct", final_mita is None or not any(
            rule.get("action") == "PROXY" for rule in final_mita.get("rules", [])), str(final_mita)[:200])
        self.report["routing_mita_egress_back_to_initial"] = final_mita == baseline["mita"]
        self.report["routing_caddyfile_returned_to_initial"] = self.host.caddyfile_sha256() == baseline["caddyfile"]
        self.check("r11_targets_without_policies", all(item.get("policy") is None for item in self._targets().values()))
        self.routing_probes.stop()
        self.stub.stop()

    # --- the Xray-router (v0.5, spec §13: router-01 … router-14) ---

    def _router_view(self, protocol: str) -> dict:
        return self._targets().get(protocol, {}).get("router") or {}

    def _wait_attached(self, protocol: str, attached: bool, seconds: float = 120) -> tuple[bool, float]:
        """Until the central's targets say the service is (not) on the router and its policy has
        settled: attach/detach on a linked node travels through a generation and a heartbeat."""
        def settled():
            item = self._targets().get(protocol, {})
            router = item.get("router") or {}
            policy = item.get("policy") or {}
            expected = "xray_router" if attached else f"{protocol}_native"
            if router.get("attached") is attached and item.get("backend") == expected and policy.get("state") != "applying":
                return item
            return None
        item, elapsed = self.wait(settled, seconds, f"{protocol} attached={attached}")
        return bool(item), elapsed

    def _attach(self, label: str, protocol: str, attached: bool) -> bool:
        action = "attach" if attached else "detach"
        status, _, body = self.central.request(f"/api/routing/targets/{self.node_id}/{protocol}/{action}", method="POST")
        if status != 200:
            self.check(f"{label}_{protocol}_{action}_accepted", False, f"{status} {redact(body)[:300]}")
            return False
        done, elapsed = self._wait_attached(protocol, attached)
        self.report["counts"][f"{label}_{protocol}_{action}_seconds"] = elapsed
        return self.check(f"{label}_{protocol}_{action}ed", done, f"after {elapsed}s: {redact(json.dumps(self._targets().get(protocol)))[:300]}")

    def _wait_state(self, protocol: str, states: tuple[str, ...], seconds: float = 90) -> tuple[dict | None, float]:
        def settled():
            policy = self._policy(protocol)
            return policy if policy and policy["state"] in states else None
        return self.wait(settled, seconds, f"{protocol} policy in {states}")

    def _socks_probe(self, port: int, credential: str | None, target: str) -> tuple[bool, str]:
        """curl straight at a router ingress: no credential, or one from a file (never argv)."""
        argv = ["curl", "--silent", "--show-error", "--max-time", "20", "--output", "/dev/null", "--write-out", "%{http_code}",
                "--socks5-hostname", f"127.0.0.1:{port}"]
        config = None
        if credential is not None:
            descriptor, config = tempfile.mkstemp(prefix="router-probe-")
            with os.fdopen(descriptor, "w") as handle:
                handle.write(f'proxy-user = "{credential}"\n')
            argv += ["--config", config]
        try:
            code, out = RoutingProbes._run(*argv, target)
        finally:
            if config:
                os.unlink(config)
        return code == 0 and out.endswith("200"), redact(f"curl {code} {out}")

    def step_05x_router(self) -> None:
        args = self.args
        allowed, other, control = args.routing_allowed, args.routing_other, args.router_control
        blocked = f"https://{args.routing_blocked_host}/"
        container = args.router_container
        self.stub.start()
        self.routing_probes.naive_artifact = self.credentials.get("naive")
        self.routing_probes.mieru_start(self.credentials.get("mieru", ""))
        protocols = [p for p in ("naive", "mieru") if p == "naive" or self.routing_probes.mihomo_up]
        baseline = {"caddyfile": self.host.caddyfile_sha256(), "nginx": self.host.nginx_sha256(),
                    "nft": self.host.nft_sha256(), "mita": self.host.mita_egress(), "xui": self.host.xui_fingerprint()}
        secrets_dir = args.router_secrets_dir
        credential = {p: self.host.secret_line(secrets_dir / f"xray-router-ingress-{p}") for p in ("naive", "mieru")}
        ports = {"naive": 45101, "mieru": 45102}

        # router-01: the node reports its router — available, nothing attached, the manager
        # runs a verified generation; the central shows it per target.
        targets = self._targets()
        for protocol in protocols:
            router = targets.get(protocol, {}).get("router") or {}
            self.check(f"x01_{protocol}_router_available_detached", router.get("available") is True and router.get("attached") is False
                       and bool(router.get("xray_version")), json.dumps(router)[:300])
            self.check(f"x01_{protocol}_native_backend_before_attach", targets.get(protocol, {}).get("backend") == f"{protocol}_native")
        identity = self.node_identity()
        node_router = identity.get("router") or {}
        self.check("x01_identity_router", node_router.get("available") is True and "egress.router.v1" in identity.get("capabilities", [])
                   and len(node_router.get("capabilities", [])) >= 12 and set(node_router.get("services", {})) == {"naive", "mieru"},
                   json.dumps({k: node_router.get(k) for k in ("available", "capabilities", "services")})[:400])
        status = self.host.router_status(container)
        self.check("x01_manager_status_verified_running", status.get("phase") == "idle" and (status.get("running") or {}).get("generation", 0) >= 1
                   and all((status.get("artifacts") or {}).get(n, {}).get("verified") is True for n in ("xray", "geoip", "geosite")),
                   json.dumps(status)[:300])
        self.report["router_xray_version"] = str(status.get("xray_version", ""))[:40]
        self.check("x01_targets_and_identity_secret_free",
                   not any(credential[p].split(":", 1)[1] in text for p in credential for text in (json.dumps(targets), json.dumps(identity))))

        # router-02: attach naive — the router first (pass-through), then Caddy's upstream; the
        # credential is on the node only (Caddyfile), never in the API, identity, audit or the
        # central's database.
        if not self._attach("x02", "naive", True):
            raise Check("naive did not attach to the router")
        caddy_text = self.host.caddyfile_text()
        self.check("x02_caddyfile_upstream_is_router", "@127.0.0.1:45101" in caddy_text and "upstream socks5://" in caddy_text)
        attached_caddyfile = self.host.caddyfile_sha256()
        ok, detail = self._probe("naive", allowed)
        self.check("x02_naive_passthrough_works", ok, detail)
        self.check("x02_passthrough_bypasses_stub", urllib.parse.urlsplit(allowed).hostname not in self.stub.hosts_since(0))
        secret = credential["naive"].split(":", 1)[1]
        audit = json.dumps(self.central.json("/api/audit?limit=200"))  # the newest 200: attach is among them
        db_bytes = b"".join(path.read_bytes() for path in Path(args.central_dir).glob("*.sqlite3*"))
        self.check("x02_credential_only_on_the_node", secret not in json.dumps(self._targets()) and secret not in json.dumps(self.node_identity())
                   and secret not in audit and secret.encode() not in db_bytes and secret in caddy_text)

        # router-03: the whole service through warp — by the router now; the stub sees the target.
        if self._apply_and_wait("x03", "naive", default="egress", backend="xray_router") is not None:
            mark = len(self.stub.lines())
            ok, detail = self._probe("naive", allowed)
            self.check("x03_naive_whole_warp_via_router", ok, detail)
            self.check("x03_stub_saw_target", urllib.parse.urlsplit(allowed).hostname in self.stub.hosts_since(mark), str(self.stub.hosts_since(mark)[-3:]))
            self.check("x03_caddyfile_unchanged_by_router_policy", self.host.caddyfile_sha256() == attached_caddyfile)

        # router-04: a block rule beside warp — what NaiveProxy alone could never do.
        rule = {"action": "block", "match": {"domains": [args.routing_blocked_host, f"*.{args.routing_blocked_host}"]}}
        if self._apply_and_wait("x04", "naive", default="egress", rules=[rule]) is not None:
            refused, detail = self._probe("naive", blocked)
            self.check("x04_blocked_domain_refused", not refused, detail)
            mark = len(self.stub.lines())
            ok, detail = self._probe("naive", allowed)
            self.check("x04_other_target_through_stub", ok and urllib.parse.urlsplit(allowed).hostname in self.stub.hosts_since(mark), detail)

        # router-05: a port rule — plain HTTP (80) refused, HTTPS (443) served.
        if self._apply_and_wait("x05", "naive", rules=[{"action": "block", "match": {"ports": [80]}}]) is not None:
            refused, detail = self._probe("naive", args.router_plain_target)
            self.check("x05_port_80_refused", not refused, detail)
            ok, detail = self._probe("naive", control)
            self.check("x05_port_443_served", ok, detail)

        # router-06: geoip and geosite — a Cloudflare address by geoip, an ad host by geosite.
        if self._apply_and_wait("x06a", "naive", rules=[{"action": "block", "match": {"geoips": ["cloudflare"]}}]) is not None:
            refused, detail = self._probe("naive", args.router_geoip_target)
            self.check("x06_geoip_cloudflare_refused", not refused, detail)
            ok, detail = self._probe("naive", control)
            self.check("x06_geoip_control_served", ok, detail)
        if self._apply_and_wait("x06b", "naive", rules=[{"action": "block", "match": {"geosites": ["category-ads-all"]}}]) is not None:
            refused, detail = self._probe("naive", f"https://{args.router_geosite_host}/")
            self.check("x06_geosite_ads_refused", not refused, detail)
            ok, detail = self._probe("naive", control)
            self.check("x06_geosite_control_served", ok, detail)
        unknown = self._put_policy("naive", rules=[{"action": "block", "match": {"geosites": ["no-such-list-x"]}}])
        self._apply_policy("naive")
        failed, elapsed = self._wait_state("naive", ("failed", "applied"))
        self.check("x06_unknown_geosite_refused_by_xray", bool(failed) and failed["state"] == "failed"
                   and failed.get("last_error") in ("geosite_unknown", "egress_invalid"), f"after {elapsed}s: {redact(json.dumps(failed))[:300]}")
        self.report["counts"]["x06_unknown_geosite_revision"] = unknown["revision"]

        # router-07: mieru attached too, with a selective rule the router enforces for it.
        if "mieru" in protocols and self._attach("x07", "mieru", True):
            selective = [{"action": "direct", "match": {"domains": [urllib.parse.urlsplit(allowed).hostname]}}]
            if self._apply_and_wait("x07", "mieru", default="egress", rules=selective, backend="xray_router") is not None:
                mark = len(self.stub.lines())
                ok, detail = self._probe("mieru", allowed)
                self.check("x07_mieru_direct_exception_works", ok and urllib.parse.urlsplit(allowed).hostname not in self.stub.hosts_since(mark), detail)
                mark = len(self.stub.lines())
                ok, detail = self._probe("mieru", other)
                self.check("x07_mieru_other_through_stub", ok and urllib.parse.urlsplit(other).hostname in self.stub.hosts_since(mark), detail)
            mita = self.host.mita_egress() or {}
            self.check("x07_mita_names_router_with_auth", any(p.get("name") == "router" and "socks5Authentication" in p
                                                             for p in mita.get("proxies", [])), str(sorted(mita))[:200])

        # router-08: the ingress is an identity — no credential, or the other service's, is refused.
        ok, detail = self._socks_probe(ports["naive"], None, control)
        self.check("x08_ingress_without_credential_refused", not ok, detail)
        ok, detail = self._socks_probe(ports["naive"], credential["mieru"], control)
        self.check("x08_cross_service_credential_refused", not ok, detail)
        ok, detail = self._socks_probe(ports["naive"], credential["naive"], control)
        self.check("x08_own_credential_accepted", ok, detail)

        # router-09: rollback walks the router back a generation; Caddy never moved.
        before = self._apply_and_wait("x09a", "naive", rules=[{"action": "block", "match": {"cidrs": [args.routing_cidr]}}])
        after = self._apply_and_wait("x09b", "naive", default="egress") if before else None
        if after is not None:
            generation = (self.host.router_status(container).get("running") or {}).get("generation")
            self.central.json(f"{self._policy_path('naive')}/rollback", method="POST", payload={"expected_revision": after["revision"]})
            rolled, elapsed = self._wait_state("naive", ("rolled_back", "failed"))
            self.check("x09_rolled_back", bool(rolled) and rolled["state"] == "rolled_back" and rolled["applied_revision"] == before["revision"],
                       f"after {elapsed}s: {redact(json.dumps(rolled))[:300]}")
            refused, detail = self._probe("naive", args.routing_cidr_target)
            self.check("x09_previous_rule_enforced_again", not refused, detail)
            self.check("x09_router_generation_advanced", (self.host.router_status(container).get("running") or {}).get("generation", 0) > (generation or 0))
            self.check("x09_caddyfile_byte_for_byte_as_after_attach", self.host.caddyfile_sha256() == attached_caddyfile)

        # router-10: the child dies — the watchdog brings the same generation back.
        generation = (self.host.router_status(container).get("running") or {}).get("generation")
        killed = self.host.router_kill_xray(container)
        self.check("x10_xray_killed", killed)
        def restarted():
            current = self.host.router_status(container)
            running = current.get("running") or {}
            return current if running.get("generation") == generation and current.get("phase") == "idle" else None
        back, elapsed = self.wait(restarted, 30, "watchdog restart")
        self.check("x10_watchdog_restarted_same_generation", bool(back), f"after {elapsed}s")
        ok, detail = self._probe("naive", control)
        self.check("x10_serving_after_restart", ok, detail)

        # router-11: the provider is down — the router refuses the policy (fail-closed) and a
        # policy already through warp fails closed too.
        self._apply_and_wait("x11a", "naive", default="egress")
        self.stub.stop()
        refused, detail = self._probe("naive", allowed)
        self.check("x11_warp_policy_fails_closed_without_provider", not refused, detail)
        self._put_policy("naive", default="egress", rules=[{"action": "block", "match": {"ports": [25]}}])
        self._apply_policy("naive")
        failed, elapsed = self._wait_state("naive", ("failed", "applied"))
        self.check("x11_apply_refused_egress_unreachable", bool(failed) and failed["state"] == "failed"
                   and failed.get("last_error") in ("egress_unreachable", "provider_unreachable"), f"after {elapsed}s: {redact(json.dumps(failed))[:300]}")
        self.stub.start()
        self._apply_and_wait("x11b", "naive")

        # router-13: nothing of the credential anywhere the operator or the central can read.
        secrets = [credential[p].split(":", 1)[1] for p in credential]
        texts = {"targets": json.dumps(self._targets()), "identity": json.dumps(self.node_identity()),
                 "audit": json.dumps(self.central.json("/api/audit?limit=200")),
                 "router_logs": self.host.docker_logs(container), "node_panel_logs": self.host.docker_logs(args.node_container),
                 "naive_manager_logs": self.host.docker_logs("proxy-control-naive-manager"),
                 "mieru_manager_logs": self.host.docker_logs("proxy-control-mieru-manager")}
        leaks = [name for name, text in texts.items() if any(s in text for s in secrets)
                 or any(shape.search(text) for shape in _SECRET_SHAPES[-2:])]
        self.check("x13_no_credential_in_api_audit_or_logs", not leaks, str(leaks))

        # router-14: rotation — the old key dies, the managers re-render, the service goes on.
        code, out = RoutingProbes._run(str(args.router_rotate), timeout=300)
        self.check("x14_rotation_script_ok", code == 0 and "rotated:" in out, redact(out)[:300])
        rotated = {p: self.host.secret_line(secrets_dir / f"xray-router-ingress-{p}") for p in ("naive", "mieru")}
        self.check("x14_secrets_changed", all(rotated[p] != credential[p] for p in rotated))
        ok, detail = self._socks_probe(ports["naive"], credential["naive"], control)
        self.check("x14_old_credential_refused", not ok, detail)
        ok, detail = self._socks_probe(ports["naive"], rotated["naive"], control)
        self.check("x14_new_credential_accepted", ok, detail)
        rendered, elapsed = self.wait(lambda: rotated["naive"].split(":", 1)[1] in self.host.caddyfile_text() or None, 90, "caddyfile re-rendered")
        self.check("x14_caddyfile_re_rendered_with_new_key", bool(rendered), f"after {elapsed}s")
        still, elapsed = self._wait_attached("naive", True)
        self.check("x14_naive_still_attached", still, f"after {elapsed}s")
        if self._apply_and_wait("x14", "naive", default="egress") is not None:
            mark = len(self.stub.lines())
            ok, detail = self._probe("naive", allowed)
            self.check("x14_whole_warp_via_router_after_rotation", ok and urllib.parse.urlsplit(allowed).hostname in self.stub.hosts_since(mark), detail)
        credential = rotated

        # router-12: detach both — the native blocks say direct, the host around is untouched.
        for protocol in protocols:
            self._apply_and_wait("x12", protocol)
            self._attach("x12", protocol, False)
            ok, detail = self._probe(protocol, allowed)
            self.check(f"x12_{protocol}_direct_after_detach", ok, detail)
        self.check("x12_caddyfile_without_router_upstream", "@127.0.0.1:45101" not in self.host.caddyfile_text())
        final_mita = self.host.mita_egress() or {}
        self.check("x12_mita_without_router", not any(p.get("name") == "router" for p in final_mita.get("proxies", [])), str(sorted(final_mita))[:200])
        self.check("x12_nginx_untouched", self.host.nginx_sha256() == baseline["nginx"])
        self.check("x12_nft_untouched", self.host.nft_sha256() == baseline["nft"])
        self.check("x12_xui_untouched", self.host.xui_fingerprint() == baseline["xui"])
        for protocol in protocols:
            status, _, body = self.central.request(self._policy_path(protocol), method="DELETE")
            self.check(f"x12_{protocol}_policy_deleted", status == 204, f"{status} {body[:200]!r}")
        targets = self._targets()
        self.check("x12_targets_detached_without_policies", all(
            (item.get("router") or {}).get("attached") is False and item.get("policy") is None for item in targets.values() if item.get("router")))
        self.routing_probes.stop()
        self.stub.stop()

    def _restore_router(self) -> None:
        """After a failure inside the router step: both services back to their native backends
        (best effort), the policies reset and deleted by `_restore_routing`."""
        if not self.args.router or self.stub is None or not self.node_id:
            return
        with contextlib.suppress(Exception):
            if self.stub.process is None:
                self.stub.start()
            for protocol in ("naive", "mieru"):
                with contextlib.suppress(Exception):
                    if self._router_view(protocol).get("attached"):
                        with contextlib.suppress(Exception):
                            policy = self._put_policy(protocol)
                            self._apply_policy(protocol)
                            self._wait_applied(protocol, policy["revision"], 60)
                        self._attach("cleanup", protocol, False)
                        self.report["cleanup"].append(f"{protocol} detached from the router after failure")

    def _restore_routing(self) -> None:
        """After a failure inside the routing step: the stub and the mihomo container go, and
        every routing policy of the node is reset to direct (best effort) and deleted."""
        if not self.args.routing or self.stub is None:
            return
        self._restore_router()
        with contextlib.suppress(Exception):
            self.routing_probes.stop()
        with contextlib.suppress(Exception):
            if self.node_id and self.client_id and not self.report["checks"].get("r11_targets_without_policies"):
                if self.stub.process is None:
                    self.stub.start()
                for protocol in ("naive", "mieru"):
                    if self._policy(protocol) is None:
                        continue
                    with contextlib.suppress(Exception):
                        policy = self._put_policy(protocol)
                        self._apply_policy(protocol)
                        self._wait_applied(protocol, policy["revision"], 60)
                    status, _, _ = self.central.request(self._policy_path(protocol), method="DELETE")
                    self.report["cleanup"].append(f"routing policy {protocol} reset and deleted: {status}")
        with contextlib.suppress(Exception):
            self.stub.stop()

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
    if args.router and not args.routing:
        print("FAILED: --router needs --routing (the stub and the routing clients)", file=sys.stderr)
        return 2
    routing = {}
    if args.routing:
        routing = {"stub": Stub(args.stub_listen, Path(args.output) / "socks5-stub.log"), "host": Host(args.caddyfile),
                   "routing_probes": RoutingProbes(args, Path(args.output) / "routing-cores")}
    scenario = Scenario(args, node=Panel(args.node_url, ca_file=args.client_ca_file), central=Panel(central_url),
                        process=CentralProcess(args), docker=Docker(), probes=Probes(args), **routing)
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
