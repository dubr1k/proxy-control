"""The actual Rust panel under test, built with the `test-hooks` Cargo feature.

`start_panel(workdir, …)` returns a `PanelServer`:

- `.client` — an `httpx.AsyncClient` with `base_url="http://testserver"`, `follow_redirects=False`;
  `.http(host)` — another one for a different `Host` (the subscription domain);
- `.db_path`, `.key_path`, `.db()` — a read-only SQLite connection to the panel's database
  (`file:…?mode=ro`, rows as `sqlite3.Row`): the schema is a frozen contract, so tests may read it;
- `.naive`, `.mieru`, `.telemt`, `.amneziawg`, `.trusttunnel`, `.xray_router`, `.versions` — the
  doubles the panel reaches over the wire (`fake_managers`);
- `await .tick("pusher" | "enforcer" | "metrics")` — one synchronous pass of a background loop;
- `await .settle()` — wait for the work a request left running (a node's apply after a 202);
- `.clock` — one fake clock for wall time and monotonic time (`.advance(s)`, `.set(t)`);
- `.probe_bridge(answer)` — what the MTProxy ingress probe answers (default True);
- `.create_admin(…)`, `.create_api_key(…)`, `.cli(…)` — seeding through the CLI, as the installer
  does;

- serve: `<bin> [PANEL_RUST_ARGS]` with the panel's own environment (`PANEL_DATABASE`,
  `PANEL_MASTER_KEY_FILE`, `PANEL_ALLOWED_HOSTS`, `PANEL_COOKIE_SECURE=false`, `NAIVE_ENABLED`, …,
  every manager socket/URL and token file pointing at the doubles, `VERSION_AGENT_SOCKET`) plus
  `PANEL_LISTEN=unix:<dir>/panel.sock` (plain HTTP/1.1 on that socket instead of 0.0.0.0:8787).
  The harness waits for `GET /healthz` → 200 (`Host: testserver`).
- test knobs that have no environment variable in production (read only with `test-hooks`):
  `PANEL_TEST_LOGIN_ATTEMPTS`, `PANEL_TEST_LOGIN_WINDOW_SECONDS`, `PANEL_TEST_REVEAL_TTL_SECONDS`,
  `PANEL_TEST_SESSION_TTL_SECONDS`, `PANEL_TEST_BODY_LIMIT_BYTES`, `PANEL_TEST_LOGIN_VERIFY_CONCURRENCY`,
  `PANEL_TEST_API_KEY_RATE_PER_MINUTE`.
- `PANEL_TEST_NODE_ROUTES=node.example=unix:/…/node.sock[,host=unix:…]`: the fleet node client dials
  that socket with plain HTTP for that host instead of TLS (`https://node.example` stays the
  link's URL; pin/verify modes are covered by Rust unit tests of the node client).
- with `test-hooks` the background loops (pusher, enforcer, metrics sampler) start paused; routes
  under `/__test/` (any Host from `PANEL_ALLOWED_HOSTS`, no session, refused without the feature):
  - `POST /__test/clock {"time": t}` sets, `{"advance": s}` moves one fake clock that feeds wall
    time and monotonic time (`monotonic = time - 1.7e9`, as `panel.metrics.fakes.FakeClock`);
    answers `{"time": t, "monotonic": m}`. Before the first call the real clock runs.
  - `POST /__test/tick/pusher|enforcer|metrics` runs one `tick()` (`metrics` also `drain()`) and
    answers 200 once it finished; `enforcer` takes `{"force": bool}`.
  - `POST /__test/probe-bridge {"answer": bool}`: what the SOCKS5 probe of the router's MTProxy
    ingress answers (no DNS lookup of `xray-router-ingress` in tests).
  - `POST /__test/settle` answers 200 once the work a request left running has finished (a node's
    reconcile still applying after `PUT /api/fleet/v2/generation` answered 202).
- CLI: `<bin> cli <command> …` with the same environment.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import shlex
import sqlite3
import subprocess
import time
from pathlib import Path

import httpx

from .fake_managers import FakeManagers, attach_pending

RUST_BIN = os.environ.get("PANEL_RUST_BIN", str(Path(__file__).resolve().parents[2] / "target/debug/panel"))
LOOPS = ("pusher", "enforcer", "metrics")
MONOTONIC_OFFSET = 1_700_000_000.0

# Settings field → environment variable of the binary.
SETTINGS_ENV = {
    "database_path": "PANEL_DATABASE",
    "master_key_file": "PANEL_MASTER_KEY_FILE",
    "session_cookie_secure": "PANEL_COOKIE_SECURE",
    "allowed_hosts": "PANEL_ALLOWED_HOSTS",
    "naive_public_host": "NAIVE_PUBLIC_HOST",
    "naive_enabled": "NAIVE_ENABLED",
    "mieru_enabled": "MIERU_ENABLED",
    "amneziawg_enabled": "AMNEZIAWG_ENABLED",
    "amneziawg_public_host": "AMNEZIAWG_PUBLIC_HOST",
    "trusttunnel_enabled": "TRUSTTUNNEL_ENABLED",
    "trusttunnel_public_host": "TRUSTTUNNEL_PUBLIC_HOST",
    "xray_router_enabled": "XRAY_ROUTER_ENABLED",
    "mtproxy_public_host": "MTPROXY_DOMAIN",
    "subscription_url": "PANEL_SUBSCRIPTION_URL",
    "subscription_host": "PANEL_SUBSCRIPTION_HOST",
    "singbox_fork_clients": "PANEL_SINGBOX_FORK_CLIENTS",
    "panel_version_file": "PANEL_VERSION_FILE",
    "fleet_heartbeat_seconds": "PANEL_FLEET_HEARTBEAT_SECONDS",
    "metrics_enabled": "PANEL_METRICS_ENABLED",
    "metrics_interval_seconds": "PANEL_METRICS_INTERVAL_SECONDS",
    "metrics_ring_points": "PANEL_METRICS_RING_POINTS",
    # test knobs (hard-coded in production)
    "login_attempts": "PANEL_TEST_LOGIN_ATTEMPTS",
    "login_window_seconds": "PANEL_TEST_LOGIN_WINDOW_SECONDS",
    "reveal_ttl_seconds": "PANEL_TEST_REVEAL_TTL_SECONDS",
    "session_ttl_seconds": "PANEL_TEST_SESSION_TTL_SECONDS",
    "body_limit_bytes": "PANEL_TEST_BODY_LIMIT_BYTES",
    "login_verify_concurrency": "PANEL_TEST_LOGIN_VERIFY_CONCURRENCY",
    "api_key_rate_per_minute": "PANEL_TEST_API_KEY_RATE_PER_MINUTE",
}
# Settings that only name the managers: the harness points them at the doubles itself.
MANAGER_SETTINGS = {"telemt_url", "telemt_token", "naive_socket", "naive_token", "mieru_socket", "mieru_token",
                    "amneziawg_socket", "amneziawg_token", "trusttunnel_socket", "trusttunnel_token",
                    "xray_router_socket", "xray_router_token", "version_agent_socket"}


def _env_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (tuple, list)):
        return ",".join(value)
    return str(value)


class HarnessClock:
    """One fake clock for wall and monotonic time, installed on first use."""

    def __init__(self, server: "PanelServer"):
        self._server = server
        self.now: float | None = None
        self._offset = MONOTONIC_OFFSET

    @property
    def installed(self) -> bool:
        return self.now is not None

    def time(self) -> float:
        return time.time() if self.now is None else self.now

    def monotonic(self) -> float:
        return time.monotonic() if self.now is None else self.now - self._offset

    def set(self, value: float) -> None:
        self._server._clock_call({"time": value})

    def advance(self, seconds: float) -> None:
        self._server._clock_call({"advance": seconds})


class PanelServer:
    def __init__(self, workdir: Path, *, name: str, hosts: tuple[str, ...], db_name: str, key_name: str,
                 memories: dict, settings: dict, node_routes: dict | None, keyring: bool):
        self.name, self.workdir, self.hosts = name, Path(workdir), tuple(hosts)
        self.db_path = self.workdir / db_name
        self.key_path = self.workdir / key_name if keyring else None
        self.settings = settings
        self.managers = FakeManagers()
        for kind, memory in memories.items():
            if memory is not None:
                self.managers.host(kind, memory)
        self.clock = HarnessClock(self)
        self._closed = False
        self.process: subprocess.Popen | None = None
        if self.key_path is not None and not self.key_path.exists():
            material = base64.b64encode(os.urandom(32)).decode()
            self.key_path.write_text(json.dumps({
                "schema": 1, "active_key_id": "test-key",
                "keys": [{"key_id": "test-key", "state": "active", "created_at": int(time.time()),
                          "key_material": material}],
            }) + "\n")
            self.key_path.chmod(0o600)
        self._start_rust(node_routes or {})
        attach_pending()

    # -- doubles -------------------------------------------------------------------------------

    def _memory(self, kind):
        return self.managers.memories.get(kind)

    naive = property(lambda self: self._memory("naive"))
    mieru = property(lambda self: self._memory("mieru"))
    telemt = property(lambda self: self._memory("telemt"))
    amneziawg = property(lambda self: self._memory("amneziawg"))
    trusttunnel = property(lambda self: self._memory("trusttunnel"))
    xray_router = property(lambda self: self._memory("router"))
    versions = property(lambda self: self._memory("versions"))


    def _rust_env(self, node_routes: dict) -> dict[str, str]:
        env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "RUST_BACKTRACE",
                                                "RUST_LOG") if key in os.environ}
        values = {"database_path": self.db_path, "session_cookie_secure": False, "allowed_hosts": self.hosts,
                  **({"master_key_file": self.key_path} if self.key_path else {}), **self.settings}
        for field, value in values.items():
            if field in MANAGER_SETTINGS:
                continue
            if field not in SETTINGS_ENV:
                raise ValueError(f"no environment variable for the setting {field!r}")
            if value is not None:
                env[SETTINGS_ENV[field]] = _env_value(value)
        env.update(self.managers.env())
        if self.xray_router is not None:
            env.setdefault("XRAY_ROUTER_ENABLED", "true")
        if node_routes:
            env["PANEL_TEST_NODE_ROUTES"] = ",".join(f"{host}=unix:{server.socket}"
                                                     for host, server in node_routes.items())
        env["PANEL_LISTEN"] = f"unix:{self.socket}"
        return env

    def _start_rust(self, node_routes: dict) -> None:
        if not Path(RUST_BIN).is_file():
            raise RuntimeError(f"build the panel with test-hooks first or set PANEL_RUST_BIN: {RUST_BIN}")
        self.socket = os.path.join(self.managers.directory, "panel.sock")
        self.env = self._rust_env(node_routes)
        self.log_path = self.workdir / f"{self.name}-rust.log"
        log = open(self.log_path, "ab")  # noqa: SIM115 - lives as long as the process
        self.process = subprocess.Popen([RUST_BIN, *shlex.split(os.environ.get("PANEL_RUST_ARGS", ""))],
                                        env=self.env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        log.close()
        deadline = time.monotonic() + float(os.environ.get("PANEL_RUST_START_TIMEOUT", "30"))
        with self._sync_http() as http:
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError(f"the panel binary exited with {self.process.returncode}:\n{self._log_tail()}")
                try:
                    if http.get("/healthz").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    self.close()
                    raise RuntimeError(f"the panel binary did not answer /healthz:\n{self._log_tail()}")
                time.sleep(0.05)
            http.post("/__test/probe-bridge", json={"answer": True}).raise_for_status()
        self.client = self.http("testserver")

    def _log_tail(self, lines: int = 40) -> str:
        with contextlib.suppress(OSError):
            return "\n".join(self.log_path.read_text(errors="replace").splitlines()[-lines:])
        return ""

    def _sync_http(self) -> httpx.Client:
        return httpx.Client(transport=httpx.HTTPTransport(uds=self.socket), base_url="http://testserver",
                            follow_redirects=False, timeout=30)

    # -- HTTP ----------------------------------------------------------------------------------

    def http(self, host: str = "testserver", **kwargs) -> httpx.AsyncClient:
        """A new client for `http://<host>` (cookies of its own)."""
        kwargs.setdefault("follow_redirects", False)
        transport = httpx.AsyncHTTPTransport(uds=self.socket)
        return httpx.AsyncClient(transport=transport, base_url=f"http://{host}", **kwargs)

    # -- hooks ---------------------------------------------------------------------------------

    async def tick(self, loop: str, **options) -> None:
        if loop not in LOOPS:
            raise ValueError(f"unknown loop {loop!r}")
        async with self.http("testserver") as http:
            response = await http.post(f"/__test/tick/{loop}", json=options or None)
        assert response.status_code == 200, f"tick {loop}: {response.status_code} {response.text}"

    async def settle(self) -> None:
        """Wait until the work a request left running has finished (a node's apply after its 202)."""
        async with self.http("testserver") as http:
            response = await http.post("/__test/settle")
        assert response.status_code == 200, f"settle: {response.status_code} {response.text}"

    def _clock_call(self, body: dict) -> None:
        clock = self.clock
        with self._sync_http() as http:
            response = http.post("/__test/clock", json=body)
        response.raise_for_status()
        answer = response.json()
        clock.now, clock._offset = answer["time"], answer["time"] - answer["monotonic"]

    def probe_bridge(self, answer: bool) -> None:
        with self._sync_http() as http:
            http.post("/__test/probe-bridge", json={"answer": bool(answer)}).raise_for_status()

    # -- CLI and database ------------------------------------------------------------------------

    def cli(self, *argv: str, stdin: str = "") -> tuple[int, str, str]:
        """Run the real panel CLI and return (exit, stdout, stderr)."""
        done = subprocess.run([RUST_BIN, "cli", "--database", str(self.db_path), *argv], input=stdin,
                              env=self.env, capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout, done.stderr

    def create_admin(self, username: str, password: str, role: str = "owner") -> None:
        code, out, err = self.cli("create-admin", "--username", username, "--role", role, "--password-stdin",
                                  stdin=password + "\n")
        assert code == 0, f"create-admin: {code} {out} {err}"

    def create_api_key(self, name: str, scope: str, expires_days: int | None = None) -> str:
        argv = ["api-key-create", "--name", name, "--scope", scope]
        if expires_days is not None:
            argv += ["--expires-days", str(expires_days)]
        code, out, err = self.cli(*argv)
        assert code == 0, f"api-key-create: {code} {out} {err}"
        return json.loads(out)["plaintext"]

    @contextlib.contextmanager
    def db(self, *, write: bool = False):
        """A connection to the panel's database: read-only by default (WAL lets it read beside the
        server); `write=True` for seeding state no route can reach (the schema is a frozen contract),
        committed when the block ends."""
        if write:
            connection = sqlite3.connect(self.db_path, timeout=10)
        else:
            connection = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            if write:
                connection.commit()
        finally:
            connection.close()

    def audits(self, limit: int = 200, *, action: str | None = None, actor: str | None = None,
               target: str | None = None, request_id: str | None = None) -> list[dict]:
        """The audit rows newest first, each with its `detail` parsed (what `Store.audits` returns)."""
        clauses, values = [], []
        for column, value in (("action", action), ("actor_username", actor), ("target", target),
                              ("request_id", request_id)):
            if value is not None:
                clauses.append(f"{column} = ?" + (" COLLATE NOCASE" if column == "actor_username" else ""))
                values.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db() as db:
            rows = db.execute(f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?", (*values, limit))
            return [{**dict(row), "detail": json.loads(row["detail_json"])} for row in rows]

    @property
    def panel_guid(self) -> str | None:
        with self.db() as db:
            row = db.execute("SELECT value FROM panel_settings WHERE key='panel_guid'").fetchone()
        return None if row is None else row["value"]

    def schema(self) -> list[str]:
        """Every `CREATE …` statement of the database (`Store.dump_schema`)."""
        with self.db() as db:
            return [row[0] for row in db.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")]

    # -- shutdown ------------------------------------------------------------------------------

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.managers.close()

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self.client.aclose()
        self.close()


def start_panel(workdir: Path, *, name: str = "panel", hosts=("testserver",), db_name: str | None = None,
                key_name: str | None = None, keyring: bool = True, telemt=None, naive=None, mieru=None,
                amneziawg=None, trusttunnel=None, router=None, versions=None,
                node_routes: dict | None = None, **settings) -> PanelServer:
    """A panel with its own database and master key in `workdir`, reaching the given doubles over
    the wire; `node_routes` maps a linked panel's host (`node.example`) to its `PanelServer`."""
    memories = {"telemt": telemt, "naive": naive, "mieru": mieru, "amneziawg": amneziawg,
                "trusttunnel": trusttunnel, "router": router, "versions": versions}
    return PanelServer(workdir, name=name, hosts=tuple(hosts), db_name=db_name or f"{name}.sqlite3",
                       key_name=key_name or f"{name}-key", memories=memories, settings=settings,
                       node_routes=node_routes, keyring=keyring)



