"""The in-memory manager doubles behind real servers that speak each manager's wire protocol.

Every `Memory*` double of the panel (`MemoryNaive`, `MemoryMieru`, `MemoryAmneziawg`,
`MemoryTrusttunnel`, `MemoryXrayRouter`, `MemoryTelemt`, `MemoryVersions`, and the metrics double
`MemoryAgentMetrics`) is served by a small HTTP/1.1 server: a Unix socket for the managers and the
version agent, TCP `127.0.0.1:<port>` for Telemt (its URL is an http URL). The server checks the
header the real client sends (`X-Naive-Token`, `X-Mieru-Token`, `X-Awg-Token`,
`X-Trusttunnel-Token`, `X-Xray-Router-Token`, Telemt's `Authorization`; none for the version agent)
and dispatches each request to the **same object the test holds**, so `naive.seed(...)`,
`naive.calls`, `telemt.users`, `router.fail_next` keep working while the panel — Python or Rust —
talks to the double only over the wire, through its real client.

Wire rules (the inverse of the panel's clients, `panel/{naive,mieru,amneziawg,trusttunnel,
xray_router,telemt,versions}.py`):

- a result is answered `200` with its JSON (`null` for None); AmneziaWG's `instances`/`peers` and
  TrustTunnel's `clients` are wrapped in their envelope key; Telemt answers its envelope
  `{"ok": true, "data": …, "revision": …}` (`config`/`patch_config` return `(data, revision)`);
- a manager error with a status answers that status and `{"detail": str(exc), "code": exc.code}`;
  a `502` without a code stands for an outage or a lost reply (the doubles raise it after the
  mutation for `lose_response` faults): the server reads the request, runs it, and closes the
  connection without an answer — the client sees a transport error, exactly as with a real outage;
  Telemt's `TelemtIndeterminate` is the same lost reply; other `TelemtError`s answer their status;
- `KeyError` from a double (an unknown user) answers `404 {"code": "not_found"}`; a method the
  double does not have answers `404`; any other exception drops the connection and is recorded in
  `server.errors` with its traceback.

The servers run on the test's own event loop, so a double that waits on an `asyncio.Event` of the
test keeps doing exactly that. A server created outside a running loop (in a sync fixture) is bound
at once (its socket exists, the kernel queues connections) and starts accepting when the test's
loop starts: `attach_pending()` is called by the harness's `pytest_pyfunc_call` wrapper in
`conftest.py` and by every async fixture that creates a panel.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import inspect
import json
import os
import re
import secrets
import shutil
import socket
import tempfile
import traceback
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import unquote

DROP = object()

_REASONS = {200: "OK", 204: "No Content", 401: "Unauthorized", 404: "Not Found", 409: "Conflict",
            412: "Precondition Failed", 422: "Unprocessable Entity", 500: "Internal Server Error",
            502: "Bad Gateway", 503: "Service Unavailable"}

# Every server created and not closed yet; the ones not attached to a loop wait here.
_SERVERS: list["FakeManagerServer"] = []
# The server whose double is running right now (set around every dispatch): a double patched by a
# test that calls "the original" it read from the panel's client lands back in the double, not on
# the wire again (`original = app.state.naive.create; monkeypatch.setattr(app.state.naive, "create", …)`).
_DISPATCHING: contextvars.ContextVar = contextvars.ContextVar("fake_manager_dispatching", default=None)
# Every manager set not closed yet (its private directory is removed by `close_all`).
_SETS: list["FakeManagers"] = []


@dataclass(frozen=True)
class Route:
    method: str
    pattern: re.Pattern
    name: str  # the method of the double
    args: Callable[[list[str], Any, dict], tuple[tuple, dict]]
    wrap: Callable[[Any], Any] | None = None


def _route(method: str, path: str, name: str, args=None, wrap=None) -> Route:
    regex = "^" + re.sub(r"\{[a-z_]+\}", "([^/]+)", path) + "$"
    return Route(method, re.compile(regex), name, args or (lambda params, body, headers: (tuple(params), {})), wrap)


def _body(*keys, optional=()):
    """Positional args from the JSON body's keys, keyword args from the optional keys present."""
    def build(params, body, _headers):
        body = body if isinstance(body, dict) else {}
        kwargs = {key: body[key] for key in optional if key in body}
        return (*params, *(body.get(key) for key in keys)), kwargs
    return build


def _whole_body(params, body, _headers):
    return (*params, body), {}


def _egress_quartet() -> list[Route]:
    return [
        _route("GET", "/v1/egress", "egress"),
        _route("POST", "/v1/egress/plan", "egress_plan", _body("expected_revision", "document")),
        _route("POST", "/v1/egress/apply", "egress_apply", _body("expected_revision", "document", "operation_id")),
        _route("POST", "/v1/egress/rollback", "egress_rollback", _body("expected_revision")),
    ]


def _lanes() -> list[Route]:
    return [_route("GET", "/v1/lanes", "lanes"), _route("PUT", "/v1/lanes", "set_lanes", _body("lanes"))]


@dataclass(frozen=True)
class Spec:
    kind: str
    header: str | None  # the token header, lowercase; None = no auth (version agent)
    routes: tuple[Route, ...]
    telemt: bool = False


NAIVE = Spec("naive", "x-naive-token", (
    _route("GET", "/v1/health", "health"),
    _route("GET", "/v1/users", "list_users"),
    _route("GET", "/v1/traffic", "traffic"),
    _route("POST", "/v1/users", "create", _body("username", "quota_bytes", optional=("password", "operation_id"))),
    _route("POST", "/v1/users/{u}/access", "reveal"),
    _route("POST", "/v1/users/{u}/rotate", "rotate", _body(optional=("password", "operation_id"))),
    _route("POST", "/v1/users/{u}/enable", "set_enabled", lambda p, b, h: ((p[0], True), {})),
    _route("POST", "/v1/users/{u}/disable", "set_enabled", lambda p, b, h: ((p[0], False), {})),
    _route("POST", "/v1/users/{u}/quota", "set_quota", _body("quota_bytes")),
    _route("DELETE", "/v1/users/{u}", "delete"),
    _route("POST", "/v1/users/{u}/traffic/reset", "reset_traffic"),
    *_egress_quartet(),
    *_lanes(),
))

MIERU = Spec("mieru", "x-mieru-token", (
    _route("GET", "/v1/health", "health"),
    _route("GET", "/v1/users", "list_users"),
    _route("GET", "/v1/metrics", "metrics"),
    _route("GET", "/v1/traffic", "traffic"),
    _route("POST", "/v1/lifecycle/{action}", "lifecycle"),
    _route("POST", "/v1/users", "create", _whole_body),
    _route("POST", "/v1/users/{u}/quotas", "set_quotas", _whole_body),
    _route("POST", "/v1/users/{u}/rotate", "rotate", _body("expected_revision", optional=("password", "operation_id"))),
    _route("POST", "/v1/users/{u}/reset-metrics", "reset_metrics"),
    _route("POST", "/v1/users/{u}/{operation}", "operation", _body("expected_revision")),
    _route("DELETE", "/v1/users/{u}", "delete", _body("expected_revision")),
    *_egress_quartet(),
    *_lanes(),
))

AMNEZIAWG = Spec("amneziawg", "x-awg-token", (
    _route("GET", "/v1/health", "health"),
    _route("GET", "/v1/instances", "instances", wrap=lambda value: {"instances": value}),
    _route("GET", "/v1/peers", "peers", wrap=lambda value: {"peers": value}),
    _route("POST", "/v1/peers", "create_peer", _whole_body),
    _route("POST", "/v1/peers/{u}/rotate", "rotate_peer", _whole_body),
    _route("POST", "/v1/peers/{u}/{action}", "peer_state"),
    _route("DELETE", "/v1/peers/{u}", "delete_peer"),
    *_egress_quartet(),
))

TRUSTTUNNEL = Spec("trusttunnel", "x-trusttunnel-token", (
    _route("GET", "/v1/health", "health"),
    _route("GET", "/v1/endpoint", "endpoint"),
    _route("GET", "/v1/clients", "clients", wrap=lambda value: {"clients": value}),
    _route("POST", "/v1/clients", "create_client", _whole_body),
    _route("POST", "/v1/clients/{u}/rotate", "rotate_client", _whole_body),
    _route("POST", "/v1/clients/{u}/{action}", "client_state"),
    _route("DELETE", "/v1/clients/{u}", "delete_client"),
    # the egress document itself is the body (trusttunnel.py)
    _route("GET", "/v1/egress", "egress"),
    _route("POST", "/v1/egress/plan", "egress_plan", _whole_body),
    _route("POST", "/v1/egress/apply", "egress_apply", _whole_body),
    _route("POST", "/v1/egress/rollback", "egress_rollback", lambda p, b, h: ((), {})),
))

ROUTER = Spec("router", "x-xray-router-token", (
    _route("GET", "/v1/status", "status"),
    _route("GET", "/v1/egress/{service}", "egress"),
    _route("POST", "/v1/egress/{service}/plan", "egress_plan", _body("expected_revision", "document")),
    _route("POST", "/v1/egress/{service}/apply", "egress_apply", _body("expected_revision", "document", "operation_id")),
    _route("POST", "/v1/egress/{service}/rollback", "egress_rollback", _body("expected_revision")),
    _route("GET", "/v1/lanes/{service}", "lanes"),
    _route("POST", "/v1/lanes/{service}", "lane_issue", _body("lane")),
    _route("DELETE", "/v1/lanes/{service}/{lane}", "lane_forget"),
    _route("GET", "/v1/relay", "relay"),
    _route("POST", "/v1/relay", "relay_enable", _body("server_name", "port")),
    _route("DELETE", "/v1/relay", "relay_disable"),
    _route("PUT", "/v1/relay/accounts", "relay_set_accounts", _body("accounts")),
    _route("GET", "/v1/ingress/{service}", "ingress"),
    _route("GET", "/v1/geodata", "geodata"),
    _route("GET", "/v1/geodata/codes", "geodata_codes"),
    _route("PUT", "/v1/geodata/settings", "geodata_settings", _whole_body),
    _route("POST", "/v1/geodata/update", "geodata_update"),
    _route("POST", "/v1/geodata/restore", "geodata_restore"),
    _route("POST", "/v1/exits/test", "exit_test", _body("exit")),
))


def _envelope(value):
    return {"ok": True, "data": value, "revision": None}


def _envelope_pair(value):
    data, revision = value
    return {"ok": True, "data": data, "revision": revision}


def _if_match(params, body, headers):
    return (*params, *(() if body is None else (body,)), headers.get("if-match")), {}


TELEMT = Spec("telemt", "authorization", (
    _route("GET", "/v1/users", "list_users", wrap=_envelope),
    _route("POST", "/v1/users", "create_user", _body("username", "secret"), wrap=_envelope),
    _route("DELETE", "/v1/users/{u}", "delete_user", wrap=_envelope),
    _route("POST", "/v1/users/{u}/enable", "set_enabled", lambda p, b, h: ((p[0], True), {}), wrap=_envelope),
    _route("POST", "/v1/users/{u}/disable", "set_enabled", lambda p, b, h: ((p[0], False), {}), wrap=_envelope),
    _route("POST", "/v1/users/{u}/rotate-secret", "rotate", _body("secret"), wrap=_envelope),
    _route("PATCH", "/v1/users/{u}", "update_user", _whole_body, wrap=_envelope),
    _route("POST", "/v1/users/{u}/reset-quota", "reset_quota", wrap=_envelope),
    _route("GET", "/v1/health/ready", "health", wrap=_envelope),
    _route("GET", "/v1/stats/summary", "stats", wrap=_envelope),
    _route("GET", "/v1/runtime/connections/summary", "connections", wrap=_envelope),
    _route("GET", "/v1/stats/users/active-ips", "active_ips", wrap=_envelope),
    _route("GET", "/v1/stats/users/quota", "quota_stats", wrap=_envelope),
    _route("GET", "/v1/config", "config", wrap=_envelope_pair),
    _route("PATCH", "/v1/config", "patch_config", _if_match, wrap=_envelope_pair),
    _route("POST", "/v1/system/reload", "reload", lambda p, b, h: ((h.get("if-match"),), {}), wrap=_envelope),
    _route("GET", "/v1/system/reload/{reload_id}", "reload_status", lambda p, b, h: ((int(p[0]),), {}),
           wrap=_envelope),
), telemt=True)

VERSIONS = Spec("versions", None, (
    _route("GET", "/v1/versions", "list_versions"),
    _route("GET", "/v1/host", "host"),
    _route("GET", "/v1/metrics", "metrics"),
    _route("POST", "/v1/upstream/check", "check"),
    _route("POST", "/v1/panel/managers/rebuild", "rebuild_managers"),
    _route("POST", "/v1/update", "update", _body("component", "version", "expected_current")),
))

SPECS = {spec.kind: spec for spec in (NAIVE, MIERU, AMNEZIAWG, TRUSTTUNNEL, ROUTER, TELEMT, VERSIONS)}


class FakeManagerServer:
    """One double behind one listening socket (see the module docstring for the wire rules)."""

    def __init__(self, spec: Spec, memory, *, token: str | None, path: str | None = None):
        self.spec, self.memory, self.token, self.path = spec, memory, token, path
        self.errors: list[str] = []
        self.requests: list[tuple[str, str]] = []
        if path is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            self.url = "http://127.0.0.1:%d" % sock.getsockname()[1]
        else:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(path)
            self.url = f"unix:{path}"
        sock.listen(128)
        sock.setblocking(False)
        self._sock = sock
        self._loop = None
        self._server = None
        self._closed = False
        _SERVERS.append(self)
        self.attach()

    # -- lifecycle -------------------------------------------------------------------------

    def attach(self) -> bool:
        """Start accepting on the running loop (no-op outside one or when already serving there)."""
        if self._closed:
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        if self._loop is loop:
            return True
        self._loop = loop
        if self.path is None:
            start = asyncio.start_server(self._handle, sock=self._sock)
        else:
            start = asyncio.start_unix_server(self._handle, sock=self._sock)
        task = loop.create_task(start)
        task.add_done_callback(self._started)
        return True

    def _started(self, task) -> None:
        if not task.cancelled() and task.exception() is None:
            self._server = task.result()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._server is not None and self._loop is not None and not self._loop.is_closed():
            with contextlib.suppress(RuntimeError):
                self._server.close()
        with contextlib.suppress(OSError):
            self._sock.close()
        if self.path:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self.path)
        with contextlib.suppress(ValueError):
            _SERVERS.remove(self)

    # -- HTTP --------------------------------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                head = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                return
            lines = head.decode("latin-1").split("\r\n")
            method, target = lines[0].split(" ")[:2]
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()
            if headers.get("transfer-encoding", "").lower() == "chunked":
                body = await _read_chunked(reader)
            else:
                length = int(headers.get("content-length") or 0)
                body = await reader.readexactly(length) if length else b""
            outcome = await self.dispatch(method, target.split("?", 1)[0], headers, body)
            if outcome is DROP:
                return
            status, payload = outcome
            data = json.dumps(payload).encode()
            writer.write((f"HTTP/1.1 {status} {_REASONS.get(status, 'Status')}\r\n"
                          "Content-Type: application/json\r\n"
                          f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
            with contextlib.suppress(ConnectionError):
                await writer.drain()
        except Exception:  # noqa: BLE001 - a broken request must never kill the test loop
            self.errors.append(traceback.format_exc())
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _authorized(self, headers: dict[str, str]) -> bool:
        if self.spec.header is None:
            return True
        return self.token is not None and headers.get(self.spec.header) == self.token

    async def dispatch(self, method: str, path: str, headers: dict[str, str], body: bytes):
        self.requests.append((method, path))
        if not self._authorized(headers):
            return 401, {"detail": "unauthorized"}
        for route in self.spec.routes:
            if route.method != method:
                continue
            match = route.pattern.fullmatch(path)
            if match is None:
                continue
            try:
                payload = json.loads(body) if body else None
            except ValueError:
                return 422, {"detail": "invalid body"}
            function = getattr(self.memory, route.name, None)
            if function is None:
                return 404, {"detail": "not found"}
            args, kwargs = route.args([unquote(group) for group in match.groups()], payload, headers)
            token = _DISPATCHING.set(self)
            try:
                result = function(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
            except Exception as exc:  # noqa: BLE001 - mapped onto the wire below
                return self._error(exc)
            finally:
                _DISPATCHING.reset(token)
            return 200, route.wrap(result) if route.wrap else result
        return 404, {"detail": "not found"}

    def _error(self, exc: Exception):
        if isinstance(exc, KeyError):
            body = {"detail": "not found", "code": "not_found"}
            return (404, {"ok": False, "error": body}) if self.spec.telemt else (404, body)
        status = getattr(exc, "status_code", None)
        if self.spec.telemt:
            from panel.telemt import TelemtError, TelemtIndeterminate
            if isinstance(exc, TelemtIndeterminate) or not isinstance(exc, TelemtError):
                self._note(exc)
                return DROP
            return status, {"ok": False, "error": {"message": str(exc)}}
        if not isinstance(status, int):
            self._note(exc)
            return DROP
        code = getattr(exc, "code", None)
        if status == 502 and code is None:
            return DROP  # an outage or a lost reply: the client sees a transport error
        payload = {"detail": str(exc)}
        if code is not None:
            payload["code"] = code
        return status, payload

    def _note(self, exc: Exception) -> None:
        self.errors.append("".join(traceback.format_exception(exc)))


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    chunks = []
    while True:
        size = int((await reader.readuntil(b"\r\n")).split(b";")[0].strip(), 16)
        if size == 0:
            await reader.readuntil(b"\r\n")
            return b"".join(chunks)
        chunks.append(await reader.readexactly(size))
        await reader.readexactly(2)


def attach_pending() -> None:
    """Attach every live server to the running loop (called once the test's loop runs)."""
    for server in list(_SERVERS):
        server.attach()


def assertion_failures() -> list[str]:
    """Tracebacks of `AssertionError`s raised inside a double (a test's "must not be called")."""
    return [error for server in _SERVERS for error in server.errors if "AssertionError" in error]


def close_all() -> None:
    for managers in list(_SETS):
        managers.close()
    for server in list(_SERVERS):
        server.close()


# -- the panel's real clients, sharing the double with the test --------------------------------

_BACKED: dict[type, type] = {}


def _backed_class(base: type) -> type:
    """A subclass of a real client whose own methods go over the wire, while every attribute it
    lacks (`seed`, `users`, `calls`, `fail_next`, …) reads and writes the double behind it. A test
    that holds `app.state.naive` (or `node.state.router.client`) therefore sees the double, and
    one that patches a method of it patches what the server dispatches to."""
    cls = _BACKED.get(base)
    if cls is not None:
        return cls

    def __init__(self, memory, server, *args, **kwargs):
        object.__setattr__(self, "_harness_init", True)
        object.__setattr__(self, "memory", memory)
        object.__setattr__(self, "server", server)
        base.__init__(self, *args, **kwargs)
        object.__setattr__(self, "_harness_own", frozenset(self.__dict__))
        object.__setattr__(self, "_harness_init", False)

    def __getattr__(self, name):
        if name.startswith("_harness") or name in {"memory", "server"}:
            raise AttributeError(name)
        return getattr(object.__getattribute__(self, "memory"), name)

    def _local(self, name) -> bool:
        state = self.__dict__
        return state.get("_harness_init", True) or name in state.get("_harness_own", ())

    def __setattr__(self, name, value):
        if _local(self, name):
            object.__setattr__(self, name, value)
        else:
            setattr(self.memory, name, value)

    def __delattr__(self, name):
        if _local(self, name):
            object.__delattr__(self, name)
        else:
            delattr(self.memory, name)

    namespace = {"__init__": __init__, "__getattr__": __getattr__, "__setattr__": __setattr__,
                 "__delattr__": __delattr__}
    for name, member in inspect.getmembers(base, inspect.iscoroutinefunction):
        if not name.startswith("_"):
            namespace[name] = _reentrant(name, member)
    cls = type(f"SocketBacked{base.__name__}", (base,), namespace)
    _BACKED[base] = cls
    return cls


def _reentrant(name: str, wire):
    """The client's method over the wire — unless the double behind it is the one calling (a test's
    patched method calling the original it captured): then the double's own, unpatched method."""
    async def method(self, *args, **kwargs):
        server = self.__dict__.get("server")
        if server is not None and _DISPATCHING.get() is server:
            own = getattr(type(server.memory), name, None)
            if own is not None:
                return await own(server.memory, *args, **kwargs)
        return await wire(self, *args, **kwargs)

    method.__name__ = method.__qualname__ = name
    return method


# kind → (env of the socket or URL, env of the token file, client class import path)
ENV = {
    "naive": ("NAIVE_MANAGER_SOCKET", "NAIVE_MANAGER_TOKEN_FILE"),
    "mieru": ("MIERU_MANAGER_SOCKET", "MIERU_MANAGER_TOKEN_FILE"),
    "amneziawg": ("AWG_MANAGER_SOCKET", "AWG_MANAGER_TOKEN_FILE"),
    "trusttunnel": ("TRUSTTUNNEL_MANAGER_SOCKET", "TRUSTTUNNEL_MANAGER_TOKEN_FILE"),
    "router": ("XRAY_ROUTER_MANAGER_SOCKET", "XRAY_ROUTER_MANAGER_TOKEN_FILE"),
    "telemt": ("TELEMT_API_URL", "TELEMT_API_TOKEN_FILE"),
    "versions": ("VERSION_AGENT_SOCKET", None),
}
KINDS = tuple(ENV)


def _client_class(kind: str) -> type:
    if kind == "naive":
        from panel.naive import NaiveClient as cls
    elif kind == "mieru":
        from panel.mieru import MieruClient as cls
    elif kind == "amneziawg":
        from panel.amneziawg import AmneziawgClient as cls
    elif kind == "trusttunnel":
        from panel.trusttunnel import TrusttunnelClient as cls
    elif kind == "router":
        from panel.xray_router import XrayRouterClient as cls
    elif kind == "telemt":
        from panel.telemt import TelemtClient as cls
    else:
        from panel.versions import VersionClient as cls
    return cls


def kind_of(memory) -> str | None:
    """Which manager a double stands for, by its class name (`MemoryNaive` → `naive`)."""
    names = {"MemoryNaive": "naive", "MemoryMieru": "mieru", "MemoryAmneziawg": "amneziawg",
             "MemoryTrusttunnel": "trusttunnel", "MemoryXrayRouter": "router", "MemoryTelemt": "telemt",
             "MemoryVersions": "versions", "MemoryAgentMetrics": "versions"}
    for klass in type(memory).__mro__:
        if klass.__name__ in names:
            return names[klass.__name__]
    return None


class FakeManagers:
    """The doubles of one panel: a short private directory (AF_UNIX paths are limited to 108
    bytes, pytest's tmp paths are not), one server per double, a token file per manager, and the
    real clients/environment that point the panel at them. A manager without a double gets a
    socket path (or a refused TCP port) where nothing answers: the panel sees it unavailable."""

    def __init__(self, directory: str | None = None):
        self.directory = directory or tempfile.mkdtemp(prefix="pcfm-", dir="/tmp")
        self._own_directory = directory is None
        self.servers: dict[str, FakeManagerServer] = {}
        self.tokens: dict[str, str] = {}
        self.memories: dict[str, Any] = {}
        self._clients: dict[str, Any] = {}
        # a bound, never-listening TCP socket: connecting to it is refused, and nobody else gets the port
        self._refusing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._refusing.bind(("127.0.0.1", 0))
        self._refused_url = "http://127.0.0.1:%d" % self._refusing.getsockname()[1]
        _SETS.append(self)

    def path(self, kind: str) -> str:
        return os.path.join(self.directory, f"{kind}.sock")

    def token_file(self, kind: str) -> str:
        return os.path.join(self.directory, f"{kind}-token")

    def token(self, kind: str) -> str:
        if kind not in self.tokens:
            value = secrets.token_urlsafe(24)
            self.tokens[kind] = f"Bearer {value}" if kind == "telemt" else value
            descriptor = os.open(self.token_file(kind), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(self.tokens[kind] + "\n")
        return self.tokens[kind]

    def host(self, kind: str, memory) -> FakeManagerServer:
        if kind in self.servers:
            raise ValueError(f"{kind} is already served")
        spec = SPECS[kind]
        token = None if spec.header is None else self.token(kind)
        server = FakeManagerServer(spec, memory, token=token, path=None if kind == "telemt" else self.path(kind))
        self.servers[kind], self.memories[kind] = server, memory
        return server

    def address(self, kind: str) -> str:
        if kind == "telemt":
            server = self.servers.get(kind)
            return server.url if server else self._refused_url
        return self.path(kind)

    def client(self, kind: str):
        """The panel's real client for this manager (shared with the double when there is one)."""
        if kind in self._clients:
            return self._clients[kind]
        cls = _client_class(kind)
        address = self.address(kind)
        args = (address,) if kind == "versions" else (address, self.token(kind))
        server = self.servers.get(kind)
        value = _backed_class(cls)(server.memory, server, *args) if server else cls(*args)
        self._clients[kind] = value
        return value

    def env(self, kinds=KINDS) -> dict[str, str]:
        """What the Rust binary needs to reach the same servers (`PANEL_IMPL=rust`)."""
        env = {}
        for kind in kinds:
            address_env, token_env = ENV[kind]
            env[address_env] = self.address(kind)
            if token_env:
                self.token(kind)
                env[token_env] = self.token_file(kind)
        return env

    def errors(self) -> list[str]:
        return [error for server in self.servers.values() for error in server.errors]

    def close(self) -> None:
        for server in self.servers.values():
            server.close()
        with contextlib.suppress(OSError):
            self._refusing.close()
        if self._own_directory:
            shutil.rmtree(self.directory, ignore_errors=True)
        with contextlib.suppress(ValueError):
            _SETS.remove(self)
