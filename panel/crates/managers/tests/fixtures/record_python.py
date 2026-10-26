"""Records what the Python manager clients send and how they classify answers (WP5 goldens).

Every case calls one method of a Python client (`panel/naive.py`, `mieru.py`, `amneziawg.py`,
`trusttunnel.py`, `xray_router.py`, `telemt.py`, `versions.py`) against a recording server that
answers with the case's canned reply, and writes the raw request bytes and the outcome (the value,
or the error class, message, status and code). The Rust tests replay every case against the Rust
clients (`tests/python_goldens.rs`).

Run on ams-test from the stand copy (needs the panel venv):

    cd /root/dev/rust-panel-wp5 && PYTHONPATH=. /root/dev/proxy-control/.venv/bin/python \
        panel/crates/managers/tests/fixtures/record_python.py > panel/crates/managers/tests/fixtures/python-clients.json
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile

from panel.amneziawg import AmneziawgClient
from panel.mieru import MieruClient
from panel.naive import NaiveClient
from panel.telemt import TelemtClient
from panel.trusttunnel import TrusttunnelClient
from panel.versions import VersionClient
from panel.xray_router import XrayRouterClient

TOKEN = "synthetic-token-0123456789abcdef0123456789"
TELEMT_AUTH = "Bearer synthetic-telemt-token-0123456789abcdef"
OK = {"ok": 1, "instances": [1], "peers": [2], "clients": [3]}
TELEMT_OK = {"ok": True, "data": {"x": 1}, "revision": "r1"}
METRICS = {"status": "error", "stale": True, "users": [], "capability": "unavailable",
           "reason": "typed_histories_unavailable"}
DOC = {"schema": 1, "upstream": None, "acl": [{"deny": ["пример.рф", "a\"b"]}], "ratio": 1.5, "tiny": 1e-05}
LINK = "tg://proxy?server=proxy.example.com&port=443&secret=ee" + "ab" * 16


def reply(status=200, body=OK, *, raw=None, close=False, hang=False):
    if raw is None and body is not None:
        raw = json.dumps(body)
    return {"status": status, "body": raw, "close": close, "hang": hang}


def kw(**values):
    """Keyword arguments of a call (the last element of its args)."""
    return {"__kw__": values}


# (client, method, args, reply)
REQUESTS = [
    ("naive", "health", [], reply()),
    ("naive", "list_users", [], reply()),
    ("naive", "traffic", [], reply()),
    ("naive", "create", ["alice", 1024], reply()),
    ("naive", "create", ["alice", None, kw(password="p" * 20, operation_id="op-1")], reply()),
    ("naive", "create", ["alice", 5, kw(operation_id="op-2")], reply()),
    ("naive", "reveal", ["a b/c"], reply()),
    ("naive", "rotate", ["alice"], reply()),
    ("naive", "rotate", ["alice", kw(password="q" * 20, operation_id="op-3")], reply()),
    ("naive", "set_enabled", ["alice", True], reply()),
    ("naive", "set_enabled", ["alice", False], reply()),
    ("naive", "set_quota", ["alice", 2048], reply()),
    ("naive", "set_quota", ["alice", None], reply()),
    ("naive", "delete", ["alice"], reply(204, None)),
    ("naive", "reset_traffic", ["alice"], reply()),
    ("naive", "egress", [], reply()),
    ("naive", "egress_plan", ["r1", DOC], reply()),
    ("naive", "egress_apply", ["r1", DOC, "op-4"], reply()),
    ("naive", "egress_rollback", ["r1"], reply()),
    ("naive", "lanes", [], reply()),
    ("naive", "set_lanes", [[{"lane": "grant:a1", "users": ["alice"], "upstream": {"user": "u", "password": "p"}}]],
     reply()),
    ("mieru", "health", [], reply()),
    ("mieru", "list_users", [], reply()),
    ("mieru", "metrics", [], reply(200, METRICS)),
    ("mieru", "traffic", [], reply()),
    ("mieru", "lifecycle", ["restart"], reply()),
    ("mieru", "create", [{"username": "ü", "quotas": [{"days": 1, "megabytes": 2}], "expected_revision": "r"}],
     reply(201, OK)),
    ("mieru", "set_quotas", ["a b/c", {"quotas": [], "expected_revision": "r"}], reply()),
    ("mieru", "operation", ["alice", "disable", "r"], reply()),
    ("mieru", "rotate", ["alice", "r"], reply()),
    ("mieru", "rotate", ["alice", "r", kw(password="x" * 20, operation_id="op-5")], reply()),
    ("mieru", "delete", ["alice", "r"], reply()),
    ("mieru", "reset_metrics", ["alice"], reply()),
    ("mieru", "egress", [], reply()),
    ("mieru", "egress_plan", ["r1", DOC], reply()),
    ("mieru", "egress_apply", ["r1", DOC, "op-6"], reply()),
    ("mieru", "egress_rollback", ["r1"], reply()),
    ("mieru", "lanes", [], reply()),
    ("mieru", "set_lanes", [[]], reply()),
    ("amneziawg", "health", [], reply()),
    ("amneziawg", "instances", [], reply()),
    ("amneziawg", "peers", [], reply()),
    ("amneziawg", "create_peer", [{"operation_id": "o", "username": "a", "version": "2.0"}], reply(201, OK)),
    ("amneziawg", "peer_state", ["a b/c", "enable"], reply()),
    ("amneziawg", "rotate_peer", ["alice", {"operation_id": "o2"}], reply()),
    ("amneziawg", "delete_peer", ["alice"], reply(204, None)),
    ("amneziawg", "egress", [], reply()),
    ("amneziawg", "egress_plan", ["0", {"schema": 1, "upstream": None}], reply()),
    ("amneziawg", "egress_apply", ["0", {"schema": 1, "upstream": None}, "op-7"], reply()),
    ("amneziawg", "egress_rollback", ["1"], reply()),
    ("trusttunnel", "health", [], reply()),
    ("trusttunnel", "endpoint", [], reply()),
    ("trusttunnel", "clients", [], reply()),
    ("trusttunnel", "create_client", [{"operation_id": "o", "username": "a", "password": "p" * 8}], reply()),
    ("trusttunnel", "client_state", ["a b/c", "disable"], reply()),
    ("trusttunnel", "rotate_client", ["alice", {"operation_id": "o2", "password": "q" * 8}], reply()),
    ("trusttunnel", "delete_client", ["alice"], reply(204, None)),
    ("trusttunnel", "egress", [], reply()),
    ("trusttunnel", "egress_plan", [{"mode": "socks5", "address": "127.0.0.1:45103"}], reply()),
    ("trusttunnel", "egress_apply", [{"mode": "direct", "address": None}], reply()),
    ("trusttunnel", "egress_rollback", [], reply()),
    ("xray_router", "status", [], reply()),
    ("xray_router", "egress", ["naive"], reply()),
    ("xray_router", "egress_plan", ["naive", "r", DOC], reply()),
    ("xray_router", "egress_apply", ["mieru", "r", DOC, "op-8"], reply()),
    ("xray_router", "egress_rollback", ["mtproxy", "r"], reply()),
    ("xray_router", "lanes", ["naive"], reply()),
    ("xray_router", "lane_issue", ["naive", "grant:a1"], reply()),
    ("xray_router", "lane_forget", ["naive", "grant:a1"], reply()),
    ("xray_router", "lane_forget", ["naive", "grant:a b"], reply()),
    ("xray_router", "relay", [], reply()),
    ("xray_router", "ingress", ["mtproxy"], reply()),
    ("xray_router", "relay_enable", ["relay.example.com", 8443], reply()),
    ("xray_router", "relay_disable", [], reply()),
    ("xray_router", "geodata", [], reply()),
    ("xray_router", "geodata_codes", [], reply()),
    ("xray_router", "geodata_settings", [{"auto_update": False, "interval_hours": 24}], reply()),
    ("xray_router", "geodata_update", [], reply()),
    ("xray_router", "geodata_restore", [], reply()),
    ("xray_router", "exit_test", [{"protocol": "socks", "address": "10.0.0.2", "port": 1080}], reply()),
    ("xray_router", "relay_set_accounts", [[{"email": "relay:a:direct", "uuid": "u"}]], reply()),
    ("versions", "list_versions", [], reply()),
    ("versions", "host", [], reply()),
    ("versions", "metrics", [], reply()),
    ("versions", "check", [], reply()),
    ("versions", "rebuild_managers", [], reply()),
    ("versions", "update", ["naive", "2.11.7", "2.11.6"], reply()),
    ("versions", "update", ["xray", "26.1.1", None], reply()),
    ("telemt", "list_users", [], reply(200, TELEMT_OK)),
    ("telemt", "create_user", ["alice"], reply(200, TELEMT_OK)),
    ("telemt", "create_user", ["alice", "ab" * 16], reply(200, TELEMT_OK)),
    ("telemt", "delete_user", ["a b/c"], reply(200, TELEMT_OK)),
    ("telemt", "set_enabled", ["alice", True], reply(200, TELEMT_OK)),
    ("telemt", "set_enabled", ["alice", False], reply(200, TELEMT_OK)),
    ("telemt", "rotate", ["alice"], reply(200, TELEMT_OK)),
    ("telemt", "rotate", ["alice", "cd" * 16], reply(200, TELEMT_OK)),
    ("telemt", "update_user", ["alice", {"data_quota_bytes": 2048, "note": "ключ"}], reply(200, TELEMT_OK)),
    ("telemt", "reset_quota", ["alice"], reply(200, TELEMT_OK)),
    ("telemt", "health", [], reply(200, TELEMT_OK)),
    ("telemt", "stats", [], reply(200, TELEMT_OK)),
    ("telemt", "connections", [], reply(200, TELEMT_OK)),
    ("telemt", "active_ips", [], reply(200, TELEMT_OK)),
    ("telemt", "quota_stats", [], reply(200, TELEMT_OK)),
    ("telemt", "config", [], reply(200, TELEMT_OK)),
    ("telemt", "patch_config", [{"upstreams": [{"type": "direct"}]}, "rev-7"], reply(200, TELEMT_OK)),
    ("telemt", "reload", ["rev-8"], reply(200, TELEMT_OK)),
    ("telemt", "reload_status", [12], reply(200, TELEMT_OK)),
]

# How each client classifies an answer: one probe method per client, many canned replies.
PROBES = {
    "naive": ("health", []), "mieru": ("health", []), "amneziawg": ("health", []),
    "trusttunnel": ("health", []), "xray_router": ("status", []), "versions": ("list_versions", []),
}
ANSWERS = [
    reply(200, {"a": [1, "x"]}),
    reply(200, [1, 2]),
    reply(200, None, raw="null"),
    reply(204, None),
    reply(200, None, raw="not json"),
    reply(200, None, raw=""),
    reply(201, {"created": True}),
    reply(302, {}),
    reply(400, {"detail": "x", "code": "geodata_invalid"}),
    reply(401, {"detail": "unauthorized"}),
    reply(404, {"detail": "no", "code": "not_found"}),
    reply(404, None, raw="not json"),
    reply(409, {"detail": "x", "code": "egress_conflict"}),
    reply(409, {"detail": "x", "code": "quota_exhausted"}),
    reply(409, {"detail": "x", "code": "operation_conflict"}),
    reply(409, {"detail": "x", "code": "some_new_code"}),
    reply(409, {"detail": "x", "code": "x" * 64}),
    reply(409, {"detail": "x", "code": "x" * 65}),
    reply(409, {"detail": "x", "code": 5}),
    reply(409, {"detail": "x", "code": None}),
    reply(409, None, raw='{"detail":"hash aaaa password secret"}'),
    reply(409, [1]),
    reply(422, {"detail": "x", "code": "egress_invalid"}),
    reply(422, {"detail": "x", "code": "geodata_rejected"}),
    reply(500, {"detail": "x", "code": "manual_intervention_required"}),
    reply(502, {"detail": "x", "code": "egress_readback_mismatch"}),
    reply(503, {"detail": "x", "code": "artifact_mismatch"}),
    reply(503, {"detail": "x", "code": "manual_intervention_required"}),
    reply(close=True, body=None),
    reply(hang=True, body=None),
]
# Per-method answer handling beyond the common rules.
SHAPES = [
    ("mieru", "metrics", [], reply(200, METRICS)),
    ("mieru", "metrics", [], reply(200, {**METRICS, "stale": 1})),
    ("mieru", "metrics", [], reply(200, {**METRICS, "stale": False})),
    ("mieru", "metrics", [], reply(200, {**METRICS, "extra": None})),
    ("mieru", "metrics", [], reply(200, dict(reversed(list(METRICS.items()))))),
    ("mieru", "metrics", [], reply(204, None)),
    ("amneziawg", "instances", [], reply(200, {})),
    ("amneziawg", "instances", [], reply(200, {"instances": None})),
    ("amneziawg", "peers", [], reply(200, {"peers": [{"username": "a"}]})),
    ("amneziawg", "peers", [], reply(204, None)),
    ("amneziawg", "peers", [], reply(200, [1])),
    ("trusttunnel", "clients", [], reply(200, {})),
    ("trusttunnel", "clients", [], reply(200, {"clients": [{"username": "a"}]})),
    ("trusttunnel", "clients", [], reply(204, None)),
    ("versions", "metrics", [], reply(500, {})),
    ("versions", "metrics", [], reply(200, None, raw="nope")),
    ("versions", "update", ["naive", "1", None], reply(409, {"detail": "x"})),
    ("versions", "update", ["naive", "1", None], reply(422, {"detail": "x"})),
    ("versions", "update", ["naive", "1", None], reply(404, {"detail": "x"})),
    ("telemt", "list_users", [], reply(200, {"ok": True, "data": [{"username": "a"}], "revision": "r"})),
    ("telemt", "list_users", [], reply(200, {"ok": True})),
    ("telemt", "list_users", [], reply(200, {"ok": False, "data": [], "revision": "r"})),
    ("telemt", "list_users", [], reply(200, {"data": []})),
    ("telemt", "list_users", [], reply(200, {"ok": 1, "data": 5})),
    ("telemt", "list_users", [], reply(200, {"ok": "", "data": 5})),
    ("telemt", "list_users", [], reply(200, [1])),
    ("telemt", "list_users", [], reply(200, None, raw="nope")),
    ("telemt", "list_users", [], reply(204, None)),
    ("telemt", "list_users", [], reply(302, {"ok": True})),
    ("telemt", "list_users", [], reply(404, {"ok": False})),
    ("telemt", "create_user", ["alice"], reply(500, None, raw="secret-material-in-body")),
    ("telemt", "create_user", ["alice"], reply(close=True, body=None)),
    ("telemt", "create_user", ["alice"], reply(hang=True, body=None)),
    ("telemt", "config", [], reply(200, {"ok": True, "data": {"upstreams": []}, "revision": "rev-1"})),
    ("telemt", "config", [], reply(200, {"ok": True, "data": {"upstreams": []}, "revision": 7})),
    ("telemt", "current_access", ["alice"],
     reply(200, {"ok": True, "data": [{"username": "bob"}, {"username": "alice", "links": {"tls": [LINK]}}]})),
    ("telemt", "current_access", ["alice"], reply(200, {"ok": True, "data": [{"username": "bob"}]})),
    ("telemt", "current_access", ["alice"],
     reply(200, {"ok": True, "data": [{"username": "alice", "links": {"tls": ["tg://proxy?port=99999&secret="]}}]})),
]


def build(client: str, path: str, port: int):
    timeout = 0.5  # every case answers at once; only the `hang` cases wait for it
    if client == "naive":
        return NaiveClient(path, TOKEN, timeout=timeout)
    if client == "mieru":
        return MieruClient(path, TOKEN, timeout=timeout)
    if client == "amneziawg":
        return AmneziawgClient(path, TOKEN, timeout=timeout)
    if client == "trusttunnel":
        return TrusttunnelClient(path, TOKEN, timeout=timeout)
    if client == "xray_router":
        return XrayRouterClient(path, TOKEN, timeout=timeout)
    if client == "versions":
        return VersionClient(path, timeout=timeout)
    return TelemtClient(f"http://127.0.0.1:{port}", TELEMT_AUTH, timeout=timeout)


class Recorder:
    def __init__(self):
        self.reply = None
        self.requests: list[bytes] = []

    async def handle(self, reader, writer):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await reader.read(65536)
            if not chunk:
                break
            head += chunk
        header, _, body = head.partition(b"\r\n\r\n")
        length = 0
        for line in header.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(body) < length:
            chunk = await reader.read(65536)
            if not chunk:
                break
            body += chunk
        self.requests.append(header + b"\r\n\r\n" + body)
        current = self.reply
        if current["hang"]:
            await asyncio.sleep(2)
        elif not current["close"]:
            raw = (current["body"] or "").encode()
            reason = {200: "OK", 201: "Created", 204: "No Content"}.get(current["status"], "Status")
            writer.write(f"HTTP/1.1 {current['status']} {reason}\r\nContent-Type: application/json\r\n"
                         f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode() + raw)
            await writer.drain()
        writer.close()


def outcome_of(value):
    if isinstance(value, tuple):
        value = list(value)
    return {"kind": "ok", "value": value}


async def run_case(recorder, client, method, args, answer, path, port):
    recorder.reply, recorder.requests = answer, []
    kwargs = args[-1]["__kw__"] if args and isinstance(args[-1], dict) and "__kw__" in args[-1] else None
    positional = args[:-1] if kwargs is not None else args
    target = build(client, path, port)
    try:
        outcome = outcome_of(await getattr(target, method)(*positional, **(kwargs or {})))
    except Exception as exc:  # noqa: BLE001 - the class is the point
        outcome = {"kind": "error", "class": type(exc).__name__, "message": str(exc),
                   "status_code": getattr(exc, "status_code", None), "code": getattr(exc, "code", None)}
    requests = [base64.b64encode(raw).decode() for raw in recorder.requests]
    return {"client": client, "method": method, "args": positional, "kwargs": kwargs or {}, "reply": answer,
            "requests": requests, "outcome": outcome}


async def main():
    recorder = Recorder()
    directory = tempfile.mkdtemp(prefix="wp5-")
    path = os.path.join(directory, "manager.sock")
    unix = await asyncio.start_unix_server(recorder.handle, path)
    tcp = await asyncio.start_server(recorder.handle, "127.0.0.1", 0)
    port = tcp.sockets[0].getsockname()[1]
    cases = []
    async with unix, tcp:
        for client, method, args, answer in REQUESTS:
            cases.append(await run_case(recorder, client, method, args, answer, path, port))
        for client, (method, args) in PROBES.items():
            for answer in ANSWERS:
                cases.append(await run_case(recorder, client, method, args, answer, path, port))
        for client, method, args, answer in SHAPES:
            cases.append(await run_case(recorder, client, method, args, answer, path, port))
        # Telemt over a closed port (nothing sent) and every client over a missing socket.
        closed = TelemtClient("http://127.0.0.1:1", TELEMT_AUTH, timeout=0.5)
        try:
            await closed.list_users()
        except Exception as exc:  # noqa: BLE001
            cases.append({"client": "telemt", "method": "list_users", "args": [], "kwargs": {}, "reply": "refused",
                          "requests": [], "outcome": {"kind": "error", "class": type(exc).__name__,
                                                      "message": str(exc), "status_code": exc.status_code,
                                                      "code": None}})
        for client, (method, args) in PROBES.items():
            target = build(client, os.path.join(directory, "missing.sock"), port)
            try:
                value = await getattr(target, method)(*args)
                outcome = outcome_of(value)
            except Exception as exc:  # noqa: BLE001
                outcome = {"kind": "error", "class": type(exc).__name__, "message": str(exc),
                           "status_code": getattr(exc, "status_code", None), "code": getattr(exc, "code", None)}
            cases.append({"client": client, "method": method, "args": args, "kwargs": {}, "reply": "missing",
                          "requests": [], "outcome": outcome})
    json.dump({"generator": "panel/crates/managers/tests/fixtures/record_python.py", "cases": cases},
              sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    asyncio.run(main())
