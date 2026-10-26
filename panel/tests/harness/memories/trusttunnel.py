"""Manager wire double: test-owned state, never a panel implementation."""
from __future__ import annotations
import hashlib
import json
import re


class TrusttunnelError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


PASSWORD = re.compile(r"[\x21-\x7e]{8,128}")


OPERATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


EGRESS_ADDRESS = re.compile(r"127\.0\.0\.1:([0-9]{4,5})")


EGRESS_DIRECT = {"mode": "direct", "address": None}


def egress_revision(document: dict) -> str:
    canonical = json.dumps({"mode": document["mode"], "address": document["address"]},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class MemoryTrusttunnel:
    """The manager contract in memory (`trusttunnel_manager/service.py`): one endpoint, clients with
    a password each, idempotent create/rotate by operation id, a revision per client, counters the
    tests can set, and the manager's egress document with one step of rollback."""

    def __init__(self, *, hostname="gate.example.com", public_port=443, certificate_der_b64=None, version="1.1.0"):
        self.hostname, self.public_port, self.version = hostname, public_port, version
        # a certificate no public CA signed: the manager then hands its DER out; None = trusted
        self.certificate_der_b64 = certificate_der_b64
        self.client_table: dict[str, dict] = {}
        self.operations: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.broken = False
        self.running = True
        self.certificate_missing = False
        # {"create": "lose_response"} performs the mutation and then raises, once.
        self.faults: dict[str, str] = {}
        self.egress_document = dict(EGRESS_DIRECT)
        self.egress_previous: dict | None = None
        self.egress_fail_next: str | None = None
        self.restarts = 0

    def _guard(self):
        if self.broken:
            raise TrusttunnelError("unavailable")

    def _lose(self, operation):
        if self.faults.get(operation) == "lose_response":
            del self.faults[operation]  # the fault fires once: the replay gets its answer
            raise TrusttunnelError("TrustTunnel manager unavailable")

    @staticmethod
    def _refuse(message="invalid request"):
        raise TrusttunnelError("TrustTunnel manager rejected request", 422, "invalid_request")

    def _view(self, username):
        row = self.client_table[username]
        return {"username": username, "enabled": row["enabled"], "revision": row["revision"],
                "rx": row.get("rx", 0), "tx": row.get("tx", 0), "sessions": row.get("sessions", 0)}

    def authenticates(self, username: str, password: str) -> bool:
        """What the endpoint would say: only an enabled client with the current password gets in."""
        row = self.client_table.get(username)
        return bool(row and row["enabled"] and row["password"] == password)

    async def health(self):
        self._guard()
        out = {"status": "ok", "endpoint": {"running": self.running, "pid": 4242 if self.running else None},
               "clients": len(self.client_table)}
        if self.certificate_missing:
            out["status"], out["code"] = "degraded", "certificate_missing"
        elif not self.running:
            out["status"], out["code"] = "degraded", "endpoint_down"
        return out

    async def endpoint(self):
        self._guard()
        trusted = self.certificate_der_b64 is None
        return {"hostname": self.hostname, "listen": "127.0.0.1:4453", "public_port": self.public_port,
                "version": self.version, "certificate_trusted": trusted,
                "certificate_der_b64": self.certificate_der_b64,
                "fingerprint": None if self.certificate_missing else hashlib.sha256(
                    (self.certificate_der_b64 or "trusted").encode()).hexdigest()}

    async def clients(self):
        self._guard()
        return [self._view(name) for name in sorted(self.client_table)]

    async def create_client(self, payload):
        self._guard()
        if (set(payload) - {"operation_id", "username", "password"}
                or not OPERATION_ID.fullmatch(str(payload.get("operation_id")))
                or not USERNAME.fullmatch(str(payload.get("username")))
                or not PASSWORD.fullmatch(str(payload.get("password")))):
            self._refuse()
        self.calls.append(("create", payload["username"]))
        operation_id, username, password = payload["operation_id"], payload["username"], payload["password"]
        body = {"username": username, "password": password}
        known = self.operations.get(operation_id)
        if known is not None:
            if known["body"] != body:
                raise TrusttunnelError("operation id reused", 409, "operation_conflict")
            if username not in self.client_table:
                raise TrusttunnelError("the client of this operation was deleted", 409, "operation_conflict")
            return {"client": self._view(username)}
        if username in self.client_table:
            raise TrusttunnelError("username exists", 409, "exists")
        self.client_table[username] = {"enabled": True, "password": password, "revision": 1}
        self.operations[operation_id] = {"body": body}
        self.restarts += 1
        self._lose("create")
        return {"client": self._view(username)}

    async def client_state(self, username, action):
        self._guard()
        if username not in self.client_table:
            raise TrusttunnelError("not found", 404, "not_found")
        row = self.client_table[username]
        if row["enabled"] != (action == "enable"):
            row["enabled"] = action == "enable"
            row["revision"] += 1
            self.restarts += 1
        return {"client": self._view(username)}

    async def rotate_client(self, username, payload):
        self._guard()
        if (set(payload) - {"operation_id", "password"} or not OPERATION_ID.fullmatch(str(payload.get("operation_id")))
                or not PASSWORD.fullmatch(str(payload.get("password")))):
            self._refuse()
        if username not in self.client_table:
            raise TrusttunnelError("not found", 404, "not_found")
        row = self.client_table[username]
        body = {"username": username, "password": payload["password"], "kind": "rotate"}
        known = self.operations.get(payload["operation_id"])
        if known is not None:
            if known["body"] != body:
                raise TrusttunnelError("operation id reused", 409, "operation_conflict")
        else:
            row["password"] = payload["password"]
            row["revision"] += 1
            self.operations[payload["operation_id"]] = {"body": body}
            self.restarts += 1
        self._lose("rotate")
        return {"client": self._view(username)}

    async def delete_client(self, username):
        """Idempotent, like the manager's: a client that is already gone is a 204 too."""
        self._guard()
        if self.client_table.pop(username, None) is not None:
            self.restarts += 1

    # -- egress -----------------------------------------------------------------------------

    @staticmethod
    def _egress_normalise(document) -> dict:
        if not isinstance(document, dict) or set(document) - {"mode", "address"}:
            MemoryTrusttunnel._refuse()
        mode, address = document.get("mode"), document.get("address")
        if mode == "direct":
            if address not in (None, ""):
                MemoryTrusttunnel._refuse()
            return dict(EGRESS_DIRECT)
        match = EGRESS_ADDRESS.fullmatch(address) if isinstance(address, str) else None
        if mode != "socks5" or not match or not 1024 <= int(match.group(1)) <= 65535:
            MemoryTrusttunnel._refuse()
        return {"mode": "socks5", "address": address}

    def _egress_view(self, document=None):
        document = document or self.egress_document
        return {**document, "revision": egress_revision(document)}

    async def egress(self):
        self._guard()
        return self._egress_view()

    async def egress_plan(self, document):
        self._guard()
        proposed = self._egress_normalise(document)
        return {"changed": proposed != self.egress_document, "current": self._egress_view(),
                "proposed": self._egress_view(proposed)}

    def _egress_fail(self):
        code, self.egress_fail_next = self.egress_fail_next, None
        if code is not None:
            raise TrusttunnelError("TrustTunnel manager rejected request", 502, code)

    async def egress_apply(self, document):
        self.calls.append(("egress_apply",))
        self._guard()
        proposed = self._egress_normalise(document)
        if proposed != self.egress_document:
            self._egress_fail()
            self.egress_previous, self.egress_document = self.egress_document, proposed
            self.restarts += 1
        return self._egress_view()

    async def egress_rollback(self):
        self.calls.append(("egress_rollback",))
        self._guard()
        if self.egress_previous is None:
            raise TrusttunnelError("nothing to roll back to", 409, "no_previous")
        self._egress_fail()
        self.egress_document, self.egress_previous = self.egress_previous, None
        self.restarts += 1
        return self._egress_view()
