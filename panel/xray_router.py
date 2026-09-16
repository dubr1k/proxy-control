"""The panel's client of the node's Xray-router manager (v0.5), and its in-memory twin.

The manager speaks the same egress vocabulary as the naive- and mieru-managers, per
service: `GET /v1/egress/{service}`, `plan`, `apply`, `rollback` — plus `GET /v1/status`
for what runs (Xray version, artifact digests, generation). See xray_router_manager/.
"""
from __future__ import annotations

import copy
import hashlib

import httpx

from .routing.document import EGRESS_REASON_CODES, ROUTER_DIRECT_INTENT, canonical

ROUTER_SERVICES = ("naive", "mieru")
# What the spike proved the router enforces (xray_router_manager/intent.py).
ROUTER_CAPABILITIES = (
    "whole_direct", "whole_warp",
    "block_domain", "block_cidr", "block_port", "block_geosite", "block_geoip",
    "selective_domain", "selective_cidr", "selective_port", "selective_geosite", "selective_geoip",
)


class XrayRouterError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code if code in EGRESS_REASON_CODES else None


class XrayRouterClient:
    def __init__(self, socket_path: str, token: str, *, timeout: float = 8.0, transport=None):
        self.socket_path = socket_path
        self.token = token
        self.timeout = timeout
        self.transport = transport

    @staticmethod
    def _reason(response) -> str | None:
        try:
            payload = response.json()
        except ValueError:
            return None
        return payload.get("code") if isinstance(payload, dict) else None

    async def _request(self, method: str, path: str, payload=None):
        transport = self.transport or httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(base_url="http://xray-router", timeout=self.timeout, transport=transport,
                                         headers={"X-Xray-Router-Token": self.token}) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise XrayRouterError("Xray-router manager unavailable") from exc
        if response.status_code >= 400:
            status = response.status_code if response.status_code in {404, 409, 422, 503} else 502
            raise XrayRouterError("Xray-router manager rejected request", status, self._reason(response))
        try:
            return response.json()
        except ValueError as exc:
            raise XrayRouterError("Invalid Xray-router manager response") from exc

    async def status(self): return await self._request("GET", "/v1/status")
    async def egress(self, service): return await self._request("GET", f"/v1/egress/{service}")
    async def egress_plan(self, service, expected_revision, document):
        return await self._request("POST", f"/v1/egress/{service}/plan",
                                   {"expected_revision": expected_revision, "document": document})
    async def egress_apply(self, service, expected_revision, document, operation_id):
        return await self._request("POST", f"/v1/egress/{service}/apply", {
            "expected_revision": expected_revision, "document": document, "operation_id": operation_id})
    async def egress_rollback(self, service, expected_revision):
        return await self._request("POST", f"/v1/egress/{service}/rollback", {"expected_revision": expected_revision})


class MemoryXrayRouter:
    """The router manager as tests see it: one intent per service, a generation counter,
    a journal per service, the manager's codes on demand (`fail_next`)."""

    def __init__(self, *, warp_url: str | None = "socks5://127.0.0.1:40000", available: bool = True):
        self.warp_url = warp_url
        self.reachable = True
        # `available` False = the manager does not answer at all (container down).
        self.available = available
        self.artifact_error: str | None = None
        self.xray_version = "Xray 26.3.27 (memory)"
        self.generation = 1
        self.documents = {service: copy.deepcopy(ROUTER_DIRECT_INTENT) for service in ROUTER_SERVICES}
        self.history: dict[str, list[dict]] = {service: [] for service in ROUTER_SERVICES}
        self.operations: dict[tuple[str, str], dict] = {}
        self.fail_next: str | None = None
        self.calls: list[tuple] = []

    def _revision(self, service: str) -> str:
        return hashlib.sha256(canonical({"generation": self.generation, "document": self.documents[service]})).hexdigest()

    def _digest(self, service: str) -> str:
        return hashlib.sha256(canonical(self.documents[service])).hexdigest()

    def _check(self, service: str, expected_revision: str | None = None) -> None:
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        if service not in ROUTER_SERVICES:
            raise XrayRouterError("not found", 404)
        if self.artifact_error:
            raise XrayRouterError("Xray-router manager rejected request", 503, "artifact_mismatch")
        if expected_revision is not None and expected_revision != self._revision(service):
            raise XrayRouterError("egress revision does not match", 409, "egress_conflict")

    def _fail(self) -> None:
        code, self.fail_next = self.fail_next, None
        if code is not None:
            status = {"egress_readback_mismatch": 502, "manual_intervention_required": 503, "geosite_unknown": 422,
                      "geoip_unknown": 422, "egress_invalid": 422}.get(code, 409)
            raise XrayRouterError("Xray-router manager rejected request", status, code)

    @staticmethod
    def _validate(document) -> dict:
        if (not isinstance(document, dict) or set(document) != {"schema", "default", "rules"} or document["schema"] != 1
                or not isinstance(document["default"], dict) or not isinstance(document["rules"], list)):
            raise XrayRouterError("invalid routing intent", 422, "egress_invalid")
        return copy.deepcopy(document)

    def _uses_warp(self, document: dict) -> bool:
        return document["default"].get("egress") == "warp" or any(rule.get("egress") == "warp" for rule in document["rules"])

    def _providers(self) -> dict:
        return {"warp": {"url": self.warp_url, "reachable": self.reachable}} if self.warp_url else {}

    async def status(self):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        if self.artifact_error:
            raise XrayRouterError("Xray-router manager rejected request", 503, "artifact_mismatch")
        return {"version": "1", "xray_version": self.xray_version, "artifact_error": None, "phase": "idle",
                "artifacts": {name: {"sha256": "0" * 64, "verified": True} for name in ("xray", "geoip", "geosite")},
                "running": {"generation": self.generation, "digest": "0" * 64, "since": None},
                "services": {service: {"revision": self._revision(service), "digest": self._digest(service),
                                       "document": copy.deepcopy(self.documents[service])} for service in ROUTER_SERVICES},
                "providers": self._providers(), "capabilities": list(ROUTER_CAPABILITIES), "restart_required": True}

    async def egress(self, service):
        self._check(service)
        document = self.documents[service]
        history = self.history[service]
        return {"revision": self._revision(service), "document": copy.deepcopy(document),
                "mode": "proxy" if self._uses_warp(document) else "direct", "generation": self.generation,
                "providers": self._providers(), "capabilities": list(ROUTER_CAPABILITIES), "restart_required": True,
                "warnings": [], "runtime_version": self.xray_version,
                "previous": {"revision": "previous"} if history else None,
                "current": {"revision": self._revision(service), "digest": self._digest(service), "generation": self.generation,
                            "operation_id": history[-1]["operation_id"] if history else None, "applied_at": None}}

    async def egress_plan(self, service, expected_revision, document):
        normalised = self._validate(document)
        self._check(service, expected_revision)
        self._fail()
        if self._uses_warp(normalised) and not self.warp_url:
            raise XrayRouterError("egress provider warp is not configured on this node", 422, "egress_invalid")
        return {"revision": expected_revision, "target_revision": "target", "generation_digest": "0" * 64,
                "rendered_sha256": "0" * 64, "diff": [] if normalised == self.documents[service] else ["-current", "+planned"],
                "warnings": [], "reachability": {"warp": self.reachable} if self._uses_warp(normalised) else {},
                "restart_required": True}

    async def egress_apply(self, service, expected_revision, document, operation_id):
        self.calls.append(("apply", service, operation_id))
        normalised = self._validate(document)
        self._check(service)
        record = self.operations.get((service, operation_id))
        if record is not None:
            if record["applied"] != normalised:
                raise XrayRouterError("operation id already used for another request", 409, "operation_conflict")
            return {**record, "replayed": True}
        self._check(service, expected_revision)
        if self._uses_warp(normalised):
            if not self.warp_url:
                raise XrayRouterError("egress provider warp is not configured on this node", 422, "egress_invalid")
            if not self.reachable:
                raise XrayRouterError("egress provider warp is unreachable", 409, "egress_unreachable")
        self._fail()
        self.history[service].append({"document": copy.deepcopy(self.documents[service]), "operation_id": operation_id})
        self.documents[service] = normalised
        self.generation += 1
        result = {"revision": self._revision(service), "applied": copy.deepcopy(normalised), "readback_sha256": "0" * 64,
                  "generation": self.generation}
        self.operations[(service, operation_id)] = result
        return {**result, "replayed": False}

    async def egress_rollback(self, service, expected_revision):
        self.calls.append(("rollback", service))
        self._check(service, expected_revision)
        if not self.history[service]:
            raise XrayRouterError("no previous egress to roll back to", 409, "egress_no_previous")
        self._fail()
        previous = self.history[service].pop()
        self.documents[service] = previous["document"]
        self.generation += 1
        return {"revision": self._revision(service), "applied": copy.deepcopy(previous["document"]),
                "readback_sha256": "0" * 64, "generation": self.generation}
