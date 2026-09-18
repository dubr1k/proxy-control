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
        # The egress vocabulary, plus the manager's own geodata codes (v0.8) — anything else is noise.
        self.code = code if code in EGRESS_REASON_CODES or (isinstance(code, str) and code.startswith("geodata_")) else None


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

    # v0.7: lanes and the relay
    async def lanes(self, service): return await self._request("GET", f"/v1/lanes/{service}")
    async def lane_issue(self, service, lane): return await self._request("POST", f"/v1/lanes/{service}", {"lane": lane})
    async def lane_forget(self, service, lane): return await self._request("DELETE", f"/v1/lanes/{service}/{lane}")
    async def relay(self): return await self._request("GET", "/v1/relay")
    async def relay_enable(self, server_name, port):
        return await self._request("POST", "/v1/relay", {"server_name": server_name, "port": port})
    async def relay_disable(self): return await self._request("DELETE", "/v1/relay")
    # v0.8: the geodata files and their source
    async def geodata(self): return await self._request("GET", "/v1/geodata")
    async def geodata_codes(self): return await self._request("GET", "/v1/geodata/codes")
    async def geodata_settings(self, body): return await self._request("PUT", "/v1/geodata/settings", body)
    async def geodata_update(self): return await self._request("POST", "/v1/geodata/update")
    async def geodata_restore(self): return await self._request("POST", "/v1/geodata/restore")
    async def relay_set_accounts(self, accounts):
        return await self._request("PUT", "/v1/relay/accounts", {"accounts": accounts})


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
        # v0.7: lane accounts per service and the relay inbound
        self.lane_accounts: dict[str, dict[str, str]] = {service: {} for service in ROUTER_SERVICES}
        self.relay_state: dict = {"enabled": False, "port": None, "server_name": None, "public_key": None,
                                  "short_ids": [], "accounts": []}
        # v0.8: the geodata the router resolves codes against, as the manager reports it
        self.geodata_state: dict = {"source": {"kind": "xray", "geosite_url": None, "geoip_url": None}, "auto_update": False,
                                    "interval_hours": 24, "origin": "seed", "version": None, "updated_at": None,
                                    "last_check_at": None, "last_error": None,
                                    "files": {"geosite": {"sha256": "a" * 64, "size": 3, "codes": 3},
                                              "geoip": {"sha256": "b" * 64, "size": 2, "codes": 2}}}
        self.geodata_codes_state = {"geosite": ["category-ads-all", "cn", "youtube"], "geoip": ["cn", "ru"]}
        self.geodata_updates = 0
        self.public_key = "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s"

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
        if isinstance(document, dict) and document.get("schema") == 2:
            if (set(document) != {"schema", "lanes", "chains"} or not isinstance(document["lanes"], dict)
                    or not document["lanes"] or not isinstance(document["chains"], dict)
                    or sum(1 for lane in document["lanes"] if lane.startswith("svc:")) != 1):
                raise XrayRouterError("invalid routing intent", 422, "egress_invalid")
            for lane, body in document["lanes"].items():
                if not isinstance(body, dict) or set(body) != {"default", "rules"}:
                    raise XrayRouterError("invalid routing intent", 422, "egress_invalid")
                for value in [body["default"].get("egress"), *(rule.get("egress") for rule in body["rules"])]:
                    if isinstance(value, str) and value.startswith("chain:") and value[6:] not in document["chains"]:
                        raise XrayRouterError("invalid routing intent", 422, "egress_invalid")
            return copy.deepcopy(document)
        if (not isinstance(document, dict) or set(document) != {"schema", "default", "rules"} or document["schema"] != 1
                or not isinstance(document["default"], dict) or not isinstance(document["rules"], list)):
            raise XrayRouterError("invalid routing intent", 422, "egress_invalid")
        return copy.deepcopy(document)

    @staticmethod
    def _lanes_of(document: dict) -> list[dict]:
        return list(document["lanes"].values()) if document.get("schema") == 2 else [document]

    def _uses_warp(self, document: dict) -> bool:
        return any(lane["default"].get("egress") == "warp" or any(rule.get("egress") == "warp" for rule in lane["rules"])
                   for lane in self._lanes_of(document))

    def _lanes_known(self, service: str, document: dict) -> None:
        if document.get("schema") != 2:
            return
        for lane in document["lanes"]:
            if lane.startswith("grant:") and lane not in self.lane_accounts[service]:
                raise XrayRouterError("lane has no account on the ingress", 422, "egress_invalid")

    # -- v0.7: lanes and the relay ---------------------------------------------------

    async def lanes(self, service):
        self._check(service)
        return {"lanes": sorted(self.lane_accounts[service])}

    async def lane_issue(self, service, lane):
        self._check(service)
        if not isinstance(lane, str) or not lane.startswith("grant:"):
            raise XrayRouterError("invalid request", 422)
        self.calls.append(("lane_issue", service, lane))
        password = hashlib.sha256(f"{service}:{lane}:{len(self.calls)}".encode()).hexdigest()[:43]
        self.lane_accounts[service][lane] = password
        self.generation += 1
        return {"lane": lane, "user": "grant-" + lane[6:], "password": password}

    async def lane_forget(self, service, lane):
        self._check(service)
        if lane not in self.lane_accounts[service]:
            raise XrayRouterError("unknown lane", 409, "lane_unknown")
        self.calls.append(("lane_forget", service, lane))
        del self.lane_accounts[service][lane]
        self.generation += 1
        return {"lane": lane, "forgotten": True}

    def _relay_view(self) -> dict:
        return {**self.relay_state, "accounts": len(self.relay_state["accounts"]),
                "emails": sorted(a["email"] for a in self.relay_state["accounts"])}

    async def relay(self):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        return self._relay_view()

    async def relay_enable(self, server_name, port):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        self.calls.append(("relay_enable", server_name, port))
        if not self.relay_state["public_key"]:
            self.relay_state["public_key"], self.relay_state["short_ids"] = self.public_key, ["0123abcd"]
        self.relay_state.update({"enabled": True, "server_name": server_name, "port": port})
        self.generation += 1
        return self._relay_view()

    async def relay_disable(self):
        self.relay_state["enabled"] = False
        self.generation += 1
        return self._relay_view()

    async def relay_set_accounts(self, accounts):
        if not self.relay_state["enabled"]:
            raise XrayRouterError("the relay is not enabled", 409, "relay_disabled")
        # as the manager: without WARP the warp accounts are set aside, the rest carried
        if not self.warp_url:
            accounts = [a for a in accounts if not a["email"].endswith(":warp")]
        self.calls.append(("relay_accounts", [a["email"] for a in accounts]))
        self.relay_state["accounts"] = [dict(a) for a in accounts]
        self.generation += 1
        return self._relay_view()

    def _providers(self) -> dict:
        return {"warp": {"url": self.warp_url, "reachable": self.reachable}} if self.warp_url else {}

    # -- v0.8: geodata -------------------------------------------------------------------

    def _geodata_view(self) -> dict:
        return {**copy.deepcopy(self.geodata_state), "seed": {"geosite": {"sha256": "a" * 64}, "geoip": {"sha256": "b" * 64}},
                "limits": {"max_file_bytes": 64 * 1024 * 1024, "interval_hours": [1, 336]}}

    async def geodata(self):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        return self._geodata_view()

    async def geodata_codes(self):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        return {"codes": copy.deepcopy(self.geodata_codes_state)}

    async def geodata_settings(self, body):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        self.calls.append(("geodata_settings", copy.deepcopy(body)))
        if "source" in body:
            source = body["source"]
            if source.get("kind") not in ("xray", "loyalsoldier", "custom"):
                raise XrayRouterError("source.kind must be xray, loyalsoldier or custom", 422, "geodata_invalid")
            if source["kind"] == "custom" and not all(str(source.get(f"{n}_url", "")).startswith("https://") for n in ("geosite", "geoip")):
                raise XrayRouterError("geosite_url must be an https URL", 422, "geodata_invalid")
            self.geodata_state["source"] = {"kind": source["kind"], "geosite_url": source.get("geosite_url"),
                                            "geoip_url": source.get("geoip_url")}
        if "auto_update" in body:
            self.geodata_state["auto_update"] = bool(body["auto_update"])
        if "interval_hours" in body:
            if not isinstance(body["interval_hours"], int) or not 1 <= body["interval_hours"] <= 336:
                raise XrayRouterError("interval_hours must be 1..336", 422, "geodata_invalid")
            self.geodata_state["interval_hours"] = body["interval_hours"]
        return self._geodata_view()

    async def geodata_update(self):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        self.calls.append(("geodata_update",))
        self._fail()
        if self.geodata_state["source"]["kind"] == "xray":
            return {**self._geodata_view(), "changed": False}
        self.geodata_updates += 1
        self.geodata_state.update({"origin": "download", "version": f"v{self.geodata_updates}", "updated_at": "2026-09-18T00:00:00Z",
                                   "last_error": None})
        self.generation += 1
        return {**self._geodata_view(), "changed": True}

    async def geodata_restore(self):
        if not self.available:
            raise XrayRouterError("Xray-router manager unavailable")
        self.calls.append(("geodata_restore",))
        self.geodata_state.update({"source": {"kind": "xray", "geosite_url": None, "geoip_url": None}, "auto_update": False,
                                   "origin": "seed", "version": None})
        self.generation += 1
        return {**self._geodata_view(), "changed": True}

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
                "providers": self._providers(), "capabilities": [*ROUTER_CAPABILITIES, "lanes", "chains", "relay", "geodata"],
                "restart_required": True, "lanes": {service: sorted(self.lane_accounts[service]) for service in ROUTER_SERVICES},
                "relay": self._relay_view(),
                "geodata": {key: self.geodata_state[key] for key in ("source", "origin", "version", "updated_at", "auto_update",
                                                                       "interval_hours", "last_error", "files")}}

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
        self._lanes_known(service, normalised)
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
        self._lanes_known(service, normalised)
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
