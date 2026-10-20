"""The panel's side of the AmneziaWG node manager (`awg_manager`): a Unix-socket client and an
in-memory stand-in that follows the same contract for the tests.

The manager owns the interfaces, the ports and the server keys; the panel owns the client
keys. A peer therefore reaches the manager as a public key only: the private half stays in the
panel's escrow and goes into the config the client downloads.
"""
from __future__ import annotations

import base64
import copy
import ipaddress
from urllib.parse import quote

import httpx

from .local_http import uds_transport


class AmneziawgError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class AmneziawgClient:
    def __init__(self, socket_path: str, token: str, *, timeout: float = 10, transport=None):
        self.socket_path, self.token, self.timeout, self.transport = socket_path, token, timeout, transport

    async def _request(self, method, path, payload=None, *, timeout: float | None = None):
        transport = self.transport or uds_transport(self.socket_path)
        try:
            async with httpx.AsyncClient(
                base_url="http://awg-manager", timeout=timeout or self.timeout, transport=transport,
                headers={"X-Awg-Token": self.token}, trust_env=False,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise AmneziawgError("AmneziaWG manager unavailable") from exc
        if response.status_code >= 400:
            status = response.status_code if response.status_code in {404, 409, 422} else 502
            raise AmneziawgError("AmneziaWG manager rejected request", status, self._code(response))
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise AmneziawgError("Invalid AmneziaWG manager response") from exc

    @staticmethod
    def _code(response) -> str | None:
        try:
            payload = response.json()
        except ValueError:
            return None
        code = payload.get("code") if isinstance(payload, dict) else None
        return code if isinstance(code, str) and len(code) <= 64 else None

    async def health(self):
        return await self._request("GET", "/v1/health")

    async def instances(self):
        return (await self._request("GET", "/v1/instances")).get("instances", [])

    async def peers(self):
        return (await self._request("GET", "/v1/peers")).get("peers", [])

    async def create_peer(self, payload):
        return await self._request("POST", "/v1/peers", payload)

    async def peer_state(self, username, action):
        return await self._request("POST", f"/v1/peers/{quote(username, safe='')}/{action}", {})

    async def rotate_peer(self, username, payload):
        return await self._request("POST", f"/v1/peers/{quote(username, safe='')}/rotate", payload)

    async def delete_peer(self, username):
        return await self._request("DELETE", f"/v1/peers/{quote(username, safe='')}")

    # -- egress (v3.0.0): direct, or a WARP tunnel of the manager's own ------------------
    # An apply through WARP may register a WARP device and waits for the tunnel's first
    # handshake (up to 12 s on the manager), hence the longer timeout.

    async def egress(self):
        return await self._request("GET", "/v1/egress")

    async def egress_plan(self, expected_revision, document):
        return await self._request("POST", "/v1/egress/plan", {"expected_revision": expected_revision, "document": document})

    async def egress_apply(self, expected_revision, document, operation_id):
        return await self._request("POST", "/v1/egress/apply", {"expected_revision": expected_revision,
                                                                "document": document, "operation_id": operation_id},
                                   timeout=45)

    async def egress_rollback(self, expected_revision):
        return await self._request("POST", "/v1/egress/rollback", {"expected_revision": expected_revision}, timeout=45)


_PORTS = {"1.5": 51820, "2.0": 51821, "3.1": 51822}
_SUBNETS = {"1.5": "10.66.15", "2.0": "10.66.20", "3.1": "10.66.31"}
_OBFUSCATION = {
    "1.5": {"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "40", "S2": "70",
            "H1": "1234567891", "H2": "1234567892", "H3": "1234567893", "H4": "1234567894",
            "I1": "<b 0xc70000000108><r 16><t>"},
    "2.0": {"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "40", "S2": "70", "S3": "20", "S4": "16",
            "H1": "100000-200000", "H2": "300000-400000", "H3": "500000-600000", "H4": "700000-800000",
            "I1": "<b 0xc70000000108><r 16><t>"},
    "3.1": {"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "24", "S2": "28", "S3": "20", "S4": "32",
            "H1": "1", "H2": "2", "H3": "3", "H4": "4", "I1": "<b 0xc70000000108><r 16><t>",
            "HeaderProtectionKey": base64.b64encode(bytes(range(32))).decode(), "ContentPaddingAddition": "0-32"},
}


class MemoryAmneziawg:
    """The manager contract in memory: one interface per enabled version, peers with an address
    each, idempotent create by operation id, a revision per peer."""

    def __init__(self, versions=("1.5", "2.0", "3.1")):
        self.versions = tuple(versions)
        self.peer_table: dict[str, dict] = {}
        self.operations: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.broken = False
        # {"create": "lose_response"} performs the mutation and then raises.
        self.faults: dict[str, str] = {}
        # egress (v3.0.0): the manager's document history; `warp_reachable` is the tunnel's state.
        self.egress_history: list[dict] = []
        self.egress_revision = 0
        self.warp_reachable: bool | None = True
        self.warp_registered = False
        # v3.0.0 variant 2: the device the Xray-router reads (None = no router device on this node).
        self.router_attached: bool | None = True

    def _guard(self):
        if self.broken:
            raise AmneziawgError("unavailable")

    def _instance(self, version):
        return {
            "version": version, "interface": "awg" + version.replace(".", ""), "port": _PORTS[version],
            "server_public_key": base64.b64encode(bytes([int(version[0]) + 40]) * 32).decode(),
            "gateway": f"{_SUBNETS[version]}.1", "subnet": f"{_SUBNETS[version]}.0/24", "mtu": 1280,
            "dns": ["1.1.1.1", "1.0.0.1"], "obfuscation": copy.deepcopy(_OBFUSCATION[version]),
        }

    def _view(self, username):
        row = self.peer_table[username]
        return {"username": username, "version": row["version"], "enabled": row["enabled"], "address": row["address"],
                "public_key": row["public_key"], "revision": row["revision"], "rx": 0, "tx": 0, "latest_handshake": None}

    async def health(self):
        self._guard()
        warp = self._egress_document()["upstream"] is not None
        return {"status": "ok", "ip_forward": True, "instances": {v: {"running": True} for v in self.versions},
                "egress": {"mode": "proxy" if warp else "direct",
                           "tunnel": ("up" if self.warp_reachable else "down") if warp else "off"}}

    def _egress_document(self):
        return copy.deepcopy(self.egress_history[-1]) if self.egress_history else {"schema": 1, "upstream": None}

    async def egress(self):
        self._guard()
        document = self._egress_document()
        warp = document["upstream"] is not None
        providers = {"warp": {"reachable": self.warp_reachable if document["upstream"] == {"provider": "warp"} else None}}
        if self.router_attached is not None:
            providers["router"] = {"reachable": self.router_attached}
        return {"revision": str(self.egress_revision), "mode": "proxy" if warp else "direct", "document": document,
                "managed": bool(self.egress_history), "providers": providers,
                "router": None if self.router_attached is None else {"device": "awgxr", "present": True,
                                                                     "attached": self.router_attached},
                "capabilities": ["whole_direct", "whole_warp"], "restart_required": False, "warnings": [],
                "warp": {"registered": self.warp_registered, "address": "172.16.0.2" if self.warp_registered else None,
                         "endpoint": "162.159.192.9:2408" if self.warp_registered else None, "account_type": "free",
                         "tunnel": ("up" if self.warp_reachable else "down") if warp else "off",
                         "latest_handshake": 1_700_000_000 if warp and self.warp_reachable else None, "rx": 0, "tx": 0}}

    def _egress_check(self, expected_revision, document=None):
        if document is not None and (not isinstance(document, dict) or set(document) != {"schema", "upstream"}
                                     or document["upstream"] not in (None, {"provider": "warp"}, {"provider": "router"})):
            raise AmneziawgError("AmneziaWG manager rejected request", 422, "egress_invalid")
        if expected_revision != str(self.egress_revision):
            raise AmneziawgError("AmneziaWG manager rejected request", 409, "egress_conflict")

    async def egress_plan(self, expected_revision, document):
        self._guard()
        self._egress_check(expected_revision, document)
        return {"revision": str(self.egress_revision), "target": document, "diff": [], "restart_required": False,
                "warnings": [], "reachability": {"warp": self.warp_reachable}}

    async def egress_apply(self, expected_revision, document, operation_id):
        self._guard()
        self.calls.append(("egress_apply", operation_id))
        self._egress_check(expected_revision, document)
        if document["upstream"] == {"provider": "router"}:
            if self.router_attached is None:
                raise AmneziawgError("AmneziaWG manager rejected request", 422, "egress_invalid")
            if not self.router_attached:
                raise AmneziawgError("AmneziaWG manager rejected request", 502, "egress_unreachable")
        elif document["upstream"] is not None:
            if self.warp_reachable is False:
                raise AmneziawgError("AmneziaWG manager rejected request", 502, "egress_unreachable")
            self.warp_registered = True
        self.egress_history.append(copy.deepcopy(document))
        self.egress_revision += 1
        return {"revision": str(self.egress_revision), "applied": document, "replayed": False}

    async def egress_rollback(self, expected_revision):
        self._guard()
        self._egress_check(expected_revision)
        if not self.egress_history:
            raise AmneziawgError("AmneziaWG manager rejected request", 409, "egress_no_previous")
        self.egress_history.pop()
        self.egress_revision += 1
        return {"revision": str(self.egress_revision), "applied": self._egress_document(), "replayed": False}

    async def instances(self):
        self._guard()
        return [self._instance(v) for v in self.versions]

    async def peers(self):
        self._guard()
        return [self._view(name) for name in self.peer_table]

    def _lose(self, operation):
        if self.faults.get(operation) == "lose_response":
            raise AmneziawgError("AmneziaWG manager unavailable")

    def _free_address(self, version):
        used = {row["address"] for row in self.peer_table.values()}
        for host in range(2, 255):
            candidate = f"{_SUBNETS[version]}.{host}"
            if candidate not in used:
                return candidate
        raise AmneziawgError("no free address", 409, "no_free_address")

    async def create_peer(self, payload):
        self._guard()
        self.calls.append(("create", payload["username"]))
        operation_id, username, version = payload["operation_id"], payload["username"], payload["version"]
        if version not in _PORTS:
            raise AmneziawgError("unknown version", 422, "unknown_version")
        if version not in self.versions:
            raise AmneziawgError("version not enabled", 409, "version_disabled")
        body = {key: payload[key] for key in ("username", "version", "public_key", "preshared_key")}
        known = self.operations.get(operation_id)
        if known is not None:
            if known["body"] != body:
                raise AmneziawgError("operation id reused", 409, "operation_conflict")
            return {"peer": self._view(username), "instance": self._instance(version)}
        if username in self.peer_table:
            raise AmneziawgError("username exists", 409, "exists")
        self.peer_table[username] = {"version": version, "enabled": True, "address": self._free_address(version),
                                     "public_key": payload["public_key"], "preshared_key": payload["preshared_key"],
                                     "revision": 1}
        self.operations[operation_id] = {"body": body}
        self._lose("create")
        return {"peer": self._view(username), "instance": self._instance(version)}

    async def peer_state(self, username, action):
        self._guard()
        if username not in self.peer_table:
            raise AmneziawgError("not found", 404, "not_found")
        row = self.peer_table[username]
        if row["enabled"] != (action == "enable"):
            row["enabled"] = action == "enable"
            row["revision"] += 1
        return {"peer": self._view(username)}

    async def rotate_peer(self, username, payload):
        self._guard()
        if username not in self.peer_table:
            raise AmneziawgError("not found", 404, "not_found")
        row = self.peer_table[username]
        if payload["operation_id"] not in self.operations:
            row["public_key"], row["preshared_key"] = payload["public_key"], payload["preshared_key"]
            row["revision"] += 1
            self.operations[payload["operation_id"]] = {"body": {"username": username}}
        self._lose("rotate")
        return {"peer": self._view(username)}

    async def delete_peer(self, username):
        self._guard()
        if username not in self.peer_table:
            raise AmneziawgError("not found", 404, "not_found")
        self.peer_table.pop(username)


def address_in(subnet: str, address: str) -> bool:
    return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(subnet)
