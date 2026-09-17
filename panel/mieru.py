from __future__ import annotations

import copy
import secrets
from urllib.parse import quote

import httpx

from .routing.document import EGRESS_REASON_CODES, document_digest

# What the pinned mita build enforces (mieru_manager/egress.py, from the spike).
MIERU_EGRESS_CAPABILITIES = ("whole_direct", "whole_warp", "block_domain", "block_cidr",
                             "selective_domain", "selective_cidr")
EGRESS_DIRECT = {"schema": 1, "proxies": [], "rules": []}
EGRESS_ACTIONS = ("DIRECT", "PROXY", "REJECT")


class MieruError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class MieruClient:
    def __init__(
        self, socket_path: str, token: str, *, timeout: float = 8, transport=None
    ):
        self.socket_path, self.token, self.timeout, self.transport = (
            socket_path,
            token,
            timeout,
            transport,
        )

    async def _request(self, method, path, payload=None):
        transport = self.transport or httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(
                base_url="http://mieru-manager",
                timeout=self.timeout,
                transport=transport,
                headers={"X-Mieru-Token": self.token},
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise MieruError("Mieru manager unavailable") from exc
        if response.status_code >= 400:
            status = (
                response.status_code if response.status_code in {404, 409, 422} else 502
            )
            raise MieruError("Mieru manager rejected request", status, self._reason(response))
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise MieruError("Invalid Mieru manager response") from exc

    @staticmethod
    def _reason(response) -> str | None:
        """The egress API's bounded codes (v0.4); anything else stays a plain refusal."""
        try:
            payload = response.json()
        except ValueError:
            return None
        code = payload.get("code") if isinstance(payload, dict) else None
        return code if code in EGRESS_REASON_CODES else None

    async def health(self):
        return await self._request("GET", "/v1/health")

    async def list_users(self):
        return await self._request("GET", "/v1/users")

    async def metrics(self):
        value = await self._request("GET", "/v1/metrics")
        if value != {
            "status": "error",
            "stale": True,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }:
            raise MieruError("Invalid Mieru metrics response")
        return value

    async def lifecycle(self, action):
        if action not in {"start", "stop", "restart"}:
            raise ValueError("invalid Mieru lifecycle action")
        return await self._request("POST", f"/v1/lifecycle/{action}", {})

    async def create(self, payload):
        return await self._request("POST", "/v1/users", payload)

    async def set_quotas(self, username, payload):
        return await self._request(
            "POST", f"/v1/users/{quote(username, safe='')}/quotas", payload
        )

    async def operation(self, username, operation, revision):
        return await self._request(
            "POST",
            f"/v1/users/{quote(username, safe='')}/{operation}",
            {"expected_revision": revision},
        )

    async def rotate(self, username, revision, *, password=None, operation_id=None):
        """Rotation carries the caller's credential so the panel can escrow it first."""
        payload = {"expected_revision": revision}
        for key, value in (("password", password), ("operation_id", operation_id)):
            if value is not None:
                payload[key] = value
        return await self._request(
            "POST", f"/v1/users/{quote(username, safe='')}/rotate", payload
        )

    async def delete(self, username, revision):
        return await self._request(
            "DELETE",
            f"/v1/users/{quote(username, safe='')}",
            {"expected_revision": revision},
        )

    async def reset_metrics(self, username):
        return await self._request(
            "POST", f"/v1/users/{quote(username, safe='')}/reset-metrics", {}
        )

    # egress (v0.4 routing): the `egress` section of the mita config, see mieru_manager/egress.py
    async def egress(self):
        return await self._request("GET", "/v1/egress")

    async def egress_plan(self, expected_revision, document):
        return await self._request(
            "POST", "/v1/egress/plan", {"expected_revision": expected_revision, "document": document}
        )

    async def egress_apply(self, expected_revision, document, operation_id):
        return await self._request("POST", "/v1/egress/apply", {
            "expected_revision": expected_revision, "document": document, "operation_id": operation_id,
        })

    async def egress_rollback(self, expected_revision):
        return await self._request("POST", "/v1/egress/rollback", {"expected_revision": expected_revision})

    # v0.7: lanes
    async def lanes(self): return await self._request("GET", "/v1/lanes")
    async def set_lanes(self, lanes): return await self._request("PUT", "/v1/lanes", {"lanes": lanes})


class MemoryMieru:
    def __init__(self):
        self.users = {}
        self.calls = []
        self.revision = "rev-1"
        self.broken = False
        self.operations = {}
        # {"create": "lose_response"} performs the mutation and then raises, the way a
        # manager does when the reply never reaches the panel.
        self.faults = {}
        # egress (v0.4): what the manager's /v1/egress API answers over a mita config with
        # no `egress` section. `provider_url` None = a host without WARP; `reachable` is what
        # the manager's pre-apply probe would find; `egress_fail_next` answers the next apply
        # or rollback with that manager code before anything changes; `egress_custom` is a
        # section somebody wrote by hand (mode `custom`, no managed document).
        self.provider_url: str | None = "socks5://127.0.0.1:40000"
        # The router ingress of this service (v0.5), None on a node without a router.
        self.router_url: str | None = None
        self.router_reachable = True
        self.reachable = True
        self.egress_document = EGRESS_DIRECT
        self.egress_history: list[dict] = []
        self.egress_operations: dict[str, dict] = {}
        self.egress_fail_next: str | None = None
        self.egress_custom: dict | None = None
        # lanes (v0.7): lane → {slot, users, upstream user}; two slots, ports 46101/46102
        self.lane_table: dict[str, dict] = {}
        self.lane_slots = {1: 46101, 2: 46102}
        self.lanes_fail_next: str | None = None

    def _next(self):
        self.revision = "rev-" + str(int(self.revision.split("-")[1]) + 1)
        return self.revision

    async def health(self):
        if self.broken:
            raise MieruError("unavailable")
        return {"ready": True, "status": "running", "revision": self.revision}

    async def list_users(self):
        return [copy.deepcopy(item) for item in self.users.values()]

    async def metrics(self):
        if self.broken:
            raise MieruError("unavailable")
        return {
            "status": "error",
            "stale": True,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }

    def _replay(self, operation_id, operation, username):
        if operation_id is None:
            return None
        record = self.operations.get(operation_id)
        if record is None:
            return None
        if (record["operation"], record["username"]) != (operation, username):
            raise MieruError("operation id already used for another request", 409, "operation_conflict")
        if record["credential_origin"] != "caller":
            # The fake never kept that password either; a link it cannot produce must
            # not be invented.
            raise MieruError(
                "operation result is unrecoverable; rotate the credential", 409, "result_unrecoverable"
            )
        return {"username": username, "revision": record["revision"], "replayed": True}

    def _remember(self, operation_id, operation, username, password, revision):
        if operation_id is not None:
            self.operations[operation_id] = {
                "operation": operation, "username": username, "revision": revision,
                "credential_origin": "caller" if password else "manager",
            }

    def _maybe_lose(self, operation):
        if self.faults.get(operation) == "lose_response":
            raise MieruError("Mieru manager unavailable")

    def _share(self, username, password):
        return (
            f"mierus://{quote(username, safe='')}:{quote(password, safe='')}"
            f"@mieru.example.com?profile={quote(username)}&port=8443&protocol=TCP"
        )

    async def create(self, payload):
        operation_id = payload.get("operation_id")
        username = payload["username"]
        replayed = self._replay(operation_id, "user.create", username)
        if replayed is not None:
            return replayed
        if payload["expected_revision"] != self.revision:
            raise MieruError("conflict", 409)
        password = payload.get("password") or secrets.token_urlsafe(18)
        self.users[username] = {
            "username": username,
            "enabled": True,
            "quotas": copy.deepcopy(payload["quotas"]),
        }
        revision = self._next()
        self._remember(operation_id, "user.create", username, payload.get("password"), revision)
        self._maybe_lose("create")
        return {
            "username": username,
            "share_url": self._share(username, password),
            "revision": revision,
        }

    async def rotate(self, username, revision, *, password=None, operation_id=None):
        replayed = self._replay(operation_id, "user.rotate", username)
        if replayed is not None:
            return replayed
        if revision != self.revision:
            raise MieruError("conflict", 409)
        secret = password or secrets.token_urlsafe(18)
        next_revision = self._next()
        self._remember(operation_id, "user.rotate", username, password, next_revision)
        self._maybe_lose("rotate")
        return {
            "username": username,
            "share_url": self._share(username, secret),
            "revision": next_revision,
        }

    async def operation(self, username, operation, revision):
        if revision != self.revision:
            raise MieruError("conflict", 409)
        if operation == "rotate":
            password = secrets.token_urlsafe(18)
            result = {
                "username": username,
                "share_url": f"mierus://{quote(username, safe='')}:{quote(password, safe='')}@mieru.example.com?profile={quote(username)}&port=8443&protocol=TCP",
            }
        else:
            self.users[username]["enabled"] = operation == "enable"
            result = {"username": username, "enabled": operation == "enable"}
        result["revision"] = self._next()
        return result

    async def set_quotas(self, username, payload):
        self.users[username]["quotas"] = payload["quotas"]
        return {"username": username, "revision": self._next()}

    async def delete(self, username, revision):
        if username not in self.users:
            raise MieruError("Mieru manager rejected request", 404, "not_found")  # as the manager answers
        self.users.pop(username)
        return {"username": username, "revision": self._next()}

    async def reset_metrics(self, username):
        raise MieruError("Mieru metrics unavailable", 409)

    # ------------------------------------------------------------------
    # egress (v0.4 routing)
    # ------------------------------------------------------------------

    def _egress_validate(self, document) -> dict:
        """The manager's `validate_document`, to the letter the adapters depend on."""
        if (not isinstance(document, dict) or set(document) - {"schema", "proxies", "rules"}
                or document.get("schema") != 1):
            raise MieruError("invalid egress document", 422, "egress_invalid")
        proxies, rules = document.get("proxies", []), document.get("rules", [])
        known = ({"name": "warp", "provider": "warp"}, {"name": "router", "provider": "router"})
        if not isinstance(proxies, list) or any(proxy not in known for proxy in proxies) or len(proxies) > 2 \
                or len({proxy["name"] for proxy in proxies}) != len(proxies):
            raise MieruError("unknown egress provider", 422, "egress_invalid")
        for proxy in proxies:
            if not self._provider_url(proxy["name"]):
                raise MieruError(f"egress provider {proxy['name']} is not configured on this node", 422, "egress_invalid")
        declared = {proxy["name"] for proxy in proxies}
        if not isinstance(rules, list):
            raise MieruError("invalid rule list", 422, "egress_invalid")
        normalised = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) - {"domains", "cidrs", "action", "proxy"}:
                raise MieruError("invalid egress rule", 422, "egress_invalid")
            domains, cidrs = list(rule.get("domains", [])), list(rule.get("cidrs", []))
            if not (domains or cidrs) or rule.get("action") not in EGRESS_ACTIONS:
                raise MieruError("invalid egress rule", 422, "egress_invalid")
            proxy = rule.get("proxy")
            if (rule["action"] == "PROXY") != (proxy is not None) or (proxy is not None and proxy not in declared):
                raise MieruError("egress rule names an undeclared proxy", 422, "egress_invalid")
            normalised.append({"domains": domains, "cidrs": cidrs, "action": rule["action"], "proxy": proxy})
        return {"schema": 1, "proxies": copy.deepcopy(proxies), "rules": normalised}

    def _provider_url(self, name: str) -> str | None:
        return self.provider_url if name == "warp" else self.router_url

    def _providers_reachable(self, document: dict) -> dict:
        return {proxy["name"]: self.reachable if proxy["name"] == "warp" else self.router_reachable
                for proxy in document["proxies"]}

    def _providers(self) -> dict:
        providers = {}
        if self.provider_url:
            providers["warp"] = {"url": self.provider_url, "reachable": self.reachable}
        if self.router_url:
            providers["router"] = {"url": self.router_url, "reachable": self.router_reachable}
        return providers

    def _egress_check(self, expected_revision):
        if self.broken:
            raise MieruError("unavailable")
        if expected_revision != self.revision:
            raise MieruError("egress revision does not match", 409, "egress_conflict")

    def _egress_fail(self):
        code, self.egress_fail_next = self.egress_fail_next, None
        if code is not None:
            raise MieruError("Mieru manager rejected request", 502 if code in {
                "manual_intervention_required", "egress_readback_mismatch"} else 409, code)

    async def egress(self):
        if self.broken:
            raise MieruError("unavailable")
        custom = self.egress_custom is not None
        document = None if custom else self.egress_document
        providers = self._providers()
        return {
            "revision": self.revision,
            "mode": "custom" if custom else "proxy" if any(r["action"] == "PROXY" for r in document["rules"]) else "direct",
            "document": document, "raw": copy.deepcopy(self.egress_custom) if custom else None,
            "managed": not custom and bool(self.egress_history),
            "providers": providers, "capabilities": list(MIERU_EGRESS_CAPABILITIES), "restart_required": True,
            "warnings": ["adopts_unmanaged_egress"] if custom else [],
            "previous": None if not self.egress_history else {"applied_at": None},
            "current": None if not self.egress_history else {"digest": document_digest(document) if document else None},
        }

    async def egress_plan(self, expected_revision, document):
        normalised = self._egress_validate(document)
        self._egress_check(expected_revision)
        return {"revision": self.revision, "target": normalised,
                "diff": [] if normalised == self.egress_document else ["-current", "+planned"],
                "reachability": self._providers_reachable(normalised), "restart_required": True,
                "warnings": ["adopts_unmanaged_egress"] if self.egress_custom is not None else []}

    async def egress_apply(self, expected_revision, document, operation_id):
        self.calls.append(("egress_apply", operation_id))
        if self.broken:
            raise MieruError("unavailable")
        normalised = self._egress_validate(document)
        record = self.egress_operations.get(operation_id)
        if record is not None:
            if record["applied"] != normalised:
                raise MieruError("operation id already used for another request", 409, "operation_conflict")
            return {**record, "replayed": True}
        self._egress_check(expected_revision)
        for name, reachable in self._providers_reachable(normalised).items():
            if not reachable:
                raise MieruError(f"egress provider {name} is unreachable", 409, "egress_unreachable")
        self._egress_fail()
        self.egress_history.append({"document": None if self.egress_custom is not None else self.egress_document,
                                    "custom": self.egress_custom})
        self.egress_custom, self.egress_document = None, normalised
        result = {"revision": self._next(), "applied": normalised}
        self.egress_operations[operation_id] = result
        return {**result, "replayed": False}

    async def egress_rollback(self, expected_revision):
        self.calls.append(("egress_rollback",))
        self._egress_check(expected_revision)
        if not self.egress_history:
            raise MieruError("no previous egress to roll back to", 409, "egress_no_previous")
        self._egress_fail()
        previous = self.egress_history.pop()
        self.egress_custom = previous["custom"]
        self.egress_document = previous["document"] if previous["document"] is not None else EGRESS_DIRECT
        return {"revision": self._next(), "applied": previous["document"], "replayed": False}

    # -- lanes (v0.7) ------------------------------------------------------------------

    def _lanes_view(self) -> dict:
        used = {entry["slot"] for entry in self.lane_table.values()}
        view = []
        for lane, entry in self.lane_table.items():
            port = self.lane_slots[entry["slot"]]
            view.append({"lane": lane, "slot": entry["slot"], "port": port, "users": list(entry["users"]),
                         "upstream": "socks5://***@127.0.0.1:45102", "status": "running" if entry["users"] else "idle",
                         "share_templates": {user: f"mierus://{{username}}:{{password}}@mieru.example.com?profile={user}&port={port}&protocol=TCP&mtu=1400"
                                             for user in entry["users"]}})
        return {"lanes": view, "free_slots": len(self.lane_slots) - len(used),
                "service_share_template": "mierus://{username}:{password}@mieru.example.com?profile={profile}&port=8443&protocol=TCP"}

    async def lanes(self):
        if self.broken:
            raise MieruError("Mieru manager unavailable")
        return self._lanes_view()

    async def set_lanes(self, lanes):
        if self.broken:
            raise MieruError("Mieru manager unavailable")
        self.calls.append(("set_lanes", [(entry["lane"], list(entry["users"])) for entry in lanes]))
        code, self.lanes_fail_next = self.lanes_fail_next, None
        if code is not None:
            raise MieruError("Mieru manager rejected request", 409, code)
        if lanes and not self.router_url:
            raise MieruError("egress provider router is not configured on this node", 422, "egress_invalid")
        seen: set[str] = set()
        for entry in lanes:
            if not entry["lane"].startswith("grant:") or not entry["users"]:
                raise MieruError("Mieru manager rejected request", 409, "lanes_invalid")
            for user in entry["users"]:
                if user not in self.users or user in seen:
                    raise MieruError("Mieru manager rejected request", 409, "lanes_invalid")
                seen.add(user)
        table: dict[str, dict] = {}
        kept = {name for name in self.lane_table if name in {entry["lane"] for entry in lanes}}
        free = [slot for slot in self.lane_slots if slot not in {self.lane_table[name]["slot"] for name in kept}]
        for entry in lanes:
            if entry["lane"] in self.lane_table:
                slot = self.lane_table[entry["lane"]]["slot"]
            else:
                if not free:
                    raise MieruError("Mieru manager rejected request", 409, "lane_slots_exhausted")
                slot = free.pop(0)
            table[entry["lane"]] = {"slot": slot, "users": list(entry["users"]), "upstream_user": entry["upstream"]["user"]}
        self.lane_table = table
        return self._lanes_view()
