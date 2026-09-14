from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from .routing.document import EGRESS_REASON_CODES, canonical

# Reasons the manager may report for a refusal (plus the egress API's bounded set, v0.4).
# Anything else is treated as a plain conflict so a manager response can never dictate
# panel copy.
NAIVE_REASON_CODES = frozenset({"quota_exhausted"}) | EGRESS_REASON_CODES
# What the pinned forwardproxy build enforces (naive_manager/egress.py, from the spike).
NAIVE_EGRESS_CAPABILITIES = ("whole_direct", "whole_warp", "block_domain", "block_cidr")
EGRESS_DIRECT = {"schema": 1, "upstream": None, "acl": []}


class NaiveError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code if code in NAIVE_REASON_CODES else None


class NaiveClient:
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
            async with httpx.AsyncClient(
                base_url="http://naive-manager",
                timeout=self.timeout,
                transport=transport,
                headers={"X-Naive-Token": self.token},
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise NaiveError("NaiveProxy manager unavailable") from exc
        if response.status_code >= 400:
            status = response.status_code if response.status_code in {404, 409, 422} else 502
            raise NaiveError("NaiveProxy manager rejected request", status, self._reason(response))
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise NaiveError("Invalid NaiveProxy manager response") from exc

    async def health(self): return await self._request("GET", "/v1/health")
    async def list_users(self): return await self._request("GET", "/v1/users")
    async def traffic(self): return await self._request("GET", "/v1/traffic")
    async def create(self, username, quota_bytes=None, *, password=None, operation_id=None):
        payload = {"username": username, "quota_bytes": quota_bytes}
        return await self._request("POST", "/v1/users", {**payload, **_optional(password, operation_id)})
    async def reveal(self, username): return await self._request("POST", f"/v1/users/{quote(username)}/access", {})
    async def rotate(self, username, *, password=None, operation_id=None):
        return await self._request(
            "POST", f"/v1/users/{quote(username)}/rotate", _optional(password, operation_id)
        )
    async def set_enabled(self, username, enabled): return await self._request("POST", f"/v1/users/{quote(username)}/{'enable' if enabled else 'disable'}", {})
    async def set_quota(self, username, quota_bytes):
        return await self._request(
            "POST", f"/v1/users/{quote(username)}/quota", {"quota_bytes": quota_bytes}
        )
    async def delete(self, username): return await self._request("DELETE", f"/v1/users/{quote(username)}")
    async def reset_traffic(self, username): return await self._request("POST", f"/v1/users/{quote(username)}/traffic/reset", {})

    # egress (v0.4 routing): the managed block of the Caddyfile, see naive_manager/egress.py
    async def egress(self): return await self._request("GET", "/v1/egress")
    async def egress_plan(self, expected_revision, document):
        return await self._request("POST", "/v1/egress/plan", {"expected_revision": expected_revision, "document": document})
    async def egress_apply(self, expected_revision, document, operation_id):
        return await self._request("POST", "/v1/egress/apply", {
            "expected_revision": expected_revision, "document": document, "operation_id": operation_id})
    async def egress_rollback(self, expected_revision):
        return await self._request("POST", "/v1/egress/rollback", {"expected_revision": expected_revision})


def _optional(password, operation_id) -> dict:
    """Only send what the caller chose; an explicit null would mean something else."""
    fields = {"password": password, "operation_id": operation_id}
    return {key: value for key, value in fields.items() if value is not None}


class MemoryNaive:
    def __init__(self, public_host="naive.example.com"):
        self.public_host = public_host
        self.users = {}
        self.calls = []
        self.period_start = datetime.now(UTC).isoformat()
        self.traffic_rows = {}
        self.operations = {}
        # {"create": "lose_response"} performs the mutation and then raises, the way a
        # manager does when the reply never reaches the panel.
        self.faults = {}
        # The one-shot form: the next call of this operation mutates, then loses its reply.
        self.lose_next: str | None = None
        # A manager that cannot answer at all (socket gone): every call is an outage.
        self.broken = False
        # egress (v0.4): what the manager's /v1/egress API answers over a Caddyfile that
        # starts direct. `provider_url` None = a host without WARP; `reachable` is what the
        # manager's pre-apply probe would find; `egress_fail_next` answers the next apply or
        # rollback with that manager code before anything changes; `egress_custom` is an
        # `upstream` line somebody wrote by hand (mode `custom`, no managed document).
        self.provider_url: str | None = "socks5://127.0.0.1:40000"
        self.reachable = True
        self.egress_document = EGRESS_DIRECT
        self.egress_history: list[dict] = []
        self.egress_operations: dict[str, dict] = {}
        self.egress_fail_next: str | None = None
        self.egress_custom: str | None = None

    def seed(self, username, password, *, enabled=True, quota_bytes=None):
        self.users[username] = {
            "username": username, "password": password, "enabled": enabled,
            "quota_bytes": quota_bytes, "disabled_reason": None if enabled else "manual",
        }
        self.traffic_rows.setdefault(username, {"upload_bytes": 0, "download_bytes": 0})

    def set_traffic(self, username, *, upload, download):
        self.traffic_rows[username] = {"upload_bytes": upload, "download_bytes": download}

    def _access(self, username):
        row = self.users[username]
        url = f"https://{quote(username, safe='')}:{quote(row['password'], safe='')}@{self.public_host}"
        return {"username": username, "proxy_url": url, "config": {"listen": "socks://127.0.0.1:1080", "proxy": url}}

    def _used(self, username):
        return sum(self.traffic_rows.get(username, {}).values())

    def _enforce_quotas(self):
        """Mirror the manager's periodic enforcement: exhaustion is persistent."""
        for username, row in self.users.items():
            quota = row["quota_bytes"]
            if row["enabled"] and quota is not None and self._used(username) >= quota:
                row["enabled"] = False
                row["disabled_reason"] = "quota"

    async def health(self):
        if self.broken:
            raise NaiveError("NaiveProxy manager unavailable")
        return {"ready": True, "host": self.public_host}
    async def list_users(self):
        self._enforce_quotas()
        return [
            {
                "username": row["username"], "enabled": row["enabled"],
                "quota_bytes": row["quota_bytes"],
                "disabled_reason": row["disabled_reason"],
            }
            for row in self.users.values()
        ]
    async def traffic(self):
        self._enforce_quotas()
        rows = []
        for username, counters in self.traffic_rows.items():
            upload = counters["upload_bytes"]
            download = counters["download_bytes"]
            rows.append({
                "username": username, "upload_bytes": upload, "download_bytes": download,
                "total_bytes": upload + download, "period_start": self.period_start,
                "updated_at": self.period_start,
                "upload_bytes_decimal": str(upload), "download_bytes_decimal": str(download),
                "total_bytes_decimal": str(upload + download),
            })
        return {
            "source": "caddy_connect_access_log", "unit": "bytes", "pending": False,
            "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
            "aggregate": {
                "upload_bytes": sum(row["upload_bytes"] for row in rows),
                "download_bytes": sum(row["download_bytes"] for row in rows),
                "total_bytes": sum(row["total_bytes"] for row in rows),
                "upload_bytes_decimal": str(sum(row["upload_bytes"] for row in rows)),
                "download_bytes_decimal": str(sum(row["download_bytes"] for row in rows)),
                "total_bytes_decimal": str(sum(row["total_bytes"] for row in rows)),
            },
            "users": rows,
            "semantics": {
                "closed_connect_tunnels_only": True, "active_tunnels_appear_on_close": True,
                "crash_can_lose_active_tunnel": True, "completed_records_survive_restart": True,
                "excludes_tls_ip_overhead": True, "reset_is_local_baseline_only": True,
            },
        }
    def _replay(self, operation_id, operation, username):
        if operation_id is None:
            return None
        record = self.operations.get(operation_id)
        if record is None:
            return None
        if (record["operation"], record["username"]) != (operation, username):
            raise NaiveError("operation id already used for another request", 409, "operation_conflict")
        return {**record["result"], "replayed": True}

    def _remember(self, operation_id, operation, username, result):
        if operation_id is not None:
            self.operations[operation_id] = {
                "operation": operation, "username": username, "result": result,
            }

    def _maybe_lose(self, operation):
        if self.lose_next == operation:
            self.lose_next = None
            raise NaiveError("NaiveProxy manager unavailable")
        if self.faults.get(operation) == "lose_response":
            raise NaiveError("NaiveProxy manager unavailable")

    async def create(self, username, quota_bytes=None, *, password=None, operation_id=None):
        self.calls.append(("create", username))
        replayed = self._replay(operation_id, "create", username)
        if replayed is not None:
            return replayed
        self.seed(username, password or secrets.token_urlsafe(18), quota_bytes=quota_bytes)
        result = self._access(username)
        self._remember(operation_id, "create", username, result)
        self._maybe_lose("create")
        return result
    async def reveal(self, username):
        self.calls.append(("access", username))
        return self._access(username)
    async def rotate(self, username, *, password=None, operation_id=None):
        self.calls.append(("rotate", username))
        replayed = self._replay(operation_id, "rotate", username)
        if replayed is not None:
            return replayed
        self.users[username]["password"] = password or secrets.token_urlsafe(18)
        result = self._access(username)
        self._remember(operation_id, "rotate", username, result)
        self._maybe_lose("rotate")
        return result
    async def set_enabled(self, username, enabled):
        self.calls.append(("enabled", username, enabled))
        if enabled:
            quota = self.users[username]["quota_bytes"]
            if quota is not None and self._used(username) >= quota:
                raise NaiveError("quota exhausted", 409, "quota_exhausted")
        self.users[username]["enabled"] = enabled
        self.users[username]["disabled_reason"] = None if enabled else "manual"
        return {
            "username": username, "enabled": enabled,
            "disabled_reason": self.users[username]["disabled_reason"],
        }
    async def set_quota(self, username, quota_bytes):
        self.calls.append(("set_quota", username, quota_bytes))
        row = self.users[username]
        used = self._used(username)
        row["quota_bytes"] = quota_bytes
        if row["enabled"] and quota_bytes is not None and used >= quota_bytes:
            row["enabled"] = False
            row["disabled_reason"] = "quota"
        elif row["disabled_reason"] == "quota" and (quota_bytes is None or used < quota_bytes):
            row["disabled_reason"] = "manual"
        return {
            "username": username, "quota_bytes": quota_bytes,
            "enabled": row["enabled"], "disabled_reason": row["disabled_reason"],
        }
    async def delete(self, username):
        self.calls.append(("delete", username))
        if username not in self.users:
            raise NaiveError("NaiveProxy manager rejected request", 404, "not_found")  # as the manager answers
        self.users.pop(username)
        return {"ok": True}
    async def reset_traffic(self, username):
        self.calls.append(("reset_traffic", username))
        self.set_traffic(username, upload=0, download=0)
        return {
            "username": username, "upload_bytes": 0, "download_bytes": 0, "total_bytes": 0,
            "upload_bytes_decimal": "0", "download_bytes_decimal": "0", "total_bytes_decimal": "0",
            "period_start": self.period_start, "updated_at": self.period_start,
        }

    # ------------------------------------------------------------------
    # egress (v0.4 routing)
    # ------------------------------------------------------------------

    def _egress_revision(self) -> str:
        if self.egress_custom is not None:
            return hashlib.sha256(f"upstream {self.egress_custom}".encode()).hexdigest()
        return hashlib.sha256(canonical(self.egress_document)).hexdigest()

    def _egress_validate(self, document) -> dict:
        """The manager's `validate_document`, to the letter the adapters depend on."""
        if (not isinstance(document, dict) or set(document) - {"schema", "upstream", "acl"}
                or document.get("schema") != 1):
            raise NaiveError("invalid egress document", 422, "egress_invalid")
        upstream, acl = document.get("upstream"), document.get("acl", [])
        if upstream is not None and upstream != {"provider": "warp"}:
            raise NaiveError("unknown egress provider", 422, "egress_invalid")
        if upstream is not None and not self.provider_url:
            raise NaiveError("egress provider warp is not configured on this node", 422, "egress_invalid")
        if not isinstance(acl, list) or any(not isinstance(rule, dict) or set(rule) != {"deny"} for rule in acl):
            raise NaiveError("invalid egress acl", 422, "egress_invalid")
        if upstream is not None and acl:
            raise NaiveError("forwardproxy ignores the acl when an upstream is set", 422, "egress_invalid")
        return {"schema": 1, "upstream": upstream, "acl": [{"deny": list(rule["deny"])} for rule in acl]}

    def _egress_check(self, expected_revision):
        if self.broken:
            raise NaiveError("NaiveProxy manager unavailable")
        if expected_revision != self._egress_revision():
            raise NaiveError("egress revision does not match", 409, "egress_conflict")

    def _egress_fail(self):
        code, self.egress_fail_next = self.egress_fail_next, None
        if code is not None:
            raise NaiveError("NaiveProxy manager rejected request", 502 if code == "egress_readback_mismatch" else 409, code)

    async def egress(self):
        if self.broken:
            raise NaiveError("NaiveProxy manager unavailable")
        custom = self.egress_custom is not None
        document = None if custom else self.egress_document
        upstream = self.egress_custom if custom else (self.provider_url if document["upstream"] else None)
        providers = {} if not self.provider_url else {"warp": {"url": self.provider_url, "reachable": self.reachable}}
        return {
            "revision": self._egress_revision(),
            "mode": "custom" if custom else "proxy" if upstream else "direct",
            "upstream": upstream, "acl": [] if custom else [item for rule in document["acl"] for item in rule["deny"]],
            "document": document, "managed": not custom and bool(self.egress_history),
            "providers": providers, "capabilities": list(NAIVE_EGRESS_CAPABILITIES), "restart_required": False,
            "warnings": ["adopts_unmanaged_upstream"] if custom else [],
            "previous": None if not self.egress_history else {"revision": "previous"},
            "current": None if not self.egress_history else {"revision": self._egress_revision()},
        }

    async def egress_plan(self, expected_revision, document):
        normalised = self._egress_validate(document)
        self._egress_check(expected_revision)
        target = hashlib.sha256(canonical(normalised)).hexdigest()
        return {"revision": expected_revision, "target_revision": target, "rendered_sha256": target,
                "diff": [] if normalised == self.egress_document else ["-current", "+planned"],
                "warnings": ["adopts_unmanaged_upstream"] if self.egress_custom is not None else [],
                "reachability": {"warp": self.reachable} if normalised["upstream"] else {}, "restart_required": False}

    async def egress_apply(self, expected_revision, document, operation_id):
        self.calls.append(("egress_apply", operation_id))
        if self.broken:
            raise NaiveError("NaiveProxy manager unavailable")
        normalised = self._egress_validate(document)
        record = self.egress_operations.get(operation_id)
        if record is not None:
            if record["applied"] != normalised:
                raise NaiveError("operation id already used for another request", 409, "operation_conflict")
            return {**record, "replayed": True}
        self._egress_check(expected_revision)
        if normalised["upstream"] is not None and not self.reachable:
            raise NaiveError("egress provider warp is unreachable", 409, "egress_unreachable")
        self._egress_fail()
        self.egress_history.append({"document": None if self.egress_custom is not None else self.egress_document,
                                    "custom": self.egress_custom})
        self.egress_custom, self.egress_document = None, normalised
        result = {"revision": self._egress_revision(), "applied": normalised,
                  "readback_sha256": hashlib.sha256(canonical(normalised)).hexdigest()}
        self.egress_operations[operation_id] = result
        return {**result, "replayed": False}

    async def egress_rollback(self, expected_revision):
        self.calls.append(("egress_rollback",))
        self._egress_check(expected_revision)
        if not self.egress_history:
            raise NaiveError("no previous egress to roll back to", 409, "egress_no_previous")
        self._egress_fail()
        previous = self.egress_history.pop()
        self.egress_custom = previous["custom"]
        self.egress_document = previous["document"] if previous["document"] is not None else EGRESS_DIRECT
        return {"revision": self._egress_revision(), "applied": previous["document"],
                "readback_sha256": hashlib.sha256(canonical(self.egress_document)).hexdigest()}
