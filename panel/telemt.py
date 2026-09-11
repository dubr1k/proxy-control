from __future__ import annotations

import copy
import re
import secrets
import time
from urllib.parse import parse_qs, quote, urlsplit

import httpx


class TelemtError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        if status_code is None:
            # `_request` always embeds the HTTP status this way; parsing it back keeps
            # errors raised elsewhere (fakes in tests) carrying the same information
            # without every caller having to pass it explicitly.
            match = re.search(r"\((\d{3})\)\s*$", message)
            status_code = int(match.group(1)) if match else 502
        self.status_code = status_code


class TelemtIndeterminate(TelemtError):
    """The request was sent and the reply never arrived: the outcome is unknown.

    Telemt has no operation id, so this is not retryable on its own. The caller must
    read the user back — the live link is the credential — before deciding anything.
    """


# Telemt's API reports the bare secret; the Fake-TLS link prefixes it with `ee`. The
# panel escrows the link form, because that is what rebuilds a working link, and
# converts back here when answering in the API's own shape.
FAKE_TLS_PREFIX = "ee"


def api_secret(link_secret: str) -> str:
    if link_secret.startswith(FAKE_TLS_PREFIX):
        return link_secret[len(FAKE_TLS_PREFIX):]
    return link_secret


def access_from_user(row) -> dict | None:
    """The current link, the secret inside it and the endpoint it points at.

    Telemt owns the public host and port: they exist nowhere in the panel's own
    configuration, so the only place to learn them is the link the runtime returns.
    """
    if not isinstance(row, dict):
        return None
    links = row.get("links") if isinstance(row.get("links"), dict) else {}
    candidates = links.get("tls") if isinstance(links.get("tls"), list) else []
    link = next((item for item in candidates if isinstance(item, str)), None)
    if not link:
        return None
    query = parse_qs(urlsplit(link).query)
    port = query.get("port", [""])[0]
    return {
        "link": link,
        "secret": query.get("secret", [None])[0],
        "server": query.get("server", [None])[0] or None,
        "port": int(port) if port.isdigit() and 1 <= int(port) <= 65535 else None,
    }


class TelemtClient:
    def __init__(self, base_url: str, auth_header: str, *, timeout=5.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.timeout = timeout
        self.transport = transport

    async def _request(self, method, path, json=None):
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout, transport=self.transport,
                                         headers={"Authorization": self.auth_header}) as client:
                response = await client.request(method, path, json=json)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # The connection was never established, so nothing was sent: a plain
            # failure, and a retry is safe.
            raise TelemtError("Telemt API unavailable") from exc
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise TelemtIndeterminate("Telemt API reply was lost") from exc
        except httpx.HTTPError as exc:
            raise TelemtError("Telemt API unavailable") from exc
        if response.status_code >= 400:
            raise TelemtError(f"Telemt API error ({response.status_code})", status_code=response.status_code)
        try:
            body = response.json()
        except ValueError as exc:
            raise TelemtError("Invalid Telemt API response") from exc
        if not body.get("ok"):
            raise TelemtError("Telemt API rejected request")
        return body.get("data"), body.get("revision")

    async def list_users(self): return (await self._request("GET", "/v1/users"))[0]

    async def create_user(self, username, secret=None):
        body = {"username": username}
        if secret is not None:
            body["secret"] = secret
        return (await self._request("POST", "/v1/users", body))[0]

    async def delete_user(self, username): return (await self._request("DELETE", f"/v1/users/{quote(username)}"))[0]
    async def set_enabled(self, username, enabled): return (await self._request("POST", f"/v1/users/{quote(username)}/{'enable' if enabled else 'disable'}"))[0]

    async def rotate(self, username, secret=None):
        body = {} if secret is None else {"secret": secret}
        return (await self._request("POST", f"/v1/users/{quote(username)}/rotate-secret", body))[0]
    async def update_user(self, username, fields): return (await self._request("PATCH", f"/v1/users/{quote(username)}", fields))[0]
    async def reset_quota(self, username): return (await self._request("POST", f"/v1/users/{quote(username)}/reset-quota", {}))[0]
    async def health(self): return (await self._request("GET", "/v1/health/ready"))[0]
    async def stats(self): return (await self._request("GET", "/v1/stats/summary"))[0]
    async def connections(self): return (await self._request("GET", "/v1/runtime/connections/summary"))[0]
    async def active_ips(self): return (await self._request("GET", "/v1/stats/users/active-ips"))[0]
    async def quota_stats(self): return (await self._request("GET", "/v1/stats/users/quota"))[0]

    async def current_access(self, username):
        """Read back what the runtime holds now — the recovery step after a lost reply."""
        for row in await self.list_users():
            if isinstance(row, dict) and row.get("username") == username:
                return access_from_user(row)
        return None


class MemoryTelemt:
    def __init__(self, public_host="localhost", public_port=443):
        self.users = {}
        self.quota_usage = {}
        self.reset_extra = {}
        self.public_host, self.public_port = public_host, public_port
        # {"create": "lose_response"} performs the mutation and then raises, the
        # way Telemt does when the reply never reaches the panel.
        self.faults = {}

    def _maybe_lose(self, operation):
        if self.faults.get(operation) == "lose_response":
            raise TelemtIndeterminate("simulated loss")

    async def current_access(self, username):
        row = self.users.get(username)
        return None if row is None else access_from_user(row)

    async def list_users(self): return list(self.users.values())
    async def create_user(self, username, secret=None):
        secret = secret or secrets.token_hex(16)
        link = f"tg://proxy?server={self.public_host}&port={self.public_port}&secret=ee{secret}"
        user = {"username": username, "enabled": True, "links": {"tls": [link]}}
        self.users[username] = user
        self._maybe_lose("create")
        # A real response is a snapshot: handing out the live row would let a later
        # rotation silently rewrite an answer the caller already received.
        return {"user": copy.deepcopy(user), "secret": secret}
    async def delete_user(self, username):
        self.users.pop(username)
        return {"username": username}
    async def set_enabled(self, username, enabled):
        self.users[username]["enabled"] = enabled
        return copy.deepcopy(self.users[username])
    async def rotate(self, username, secret=None):
        secret = secret or secrets.token_hex(16)
        link = f"tg://proxy?server={self.public_host}&port={self.public_port}&secret=ee{secret}"
        self.users[username]["links"] = {"tls": [link]}
        self._maybe_lose("rotate")
        return {"user": copy.deepcopy(self.users[username]), "secret": secret}
    async def update_user(self, username, fields):
        self.users[username].update(fields)
        if "data_quota_bytes" in fields and fields["data_quota_bytes"] is None:
            self.quota_usage.pop(username, None)
        elif "data_quota_bytes" in fields:
            current = self.quota_usage.setdefault(username, {
                "username": username, "used_bytes": 0, "last_reset_epoch_secs": 0,
            })
            current["data_quota_bytes"] = fields["data_quota_bytes"]
        return self.users[username]
    async def reset_quota(self, username):
        current = self.quota_usage.setdefault(username, {
            "username": username,
            "data_quota_bytes": self.users[username].get("data_quota_bytes", 0),
        })
        current.update({"used_bytes": 0, "last_reset_epoch_secs": int(time.time())})
        return {
            "username": username, "used_bytes": 0,
            "last_reset_epoch_secs": current["last_reset_epoch_secs"], **self.reset_extra,
        }
    async def health(self): return {"ready": True}
    async def stats(self): return {"connections": 0, "bytes": 0}
    async def connections(self): return {"active": 0, "top_users": []}
    async def active_ips(self): return []
    async def quota_stats(self): return {"users": list(self.quota_usage.values())}
