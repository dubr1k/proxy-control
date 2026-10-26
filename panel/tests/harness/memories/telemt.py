"""Manager wire double: test-owned state, never a panel implementation."""
from __future__ import annotations
import copy
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit


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


class MemoryTelemt:
    def __init__(self, public_host="localhost", public_port=443):
        self.users = {}
        self.quota_usage = {}
        self.reset_extra = {}
        self.public_host, self.public_port = public_host, public_port
        # {"create": "lose_response"} performs the mutation and then raises, the
        # way Telemt does when the reply never reaches the panel.
        self.faults = {}
        # v1.1: the config API — what the entrypoint writes, a counter for the revision, and
        # how the next reload ends (`succeeded`, `failed`, `rolled_back`, or `stuck`).
        self.config_api = True
        self.upstreams = [{"type": "direct", "ipv4": True, "ipv6": False}]
        self.config_version = 1
        self.reload_outcome = "succeeded"
        self.reloads: dict[int, dict] = {}
        self.runtime_upstreams = copy.deepcopy(self.upstreams)
        self.config_calls: list[tuple] = []

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

    def _config_revision(self) -> str:
        return f"{self.config_version:064x}"

    def _config_check(self) -> None:
        if not self.config_api:
            raise TelemtError("Telemt API error (404)", status_code=404)

    async def config(self):
        self._config_check()
        return {"general": {"use_middle_proxy": False}, "upstreams": copy.deepcopy(self.upstreams)}, self._config_revision()

    async def patch_config(self, body, revision):
        self._config_check()
        self.config_calls.append(("patch", copy.deepcopy(body)))
        if revision != self._config_revision():
            raise TelemtError("Telemt API error (412)", status_code=412)
        self.upstreams = copy.deepcopy(body["upstreams"])
        self.config_version += 1
        self._maybe_lose("patch")
        return ({"revision": self._config_revision(), "runtime_reload_required": True, "process_restart_required": False,
                 "changed": ["upstreams"]}, self._config_revision())

    async def reload(self, revision):
        self._config_check()
        if revision != self._config_revision():
            raise TelemtError("Telemt API error (412)", status_code=412)
        reload_id = len(self.reloads) + 1
        self.config_calls.append(("reload", reload_id))
        state = {"stuck": "preparing"}.get(self.reload_outcome, self.reload_outcome)
        if state == "succeeded":
            self.runtime_upstreams = copy.deepcopy(self.upstreams)
        self.reloads[reload_id] = {"reload_id": reload_id, "state": state}
        return {"reload_id": reload_id, "state": "accepted"}

    async def reload_status(self, reload_id):
        self._config_check()
        return copy.deepcopy(self.reloads[int(reload_id)])
