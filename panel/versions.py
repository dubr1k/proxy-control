from __future__ import annotations

import httpx


class VersionAgentError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class VersionClient:
    def __init__(self, socket_path: str, *, timeout: float = 20.0, transport=None):
        self.socket_path = socket_path
        self.timeout = timeout
        self.transport = transport

    async def _request(self, method: str, path: str, payload=None, *, timeout=None):
        transport = self.transport or httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(
                base_url="http://version-agent",
                timeout=self.timeout if timeout is None else timeout,
                transport=transport,
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise VersionAgentError("version agent unavailable") from exc
        if response.status_code >= 400:
            status = response.status_code if response.status_code in {409, 422} else 502
            raise VersionAgentError("version agent rejected request", status)
        try:
            return response.json()
        except ValueError as exc:
            raise VersionAgentError("invalid version agent response") from exc

    async def list_versions(self):
        return await self._request("GET", "/v1/versions")

    async def host(self):
        # The overview must not wait on the agent the way an update may: a slow
        # or wedged agent has to cost the dashboard a card, not the whole page.
        return await self._request("GET", "/v1/host", timeout=3.0)

    async def check(self):
        # v0.11: the agent polls upstream (GitHub Releases, registries) and answers with
        # the same shape as `/v1/versions`; several sources in a row need more than the
        # default 20 s.
        return await self._request("POST", "/v1/upstream/check", timeout=90.0)

    async def update(self, component: str, version: str, expected_current: str | None):
        # A `naive` update rebuilds Caddy on the host (up to 15 min): the panel waits for
        # the agent's verdict instead of guessing.
        return await self._request(
            "POST",
            "/v1/update",
            {
                "component": component,
                "version": version,
                "expected_current": expected_current,
            },
            timeout=1200.0,
        )


class MemoryVersions:
    def __init__(self, router: bool = False):
        self.checks = 0
        self.checked_at = None
        self.components = {
            "telemt": {
                "current": "3.4.24",
                "available": [
                    {"version": "3.4.24", "kind": "image"},
                    {"version": "3.4.25", "kind": "image"},
                ],
            },
            "naive": {
                "current": "2.11.3",
                "available": [
                    {"version": "2.11.3", "kind": "binary"},
                    {"version": "2.11.4", "kind": "binary"},
                ],
            },
            "mita": {
                "current": "3.34.0",
                "available": [
                    {"version": "3.34.0", "kind": "binary"},
                    {"version": "3.35.0", "kind": "binary"},
                    {"version": "3.36.0", "kind": "binary"},
                ],
            },
        }
        if router:
            # The agent reports `xray` only on a host that runs the Xray-router.
            self.components["xray"] = {
                "current": "26.3.27",
                "available": [
                    {"version": "26.3.27", "kind": "binary"},
                    {"version": "26.4.1", "kind": "binary", "source": "upstream"},
                ],
            }
        self.calls = []
        self.host_metrics = {
            "cpu": {"used_percent": 12.5, "cores": 4, "load_average": [0.5, 0.4, 0.3]},
            "memory": {
                "total_bytes": 4_106_223_616,
                "available_bytes": 2_979_237_888,
                "used_bytes": 1_126_985_728,
                "used_percent": 27.4,
            },
            "disk": {
                "total_bytes": 84_825_800_704,
                "available_bytes": 71_940_702_208,
                "used_bytes": 9_771_899_289,
                "used_percent": 11.5,
            },
        }

    async def list_versions(self):
        return {
            "enabled": True,
            "upstream_enabled": True,
            "checked_at": self.checked_at,
            "components": self.components,
        }

    async def check(self):
        self.checks += 1
        self.checked_at = self.checks
        candidate = {"version": "3.37.0", "kind": "binary", "source": "upstream"}
        if candidate not in self.components["mita"]["available"]:
            self.components["mita"]["available"].append(candidate)
        return await self.list_versions()

    async def host(self):
        return self.host_metrics

    async def update(self, component, version, expected_current):
        self.calls.append((component, version, expected_current))
        if component not in self.components:
            # The real agent refuses a component this host does not run (`xray` without
            # the router) with a validation error, not a crash.
            raise VersionAgentError("unknown component", 422)
        current = self.components[component]["current"]
        if expected_current != current:
            raise VersionAgentError("version changed", 409)
        self.components[component]["current"] = version
        return {"component": component, "version": version, "changed": True}
