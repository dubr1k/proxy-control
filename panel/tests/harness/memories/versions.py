"""Manager wire double: test-owned state, never a panel implementation."""
from __future__ import annotations


class VersionAgentError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


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
            # v0.11: the panel itself; the agent reports its `status` (ready | updating |
            # update_failed | rollback_failed) because the update runs in the background.
            "panel": {
                "current": "0.10.0-beta.1",
                "status": "ready",
                "available": [
                    {"version": "0.10.0-beta.1", "kind": "release", "source": "upstream"},
                    {"version": "0.11.0-beta.1", "kind": "release", "source": "upstream"},
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
            "swap": {
                "total_bytes": 2_147_483_648,
                "available_bytes": 2_013_265_920,
                "used_bytes": 134_217_728,
                "used_percent": 6.2,
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

    async def metrics(self):
        return getattr(self, "agent_metrics", None)

    async def rebuild_managers(self):
        self.calls.append(("rebuild_managers",))
        panel = self.components["panel"]
        if panel.get("status") == "updating":
            raise VersionAgentError("update is running", 409)
        panel["pending_rebuild"] = [n for n in panel.get("pending_rebuild", []) if n == "docker"]
        return {"pending_rebuild": panel["pending_rebuild"], "rebuilding": False}

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
        if component == "panel":
            # The real agent answers before the panel restarts and reports the outcome
            # through `status`; the memory double finishes at once.
            self.components[component]["status"] = "ready"
            return {"component": component, "version": version, "changed": True, "async": True}
        return {"component": component, "version": version, "changed": True}
