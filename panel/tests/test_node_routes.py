"""The node API: read for everyone, lifecycle for the owner, no inventory leaks."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio




















async def test_local_node_reports_unavailable_managers(client, login_user, mieru, telemt):
    from panel.tests.harness.memories.telemt import TelemtError

    await login_user(client)
    mieru.broken = True

    async def failing_health():
        raise TelemtError("Telemt API unavailable")

    telemt.health = failing_health
    services = (await client.get("/api/nodes/local")).json()["services"]
    assert services == {"telemt": "unavailable", "naive": "ok", "mieru": "unavailable", "amneziawg": "disabled", "trusttunnel": "disabled"}


async def test_local_node_marks_switched_off_protocols_disabled(panel_server, login_user):
    from panel.tests.harness.memories.mieru import MemoryMieru
    from panel.tests.harness.memories.naive import MemoryNaive
    from panel.tests.harness.memories.telemt import MemoryTelemt

    class MustNotBeAsked(MemoryNaive):
        async def health(self):
            raise AssertionError("a disabled protocol was polled for node health")

    class MieruMustNotBeAsked(MemoryMieru):
        async def health(self):
            raise AssertionError("a disabled protocol was polled for node health")

    server = panel_server(name="disabled-protocols", naive_enabled=False, mieru_enabled=False,
                          telemt=MemoryTelemt(), naive=MustNotBeAsked(), mieru=MieruMustNotBeAsked())
    server.create_admin("owner", "correct horse battery staple", "owner")
    async with server.http() as client:
        await login_user(client)
        services = (await client.get("/api/nodes/local")).json()["services"]
    assert services == {"telemt": "ok", "naive": "disabled", "mieru": "disabled", "amneziawg": "disabled", "trusttunnel": "disabled"}



