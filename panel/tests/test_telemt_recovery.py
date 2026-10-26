"""Telemt has no operation id, so a lost response is recovered by reading the truth back.

Telemt's API is not idempotent and cannot be made so from the panel side. What it does
offer is that the live link *is* the credential: after a request whose reply never
arrived, reading the user back tells the panel exactly what the runtime now holds.
"""

from __future__ import annotations

import httpx
import pytest

from panel.telemt import MemoryTelemt, TelemtClient, TelemtError, TelemtIndeterminate

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def telemt():
    return MemoryTelemt(public_host="proxy.example.com", public_port=443)


def _client(handler) -> TelemtClient:
    return TelemtClient("http://telemt", "Bearer t", transport=httpx.MockTransport(handler))


async def test_lost_create_response_is_recovered_by_reading_the_current_link(telemt):
    telemt.faults["create"] = "lose_response"
    with pytest.raises(TelemtIndeterminate):
        await telemt.create_user("alice")
    # The user exists despite the failure — that is exactly what "indeterminate" means.
    access = await telemt.current_access("alice")
    assert access is not None and access["link"].startswith("tg://proxy")
    assert access["secret"] and access["secret"] in access["link"]
    assert await telemt.current_access("nobody") is None


async def test_lost_rotate_response_yields_the_new_secret_not_the_old(telemt):
    created = await telemt.create_user("alice")
    before = await telemt.current_access("alice")
    telemt.faults["rotate"] = "lose_response"
    with pytest.raises(TelemtIndeterminate):
        await telemt.rotate("alice")
    after = await telemt.current_access("alice")
    assert after["secret"] != before["secret"]
    assert after["link"] != created["user"]["links"]["tls"][0]









