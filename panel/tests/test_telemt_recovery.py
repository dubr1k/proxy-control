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


async def test_a_request_that_never_left_is_a_plain_failure_not_indeterminate():
    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    client = _client(refuse)
    with pytest.raises(TelemtError) as failure:
        await client.list_users()
    # A connection that was never established sent nothing, so a retry is safe and the
    # caller must not be pushed into a recovery read.
    assert not isinstance(failure.value, TelemtIndeterminate)


async def test_a_reply_lost_after_the_request_was_sent_is_indeterminate():
    def timeout(request):
        raise httpx.ReadTimeout("no reply", request=request)

    with pytest.raises(TelemtIndeterminate):
        await _client(timeout).create_user("alice")


async def test_current_access_reads_the_live_link_from_the_user_listing():
    link = "tg://proxy?server=proxy.example.com&port=443&secret=ee" + "ab" * 16

    def listing(request):
        assert request.url.path == "/v1/users"
        return httpx.Response(
            200,
            json={"ok": True, "data": [{"username": "alice", "links": {"tls": [link]}}]},
        )

    access = await _client(listing).current_access("alice")
    assert access == {"link": link, "secret": "ee" + "ab" * 16}
