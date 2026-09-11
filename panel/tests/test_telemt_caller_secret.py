import pytest

from panel.clients.models import GrantIntent, MtproxyOptions
from panel.protocols.base import CredentialPlan, GrantRef
from panel.protocols.telemt import TelemtAdapter
from panel.telemt import MemoryTelemt, TelemtError, TelemtIndeterminate

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


SECRET = "0123456789abcdef0123456789abcdef"


def _intent(username="alice"):
    return GrantIntent(protocol="mtproxy", runtime_username=username, options=MtproxyOptions())


async def test_caller_secret_is_passed_through_and_returned_in_the_link():
    telemt = MemoryTelemt()
    applied = await TelemtAdapter(telemt).create("op", _intent(), CredentialPlan("caller", SECRET.encode()))
    assert applied.credential == f"ee{SECRET}".encode() and applied.credential_origin == "caller"
    rotated = await TelemtAdapter(telemt).rotate("op2", GrantRef("mtproxy", "alice"), CredentialPlan("caller", b"f" * 32))
    assert rotated.credential == b"ee" + b"f" * 32


async def test_manager_plan_still_works_unchanged():
    telemt = MemoryTelemt()
    applied = await TelemtAdapter(telemt).create("op", _intent(), CredentialPlan("manager", None))
    assert applied.credential and applied.credential_origin == "manager"


async def test_runtime_that_rejects_the_secret_field_falls_back_to_manager():
    class Rejecting(MemoryTelemt):
        async def create_user(self, username, secret=None):
            if secret is not None:
                raise TelemtError("Telemt API error (400)")
            return await super().create_user(username)

    applied = await TelemtAdapter(Rejecting()).create("op", _intent(), CredentialPlan("caller", SECRET.encode()))
    assert applied.credential_origin == "manager" and applied.credential


async def test_create_double_indeterminate_propagates_raw_not_adapter_error():
    """Initial call indeterminate, recovery finds nothing, retry indeterminate again:
    the outcome is still unknown, so the saga must resume — never compensate."""

    class AlwaysLost(MemoryTelemt):
        async def create_user(self, username, secret=None):
            raise TelemtIndeterminate("simulated loss")

        async def current_access(self, username):
            return None

    with pytest.raises(TelemtIndeterminate):
        await TelemtAdapter(AlwaysLost()).create("op", _intent(), CredentialPlan("manager", None))


async def test_rotate_double_indeterminate_propagates_raw_not_adapter_error():
    class AlwaysLost(MemoryTelemt):
        async def rotate(self, username, secret=None):
            raise TelemtIndeterminate("simulated loss")

        async def current_access(self, username):
            return None

    with pytest.raises(TelemtIndeterminate):
        await TelemtAdapter(AlwaysLost()).rotate(
            "op", GrantRef("mtproxy", "alice"), CredentialPlan("manager", None)
        )


async def test_update_options_changes_limits_and_reports_unsupported_fields():
    telemt = MemoryTelemt()
    adapter = TelemtAdapter(telemt)
    await adapter.create("op", _intent(), CredentialPlan("manager", None))
    applied = await adapter.update_options(GrantRef("mtproxy", "alice"), {"max_tcp_conns": 3, "host": "x"})
    assert applied is not None and telemt.users["alice"]["max_tcp_conns"] == 3
    assert await adapter.update_options(GrantRef("mtproxy", "alice"), {"host": "x"}) is None
