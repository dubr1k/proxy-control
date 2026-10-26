import pytest

from panel.clients.models import GrantIntent, MtproxyOptions
from panel.protocols.base import AdapterError, CredentialPlan, GrantRef
from panel.protocols.telemt import TelemtAdapter
from panel.telemt import MemoryTelemt, TelemtError, TelemtIndeterminate

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


SECRET = "0123456789abcdef0123456789abcdef"


def _intent(username="alice"):
    return GrantIntent(protocol="mtproxy", runtime_username=username, options=MtproxyOptions())





















