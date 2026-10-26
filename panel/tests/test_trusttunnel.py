"""TrustTunnel: the panel's password, the node manager's account list, the tt:// deep link."""
from __future__ import annotations






import pytest




from pydantic import ValidationError

from panel.clients.models import GrantIntent, MieruOptions, TrusttunnelOptions



from panel.tests.harness.memories.trusttunnel import MemoryTrusttunnel, TrusttunnelError


pytestmark = pytest.mark.anyio








# ---- the deep link ---------------------------------------------------------------------------------

























# ---- credential and options -------------------------------------------------------------------------










# ---- the adapter against the manager contract -------------------------------------------------------































# ---- artifacts ----------------------------------------------------------------------------------------













# ---- egress (the manager's own document) -------------------------------------------------------------










# ---- the real client speaks the manager contract ------------------------------------------------------




# ---- through the whole panel ---------------------------------------------------------------------------

import httpx  # noqa: E402

from panel.tests.harness.memories.amneziawg import MemoryAmneziawg  # noqa: E402
from panel.app import Settings  # noqa: E402
from panel.tests.harness.server import panel_app  # noqa: E402
from panel.keyring import Keyring  # noqa: E402
from panel.tests.harness.memories.mieru import MemoryMieru  # noqa: E402
from panel.tests.harness.memories.naive import MemoryNaive  # noqa: E402
from panel.tests.harness.memories.telemt import MemoryTelemt  # noqa: E402
from panel.versions import VersionClient  # noqa: E402


@pytest.fixture
def tt() -> MemoryTrusttunnel:
    return MemoryTrusttunnel()


@pytest.fixture
async def api(tmp_path, tt):
    master_key = tmp_path / "panel-master-key"
    Keyring.generate().save(master_key)
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3", master_key_file=master_key, session_cookie_secure=False,
        allowed_hosts=("testserver",), reveal_ttl_seconds=60, naive_public_host="vpn.example.com",
        naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True, trusttunnel_enabled=True,
        trusttunnel_public_host="gate.example.com", vnext_writer="domain",
    )
    app = panel_app(settings, telemt=MemoryTelemt(public_host="proxy.example.com"), naive=MemoryNaive(),
                     mieru=MemoryMieru(), amneziawg=MemoryAmneziawg(), trusttunnel=tt,
                     version_client=VersionClient(str(tmp_path / "missing-version-agent.sock")))
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver",
                                 follow_redirects=False) as client:
        page = await client.get("/login")
        await client.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"},
                          headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
        client.app_state = app.state
        yield client


def _headers(api):
    return {"X-CSRF-Token": api.cookies["panel_csrf"]}























# ---- the screen's backend ---------------------------------------------------------------------------------










# ---- a central and a linked node -------------------------------------------------------------------------

  # noqa: E402





























