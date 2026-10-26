"""TrustTunnel: the panel's password, the node manager's account list, the tt:// deep link."""
from __future__ import annotations

import base64
import datetime
import json
import tomllib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from panel.clients.models import AccessGrant, GrantIntent, MieruOptions, TrusttunnelOptions
from panel.clients.provisioning import new_credential
from panel.protocols import AdapterError, CredentialPlan, GrantRef, TrusttunnelAdapter
from panel.protocols.trusttunnel import certificate_pem, parse_credential, render_toml, split_der
from panel.trusttunnel import MemoryTrusttunnel, TrusttunnelClient, TrusttunnelError
from panel.trusttunnel_link import (
    DeepLinkError,
    decode_deeplink,
    decode_varint,
    encode_deeplink,
    encode_varint,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _certificate(common_name="gate.example.com") -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now)
                   .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.DER)


# ---- the deep link ---------------------------------------------------------------------------------

























# ---- credential and options -------------------------------------------------------------------------







def test_options_are_bounded():
    assert TrusttunnelOptions().hostname is None
    for bad in ({"hostname": "bad host"}, {"hostname": "-x.example"}, {"port": 0}, {"port": 70000},
                {"certificate_der_b64": "not base64!"}, {"name": ""}, {"name": "x" * 65}, {"unknown": 1}):
        with pytest.raises(ValidationError):
            TrusttunnelOptions(**bad)
    with pytest.raises(ValidationError):
        GrantIntent(protocol="trusttunnel", runtime_username="x", options=MieruOptions())


# ---- the adapter against the manager contract -------------------------------------------------------

def _adapter(manager=None):
    manager = manager or MemoryTrusttunnel()
    return manager, TrusttunnelAdapter(manager, public_host="fallback.example.com")


def _intent(username="alice", **options):
    return GrantIntent(protocol="trusttunnel", runtime_username=username, options=TrusttunnelOptions(**options))


def _grant(applied, username="alice", **options):
    return AccessGrant(
        id="g1", client_id="c1", protocol="trusttunnel", node_id="local", endpoint_id="default",
        runtime_username=username, desired_state="enabled",
        options=TrusttunnelOptions(**{**applied.artifact_template, **options}),
        origin="provisioned", created_at=1, updated_at=1,
    )























# ---- artifacts ----------------------------------------------------------------------------------------













# ---- egress (the manager's own document) -------------------------------------------------------------







async def test_the_manager_refuses_what_its_contract_forbids():
    manager = MemoryTrusttunnel()
    for payload in ({"operation_id": "o", "username": "bad name", "password": "password-1234"},
                    {"operation_id": "o", "username": "a", "password": "short"},
                    {"operation_id": "", "username": "a", "password": "password-1234"},
                    {"operation_id": "o", "username": "a", "password": "password-1234", "extra": 1}):
        with pytest.raises(TrusttunnelError) as error:
            await manager.create_client(payload)
        assert (error.value.status_code, error.value.code) == (422, "invalid_request")
    await manager.create_client({"operation_id": "o", "username": "a", "password": "password-1234"})
    with pytest.raises(TrusttunnelError) as reused:
        await manager.create_client({"operation_id": "o", "username": "a", "password": "password-9999"})
    assert reused.value.code == "operation_conflict"
    manager.certificate_missing = True
    assert (await manager.health())["code"] == "certificate_missing"


# ---- the real client speaks the manager contract ------------------------------------------------------




# ---- through the whole panel ---------------------------------------------------------------------------

import httpx  # noqa: E402

from panel.amneziawg import MemoryAmneziawg  # noqa: E402
from panel.app import Settings  # noqa: E402
from panel.tests.harness.server import panel_app  # noqa: E402
from panel.keyring import Keyring  # noqa: E402
from panel.mieru import MemoryMieru  # noqa: E402
from panel.naive import MemoryNaive  # noqa: E402
from panel.telemt import MemoryTelemt  # noqa: E402
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


async def _issue(api, grants):
    created = await api.post("/api/clients", json={"display_name": "Alice"}, headers=_headers(api))
    client_id = created.json()["id"]
    started = await api.post(f"/api/clients/{client_id}/grants", json={"grants": grants}, headers=_headers(api))
    assert started.status_code == 200 and started.json()["status"] == "succeeded", started.text
    return client_id


async def _artifacts_of(api, client_id, grant_id):
    issued = await api.post(f"/api/clients/{client_id}/links?grant_id={grant_id}", headers=_headers(api))
    assert issued.status_code == 200, issued.text
    revealed = await api.get(f"/api/reveal/{issued.json()['reveal_token']}")
    [grant] = revealed.json()["grants"]
    return {artifact["kind"]: artifact for artifact in grant["artifacts"]}








async def test_options_the_node_teaches_cannot_be_forged_into_a_foreign_shape(api):
    created = await api.post("/api/clients", json={"display_name": "Eve"}, headers=_headers(api))
    refused = await api.post(f"/api/clients/{created.json()['id']}/grants", headers=_headers(api), json={
        "grants": [{"protocol": "trusttunnel", "runtime_username": "eve-tt", "options": {"version": "2.0"}}]})
    assert refused.status_code == 422








# ---- the screen's backend ---------------------------------------------------------------------------------










# ---- a central and a linked node -------------------------------------------------------------------------

from panel.tests.harness.server import start_panel  # noqa: E402

ACTOR = {"id": 1, "username": "owner"}


def _tt_app(tmp_path, name, manager=None, enabled=True, node_routes=None):
    return start_panel(tmp_path, name=name, hosts=("testserver", f"{name}.example"), naive_public_host=f"{name}.example",
                       trusttunnel_enabled=enabled, trusttunnel_public_host=f"gate.{name}.example" if enabled else "",
                       telemt=MemoryTelemt(public_host=f"{name}.example"), naive=MemoryNaive(), mieru=MemoryMieru(),
                       amneziawg=MemoryAmneziawg(),
                       trusttunnel=manager or MemoryTrusttunnel(hostname=f"gate.{name}.example"),
                       node_routes=node_routes)


async def _linked_tt(tmp_path, *, node_enabled=True):
    node = _tt_app(tmp_path, "node", enabled=node_enabled)
    central = _tt_app(tmp_path, "central", enabled=False, node_routes={"node.example": node})
    plaintext = node.create_api_key("central", "node-sync")
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    return node, central, node_id




















def test_the_manager_token_is_read_from_the_staged_file(tmp_path, monkeypatch):
    token = tmp_path / "trusttunnel-manager-token"
    token.write_text("staged-token-0123456789\n")
    monkeypatch.setenv("TRUSTTUNNEL_MANAGER_TOKEN_FILE", str(token))
    monkeypatch.setenv("TRUSTTUNNEL_MANAGER_SOCKET", "/run/x/manager.sock")
    settings = Settings()
    assert settings.trusttunnel_token == "staged-token-0123456789"
    assert settings.trusttunnel_enabled is False
