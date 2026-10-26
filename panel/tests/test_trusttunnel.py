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

def test_varints_follow_rfc_9000():
    assert encode_varint(0) == b"\x00" and encode_varint(63) == b"\x3f"
    assert encode_varint(64) == b"\x40\x40" and encode_varint(300) == b"\x41\x2c"
    assert encode_varint(16383) == b"\x7f\xff" and encode_varint(16384) == b"\x80\x00\x40\x00"
    assert encode_varint(1 << 30) == b"\xc0\x00\x00\x00\x40\x00\x00\x00"
    for value in (0, 1, 63, 64, 300, 16383, 16384, 2**30 - 1, 2**30, 2**62 - 1):
        assert decode_varint(encode_varint(value), 0) == (value, len(encode_varint(value)))
    with pytest.raises(DeepLinkError):
        encode_varint(2**62)
    with pytest.raises(DeepLinkError):
        decode_varint(b"\x41", 0)  # a two-byte integer cut short


def test_a_known_vector_derived_by_hand():
    """version=1 (00 01 01), hostname "h" (01 01 68), address "a:1" (02 03 61 3a 31), username "u"
    (05 01 75), password "p" (06 01 70), upstream http2 (09 01 01): 20 bytes, base64url, no padding.
    Version 1, not 2: the stable official client (TrustTunnelClient 1.1.11, deep-link decoder 1.0.33)
    refuses a version-2 link outright, and the panel never writes the one field version 2 adds."""
    payload = bytes.fromhex("000101" "010168" "0203613a31" "050175" "060170" "090101")
    assert base64.urlsafe_b64encode(payload).rstrip(b"=").decode() == "AAEBAQFoAgNhOjEFAXUGAXAJAQE"
    link = encode_deeplink(hostname="h", addresses=["a:1"], username="u", password="p")
    assert link == "tt://?AAEBAQFoAgNhOjEFAXUGAXAJAQE"
    decoded = decode_deeplink(link)
    assert (decoded["version"], decoded["hostname"], decoded["addresses"]) == (1, "h", ["a:1"])
    assert (decoded["username"], decoded["password"], decoded["upstream_protocol"]) == ("u", "p", 1)
    assert decoded["has_ipv6"] is True and decoded["skip_verification"] is False and "certificate" not in decoded


def test_the_panel_writes_a_link_the_stable_official_client_reads():
    """The decoder of TrustTunnelClient 1.1.11 stops at «Unsupported deep link version: 2 (max
    supported: 1)»: the AdGuard app and the CLI then import nothing. The panel writes version 1
    and still reads version 2 links (a subscription_url link) back."""
    link = encode_deeplink(hostname="h", addresses=["a:1"], username="u", password="secret-1", name="n",
                           certificate_der=_certificate(), skip_verification=True)
    body = link[len("tt://?"):]
    payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    assert payload[:3] == b"\x00\x01\x01"
    assert decode_deeplink(link)["version"] == 1


def test_a_link_round_trips_with_a_certificate_a_name_and_unicode():
    chain = _certificate() + _certificate("other")
    link = encode_deeplink(hostname="gate.example.com", addresses=["gate.example.com:443", "[2001:db8::1]:443"],
                           username="alice-1.x_y", password="Zz9-_" * 8, certificate_der=chain,
                           name="Алиса · телефон", skip_verification=True)
    assert link.startswith("tt://?") and not set("=+/") & set(link[len("tt://?"):])
    decoded = decode_deeplink(link)
    assert decoded["addresses"] == ["gate.example.com:443", "[2001:db8::1]:443"]
    assert decoded["certificate"] == chain and decoded["name"] == "Алиса · телефон"
    assert decoded["username"] == "alice-1.x_y" and decoded["password"] == "Zz9-_" * 8
    assert decoded["skip_verification"] is True and decoded["upstream_protocol"] == 1


def test_a_long_value_uses_a_two_byte_length():
    link = encode_deeplink(hostname="h", addresses=["a:1"], username="u", password="p" * 300)
    assert decode_deeplink(link)["password"] == "p" * 300


def test_the_decoder_skips_unknown_tags_and_reads_every_known_one():
    def tlv(tag, value):
        return encode_varint(tag) + encode_varint(len(value)) + value

    dns = b"".join(encode_varint(len(item)) + item for item in (b"1.1.1.1", b"tls://dns.example.com"))
    payload = (tlv(0, encode_varint(2)) + tlv(0x40, b"future") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(2, b"b:2")
               + tlv(3, b"sni.example") + tlv(4, b"\x00") + tlv(5, b"u") + tlv(6, b"p") + tlv(0x0A, b"\x01")
               + tlv(0x0B, b"aabb/ff00") + tlv(0x0D, dns) + tlv(0x0F, b"00ff"))
    decoded = decode_deeplink("tt://?" + base64.urlsafe_b64encode(payload).rstrip(b"=").decode())
    assert decoded["addresses"] == ["a:1", "b:2"] and decoded["custom_sni"] == "sni.example"
    assert decoded["has_ipv6"] is False and decoded["anti_dpi"] is True
    assert decoded["client_random_prefix"] == "aabb/ff00" and decoded["client_random_auth_key"] == "00ff"
    assert decoded["dns_upstreams"] == ["1.1.1.1", "tls://dns.example.com"]


def test_a_subscription_only_link_needs_no_static_fields():
    def tlv(tag, value):
        return encode_varint(tag) + encode_varint(len(value)) + value

    payload = tlv(0, encode_varint(2)) + tlv(0x0E, b"https://sub.example/x")
    decoded = decode_deeplink("tt://?" + base64.urlsafe_b64encode(payload).rstrip(b"=").decode())
    assert decoded["subscription_url"] == "https://sub.example/x"


def test_a_bad_link_is_refused_without_echoing_it():
    good = encode_deeplink(hostname="h", addresses=["a:1"], username="u", password="p")
    body = good[len("tt://?"):]
    newer = base64.urlsafe_b64encode(bytes.fromhex("000103") + base64.urlsafe_b64decode(body + "=")[3:]).rstrip(b"=")
    for bad in ("", "https://x", "tt://", "tt://?!!!", good[:-3] + "A", "tt://?" + newer.decode(), "tt://?AAEC",
                "tt://?" + base64.urlsafe_b64encode(b"\x01\x01h").decode()):
        with pytest.raises(DeepLinkError) as error:
            decode_deeplink(bad)
        assert "p" * 5 not in str(error.value)
    with pytest.raises(DeepLinkError):
        encode_deeplink(hostname="", addresses=["a:1"], username="u", password="p")
    with pytest.raises(DeepLinkError):
        encode_deeplink(hostname="h", addresses=[], username="u", password="p")
    with pytest.raises(DeepLinkError):
        encode_deeplink(hostname="h", addresses=["a:1"], username="u", password="p", upstream_protocol=9)


# ---- credential and options -------------------------------------------------------------------------

def test_a_new_credential_is_a_url_safe_password():
    first, second = new_credential("trusttunnel"), new_credential("trusttunnel")
    assert first != second and len(first) == 32
    assert parse_credential(first) == first.decode() and set(first.decode()) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_a_malformed_credential_is_refused():
    for bad in (b"", b"\xff\xfe", b"line\nbreak", b"x" * 129, b"del\x7f1234", b"short", b"has space1",
                "пароль-длинный".encode()):
        with pytest.raises(AdapterError):
            parse_credential(bad)


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


async def test_the_manager_receives_the_password_and_the_panel_learns_the_endpoint():
    manager, adapter = _adapter()
    credential = new_credential("trusttunnel")
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", credential))
    assert manager.client_table["alice"]["password"] == credential.decode()
    assert applied.credential == credential and applied.enabled and applied.recovered is False
    assert applied.artifact_template == {"hostname": "gate.example.com", "port": 443, "certificate_der_b64": None}
    assert manager.authenticates("alice", credential.decode())


async def test_a_certificate_the_system_does_not_trust_is_learned_but_a_trusted_one_is_not():
    der_b64 = base64.b64encode(_certificate()).decode()
    manager, adapter = _adapter(MemoryTrusttunnel(certificate_der_b64=der_b64))
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", new_credential("trusttunnel")))
    assert applied.artifact_template["certificate_der_b64"] == der_b64

    # an endpoint that reports a trusted certificate (even with a DER attached) teaches none
    class Trusted(MemoryTrusttunnel):
        async def endpoint(self):
            return {**await super().endpoint(), "certificate_trusted": True}

    _, trusted = _adapter(Trusted(certificate_der_b64=der_b64))
    plain = await trusted.create("op-1", _intent("bob"), CredentialPlan("caller", new_credential("trusttunnel")))
    assert plain.artifact_template["certificate_der_b64"] is None


async def test_full_lifecycle_and_a_disabled_client_stops_authenticating():
    manager, adapter = _adapter()
    first = new_credential("trusttunnel")
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", first))
    ref = GrantRef("trusttunnel", "alice", applied.revision)
    assert (await adapter.disable(ref)).enabled is False
    assert not manager.authenticates("alice", first.decode())
    assert (await adapter.enable(ref)).enabled is True
    assert manager.authenticates("alice", first.decode())  # the same password comes back

    second = new_credential("trusttunnel")
    rotated = await adapter.rotate("op-2", ref, CredentialPlan("caller", second))
    assert rotated.credential == second
    assert manager.authenticates("alice", second.decode()) and not manager.authenticates("alice", first.decode())

    assert await adapter.capture(ref) is None and await adapter.update_options(ref, {"name": "x"}) is None
    assert [(item.runtime_username, item.enabled) for item in (await adapter.discover()).items] == [("alice", True)]
    await adapter.delete(ref)
    assert (await adapter.discover()).items == ()
    await adapter.delete(ref)  # the manager's delete is idempotent: a client already gone is a 204 too


async def test_preflight_refuses_a_taken_name_and_a_node_without_a_hostname():
    manager, adapter = _adapter()
    assert (await adapter.preflight(_intent())).ok
    await adapter.create("op-1", _intent(), CredentialPlan("caller", new_credential("trusttunnel")))
    taken = await adapter.preflight(_intent())
    assert taken.ok is False and "already" in taken.reason
    bare = MemoryTrusttunnel(hostname="")
    refused = await TrusttunnelAdapter(bare).preflight(_intent())
    assert refused.ok is False and "hostname" in refused.reason
    with pytest.raises(AdapterError):
        await TrusttunnelAdapter(bare).create("op-1", _intent(), CredentialPlan("caller", b"password-1234"))
    assert bare.client_table == {}


async def test_a_lost_reply_is_replayed_without_a_second_client():
    manager, adapter = _adapter()
    manager.faults["create"] = "lose_response"
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", new_credential("trusttunnel")))
    assert applied.recovered is True and list(manager.client_table) == ["alice"]
    manager.faults["rotate"] = "lose_response"
    rotated = await adapter.rotate("op-2", GrantRef("trusttunnel", "alice"), CredentialPlan("caller", b"new-password-1"))
    assert rotated.recovered is True and manager.client_table["alice"]["revision"] == 2


async def test_the_manager_being_down_is_an_adapter_error_not_a_crash():
    manager, adapter = _adapter()
    manager.broken = True
    with pytest.raises(AdapterError):
        await adapter.discover()
    with pytest.raises(AdapterError):
        await adapter.create("op-1", _intent(), CredentialPlan("caller", new_credential("trusttunnel")))
    with pytest.raises(AdapterError):
        await adapter.disable(GrantRef("trusttunnel", "alice"))


async def test_a_manager_credential_is_refused():
    manager, adapter = _adapter()
    with pytest.raises(AdapterError, match="caller-supplied"):
        await adapter.create("op-1", _intent(), CredentialPlan("manager", None))


# ---- artifacts ----------------------------------------------------------------------------------------

async def test_the_link_and_the_config_are_built_from_escrow_alone():
    der = _certificate()
    manager, adapter = _adapter(MemoryTrusttunnel(certificate_der_b64=base64.b64encode(der).decode()))
    credential = new_credential("trusttunnel")
    applied = await adapter.create("op-1", _intent("carol"), CredentialPlan("caller", credential))
    grant = _grant(applied, "carol", name='Carol "phone"')
    link, config, manual = adapter.render_artifacts(grant, credential, public_host="fallback.example.com")
    assert (link.kind, link.media_type) == ("trusttunnel_link", "text/uri-list")
    assert (config.kind, config.media_type) == ("trusttunnel_toml", "application/toml")
    assert (manual.kind, manual.media_type) == ("trusttunnel_manual", "application/json")
    fields = json.loads(manual.value)
    assert fields == {
        "server": "gate.example.com", "port": 443, "username": "carol", "password": credential.decode(),
        "sni": "gate.example.com", "protocol": "HTTP/2", "quic": False,
        "certificate_pem": tomllib.loads(config.value)["endpoint"]["certificate"],
        "surge": f"trust-tunnel, gate.example.com, 443, username=carol, password={credential.decode()}",
    }

    decoded = decode_deeplink(link.value)
    assert decoded["hostname"] == "gate.example.com" and decoded["addresses"] == ["gate.example.com:443"]
    assert decoded["username"] == "carol" and decoded["password"] == credential.decode()
    assert decoded["certificate"] == der and decoded["name"] == 'Carol "phone"' and decoded["upstream_protocol"] == 1

    toml = tomllib.loads(config.value)
    endpoint = toml["endpoint"]
    assert endpoint["hostname"] == "gate.example.com" and endpoint["addresses"] == ["gate.example.com:443"]
    assert endpoint["username"] == "carol" and endpoint["password"] == credential.decode()
    assert endpoint["upstream_protocol"] == "http2" and endpoint["skip_verification"] is False
    assert endpoint["name"] == 'Carol "phone"'
    assert endpoint["certificate"].startswith("-----BEGIN CERTIFICATE-----\n")
    pem_body = "".join(endpoint["certificate"].splitlines()[1:-1])
    assert base64.b64decode(pem_body) == der
    assert toml["listener"]["tun"]["included_routes"] == ["0.0.0.0/0", "2000::/3"]
    assert toml["vpn_mode"] == "general"


async def test_no_certificate_and_no_name_leave_those_keys_out():
    manager, adapter = _adapter()
    credential = new_credential("trusttunnel")
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", credential))
    link, config, manual = adapter.render_artifacts(_grant(applied), credential, public_host="")
    assert json.loads(manual.value)["certificate_pem"] is None
    decoded = decode_deeplink(link.value)
    assert "certificate" not in decoded and "name" not in decoded
    endpoint = tomllib.loads(config.value)["endpoint"]
    assert "certificate" not in endpoint and "name" not in endpoint


def test_toml_values_are_escaped_and_a_chain_is_split():
    grant = AccessGrant(
        id="g", client_id="c", protocol="trusttunnel", node_id="local", runtime_username="u",
        desired_state="enabled", origin="provisioned", created_at=1, updated_at=1,
        options=TrusttunnelOptions(hostname="h.example", port=8443, name="a\\b\"c\td"))
    parsed = tomllib.loads(render_toml(grant, b"pa\"ss\\word", public_host=""))
    assert parsed["endpoint"]["password"] == 'pa"ss\\word' and parsed["endpoint"]["name"] == "a\\b\"c\td"
    assert parsed["endpoint"]["addresses"] == ["h.example:8443"]
    chain = _certificate() + _certificate("two")
    assert len(split_der(chain)) == 2 and b"".join(split_der(chain)) == chain
    assert certificate_pem(base64.b64encode(chain).decode()).count("BEGIN CERTIFICATE") == 2
    for bad in (b"\x00\x01", b"\x30\x05\x01"):
        with pytest.raises(AdapterError):
            split_der(bad)


def test_an_access_that_has_not_learned_its_endpoint_cannot_render():
    unlearned = AccessGrant(
        id="g1", client_id="c1", protocol="trusttunnel", node_id="local", runtime_username="x",
        desired_state="enabled", options=TrusttunnelOptions(), origin="provisioned", created_at=1, updated_at=1)
    adapter = TrusttunnelAdapter(MemoryTrusttunnel())
    with pytest.raises(AdapterError, match="not learned"):
        adapter.render_artifacts(unlearned, b"password-1234", public_host="")
    # a host from the settings stands in for a hostname the access did not record
    link, *_ = adapter.render_artifacts(unlearned, b"password-1234", public_host="gate.example.com")
    assert decode_deeplink(link.value)["hostname"] == "gate.example.com"


# ---- egress (the manager's own document) -------------------------------------------------------------

async def test_egress_follows_the_naive_pattern_against_the_manager():
    manager, adapter = _adapter()
    target = await adapter.egress_target()
    assert target.protocol == "trusttunnel" and target.backend == "trusttunnel_native"
    assert target.mode == "direct" and target.applied["document"] == {"mode": "direct"}
    document = {"mode": "socks5", "address": "127.0.0.1:41001"}
    plan = await adapter.plan_egress(document, expected_revision=target.revision)
    assert plan["diff"] and plan["revision"] == target.revision and plan["target_revision"] != target.revision
    assert (await adapter.plan_egress({"mode": "direct"}, expected_revision=target.revision))["diff"] == []
    applied = await adapter.apply_egress(document, expected_revision=target.revision, operation_id="e1")
    assert applied.digest and applied.revision != target.revision and manager.egress_document["address"] == "127.0.0.1:41001"
    proxied = await adapter.egress_target()
    assert proxied.mode == "proxy" and proxied.revision == applied.revision
    assert proxied.applied["document"] == document
    # an apply of the document the manager already runs changes nothing
    again = await adapter.apply_egress(document, expected_revision=applied.revision, operation_id="e1")
    assert again.revision == applied.revision
    rolled = await adapter.rollback_egress(expected_revision=applied.revision)
    assert rolled.revision == target.revision
    assert (await adapter.egress_target()).mode == "direct"


async def test_egress_refusals_carry_the_bounded_codes():
    manager, adapter = _adapter()
    target = await adapter.egress_target()
    for bad in ({"mode": "socks5", "address": "evil.example:1"}, {"mode": "socks5", "address": "127.0.0.1:80"},
                {"mode": "direct", "address": "127.0.0.1:2000"}, {"mode": "http"}):
        with pytest.raises(AdapterError) as invalid:
            await adapter.apply_egress(bad, expected_revision=target.revision, operation_id="e1")
        assert invalid.value.code == "egress_invalid"
    with pytest.raises(AdapterError) as stale:
        await adapter.apply_egress({"mode": "direct"}, expected_revision="old", operation_id="e2")
    assert stale.value.code == "egress_conflict"
    with pytest.raises(AdapterError) as none:
        await adapter.rollback_egress(expected_revision=target.revision)
    assert none.value.code == "egress_no_previous"
    manager.egress_fail_next = "egress_readback_mismatch"
    with pytest.raises(AdapterError) as failed:
        await adapter.apply_egress({"mode": "socks5", "address": "127.0.0.1:41001"},
                                   expected_revision=target.revision, operation_id="e3")
    assert failed.value.code == "egress_readback_mismatch" and manager.egress_document["mode"] == "direct"
    manager.broken = True
    with pytest.raises(AdapterError) as down:
        await adapter.egress_target()
    assert down.value.code == "manager_unavailable"


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

async def test_the_real_client_speaks_the_manager_contract():
    import httpx

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.headers.get("x-trusttunnel-token")))
        if request.url.path == "/v1/clients/ghost/enable":
            return httpx.Response(404, json={"detail": "no", "code": "not_found"})
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.url.path == "/v1/clients" and request.method == "POST":
            return httpx.Response(409, json={"detail": "x", "code": "exists"})
        return httpx.Response(200, json={"clients": []})

    client = TrusttunnelClient("/unused", "tok", transport=httpx.MockTransport(handler))
    assert await client.clients() == []
    await client.egress_apply({"mode": "direct"})
    await client.egress_rollback()
    assert ("POST", "/v1/egress/apply", "tok") in calls and ("POST", "/v1/egress/rollback", "tok") in calls
    await client.delete_client("alice")
    with pytest.raises(TrusttunnelError) as missing:
        await client.client_state("ghost", "enable")
    assert missing.value.status_code == 404 and missing.value.code == "not_found"
    with pytest.raises(TrusttunnelError) as exists:
        await client.create_client({"operation_id": "o", "username": "a", "password": "p"})
    assert exists.value.status_code == 409 and exists.value.code == "exists"
    assert all(token == "tok" for _m, _p, token in calls)
    assert ("DELETE", "/v1/clients/alice", "tok") in calls


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


async def test_an_access_is_issued_shown_rotated_switched_off_and_deleted(api, tt):
    client_id = await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt",
                                    "options": {"name": "Alice phone"}}])
    [grant] = (await api.get(f"/api/clients/{client_id}")).json()["grants"]
    assert grant["observed_state"] == "enabled"
    assert grant["options"]["hostname"] == "gate.example.com" and grant["options"]["port"] == 443
    assert grant["options"]["name"] == "Alice phone"

    artifacts = await _artifacts_of(api, client_id, grant["id"])
    link, config = decode_deeplink(artifacts["trusttunnel_link"]["value"]), artifacts["trusttunnel_toml"]
    assert artifacts["trusttunnel_link"]["qr"].startswith("data:image/svg+xml;base64,")
    assert config["media_type"] == "application/toml" and "qr" in config and config["qr"] is None
    manual = artifacts["trusttunnel_manual"]  # typed by hand, never scanned: no QR
    assert manual["media_type"] == "application/json" and manual["qr"] is None
    assert json.loads(manual["value"])["username"] == "alice-tt" and json.loads(manual["value"])["quic"] is False
    password = link["password"]
    assert link["username"] == "alice-tt" and link["name"] == "Alice phone" and tt.authenticates("alice-tt", password)
    assert tomllib.loads(config["value"])["endpoint"]["password"] == password

    assert (await api.post(f"/api/clients/grants/{grant['id']}/disable", headers=_headers(api))).status_code == 200
    assert not tt.authenticates("alice-tt", password)
    assert (await api.post(f"/api/clients/grants/{grant['id']}/enable", headers=_headers(api))).status_code == 200
    assert tt.authenticates("alice-tt", password)
    assert (await api.post(f"/api/clients/grants/{grant['id']}/rotate", headers=_headers(api))).status_code == 200
    again = decode_deeplink((await _artifacts_of(api, client_id, grant["id"]))["trusttunnel_link"]["value"])
    assert again["password"] != password and tt.authenticates("alice-tt", again["password"])
    assert not tt.authenticates("alice-tt", password)
    assert (await api.post(f"/api/clients/grants/{grant['id']}/delete", headers=_headers(api))).status_code == 200
    assert tt.client_table == {}


async def test_a_taken_account_name_is_refused_before_anything_is_written(api, tt):
    await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {}}])
    created = await api.post("/api/clients", json={"display_name": "Bob"}, headers=_headers(api))
    refused = await api.post(f"/api/clients/{created.json()['id']}/grants", headers=_headers(api), json={
        "grants": [{"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {}}]})
    assert refused.status_code in (409, 422) and "already" in refused.text
    assert list(tt.client_table) == ["alice-tt"]


async def test_options_the_node_teaches_cannot_be_forged_into_a_foreign_shape(api):
    created = await api.post("/api/clients", json={"display_name": "Eve"}, headers=_headers(api))
    refused = await api.post(f"/api/clients/{created.json()['id']}/grants", headers=_headers(api), json={
        "grants": [{"protocol": "trusttunnel", "runtime_username": "eve-tt", "options": {"version": "2.0"}}]})
    assert refused.status_code == 422


async def test_the_node_reports_the_daemon_and_the_dashboard_counts_clients(api, tt):
    await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {}}])
    # measured on a real endpoint (2026-10-18): rx = what the client uploaded, tx = what it downloaded
    tt.client_table["alice-tt"].update(rx=500, tx=2000, sessions=1)
    local = (await api.get("/api/nodes/local")).json()
    assert local["services"]["trusttunnel"] == "ok"
    me = (await api.get("/api/auth/me")).json()
    assert me["features"]["trusttunnel"] is True
    dashboard = (await api.get("/api/dashboard")).json()["protocols"]["trusttunnel"]
    assert dashboard["ready"] is True and dashboard["credentials"] == {"active": 1, "disabled": 0, "total": 1}
    assert dashboard["traffic"] == {"available": True, "upload_bytes": 500, "download_bytes": 2000}


async def test_the_protocol_filter_and_the_search_know_trusttunnel(api):
    client_id = await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {}}])
    listed = (await api.get("/api/clients?protocol=trusttunnel")).json()
    assert [item["client"]["id"] for item in listed["items"]] == [client_id]
    found = (await api.get("/api/clients?q=trusttunnel")).json()
    assert [item["client"]["id"] for item in found["items"]] == [client_id]


# ---- the screen's backend ---------------------------------------------------------------------------------

async def test_the_overview_joins_the_manager_with_the_clients_that_hold_the_accesses(api, tt):
    client_id = await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt",
                                    "options": {"name": "Alice phone"}}])
    # an account on the node the panel knows nothing about (made by hand on the manager)
    await tt.create_client({"operation_id": "x", "username": "stranger", "password": "stranger-password"})
    tt.client_table["alice-tt"].update(rx=500, tx=2000, sessions=2)
    data = (await api.get("/api/trusttunnel/overview")).json()
    assert data["status"] == "ok" and data["public_host"] == "gate.example.com"
    assert data["endpoint"] == {"hostname": "gate.example.com", "port": 443, "version": "1.1.0", "running": True,
                                "certificate_trusted": True, "fingerprint": data["endpoint"]["fingerprint"]}
    by_name = {row["username"]: row for row in data["clients"]}
    alice = by_name["alice-tt"]
    assert alice["client_name"] == "Alice" and alice["client_id"] == client_id and alice["grant_id"]
    assert (alice["download_bytes"], alice["upload_bytes"], alice["sessions"], alice["name"]) == (2000, 500, 2, "Alice phone")
    assert by_name["stranger"]["client_id"] is None and by_name["stranger"]["grant_id"] is None
    assert data["totals"] == {"clients": 2, "active": 2, "sessions": 2, "upload_bytes": 500, "download_bytes": 2000}
    assert data["pending"] == []
    # nothing secret leaves: no password, no link
    text = json.dumps(data)
    assert "password" not in text.lower() and "tt://" not in text and tt.client_table["alice-tt"]["password"] not in text


async def test_the_overview_lists_accesses_the_manager_lost_as_pending(api, tt):
    await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {}}])
    tt.client_table.clear()
    data = (await api.get("/api/trusttunnel/overview")).json()
    assert data["clients"] == [] and [item["username"] for item in data["pending"]] == ["alice-tt"]


async def test_the_overview_says_so_when_the_manager_is_down_or_the_feature_is_off(api, tt, tmp_path):
    await _issue(api, [{"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {}}])
    tt.broken = True
    down = (await api.get("/api/trusttunnel/overview")).json()
    assert down["status"] == "down" and down["clients"] == [] and [p["username"] for p in down["pending"]] == ["alice-tt"]

    master_key = tmp_path / "off-key"
    Keyring.generate().save(master_key)
    app = panel_app(Settings(database_path=tmp_path / "off.sqlite3", master_key_file=master_key,
                              session_cookie_secure=False, allowed_hosts=("testserver",), vnext_writer="domain"),
                     telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(), amneziawg=MemoryAmneziawg(),
                     trusttunnel=MemoryTrusttunnel(), version_client=VersionClient(str(tmp_path / "none.sock")))
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as off:
        page = await off.get("/login")
        await off.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"},
                       headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
        assert (await off.get("/api/trusttunnel/overview")).status_code == 404
        assert (await off.get("/api/auth/me")).json()["features"]["trusttunnel"] is False
        assert (await off.get("/api/dashboard")).json()["protocols"]["trusttunnel"] == {"available": False, "status": "disabled"}


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


async def test_a_linked_node_applies_the_access_and_the_central_learns_its_details(tmp_path):
    node, central, node_id = await _linked_tt(tmp_path)
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="trusttunnel", node_id=node_id, runtime_username="alice-tt",
                         options=TrusttunnelOptions(name="Alice"))
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    # the central has no TrustTunnel manager of its own and never called one
    await central.tick("pusher")
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert list(node.trusttunnel.client_table) == ["alice-tt"]
    [grant] = central.state.clients.client_with_grants(client.id)[1]
    assert grant.observed_state == "enabled" and grant.options.hostname == "gate.node.example"
    assert grant.options.port == 443 and grant.options.name == "Alice"
    with central.state.database.connect() as db:
        credential = central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential",
                                                  grant_id=grant.id, permitted_node_id=node_id)
    assert node.trusttunnel.authenticates("alice-tt", credential.decode())
    from panel.fleet_v2.central_routes import public_hosts_for

    host = public_hosts_for(central.state, node_id)["trusttunnel"]
    assert host == "gate.node.example"
    link, *_rest = central.state.adapters["trusttunnel"].render_artifacts(grant, credential, public_host=host)
    assert decode_deeplink(link.value)["addresses"] == ["gate.node.example:443"]


async def test_a_node_without_trusttunnel_is_refused_before_anything_is_written(tmp_path):
    from panel.clients.store import ClientConflict

    node, central, node_id = await _linked_tt(tmp_path, node_enabled=False)
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="trusttunnel", node_id=node_id, runtime_username="alice-tt",
                         options=TrusttunnelOptions())
    with pytest.raises(ClientConflict, match="not enabled"):
        await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert db.execute("SELECT count(*) FROM access_grants").fetchone()[0] == 0


async def test_an_older_node_never_receives_the_resource(tmp_path):
    from panel.clients.store import ClientConflict

    node, central, node_id = await _linked_tt(tmp_path)
    with central.state.database.connect() as db:
        identity = json.loads(db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0])
    identity["capabilities"] = [c for c in identity["capabilities"] if c != "protocol.trusttunnel.v1"]
    with central.state.database.transaction() as db:
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps(identity), node_id))
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="trusttunnel", node_id=node_id, runtime_username="alice-tt",
                         options=TrusttunnelOptions())
    with pytest.raises(ClientConflict, match="without TrustTunnel"):
        await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")


async def test_the_generation_skips_a_node_without_the_capability(tmp_path):
    """A grant that already exists never reaches a node that lost the capability (an older panel)."""
    from panel.fleet_v2.generations import compile as compile_generation

    node, central, node_id = await _linked_tt(tmp_path)
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="trusttunnel", node_id=node_id, runtime_username="alice-tt",
                         options=TrusttunnelOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")

    def resources():
        with central.state.database.connect() as db:
            document = compile_generation(db, central.state.clients.store, node_id=node_id,
                                          node_guid="g", master_guid="m", previous=0, generation=1,
                                          now=1, created_by="owner")
        return [item.runtime_username for item in document.resources]

    assert resources() == ["alice-tt"]
    with central.state.database.connect() as db:
        identity = json.loads(db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0])
    identity["capabilities"] = [c for c in identity["capabilities"] if c != "protocol.trusttunnel.v1"]
    with central.state.database.transaction() as db:
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps(identity), node_id))
    assert resources() == []


async def test_the_node_declares_the_capability_and_its_endpoint_host(tmp_path):
    node, central, node_id = await _linked_tt(tmp_path)
    with central.state.database.connect() as db:
        identity = json.loads(db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0])
    assert "protocol.trusttunnel.v1" in identity["capabilities"]
    entry = identity["protocols"]["trusttunnel"]
    assert entry["enabled"] is True and entry["daemon"] == "ok" and entry["public_host"] == "gate.node.example"
    assert entry["public_port"] == 443


async def test_the_node_inventory_and_traffic_know_trusttunnel(tmp_path):
    node, central, node_id = await _linked_tt(tmp_path)
    await node.trusttunnel.create_client({"operation_id": "x", "username": "local-one", "password": "pw-local-1"})
    node.trusttunnel.client_table["local-one"].update(rx=100, tx=900)
    key = node.state.api_keys.create("probe", "node-sync", None, actor=ACTOR, ip="x")[1]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=node), base_url="http://testserver",
                                 headers={"Authorization": f"Bearer {key}"}) as client:
        inventory = (await client.get("/api/fleet/v2/inventory")).json()["protocols"]["trusttunnel"]
        assert [(row["runtime_username"], row["ownership"]) for row in inventory] == [("local-one", "local")]
        status = (await client.get("/api/fleet/v2/status")).json()["protocols"]["trusttunnel"]
        assert status["traffic"] == {"upload_bytes": 100, "download_bytes": 900, "total_bytes": 1000}


def test_the_manager_token_is_read_from_the_staged_file(tmp_path, monkeypatch):
    token = tmp_path / "trusttunnel-manager-token"
    token.write_text("staged-token-0123456789\n")
    monkeypatch.setenv("TRUSTTUNNEL_MANAGER_TOKEN_FILE", str(token))
    monkeypatch.setenv("TRUSTTUNNEL_MANAGER_SOCKET", "/run/x/manager.sock")
    settings = Settings()
    assert settings.trusttunnel_token == "staged-token-0123456789"
    assert settings.trusttunnel_enabled is False
