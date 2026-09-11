"""Renderers are pure functions over a manifest and its artifacts.

Three things are checked here beyond "each format parses". A renderer never emits a
link a target client cannot parse — MTProxy is `unsupported` in sing-box and Clash, naive
is `unsupported` in Clash — and says so with a reason instead of staying silent. A grant
without a stored credential, or one that is not effective right now, never turns into a
link in any format. And the plaintext credential exists only inside the render call: it
is not in the database, not in logs, and not in the text of an error.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from pathlib import Path

import pytest

from panel.clients.models import AccessGrant, Client, MieruOptions, MtproxyOptions, NaiveOptions
from panel.clients.service import CREDENTIAL_PURPOSE
from panel.clients.store import ClientStore
from panel.database import Database
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.secrets_store import SecretStore
from panel.subscriptions.compatibility import MATRIX, NOTES
from panel.subscriptions.models import Manifest, ManifestGrant
from panel.subscriptions.renderers import (
    MEDIA_TYPE_MANIFEST,
    RENDERERS,
    RenderError,
    resolve_artifacts,
)
from panel.subscriptions.renderers import clash as clash_module
from panel.telemt import MemoryTelemt

ROOT = Path(__file__).resolve().parents[2]
HOSTS = {"mtproxy": "proxy.example.com", "naive": "naive.example.com", "mieru": "mieru.example.com"}
NOW = 1_800_000_000
MIERU_TEMPLATE = "mierus://{username}:{password}@mieru.example.com?profile={profile}&port=8443&protocol=TCP"
MIERU_RANGE_TEMPLATE = "mierus://{username}:{password}@mieru.example.com?profile={profile}&port=8000-8010&protocol=TCP"


@pytest.fixture
def database(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        ClientStore.insert_client(
            db,
            Client(id="c1", display_name="Sergey <b>&</b>", state="active", metadata={},
                   created_at=NOW, updated_at=NOW),
        )
    return database


@pytest.fixture
def secrets():
    return SecretStore(Keyring.generate())


@pytest.fixture
def adapters():
    return {
        "mtproxy": TelemtAdapter(
            MemoryTelemt(public_host="proxy.example.com", public_port=443), public_host="proxy.example.com"
        ),
        "naive": NaiveAdapter(MemoryNaive(), public_host="naive.example.com"),
        "mieru": MieruAdapter(MemoryMieru(), public_host="mieru.example.com"),
    }


def _seed(database, secrets, protocol, username, *, password=None, enabled=True, template=None):
    """One grant row, escrowed when `password` is given — the shape provisioning leaves behind."""
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(),
        "mieru": MieruOptions(quotas=[], share_template=template),
    }[protocol]
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id="c1", protocol=protocol, node_id="local",
        endpoint_id="default", runtime_username=username,
        desired_state="enabled" if enabled else "disabled", observed_state="enabled",
        options=options, origin="provisioned" if password else "imported",
        created_at=NOW, updated_at=NOW,
    )
    version = 0
    store = ClientStore(database)
    with database.transaction() as db:
        store.insert_grant(db, grant)
        if password is not None:
            reference = secrets.store(
                db, secret_id=f"grant:{grant.id}", version=1, purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id, permitted_node_id="local", plaintext=password, state="active",
            )
            store.update_grant(
                db, grant.id, secret_id=reference.secret_id, secret_version=reference.version,
            )
            version = reference.version
    return ManifestGrant(
        grant_id=grant.id, protocol=protocol, node_id="local", endpoint_id="default",
        runtime_username=username, secret_version=version, options=options.model_dump(),
        enabled=enabled,
    )


@pytest.fixture
def manifest(database, secrets):
    grants = [
        _seed(database, secrets, "mtproxy", "alice", password=b"ee00112233445566778899aabbccddeeff"),
        _seed(database, secrets, "naive", "bob", password=b"naive-pass-01"),
        _seed(database, secrets, "mieru", "carol", password=b"mieru-pass-01", template=MIERU_TEMPLATE),
        # Imported from a running mita: no credential, so nothing can be rendered.
        _seed(database, secrets, "mieru", "dave"),
        # Suspended right now: has a credential, must still produce no link.
        _seed(database, secrets, "naive", "erin", password=b"naive-pass-02", enabled=False),
        # A port range: fine for Clash, not for the sing-box outbound shape we ship.
        _seed(database, secrets, "mieru", "frank", password=b"mieru-pass-03", template=MIERU_RANGE_TEMPLATE),
    ]
    return Manifest(client_id="c1", client_name="Sergey <b>&</b>", generation=3, grants=grants)


@pytest.fixture
def artifacts(manifest, secrets, adapters, database):
    with database.connect() as db:
        return resolve_artifacts(manifest, secrets, adapters, db, public_hosts=HOSTS)


@pytest.fixture
def manifest_with_canary(database, secrets):
    grant = _seed(database, secrets, "naive", "zed", password=b"CANARY-PASSWORD")
    return Manifest(client_id="c1", client_name="Sergey", generation=1, grants=[grant])


def _database_bytes(database) -> bytes:
    # The WAL holds the newest pages; reading only the main file checks nothing.
    payload = database.path.read_bytes()
    wal = database.path.with_name(database.path.name + "-wal")
    return payload + (wal.read_bytes() if wal.exists() else b"")


# --- every format --------------------------------------------------------------------


def test_the_renderer_set_is_the_one_the_owner_decided():
    assert set(RENDERERS) == {"manifest", "singbox", "clash", "raw", "html"}
    assert RENDERERS["manifest"].media_type == MEDIA_TYPE_MANIFEST
    assert all(renderer.name == name and renderer.version >= 1 for name, renderer in RENDERERS.items())


@pytest.mark.parametrize("name", ["manifest", "singbox", "clash", "raw", "html"])
def test_every_renderer_emits_its_media_type_and_no_malformed_links(name, manifest, artifacts):
    renderer = RENDERERS[name]
    body = renderer.render(manifest, artifacts)
    assert renderer.media_type and body
    if name == "raw":
        lines = body.decode().splitlines()
        assert any(line.startswith("tg://proxy?server=proxy.example.com&port=443&secret=ee") for line in lines)
        assert any(line.startswith("naive+https://bob:naive-pass-01@naive.example.com:443") for line in lines)
        assert any(line.startswith("mierus://carol:mieru-pass-01@mieru.example.com?") for line in lines)
        assert "# unsupported mieru dave: no stored credential" in lines
        assert all(line.startswith(("tg://", "naive+https://", "mierus://", "# ")) for line in lines)
    if name == "singbox":
        data = json.loads(body)
        assert {o["type"] for o in data["outbounds"]} <= {"naive", "mieru"}
        assert data["proxy_control"]["generation"] == 3
        assert {(item["protocol"], item["runtime_username"]) for item in data["proxy_control"]["unsupported"]} == {
            ("mtproxy", "alice"), ("mieru", "dave"), ("mieru", "frank"),
        }
    if name == "clash":
        text = body.decode()
        assert "type: 'mieru'" in text and "udp: true" in text
        assert "naive" not in text.split("proxy-control:")[0]  # naive is only ever in unsupported
        assert "\t" not in text and "\r" not in text
    if name == "html":
        text = body.decode()
        assert '<meta name="robots" content="noindex">' in text
        assert "<script" not in text.lower()


# --- what never becomes a link --------------------------------------------------------


def test_disabled_and_credential_less_grants_never_become_links(manifest, artifacts):
    for name, renderer in RENDERERS.items():
        text = renderer.render(manifest, artifacts).decode()
        assert "naive-pass-02" not in text, name  # erin's credential is revealed nowhere
        if name == "raw":
            assert "# disabled naive erin" in text.splitlines()
        if name == "singbox":
            data = json.loads(text)
            assert "erin" not in {o["username"] for o in data["outbounds"]}
            assert "dave" not in {o["username"] for o in data["outbounds"]}
        if name == "clash":
            proxies = text.split("proxy-control:")[0]
            assert "erin" not in proxies and "dave" not in proxies


def test_resolve_artifacts_reveals_only_what_will_be_rendered(manifest, artifacts):
    by_user = {grant.runtime_username: grant.grant_id for grant in manifest.grants}
    assert set(artifacts) == {by_user["alice"], by_user["bob"], by_user["carol"], by_user["frank"]}
    assert artifacts[by_user["bob"]][0].value == "https://bob:naive-pass-01@naive.example.com"


# --- sing-box and clash shapes --------------------------------------------------------


def test_singbox_outbounds_match_the_shapes_the_reveal_already_ships(manifest, artifacts):
    data = json.loads(RENDERERS["singbox"].render(manifest, artifacts))
    by_type = {o["type"]: o for o in data["outbounds"]}
    assert by_type["naive"] == {
        "type": "naive", "tag": "naive-bob", "server": "naive.example.com", "server_port": 443,
        "username": "bob", "password": "naive-pass-01",
        "tls": {"enabled": True, "server_name": "naive.example.com"},
    }
    assert by_type["mieru"] == {
        "type": "mieru", "tag": "mieru-carol-TCP-8443", "server": "mieru.example.com",
        "server_port": 8443, "transport": "TCP", "username": "carol", "password": "mieru-pass-01",
    }
    reasons = {item["runtime_username"]: item["reason"] for item in data["proxy_control"]["unsupported"]}
    assert reasons["alice"] == NOTES["mtproxy"]["karing"] and data["proxy_control"]["client"] == "karing"
    assert "range" in reasons["frank"]


def test_the_official_singbox_variant_carries_naive_only(manifest, artifacts):
    """An official sing-box refuses a config with an outbound type it does not know."""
    data = json.loads(RENDERERS["singbox"].render(manifest, artifacts, client="singbox"))
    assert [o["type"] for o in data["outbounds"]] == ["naive"]
    assert data["proxy_control"]["client"] == "singbox"
    reasons = {item["runtime_username"]: item["reason"] for item in data["proxy_control"]["unsupported"]}
    assert reasons["carol"] == reasons["frank"] == NOTES["mieru"]["singbox"]
    assert reasons["alice"] == NOTES["mtproxy"]["singbox"] and reasons["dave"] == "no stored credential"
    assert "mieru-pass" not in json.dumps(data)
    with pytest.raises(RenderError):
        RENDERERS["singbox"].render(manifest, artifacts, client="mihomo")


def test_clash_lists_mieru_only_and_writes_nothing_but_quoted_scalars(manifest, artifacts):
    text = RENDERERS["clash"].render(manifest, artifacts).decode()
    proxies, tail = text.split("proxy-control:")
    assert "  - name: 'mieru-carol-TCP-8443'\n    type: 'mieru'\n    server: 'mieru.example.com'\n    port: 8443\n" in proxies
    assert "port-range: '8000-8010'" in proxies
    assert "username: 'carol'\n    password: 'mieru-pass-01'" in proxies
    assert "udp: true" in proxies and "proxy-groups:" in proxies
    assert NOTES["naive"]["mihomo"] in tail and NOTES["mtproxy"]["mihomo"] in tail
    # Every string scalar is single-quoted; the writer knows no other form.
    for line in text.splitlines():
        value = line.split(": ", 1)[1] if ": " in line else ""
        if value and not value.isdigit() and value not in {"true", "false"}:
            assert value.startswith("'") and value.endswith("'"), line


@pytest.mark.parametrize("value", ["line\nbreak", "quote'inside", "tab\there", "\x1b[31m", "\u2028"])
def test_the_yaml_writer_refuses_values_it_cannot_prove_safe(value):
    with pytest.raises(RenderError):
        clash_module.scalar(value)


def test_the_yaml_writer_quotes_the_ordinary_and_doubles_nothing():
    assert clash_module.scalar("mieru-carol-TCP-8443") == "'mieru-carol-TCP-8443'"
    assert clash_module.scalar("MetaCubeX/mihomo#273: open") == "'MetaCubeX/mihomo#273: open'"
    assert clash_module.scalar(8443) == "8443"
    assert clash_module.scalar(True) == "true"


# --- manifest and html ----------------------------------------------------------------


def test_manifest_json_carries_grants_artifacts_and_compatibility(manifest, artifacts):
    data = json.loads(RENDERERS["manifest"].render(manifest, artifacts))
    assert data["version"] == 1 and data["generation"] == 3 and data["client_name"] == "Sergey <b>&</b>"
    assert data["compatibility"] == MATRIX
    grants = {item["runtime_username"]: item for item in data["grants"]}
    assert grants["bob"]["artifacts"][0]["value"] == "https://bob:naive-pass-01@naive.example.com"
    assert grants["bob"]["artifacts"][0]["auto_refresh"] == "supported"
    assert grants["dave"]["artifacts"] == [] and grants["dave"]["unsupported"] == "no stored credential"
    assert grants["erin"]["enabled"] is False and grants["erin"]["artifacts"] == []
    assert "secret_version" in grants["alice"] and "secret_ref" not in json.dumps(data)


def test_html_escapes_every_value_and_carries_qr_codes(manifest, artifacts):
    text = RENDERERS["html"].render(manifest, artifacts).decode()
    assert "Sergey &lt;b&gt;&amp;&lt;/b&gt;" in text and "<b>&</b>" not in text
    assert text.count("data:image/svg+xml;base64,") == 4  # alice, bob, carol, frank
    assert "tg://proxy?server=proxy.example.com&amp;port=443&amp;secret=ee" in text
    assert "no stored credential" in text and "dave" in text
    assert "naive-pass-02" not in text
    assert "unsupported" in text and "supported" in text  # the compatibility matrix is on the page


# --- secrets and bounds ---------------------------------------------------------------


def test_rendering_leaves_no_secret_in_database_logs_or_errors(
    database, manifest_with_canary, secrets, adapters, caplog
):
    with database.connect() as db:
        artifacts = resolve_artifacts(manifest_with_canary, secrets, adapters, db, public_hosts=HOSTS)
    body = RENDERERS["raw"].render(manifest_with_canary, artifacts)
    assert b"CANARY-PASSWORD" in body  # the render itself is the only place it may appear
    assert b"CANARY-PASSWORD" not in _database_bytes(database)
    assert "CANARY-PASSWORD" not in caplog.text
    broken = dataclasses.replace(manifest_with_canary, grants=manifest_with_canary.grants * 65)
    for renderer in RENDERERS.values():
        with pytest.raises(RenderError) as exc:
            renderer.render(broken, artifacts)
        assert "too many grants" in str(exc.value) and "CANARY-PASSWORD" not in str(exc.value)


def test_a_body_over_the_size_limit_is_refused_not_truncated(manifest, artifacts, monkeypatch):
    from panel.subscriptions.renderers import base

    monkeypatch.setattr(base, "MAX_BYTES", 64)
    for renderer in RENDERERS.values():
        with pytest.raises(RenderError, match="too large"):
            renderer.render(manifest, artifacts)


# --- compatibility matrix -------------------------------------------------------------


def test_compatibility_matrix_follows_the_fixture_and_never_claims_telegram_auto_refresh():
    assert set(MATRIX) == {"mtproxy", "naive", "mieru"}
    assert all(
        value in {"supported", "unsupported", "unproven"} for row in MATRIX.values() for value in row.values()
    )
    assert MATRIX["mtproxy"]["telegram"] == "unsupported"
    assert MATRIX["naive"]["karing"] == MATRIX["mieru"]["karing"] == "supported"
    assert MATRIX["naive"]["singbox"] == "supported" and MATRIX["mieru"]["singbox"] == "unsupported"
    assert MATRIX["mieru"]["mihomo"] == "supported" and MATRIX["naive"]["mihomo"] == "unsupported"
    fixture = json.loads((ROOT / "tests/fixtures/vnext-capabilities.json").read_text())["clients"]
    # The fixture from Task 3 is the only source; the module is a copy because the
    # panel image does not ship tests/fixtures.
    assert {
        protocol: {client: cells[protocol]["status"] for client, cells in fixture.items()}
        for protocol in MATRIX
    } == MATRIX
    assert {
        protocol: {client: cells[protocol]["note"] for client, cells in fixture.items()}
        for protocol in NOTES
    } == NOTES
