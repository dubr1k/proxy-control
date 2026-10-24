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
import re
import uuid
from pathlib import Path

import pytest

from panel.clients.models import (
    AccessGrant,
    Client,
    MieruOptions,
    MtproxyOptions,
    NaiveOptions,
    TrusttunnelOptions,
)
from panel.clients.service import CREDENTIAL_PURPOSE
from panel.clients.store import ClientStore
from panel.database import Database
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter, TrusttunnelAdapter
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
from panel.trusttunnel import MemoryTrusttunnel
from panel.trusttunnel_link import decode_deeplink

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
        assert "<script src" not in text.lower() and text.lower().count("<script") == 1  # one inline copy script


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
        "type": "naive", "tag": by_type["naive"]["tag"], "server": "naive.example.com", "server_port": 443,
        "username": "bob", "password": "naive-pass-01",
        "tls": {"enabled": True, "server_name": "naive.example.com"},
    }
    assert by_type["mieru"] == {
        "type": "mieru", "tag": by_type["mieru"]["tag"], "server": "mieru.example.com",
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
    assert " · TCP 8443'\n    type: 'mieru'\n    server: 'mieru.example.com'\n    port: 8443\n" in proxies
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
    assert "no stored credential" in text
    assert "naive-pass-02" not in text
    assert "<table><tr><th></th>" not in text  # the ten-column matrix that made phones zoom out is gone
    # long values wrap inside their cell; a row label never breaks mid-word («Серве р»)
    assert "td{overflow-wrap:anywhere}th{white-space:nowrap" in text and 'class="scroll"' not in text
    assert 'style="' not in text and "onclick" not in text


SUB = "https://sub.example.com/s/TOKEN"


def _page(manifest, artifacts, **options):
    return RENDERERS["html"].render(manifest, artifacts, url=SUB, **options).decode()


def test_the_page_starts_with_the_add_buttons_and_the_copy_button_and_hides_the_qr(manifest, artifacts):
    text = _page(manifest, artifacts, updated_at=1_800_000_000)
    head, _, rest = text.partition("<h2>Все доступы</h2>")
    assert "Подписка обновляется сама" in head and "Копировать ссылку подписки" in head
    # Karing leads (it takes Naive and Mieru, both proven); the link it gets is its own sing-box cut
    assert "Добавить в Karing" in head and "Добавить в FlClash" in head
    assert head.index("Добавить в Karing") < head.index("Добавить в FlClash")
    assert 'href="karing://install-config?url=https%3A%2F%2Fsub.example.com%2Fs%2FTOKEN%3Fformat%3Dsingbox&amp;name=Sergey%20%3Cb%3E%26%3C%2Fb%3E"' in head
    assert "clash://install-config?url=https%3A%2F%2Fsub.example.com%2Fs%2FTOKEN%3Fformat%3Dclash" in head
    # apps without a verified scheme or taking nothing here get no button
    assert "Добавить в Throne" not in text and "Добавить в Hiddify" not in text
    # the subscription QR is behind «Показать QR», never open on load
    assert "<details class=\"qr\"><summary>Показать QR</summary>" in head and "<details class=\"qr\" open" not in text
    # the personal-key warning stays; the version moves to a small footer with the date
    assert "ваш личный ключ" in head and "Версия набора" not in text
    assert "<footer>Обновлено 2027-01-15 08:00 UTC · версия набора 3</footer>" in text


def test_the_page_never_names_the_local_node_and_wraps_each_access_in_a_collapsed_section(manifest, artifacts):
    grants = [dataclasses.replace(g, node_name="Этот сервер") for g in manifest.grants]
    named = dataclasses.replace(
        manifest, grants=[dataclasses.replace(grants[1], label="Телефон мамы"), *grants[:1], *grants[2:]]
    )
    text = _page(named, artifacts)
    titles = re.findall(r"<details class=\"card\"><summary>([^<]*)</summary>", text)
    assert "Телефон мамы" in titles and "NaiveProxy · naive.example.com" not in titles
    assert "Mieru · mieru.example.com · carol" in titles and "MTProxy · proxy.example.com" in titles
    assert not any("Этот сервер" in title for title in titles)
    assert "<details class=\"card\" open" not in text
    # the names inside the links are the unchanged `#fragment` ones
    assert "profile=%D0%AD%D1%82%D0%BE%D1%82%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80%20%C2%B7%20Mieru" in text
    assert text.count("data-copy=") >= 4 and "Копировать ссылку</button>" in text


def test_the_page_speaks_english_on_request_and_escapes_the_deep_link_name(manifest, artifacts):
    renamed = dataclasses.replace(manifest, client_name="O'Brien \"x\"")
    text = _page(renamed, artifacts, lang="en")
    assert 'lang="en"' in text and "Add to Karing" in text and "Copy the subscription link" in text
    assert "The link to this page is your personal key" in text and "Show QR" in text
    assert "name=O%27Brien%20%22x%22" in text  # quotes are percent-encoded, so the guard keeps the button
    assert "О'Brien" not in text and "javascript:" not in text
    assert "Подписка" not in text and "Копировать" not in text


def test_amneziawg_and_apps_that_take_nothing_stay_off_the_page(manifest, artifacts):
    only_mtproxy = dataclasses.replace(manifest, grants=manifest.grants[:1])
    text = _page(only_mtproxy, artifacts)
    assert "Добавить в" not in text and "AmneziaWG" not in text
    assert "Копировать ссылку подписки" in text  # the link itself is still offered


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
    assert set(MATRIX) == {"mtproxy", "naive", "mieru", "trusttunnel"}
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


def test_nekobox_preserves_naive_and_mieru_in_a_mixed_subscription(manifest, artifacts):
    data = json.loads(RENDERERS["singbox"].render(manifest, artifacts, client="nekobox"))
    assert {item["type"] for item in data["outbounds"]} == {"naive", "mieru"}
    assert {item["username"] for item in data["outbounds"]} == {"bob", "carol"}
    reasons = {item["runtime_username"]: item["reason"] for item in data["proxy_control"]["unsupported"]}
    assert set(reasons) == {"alice", "dave", "frank"}
    assert reasons["dave"] == "no stored credential"
    assert "port range" in reasons["frank"]


def test_nekobox_mixed_subscription_keeps_trusttunnel_too(manifest, artifacts, tt_feed):
    tt_manifest, tt_artifacts = tt_feed
    mixed = dataclasses.replace(manifest, grants=manifest.grants + tt_manifest.grants)
    data = json.loads(RENDERERS["singbox"].render(mixed, {**artifacts, **tt_artifacts}, client="nekobox"))
    assert {item["type"] for item in data["outbounds"]} == {"naive", "mieru", "trusttunnel"}


# --- TrustTunnel ----------------------------------------------------------------------

SELF_SIGNED_DER_B64 = "MAMCAQU="  # a DER SEQUENCE the adapter can split; the content is irrelevant here
TT_PASSWORD = b"tt-pass-CANARY-01"


def _seed_tt(database, secrets, username, *, certificate=None, name=None, enabled=True):
    options = TrusttunnelOptions(hostname="gate.example.com", port=443, certificate_der_b64=certificate, name=name)
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id="c1", protocol="trusttunnel", node_id="local",
        endpoint_id="default", runtime_username=username,
        desired_state="enabled" if enabled else "disabled", observed_state="enabled",
        options=options, origin="provisioned", created_at=NOW, updated_at=NOW,
    )
    store = ClientStore(database)
    with database.transaction() as db:
        store.insert_grant(db, grant)
        reference = secrets.store(
            db, secret_id=f"grant:{grant.id}", version=1, purpose=CREDENTIAL_PURPOSE,
            grant_id=grant.id, permitted_node_id="local", plaintext=TT_PASSWORD, state="active",
        )
        store.update_grant(db, grant.id, secret_id=reference.secret_id, secret_version=reference.version)
    return ManifestGrant(
        grant_id=grant.id, protocol="trusttunnel", node_id="local", endpoint_id="default",
        runtime_username=username, secret_version=1, options=options.model_dump(), enabled=enabled,
    )


@pytest.fixture
def tt_feed(database, secrets):
    grants = [
        _seed_tt(database, secrets, "trusted"),
        _seed_tt(database, secrets, "selfsigned", certificate=SELF_SIGNED_DER_B64),
        _seed_tt(database, secrets, "paused", enabled=False),
    ]
    manifest = Manifest(client_id="c1", client_name="Sergey", generation=5, grants=grants)
    adapters = {"trusttunnel": TrusttunnelAdapter(MemoryTrusttunnel(), public_host="gate.example.com")}
    with database.connect() as db:
        artifacts = resolve_artifacts(manifest, secrets, adapters, db, public_hosts={"trusttunnel": "gate.example.com"})
    return manifest, artifacts


def test_trusttunnel_grants_reach_the_renderers_with_both_artifacts(tt_feed):
    manifest, artifacts = tt_feed
    by_user = {grant.runtime_username: grant.grant_id for grant in manifest.grants}
    assert set(artifacts) == {by_user["trusted"], by_user["selfsigned"]}
    assert [a.kind for a in artifacts[by_user["trusted"]]] == ["trusttunnel_link", "trusttunnel_toml", "trusttunnel_manual"]


def test_clash_emits_a_trusttunnel_proxy_with_exactly_the_documented_keys(tt_feed):
    manifest, artifacts = tt_feed
    text = RENDERERS["clash"].render(manifest, artifacts).decode()
    proxies, tail = text.split("proxy-control:")
    assert "    type: 'trusttunnel'\n    server: 'gate.example.com'\n    port: 443\n" in proxies
    assert "    username: 'trusted'\n    password: 'tt-pass-CANARY-01'\n    udp: false\n    quic: false\n" in proxies
    block = proxies.split("- name:")[1]  # the trusted entry: no certificate, so no skip-cert-verify
    assert "skip-cert-verify" not in block.split("- name:")[0]
    keys = [line.split(":")[0].strip() for line in block.splitlines()[1:] if line.startswith("    ") and not line.startswith("     ")]
    assert keys == ["type", "server", "port", "username", "password", "udp", "quic"]
    assert "paused" not in proxies
    assert "tt-pass-CANARY-01" not in tail


def test_clash_skips_certificate_verification_only_for_an_untrusted_certificate(tt_feed):
    manifest, artifacts = tt_feed
    proxies = RENDERERS["clash"].render(manifest, artifacts).decode().split("proxy-groups:")[0]
    entries = proxies.split("  - name:")[1:]
    flags = {("trusted" if "username: 'trusted'" in e else "selfsigned"): "skip-cert-verify: true" in e for e in entries}
    assert flags == {"trusted": False, "selfsigned": True}


def test_clash_group_lists_the_trusttunnel_proxies(tt_feed):
    manifest, artifacts = tt_feed
    text = RENDERERS["clash"].render(manifest, artifacts).decode()
    group = text.split("proxy-groups:")[1].split("proxy-control:")[0]
    assert group.count("TrustTunnel") == 2


def test_singbox_names_the_gap_for_trusttunnel_and_stays_valid(tt_feed):
    manifest, artifacts = tt_feed
    for client in ("karing", "singbox"):
        data = json.loads(RENDERERS["singbox"].render(manifest, artifacts, client=client))
        assert data["outbounds"] == []
        reasons = {item["runtime_username"]: item["reason"] for item in data["proxy_control"]["unsupported"]}
        assert reasons == {"trusted": NOTES["trusttunnel"][client], "selfsigned": NOTES["trusttunnel"][client]}
        assert "TrustTunnel" in reasons["trusted"]
        assert "tt-pass" not in json.dumps(data)


HIDDIFY_OUTBOUND = {
    "type": "trusttunnel", "tag": None, "server": "gate.example.com", "server_port": 443,
    "username": None, "password": TT_PASSWORD.decode(), "quic": False,
    "tls": {"enabled": True, "server_name": "gate.example.com"},
}


@pytest.mark.parametrize("client", ["hiddify", "nekobox"])
def test_singbox_emits_the_trusttunnel_outbound_only_for_a_fork_core_client(tt_feed, client):
    manifest, artifacts = tt_feed
    data = json.loads(RENDERERS["singbox"].render(manifest, artifacts, client=client))
    outbounds = {item["username"]: item for item in data["outbounds"]}
    assert set(outbounds) == {"trusted", "selfsigned"}  # the paused one is not in the feed
    trusted = outbounds["trusted"]
    assert trusted == {**HIDDIFY_OUTBOUND, "tag": trusted["tag"], "username": "trusted"}
    assert trusted["tag"].startswith("local · TrustTunnel")
    # `insecure` only where the grant learned an untrusted certificate (the link then carries it)
    assert "insecure" not in trusted["tls"]
    assert outbounds["selfsigned"]["tls"] == {"enabled": True, "server_name": "gate.example.com", "insecure": True}
    assert data["proxy_control"]["client"] == client and data["proxy_control"]["unsupported"] == []


def test_singbox_cuts_that_cannot_load_the_outbound_never_carry_it(tt_feed):
    manifest, artifacts = tt_feed
    for client in ("karing", "singbox"):
        text = RENDERERS["singbox"].render(manifest, artifacts, client=client).decode()
        assert '"trusttunnel"' not in text.replace('"protocol": "trusttunnel"', "")
    with pytest.raises(RenderError):
        RENDERERS["singbox"].render(manifest, artifacts, client="sagernet")


def test_the_trusttunnel_outbound_keeps_the_password_out_of_logs_and_errors(tt_feed, caplog):
    manifest, artifacts = tt_feed
    RENDERERS["singbox"].render(manifest, artifacts, client="hiddify")
    assert "tt-pass-CANARY-01" not in caplog.text
    broken = {key: [dataclasses.replace(item, value="tt://?broken") if item.kind == "trusttunnel_link" else item for item in value]
              for key, value in artifacts.items()}
    with pytest.raises(RenderError) as exc:
        RENDERERS["singbox"].render(manifest, broken, client="hiddify")
    assert "tt-pass-CANARY-01" not in str(exc.value)


def test_raw_carries_the_tt_link_with_its_name_and_a_comment_for_the_paused_one(tt_feed):
    manifest, artifacts = tt_feed
    lines = RENDERERS["raw"].render(manifest, artifacts).decode().splitlines()
    links = [line for line in lines if line.startswith("tt://?")]
    assert len(links) == 2
    fields = [decode_deeplink(link) for link in links]
    assert {f["username"] for f in fields} == {"trusted", "selfsigned"}
    assert all(f["password"] == TT_PASSWORD.decode() and f["hostname"] == "gate.example.com" for f in fields)
    # the feed's display name, not the adapter's, labels the profile in the client app
    assert len({f["name"] for f in fields}) == 2 and all(f["name"].startswith("local · TrustTunnel") for f in fields)
    assert "# disabled trusttunnel paused" in lines
    certificates = {f["username"]: f.get("certificate") for f in fields}
    assert certificates["trusted"] is None and certificates["selfsigned"]


def test_trusttunnel_profile_names_follow_the_client_labels(database, secrets):
    grant = dataclasses.replace(_seed_tt(database, secrets, "named"), label="Phone")
    manifest = Manifest(client_id="c1", client_name="Sergey", generation=1, grants=[grant])
    adapters = {"trusttunnel": TrusttunnelAdapter(MemoryTrusttunnel(), public_host="gate.example.com")}
    with database.connect() as db:
        artifacts = resolve_artifacts(manifest, secrets, adapters, db, public_hosts={})
    link = RENDERERS["raw"].render(manifest, artifacts).decode().strip()
    assert decode_deeplink(link)["name"] == "Phone"
    assert "name: 'Phone'" in RENDERERS["clash"].render(manifest, artifacts).decode()


def test_html_shows_the_trusttunnel_link_qr_and_toml_download(tt_feed):
    manifest, artifacts = tt_feed
    text = RENDERERS["html"].render(manifest, artifacts).decode()
    assert text.count("tt://?") >= 2 and text.count("data:image/svg+xml;base64,") == 2
    assert "[endpoint]" in text and 'download="trusttunnel_client.toml"' in text
    assert 'href="data:application/toml;base64,' in text
    assert 'href="[' not in text and "<script src" not in text.lower()
    assert "TrustTunnel" in text


def test_html_shows_the_manual_fields_and_the_app_table_for_trusttunnel(tt_feed):
    manifest, artifacts = tt_feed
    text = RENDERERS["html"].render(manifest, artifacts).decode()
    assert "Данные для ручной настройки" in text and "HTTP/2, QUIC выключен" in text
    assert "Proxy-TrustTunnel" not in text and "Surge" not in text  # the Surge line was never run by us
    assert text.count("Как подключить") == 2  # one per enabled TrustTunnel access
    for name in ("AdGuard TrustTunnel", "TrustTunnel CLI", "mihomo"):
        assert name in text
    for unverified in ("Throne", "Hiddify", "NekoBox", "Shadowrocket", "Trusty", "не проверено"):
        assert unverified not in text
    assert "https://apps.apple.com/us/app/trusttunnel/id6755807890" in text
    assert 'rel="noopener noreferrer"' in text and "style=\"" not in text
    assert "BEGIN CERTIFICATE" in text  # the self-signed access carries its certificate


def test_manifest_carries_trusttunnel_artifacts_and_its_matrix_row(tt_feed):
    manifest, artifacts = tt_feed
    data = json.loads(RENDERERS["manifest"].render(manifest, artifacts))
    grants = {item["runtime_username"]: item for item in data["grants"]}
    assert [a["kind"] for a in grants["trusted"]["artifacts"]] == ["trusttunnel_link", "trusttunnel_toml", "trusttunnel_manual"]
    assert grants["paused"]["artifacts"] == []
    assert set(data["compatibility"]["trusttunnel"]) == set(MATRIX["mtproxy"])


def test_trusttunnel_password_stays_out_of_the_database_logs_and_errors(database, tt_feed, caplog):
    manifest, artifacts = tt_feed
    for renderer in RENDERERS.values():
        renderer.render(manifest, artifacts)
    assert b"tt-pass-CANARY-01" not in _database_bytes(database)
    assert "tt-pass-CANARY-01" not in caplog.text
    broken = dataclasses.replace(manifest, grants=manifest.grants * 30)
    for renderer in RENDERERS.values():
        with pytest.raises(RenderError) as exc:
            renderer.render(broken, artifacts)
        assert "tt-pass-CANARY-01" not in str(exc.value)


def test_trusttunnel_matrix_row_is_evidence_honest():
    row = MATRIX["trusttunnel"]
    assert set(row) == set(MATRIX["mtproxy"]) and set(NOTES["trusttunnel"]) == set(row)
    assert row["mihomo"] == "supported"
    assert row["singbox"] == row["mieru_cli"] == row["telegram"] == "unsupported"
    # mihomo was run against the Clash feed; Hiddify's core only as built from source (no app release has
    # the outbound), NekoBox's and Throne's not at all: those cells stay unproven and say so.
    assert row["hiddify"] == row["nekobox"] == row["throne"] == "unproven"
    assert "verified 2026-10-20 with mihomo v1.19.32" in NOTES["trusttunnel"]["mihomo"]
    assert "verified 2026-10-19 only" in NOTES["trusttunnel"]["hiddify"]
    assert "unverified" in NOTES["trusttunnel"]["nekobox"] and "unverified" in NOTES["trusttunnel"]["throne"]
    assert "supported" not in {v for k, v in row.items() if k != "mihomo"}
