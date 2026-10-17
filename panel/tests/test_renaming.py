"""Names an operator gives: a client, one access in the subscription, and a node.

Only presentation changes — the account name, the endpoint and the credential stay as
they were, and the subscription URL does not move.
"""
import dataclasses
import json
from urllib.parse import quote

import pytest

from panel.migrations import MIGRATIONS
from panel.protocols.base import AccessArtifact
from panel.subscriptions.models import Manifest, ManifestGrant
from panel.subscriptions.renderers import RENDERERS

pytestmark = pytest.mark.anyio


async def _client_with_grant(client, login_user, name="A"):
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    client_id = (await client.post("/api/clients", json={"display_name": name}, headers=csrf)).json()["id"]
    await client.post(f"/api/clients/{client_id}/grants", headers=csrf, json={
        "grants": [{"protocol": "naive", "node_id": "local", "runtime_username": "alice", "options": {}}]})
    grant = (await client.get(f"/api/clients/{client_id}")).json()["grants"][0]
    return client_id, grant["id"], csrf


async def test_a_client_is_renamed_and_the_rename_is_audited(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    response = await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "  Мама   Samsung "}, headers=csrf)
    assert response.status_code == 200 and response.json()["display_name"] == "Мама Samsung"
    shown = (await client.get(f"/api/clients/{client_id}")).json()
    assert shown["client"]["display_name"] == "Мама Samsung"
    assert shown["grants"][0]["runtime_username"] == "alice"  # the account is not renamed
    assert "client.rename" in {row["action"] for row in (await client.get("/api/audit")).json()["items"]}


async def test_renaming_a_client_refuses_blank_missing_and_needs_csrf(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    assert (await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "   "}, headers=csrf)).status_code == 422
    assert (await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "x" * 129}, headers=csrf)).status_code == 422
    assert (await client.post("/api/clients/nope/rename", json={"display_name": "B"}, headers=csrf)).status_code == 404
    assert (await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "B"})).status_code in (401, 403)


async def test_a_grant_label_is_set_shown_and_reset(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    saved = await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": " Дом  Naive "}, headers=csrf)
    assert saved.status_code == 200 and saved.json()["label"] == "Дом Naive"
    assert saved.json()["runtime_username"] == "alice"
    assert (await client.get(f"/api/clients/{client_id}")).json()["grants"][0]["label"] == "Дом Naive"
    reset = await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": ""}, headers=csrf)
    assert reset.json()["label"] is None
    assert "grant.label" in {row["action"] for row in (await client.get("/api/audit")).json()["items"]}


async def test_a_grant_label_refuses_too_long_unknown_and_deleted(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    assert (await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": "x" * 65}, headers=csrf)).status_code == 422
    assert (await client.post("/api/clients/grants/nope/label", json={"label": "A"}, headers=csrf)).status_code == 404
    await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)
    assert (await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": "A"}, headers=csrf)).status_code == 404


def _feed(label=""):
    grants = [
        ManifestGrant(grant_id=f"g{i}", protocol="naive", node_id=f"n{i}", endpoint_id="default",
                      runtime_username="alice", secret_version=1, options={}, enabled=True,
                      node_name="AMS", label=label if i == 0 else "")
        for i in range(2)
    ]
    artifacts = {g.grant_id: [AccessArtifact("link", "Connection", "text/uri-list", f"https://u:p@{g.node_id}.example:443")] for g in grants}
    return Manifest("c", "alice", 1, grants), artifacts


def _tags(manifest, artifacts):
    return [out["tag"] for out in json.loads(RENDERERS["singbox"].render(manifest, artifacts))["outbounds"]]


def test_a_label_replaces_the_default_name_in_every_format():
    manifest, artifacts = _feed("Дом · быстрый")
    assert "Дом · быстрый" in _tags(manifest, artifacts)
    assert "Дом · быстрый" in RENDERERS["html"].render(manifest, artifacts).decode()
    assert quote("Дом · быстрый") in RENDERERS["raw"].render(manifest, artifacts).decode()


def test_the_same_label_on_two_accesses_gets_stable_suffixes():
    manifest, artifacts = _feed("Дом")
    shared = dataclasses.replace(manifest, grants=[dataclasses.replace(g, label="Дом") for g in manifest.grants])
    tags = _tags(shared, artifacts)
    assert len(set(tags)) == 2 and all(tag.startswith("Дом [") for tag in tags)


def test_a_label_is_not_a_wire_field_of_the_public_manifest():
    manifest, artifacts = _feed("Дом")
    body = RENDERERS["manifest"].render(manifest, artifacts).decode()
    assert "Дом" not in body and '"label": "Дом' not in body


def test_the_grant_label_column_is_a_migration_of_its_own():
    assert MIGRATIONS[-1].name == "grant-labels" and MIGRATIONS[-1].statements == (
        "ALTER TABLE access_grants ADD COLUMN label TEXT",)


def test_the_screens_offer_the_renames_with_the_dialog_they_need():
    from pathlib import Path

    static = Path(__file__).resolve().parents[1] / "static"
    clients = (static / "js/clients.js").read_text(encoding="utf-8")
    grant = (static / "js/grant.js").read_text(encoding="utf-8")
    ui = (static / "js/ui.js").read_text(encoding="utf-8")
    index = (static / "index.html").read_text(encoding="utf-8")
    assert 'data-client-action="rename"' in clients and "/rename`" in clients
    assert 'data-grant-action="label"' in grant and "/label`" in grant
    assert "askText" in ui and 'id="ask-text"' in index
    # An MTProxy access has no subscription entry, so it offers no subscription name.
    assert 'grant.protocol === "mtproxy" ? ""' in grant
