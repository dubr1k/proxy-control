"""Ссылки клиента по запросу: `POST /api/clients/{id}/links`.

Telegram не умеет подписку — он умеет ссылку `tg://proxy` и QR к ней. Поэтому доступ
MTProxy раздаётся ссылками, а не URL подписки, и показать их нужно не только в момент
выдачи: оператор возвращается к карточке клиента через неделю.

Как и bundle операции, это разовый reveal из escrow — ни одного обращения к менеджеру.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.anyio


async def _client_with_grants(client, login_user, grants):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/clients", json={"display_name": "Sergey"}, headers=headers)
    client_id = created.json()["id"]
    started = await client.post(f"/api/clients/{client_id}/grants", json={"grants": grants}, headers=headers)
    assert started.status_code == 200 and started.json()["status"] == "succeeded", started.json()
    return client_id, headers


async def _reveal(client, headers, client_id):
    issued = await client.post(f"/api/clients/{client_id}/links", headers=headers)
    assert issued.status_code == 200, issued.text
    token = issued.json()["reveal_token"]
    revealed = await client.get(f"/api/reveal/{token}")
    assert revealed.status_code == 200, revealed.text
    return token, revealed.json()


async def test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(client, login_user, telemt, naive, mieru):
    client_id, headers = await _client_with_grants(client, login_user, [
        {"protocol": "mtproxy", "runtime_username": "laptop", "options": {}},
        {"protocol": "naive", "runtime_username": "laptop", "options": {}},
    ])
    _token, payload = await _reveal(client, headers, client_id)
    by_protocol = {grant["protocol"]: grant for grant in payload["grants"]}
    assert set(by_protocol) == {"mtproxy", "naive"}
    mtproxy = by_protocol["mtproxy"]
    assert mtproxy["runtime_username"] == "laptop" and mtproxy["node_id"] == "local"
    link = mtproxy["artifacts"][0]
    assert link["kind"] == "link" and link["value"].startswith("tg://proxy?")
    # QR рисуется здесь же: оператор показывает экран, а не пересылает ссылку в мессенджер.
    assert link["qr"].startswith("data:image/svg+xml;base64,")


async def test_only_the_protocol_the_screen_shows_is_decrypted(client, login_user, telemt, naive, mieru):
    """Экран ссылок MTProxy просит только их: секрет NaiveProxy незачем расшифровывать,
    чтобы выбросить его по дороге в браузер."""
    client_id, headers = await _client_with_grants(client, login_user, [
        {"protocol": "mtproxy", "runtime_username": "laptop", "options": {}},
        {"protocol": "naive", "runtime_username": "laptop", "options": {}},
    ])
    issued = await client.post(f"/api/clients/{client_id}/links?protocol=mtproxy", headers=headers)
    payload = (await client.get(f"/api/reveal/{issued.json()['reveal_token']}")).json()
    assert [grant["protocol"] for grant in payload["grants"]] == ["mtproxy"]


async def test_the_links_reveal_is_one_time(client, login_user, telemt, naive, mieru):
    client_id, headers = await _client_with_grants(client, login_user, [
        {"protocol": "mtproxy", "runtime_username": "laptop", "options": {}},
    ])
    token, _payload = await _reveal(client, headers, client_id)
    assert (await client.get(f"/api/reveal/{token}")).status_code == 410


async def test_a_deleted_grant_is_not_handed_out_again(client, login_user, telemt, naive, mieru):
    client_id, headers = await _client_with_grants(client, login_user, [
        {"protocol": "mtproxy", "runtime_username": "laptop", "options": {}},
        {"protocol": "mtproxy", "runtime_username": "phone", "options": {}},
    ])
    listed = (await client.get(f"/api/clients/{client_id}")).json()
    doomed = [grant for grant in listed["grants"] if grant["runtime_username"] == "phone"][0]
    dropped = await client.post(f"/api/clients/grants/{doomed['id']}/delete", headers=headers)
    assert dropped.status_code == 200, dropped.text
    _token, payload = await _reveal(client, headers, client_id)
    assert [grant["runtime_username"] for grant in payload["grants"]] == ["laptop"]


async def test_showing_the_links_is_audited_without_the_secret(client, login_user, telemt, naive, mieru):
    """Показ ссылки — выдача живого секрета, как и показ подписки: он попадает в журнал,
    но сама ссылка в журнал не идёт."""
    client_id, headers = await _client_with_grants(client, login_user, [
        {"protocol": "mtproxy", "runtime_username": "laptop", "options": {}},
    ])
    await _reveal(client, headers, client_id)
    rows = (await client.get("/api/audit")).json()["items"]
    reveals = [row for row in rows if row["action"] == "client.links.reveal"]
    assert len(reveals) == 1 and reveals[0]["target"] == client_id
    assert "tg://" not in json.dumps(rows)


async def test_an_unknown_client_has_no_links(client, login_user, telemt, naive, mieru):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    assert (await client.post("/api/clients/nope/links", headers=headers)).status_code == 404
