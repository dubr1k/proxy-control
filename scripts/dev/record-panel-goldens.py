#!/usr/bin/env python3
"""Record the byte-exact outputs of the Python panel as golden vectors for the Rust port.

    python3 scripts/dev/record-panel-goldens.py [--out panel/tests/goldens]

Everything is generated in a throwaway temporary directory: fresh keyrings, a fresh database per
scenario, the in-memory manager doubles served over their wire protocols (panel/tests/harness).
No real secret is read or written. Each run produces new random tokens, keys and ids, so the
recorded outputs come with the inputs that produced them (keyring files, database snapshots taken
before the requests): a Rust test loads those inputs and must answer the same bytes.

Sections (one directory each, described in `index.json`):

- keyring/       keyring files and `secret_versions` rows (nonce, ciphertext, AAD, plaintext) per keyring
- migrations/    the schema (`sqlite_master`) and `schema_migrations` rows after each migration version
- subscriptions/ a database + keyring snapshot and `/s/{token}` per format × User-Agent × client ×
                 language, HEAD, 304 and refusals, with status, headers (incl. ETag) and body
- clients/       the client-list cursor pages
- routing/       policy previews/applies (compiled documents, digests) and what each manager received
- fleet/         fleet v2 generation documents + digests on both sides and the central↔node wire
- links/         `tt://` deep links (inputs → link → decoded)
- errors/        the error bodies of every class (§2.6 of the port inventory)
- audit/         `audit_log` rows (exact `detail_json`) of every scenario database

Run on the lab host (ams-test), commit the output.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ["PANEL_IMPL"] = "python"

import httpx  # noqa: E402

import panel.protocols.telemt as telemt_adapter  # noqa: E402
from panel import migrations  # noqa: E402
from panel.amneziawg import MemoryAmneziawg  # noqa: E402
from panel.database import Database  # noqa: E402
from panel.keyring import Keyring  # noqa: E402
from panel.mieru import MemoryMieru  # noqa: E402
from panel.naive import MemoryNaive  # noqa: E402
from panel.secrets_store import SecretStore, _aad  # noqa: E402
from panel.telemt import MemoryTelemt  # noqa: E402
from panel.tests.harness import fake_managers  # noqa: E402
from panel.tests.harness.server import start_panel  # noqa: E402
from panel.trusttunnel import MemoryTrusttunnel  # noqa: E402
from panel.trusttunnel_link import UPSTREAM_HTTP3, decode_deeplink, encode_deeplink  # noqa: E402
from panel.versions import MemoryVersions  # noqa: E402
from panel.xray_router import MemoryXrayRouter  # noqa: E402

PASSWORD = "correct horse battery staple"
SUB_HOST = "sub.example.com"
VOLATILE_HEADERS = {"x-request-id", "date", "server"}


async def _bridge(_ingress):
    return True


telemt_adapter._probe_bridge = _bridge  # no DNS lookup of the router ingress


# -- recording helpers -------------------------------------------------------------------------------

def b64(value: bytes | None) -> str | None:
    return None if value is None else base64.b64encode(value).decode()


def body_record(content: bytes) -> dict:
    try:
        return {"text": content.decode("utf-8")}
    except UnicodeDecodeError:
        return {"base64": b64(content)}


def response_record(response: httpx.Response, bodies: dict | None = None) -> dict:
    """Status, headers in wire order (volatile values masked) and the body; with `bodies`, the body
    is stored once there under its sha256 and the record names it (`"body": {"ref": sha256}`)."""
    headers = [[name.decode("latin-1"), "<volatile>" if name.decode("latin-1").lower() in VOLATILE_HEADERS
                else value.decode("latin-1")] for name, value in response.headers.raw]
    digest = hashlib.sha256(response.content).hexdigest()
    body = body_record(response.content)
    if bodies is not None:
        bodies.setdefault(digest, body)
        body = {"ref": digest}
    return {"status": response.status_code, "headers": headers, "body": body, "sha256": digest}


def request_record(request: httpx.Request) -> dict:
    headers = {name: value for name, value in request.headers.items()
               if name.lower() in {"accept", "user-agent", "if-none-match", "content-type", "accept-language"}}
    return {"method": request.method, "path": request.url.raw_path.decode(), "host": request.url.host,
            "headers": headers, "body": body_record(request.content) if request.content else None}


class Recorder:
    def __init__(self, *, dedupe: bool = False):
        self.items: list[dict] = []
        self.bodies: dict | None = {} if dedupe else None

    async def call(self, http: httpx.AsyncClient, name: str, method: str, path: str, **kwargs) -> httpx.Response:
        response = await http.request(method, path, **kwargs)
        self.items.append({"name": name, "request": request_record(response.request),
                           "response": response_record(response, self.bodies)})
        return response


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False, sort_keys=False) + "\n")


def rows(db_path: Path, query: str, params=()) -> list[dict]:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        out = []
        for row in connection.execute(query, params):
            out.append({key: (b64(row[key]) if isinstance(row[key], bytes) else row[key]) for key in row.keys()})
        return out
    finally:
        connection.close()


def snapshot_database(source: Path, target: Path) -> None:
    """A self-contained copy (WAL folded in, rollback journal mode) of a live database."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        target.unlink()
    src = sqlite3.connect(source)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
        dst.execute("VACUUM")
    finally:
        src.close()
        dst.close()


async def owner_session(server, host: str = "testserver") -> httpx.AsyncClient:
    http = server.http(host)
    page = await http.get("/login")
    csrf = page.cookies["panel_csrf"]
    response = await http.post("/api/auth/login", json={"username": "owner", "password": PASSWORD},
                               headers={"X-CSRF-Token": csrf})
    assert response.status_code in (200, 204), (response.status_code, response.text)
    http.headers["X-CSRF-Token"] = http.cookies["panel_csrf"]
    return http


async def must(response: httpx.Response, *statuses: int) -> dict:
    assert response.status_code in (statuses or (200, 201)), (response.request.url, response.status_code,
                                                              response.text)
    return response.json() if response.content else {}


# -- sections ----------------------------------------------------------------------------------------

def record_keyring(out: Path, work: Path) -> dict:
    """Keyring files and the secret rows they decrypt, before and after a rotation."""
    database = Database(work / "keyring.sqlite3")
    migrations.apply_migrations(database)
    first = Keyring.generate()
    first.save(work / "keyring-1")
    cases = [
        ("grant:g-ascii", 1, "grant.credential", "g-ascii", "local", b"plain-ascii-secret"),
        ("grant:g-unicode", 2, "grant.credential", "g-unicode", "node-1", "пароль «тест» ✓ 🚀".encode()),
        ("grant:g-empty", 1, "grant.credential", "g-empty", None, b""),
        ("node-link:n1", 1, "node.api_key", None, "n1", b"pc_0123abcd_" + b"x" * 43),
        ("misc:binary", 3, "custom.purpose/ünïcode", "gé", "né", bytes(range(256)) * 4),
    ]

    def dump(keyring_file: str, keyring: Keyring) -> dict:
        found = rows(database.path, "SELECT * FROM secret_versions ORDER BY secret_id, version")
        plain = {(secret_id, version): plaintext for secret_id, version, _, _, _, plaintext in cases}
        for row in found:
            row["aad"] = _aad(row["secret_id"], row["version"], row["purpose"], row["grant_id"],
                              row["permitted_node_id"]).decode()
            row["plaintext_base64"] = b64(plain[(row["secret_id"], row["version"])])
        return {"keyring_file": keyring_file, "keyring_json": keyring.to_json(), "rows": found}

    store = SecretStore(first)
    with database.transaction() as db:
        for secret_id, version, purpose, grant_id, node, plaintext in cases:
            store.store(db, secret_id=secret_id, version=version, purpose=purpose, grant_id=grant_id,
                        permitted_node_id=node, plaintext=plaintext, state="active")
    single = dump("keyring-1.json", first)
    rotated = first.rotate()
    rotated.save(work / "keyring-2")
    rewrapping = SecretStore(rotated)
    with database.transaction() as db:
        rewrapping.rewrap(db, batch_size=2)  # a half-rotated database: rows under both keys
    overlap = dump("keyring-2.json", rotated)
    with database.transaction() as db:
        while rewrapping.rewrap(db, batch_size=200):
            pass
    narrowed = rotated.retire_all_but_active()
    narrowed.save(work / "keyring-3")
    final = dump("keyring-3.json", narrowed)
    for name in ("keyring-1", "keyring-2", "keyring-3"):
        shutil.copyfile(work / name, out / f"{name}.json")
    write_json(out / "secret_versions.json", {
        "aad_format": "json.dumps({secret_id, version, purpose, grant_id, permitted_node_id}, sort_keys=True, "
                      "separators=(',', ':')) (ensure_ascii=True); AES-256-GCM, 12-byte nonce, ciphertext||tag",
        "single_key": single, "overlap_after_partial_rewrap": overlap, "after_full_rewrap_narrowed": final})
    return {"files": ["keyring-1.json", "keyring-2.json", "keyring-3.json", "secret_versions.json"],
            "rows": len(cases)}


def record_migrations(out: Path, work: Path) -> dict:
    """The schema after every migration version, from an empty database."""
    every = migrations.MIGRATIONS
    write_json(out / "migrations.json", [
        {"version": item.version, "name": item.name, "checksum": item.checksum, "statements": list(item.statements)}
        for item in every])
    for count in range(1, len(every) + 1):
        path = work / f"migrate-{count}.sqlite3"
        with mock.patch.object(migrations, "MIGRATIONS", every[:count]):
            migrations.apply_migrations(Database(path))
        version = every[count - 1].version
        write_json(out / f"schema-v{version:02d}.json", {
            "version": version,
            "sqlite_master": rows(path, "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid"),
            "schema_migrations": rows(path, "SELECT version, name, checksum FROM schema_migrations ORDER BY version"),
        })
    return {"versions": [item.version for item in every]}


GRANTS = [
    {"protocol": "mtproxy", "runtime_username": "alice-mt"},
    {"protocol": "naive", "runtime_username": "alice-naive"},
    {"protocol": "mieru", "runtime_username": "alice-mieru"},
    {"protocol": "amneziawg", "runtime_username": "alice-awg31", "options": {"version": "3.1"}},
    {"protocol": "trusttunnel", "runtime_username": "alice-tt"},
]


def full_panel(work: Path, name: str, **extra):
    return start_panel(
        work, name=name, hosts=("testserver", SUB_HOST, f"{name}.example"),
        telemt=MemoryTelemt(public_host="proxy.example.com", public_port=443), naive=MemoryNaive(),
        mieru=MemoryMieru(), amneziawg=MemoryAmneziawg(),
        trusttunnel=MemoryTrusttunnel(hostname="gate.example.com"), versions=MemoryVersions(),
        naive_public_host="naive.example.com", naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True,
        amneziawg_public_host="awg.example.com", trusttunnel_enabled=True, trusttunnel_public_host="gate.example.com",
        mtproxy_public_host="proxy.example.com", subscription_url=f"https://{SUB_HOST}", vnext_writer="domain",
        **extra)


async def client_with_grants(http, display_name: str, grants: list[dict]) -> tuple[str, str | None]:
    created = await must(await http.post("/api/clients", json={"display_name": display_name}), 201)
    client_id = created["id"]
    result = await must(await http.post(f"/api/clients/{client_id}/grants", json={"grants": grants}))
    assert result["status"] == "succeeded", result
    token = None
    if created.get("subscription_reveal_token"):
        revealed = await must(await http.get(f"/api/reveal/{created['subscription_reveal_token']}"))
        token = urlsplit(revealed["url"]).path.rsplit("/", 1)[1]
    return client_id, token


async def record_subscriptions(out: Path, work: Path, scenario_dbs: dict) -> dict:
    server = full_panel(work, "subs", singbox_fork_clients="karing,streisand")
    server.create_admin("owner", PASSWORD)
    http = await owner_session(server)
    # one client with every protocol and a Unicode name, one with labels, a disabled and a duplicate-name grant
    alice, alice_token = await client_with_grants(http, "Алиса «тест» 🚀", GRANTS)
    bob, bob_token = await client_with_grants(http, "Bob's phone", [
        {"protocol": "naive", "runtime_username": "bob-naive"},
        {"protocol": "naive", "runtime_username": "bob-naive-2"},
        {"protocol": "mieru", "runtime_username": "bob-mieru"},
        {"protocol": "trusttunnel", "runtime_username": "bob-tt"},
    ])
    detail = await must(await http.get(f"/api/clients/{bob}"))
    grant_ids = {grant["runtime_username"]: grant["id"] for grant in detail["grants"]}
    await must(await http.post(f"/api/clients/grants/{grant_ids['bob-naive']}/label",
                               json={"label": "Дом   'кухня'\u0007 — Wi‑Fi"}))
    await must(await http.post(f"/api/clients/grants/{grant_ids['bob-mieru']}/disable"))
    empty, empty_token = await client_with_grants(http, "Empty", [{"protocol": "naive", "runtime_username": "e-1"}])
    await must(await http.post(f"/api/clients/grants/{(await must(await http.get(f'/api/clients/{empty}')))['grants'][0]['id']}/delete"))
    await http.aclose()
    snapshot_database(server.db_path, out / "subscriptions.sqlite3")
    shutil.copyfile(server.key_path, out / "subscriptions-master-key.json")
    recorder = Recorder(dedupe=True)
    counter = 0

    def public(user_ip: int) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=server.app, client=(f"10.20.{user_ip // 250}.{user_ip % 250 + 1}", 40000))
        return httpx.AsyncClient(transport=transport, base_url=f"http://{SUB_HOST}", follow_redirects=False)

    async def fetch(name, token, *, method="GET", query="", headers=None, host=SUB_HOST):
        nonlocal counter
        counter += 1
        async with public(counter) as sub:
            if host != SUB_HOST:
                sub.base_url = f"http://{host}"
            return await recorder.call(sub, name, method, f"/s/{token}{query}", headers=headers or {})

    accepts = {"none": None, "html": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
               "manifest": "application/vnd.proxy-control.subscription+json;version=1", "yaml": "text/yaml",
               "app-yaml": "application/yaml", "json": "application/json", "any": "*/*"}
    agents = {"none": None, "sing-box": "sing-box 1.12.0", "sfa": "SFA/1.11.9 (Android 14)", "sfi": "SFI/1.11 (iOS)",
              "hiddify": "HiddifyNext/2.5.7", "nekobox": "NekoBox/Android 1.3.6", "nyamebox": "nyamebox/1.0",
              "nekoray": "NekoRay/4.0", "throne": "Throne/1.0.0", "karing": "karing/1.1.0",
              "streisand": "Streisand/2.0", "clash-meta": "ClashMeta/1.18", "mihomo": "mihomo/1.19",
              "browser": "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}
    for token_name, token in (("alice", alice_token), ("bob", bob_token), ("empty", empty_token)):
        for accept_name, accept in accepts.items():
            for agent_name, agent in agents.items():
                headers = {key: value for key, value in (("Accept", accept), ("User-Agent", agent)) if value}
                await fetch(f"{token_name}:accept={accept_name}:ua={agent_name}", token, headers=headers)
        for fmt in ("raw", "clash", "singbox", "manifest", "html", "bogus"):
            await fetch(f"{token_name}:format={fmt}", token, query=f"?format={fmt}")
            await fetch(f"{token_name}:format={fmt}:lang=en", token, query=f"?format={fmt}&lang=en")
        for client in ("karing", "singbox", "hiddify", "nekobox", "nyamebox", "throne", "fork", "x"):
            await fetch(f"{token_name}:format=singbox:client={client}", token, query=f"?format=singbox&client={client}")
            await fetch(f"{token_name}:accept=json:client={client}", token, query=f"?client={client}",
                        headers={"Accept": "application/json"})
        await fetch(f"{token_name}:format=raw:client=karing", token, query="?format=raw&client=karing")
        await fetch(f"{token_name}:html:lang=ru", token, headers={"Accept": "text/html"}, query="?lang=ru")
        await fetch(f"{token_name}:html:lang=en", token, headers={"Accept": "text/html"}, query="?lang=en")
        await fetch(f"{token_name}:html:lang=de", token, headers={"Accept": "text/html"}, query="?lang=de")
        for fmt in ("raw", "html", "singbox"):
            head = await fetch(f"{token_name}:HEAD:format={fmt}", token, method="HEAD", query=f"?format={fmt}")
            etag = head.headers.get("etag", "")
            await fetch(f"{token_name}:304:format={fmt}", token, query=f"?format={fmt}", headers={"If-None-Match": etag})
            await fetch(f"{token_name}:304-list:format={fmt}", token, query=f"?format={fmt}",
                        headers={"If-None-Match": f'"nope", {etag}'})
            await fetch(f"{token_name}:weak-etag:format={fmt}", token, query=f"?format={fmt}",
                        headers={"If-None-Match": f"W/{etag}"})
    unknown = "A" * 43
    await fetch("refusal:unknown-token", unknown)
    await fetch("refusal:short-token", "short")
    await fetch("refusal:long-token", "A" * 65)
    await fetch("refusal:bad-character", "A" * 42 + "!")
    await fetch("refusal:panel-host", alice_token, host="testserver")
    await fetch("refusal:host-with-port", alice_token, host=f"{SUB_HOST}:8443")
    # the rate limit: one address, more than 60 fetches a minute
    async with public(0) as sub:
        statuses = []
        for _ in range(62):
            statuses.append((await sub.get(f"/s/{unknown}")).status_code)
        limited = await recorder.call(sub, "refusal:rate-limited", "GET", f"/s/{unknown}")
    assert limited.status_code == 429, statuses
    write_json(out / "subscriptions.json", {
        "settings": {"PANEL_SUBSCRIPTION_URL": f"https://{SUB_HOST}", "PANEL_SINGBOX_FORK_CLIENTS": "karing,streisand",
                     "NAIVE_PUBLIC_HOST": "naive.example.com", "AMNEZIAWG_PUBLIC_HOST": "awg.example.com",
                     "TRUSTTUNNEL_PUBLIC_HOST": "gate.example.com", "MTPROXY_DOMAIN": "proxy.example.com"},
        "database": "subscriptions.sqlite3 (snapshot before the first fetch)",
        "master_key_file": "subscriptions-master-key.json",
        "tokens": {"alice": alice_token, "bob": bob_token, "empty": empty_token},
        "exchanges": recorder.items, "bodies": recorder.bodies})
    scenario_dbs["subscriptions"] = server.db_path
    return {"exchanges": len(recorder.items), "server": server}


async def record_cursor(out: Path, server, scenario_dbs: dict) -> dict:
    http = await owner_session(server)
    for index in range(7):
        await must(await http.post("/api/clients", json={"display_name": f"Cursor {index} Ж", "subscription": False}),
                   201)
    recorder = Recorder()
    for query in ("limit=2", "limit=3&query=cursor", "limit=1&state=active", "limit=2&protocol=naive",
                  "limit=1&issue=empty", "limit=200"):
        cursor, page = None, 0
        while True:
            suffix = f"&cursor={cursor}" if cursor else ""
            response = await recorder.call(http, f"{query}:page={page}", "GET", f"/api/clients?{query}{suffix}")
            cursor = response.json().get("next_cursor")
            page += 1
            if not cursor or page > 20:
                break
    for bad in ("limit=2&cursor=bogus", "limit=2&cursor=" + "A" * 600, "limit=0", "limit=201"):
        await recorder.call(http, f"invalid:{bad}", "GET", f"/api/clients?{bad}")
    await http.aclose()
    write_json(out / "client_cursor.json", {"database": "see subscriptions/ (same panel, more clients)",
                                            "exchanges": recorder.items})
    return {"exchanges": len(recorder.items)}


POLICIES = {
    "warp": {"default_action": "egress", "default_egress": "warp", "fallback": "fail_closed", "rules": []},
    "block": {"rules": [{"action": "block", "match": {"domains": ["example.com", "*.example.com"]}, "note": "ads"}]},
    "block-cidr": {"rules": [{"action": "block", "match": {"cidrs": ["203.0.113.0/24", "2001:db8::/32"]}}]},
    "selective": {"rules": [{"action": "egress", "egress": "warp", "match": {"domains": ["openai.com", "*.ru"]}}]},
    "router-geosite": {"rules": [
        {"action": "block", "match": {"geosites": ["category-ads-all"]}},
        {"action": "egress", "egress": "warp", "match": {"geoips": ["ru"], "ports": ["443", "8000-8100"]}},
        {"action": "direct", "match": {"protocols": ["bittorrent"]}}]},
}


async def record_routing(out: Path, work: Path, scenario_dbs: dict) -> dict:
    router = MemoryXrayRouter()
    server = start_panel(
        work, name="routing", telemt=MemoryTelemt(public_host="proxy.example.com"), naive=MemoryNaive(),
        mieru=MemoryMieru(), amneziawg=MemoryAmneziawg(), trusttunnel=MemoryTrusttunnel(), router=router,
        naive_public_host="naive.example.com", naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True,
        trusttunnel_enabled=True, trusttunnel_public_host="gate.example.com", xray_router_enabled=True,
        vnext_writer="domain")
    server.create_admin("owner", PASSWORD)
    http = await owner_session(server)
    recorder = Recorder()
    await recorder.call(http, "targets", "GET", "/api/routing/targets")
    await recorder.call(http, "presets", "GET", "/api/routing/presets")
    received = {}
    for protocol in ("naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"):
        for name, policy in POLICIES.items():
            label = f"{protocol}:{name}"
            await recorder.call(http, f"{label}:preview", "POST", f"/api/routing/policies/local/{protocol}/preview",
                                json=policy)
            current = await http.get(f"/api/routing/policies/local/{protocol}")
            revision = current.json().get("revision") if current.status_code == 200 else None
            put = await recorder.call(http, f"{label}:put", "PUT", f"/api/routing/policies/local/{protocol}",
                                      json={**policy, "expected_revision": revision})
            if put.status_code != 200:
                continue
            await recorder.call(http, f"{label}:apply", "POST", f"/api/routing/policies/local/{protocol}/apply",
                                json={"expected_revision": put.json()["revision"]})
            await recorder.call(http, f"{label}:explain", "POST", f"/api/routing/policies/local/{protocol}/explain",
                                json={"host": "www.example.com", "port": 443})
            received[label] = {
                "naive": server.naive.egress_document, "mieru": server.mieru.egress_document,
                "router": {service: router.documents[service] for service in router.documents},
                "trusttunnel": server.trusttunnel.egress_document,
                "telemt_upstreams": server.telemt.upstreams,
            }
        await recorder.call(http, f"{protocol}:history", "GET", f"/api/routing/policies/local/{protocol}/history")
        await recorder.call(http, f"{protocol}:rollback", "POST", f"/api/routing/policies/local/{protocol}/rollback",
                            json={"expected_revision": (await http.get(f"/api/routing/policies/local/{protocol}"))
                                  .json().get("revision")})
    await http.aclose()
    write_json(out / "routing.json", {"exchanges": recorder.items, "manager_documents_after_apply": received})
    scenario_dbs["routing"] = server.db_path
    server.close()
    return {"exchanges": len(recorder.items)}


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner, items):
        self.inner, self.items = inner, items

    async def handle_async_request(self, request):
        body = request.content
        response = await self.inner.handle_async_request(request)
        content = await response.aread()
        self.items.append({"request": {"method": request.method, "url": str(request.url),
                                       "body": body_record(body) if body else None},
                           "response": {"status": response.status_code, "body": body_record(content)}})
        return httpx.Response(response.status_code, headers=response.headers, content=content, request=request)


async def record_fleet(out: Path, work: Path, scenario_dbs: dict) -> dict:
    from panel.fleet_v2.client import NodeClient
    from panel.fleet_v2.protocol import GenerationDocument, canonical_digest
    from panel.fleet_v2.generations import content_digest

    node = full_panel(work, "node")
    central = full_panel(work, "central", node_routes={"node.example": node})
    central.create_admin("owner", PASSWORD)
    wire: list[dict] = []
    factory = central.app.state.links.client_factory

    def recording(url, key, **kwargs):
        made = factory(url, key, **kwargs)
        return NodeClient(url, key, transport=RecordingTransport(made.transport, wire), **{
            name: value for name, value in kwargs.items() if name != "transport"})

    central.app.state.links.client_factory = recording
    plaintext = node.create_api_key("central", "node-sync")
    http = await owner_session(central)
    recorder = Recorder()
    link = await recorder.call(http, "link", "POST", "/api/nodes/link", json={
        "display_name": "Edge «1»", "url": "https://node.example", "api_key": plaintext, "tls_verify": "verify",
        "allow_private_address": False, "auto_import": True})
    node_id = link.json()["node_id"]
    await central.tick("pusher")
    client = await must(await http.post("/api/clients", json={"display_name": "Fleet client"}), 201)
    grants = [{**grant, "node_id": node_id, "runtime_username": grant["runtime_username"].replace("alice", "fleet")}
              for grant in GRANTS]
    await recorder.call(http, "grants", "POST", f"/api/clients/{client['id']}/grants", json={"grants": grants})
    for _ in range(3):
        await central.tick("pusher")
    await recorder.call(http, "policy", "PUT", f"/api/routing/policies/{node_id}/naive",
                        json={**POLICIES["block"], "expected_revision": None})
    await recorder.call(http, "apply", "POST", f"/api/routing/policies/{node_id}/naive/apply",
                        json={"expected_revision": 1})
    for _ in range(2):
        await central.tick("pusher")
    await recorder.call(http, "suspend", "POST", f"/api/clients/{client['id']}/state", json={"state": "suspended"})
    await central.tick("pusher")
    await recorder.call(http, "resume", "POST", f"/api/clients/{client['id']}/state", json={"state": "active"})
    await central.tick("pusher")
    detail = await must(await http.get(f"/api/clients/{client['id']}"))
    first = detail["grants"][0]["id"]
    await recorder.call(http, "delete-grant", "POST", f"/api/clients/grants/{first}/delete")
    for _ in range(2):
        await central.tick("pusher")
    await recorder.call(http, "nodes", "GET", "/api/nodes")
    await recorder.call(http, "generations", "GET", f"/api/nodes/{node_id}/generations")
    await http.aclose()
    desired = rows(central.db_path, "SELECT * FROM desired_generations ORDER BY node_id, generation")
    for row in desired:
        document = GenerationDocument.model_validate_json(row["document_json"])
        row["wire_json"] = json.dumps(document.wire(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        row["recomputed_digest"] = canonical_digest(document)
        row["recomputed_content_digest"] = content_digest(document)
    managed = rows(node.db_path, "SELECT * FROM managed_generations ORDER BY generation")
    write_json(out / "fleet.json", {
        "node_id": node_id, "desired_generations": desired,
        "observed_generations": rows(central.db_path, "SELECT * FROM observed_generations"),
        "node_links": rows(central.db_path, "SELECT node_id, panel_url, tls_verify, status, identity_json, status_json,"
                                            " desired_generation, acknowledged_generation FROM node_links"),
        "managed_generations": managed,
        "managed_resources": rows(node.db_path, "SELECT * FROM managed_resources ORDER BY protocol, runtime_username"),
        "wire": wire, "exchanges": recorder.items})
    scenario_dbs["fleet-central"] = central.db_path
    scenario_dbs["fleet-node"] = node.db_path
    node.close()
    central.close()
    return {"generations": len(desired), "wire": len(wire)}


def record_links(out: Path) -> dict:
    certificate = hashlib.sha512(b"proxy-control golden certificate").digest() * 5
    cases = [
        {"hostname": "gate.example.com", "addresses": ["gate.example.com:443"], "username": "alice",
         "password": "s3cret-password"},
        {"hostname": "gate.example.com", "addresses": ["203.0.113.7:443", "[2001:db8::7]:443"], "username": "bob.tt",
         "password": "p" * 128, "name": "Дом · TrustTunnel 🚀"},
        {"hostname": "self.example", "addresses": ["self.example:8443"], "username": "carol", "password": "x!y~z{}",
         "certificate_der": certificate, "upstream_protocol": UPSTREAM_HTTP3},
        {"hostname": "insecure.example", "addresses": ["insecure.example:443"], "username": "dave",
         "password": "password1", "skip_verification": True, "name": "a" * 300},
    ]
    vectors = []
    for case in cases:
        link = encode_deeplink(**case)
        decoded = decode_deeplink(link)
        vectors.append({"input": {**case, "certificate_der": b64(case.get("certificate_der"))}, "link": link,
                        "decoded": json.loads(json.dumps(decoded, default=lambda v: b64(v) if isinstance(v, bytes)
                                                         else str(v)))})
    write_json(out / "tt_links.json", vectors)
    return {"vectors": len(vectors)}


async def record_errors(out: Path, work: Path, subs_server, scenario_dbs: dict) -> dict:
    recorder = Recorder()
    routes = {"subs.example": subs_server} if subs_server is not None else None
    server = start_panel(work, name="errors", node_routes=routes, telemt=None, naive=MemoryNaive(), mieru=MemoryMieru(),
                         amneziawg=MemoryAmneziawg(), trusttunnel=MemoryTrusttunnel(), versions=MemoryVersions(),
                         naive_public_host="naive.example.com", naive_enabled=True, mieru_enabled=True,
                         amneziawg_enabled=True, trusttunnel_enabled=True, trusttunnel_public_host="gate.example.com",
                         vnext_writer="legacy", metrics_enabled=True)
    server.create_admin("owner", PASSWORD)
    anonymous = server.http("testserver")
    await recorder.call(anonymous, "401:unauthenticated", "GET", "/api/clients")
    await recorder.call(anonymous, "404:unknown-route", "GET", "/api/nope")
    await recorder.call(anonymous, "405:method", "DELETE", "/healthz")
    await recorder.call(anonymous, "307:trailing-slash", "GET", "/api/clients/")
    await recorder.call(anonymous, "422:malformed-json-before-auth", "POST", "/api/clients", content=b"{nope",
                        headers={"Content-Type": "application/json"})
    await recorder.call(anonymous, "413:body-limit", "POST", "/api/auth/login", content=b"x" * 70000,
                        headers={"Content-Type": "application/json"})
    await recorder.call(anonymous, "login:no-csrf", "POST", "/api/auth/login",
                        json={"username": "owner", "password": "wrong"})
    csrf = (await anonymous.get("/login")).cookies["panel_csrf"]
    await recorder.call(anonymous, "login:bad-password", "POST", "/api/auth/login",
                        json={"username": "owner", "password": "wrong"}, headers={"X-CSRF-Token": csrf})
    await recorder.call(anonymous, "login:invalid-body", "POST", "/api/auth/login",
                        json={"username": "owner"}, headers={"X-CSRF-Token": csrf})
    async with server.http("evil.example") as evil:
        await recorder.call(evil, "400:host", "GET", "/healthz")
    await anonymous.aclose()
    http = await owner_session(server)
    no_csrf = server.http("testserver")
    no_csrf.cookies = http.cookies
    await recorder.call(no_csrf, "403:csrf", "POST", "/api/clients", json={"display_name": "x"})
    await no_csrf.aclose()
    await recorder.call(http, "422:validation", "POST", "/api/clients", json={})
    await recorder.call(http, "422:validation-extra", "POST", "/api/clients/x/grants",
                        json={"grants": [{"protocol": "nope", "runtime_username": "a b"}]})
    await recorder.call(http, "422:query", "GET", "/api/clients?limit=0")
    await recorder.call(http, "502:telemt", "GET", "/api/users")
    server.naive.broken = True
    await recorder.call(http, "502:naive", "GET", "/api/naive/users")
    server.naive.broken = False
    server.naive.seed("quota-user", "pw", quota_bytes=10)
    server.naive.set_traffic("quota-user", upload=10, download=10)
    await recorder.call(http, "409:naive-quota-exhausted", "POST", "/api/naive/users/quota-user/enable")
    server.mieru.broken = True
    await recorder.call(http, "502:mieru", "GET", "/api/mieru/users")
    server.amneziawg.broken = True
    await recorder.call(http, "overview:amneziawg-down", "GET", "/api/amneziawg/overview")
    server.trusttunnel.broken = True
    await recorder.call(http, "overview:trusttunnel-down", "GET", "/api/trusttunnel/overview")
    await recorder.call(http, "dashboard:managers-down", "GET", "/api/dashboard")
    await recorder.call(http, "409:version-agent", "POST", "/api/versions/telemt/update",
                        json={"version": "3.4.25", "expected_current": "0.0.0"})
    await recorder.call(http, "422:version-agent", "POST", "/api/versions/xray/update",
                        json={"version": "1", "expected_current": "1"})
    await recorder.call(http, "routing:node-not-found", "PUT", "/api/routing/policies/ghost/naive",
                        json=POLICIES["block"])
    await recorder.call(http, "routing:protocol-out-of-scope", "PUT", "/api/routing/policies/local/socks",
                        json=POLICIES["block"])
    await recorder.call(http, "routing:backend-mismatch", "PUT", "/api/routing/policies/local/naive",
                        json={**POLICIES["block"], "backend": "mieru_native"})
    await recorder.call(http, "routing:create", "PUT", "/api/routing/policies/local/naive", json=POLICIES["block"])
    await recorder.call(http, "routing:policy-conflict", "PUT", "/api/routing/policies/local/naive",
                        json={**POLICIES["block"], "expected_revision": 9})
    await recorder.call(http, "routing:policy-not-found", "GET", "/api/routing/policies/local/mieru")
    await recorder.call(http, "fleet:node-auth-failed", "POST", "/api/nodes/link", json={
        "display_name": "E", "url": "https://subs.example", "api_key": "pc_x_y", "tls_verify": "verify",
        "allow_private_address": False})
    await recorder.call(http, "fleet:node-unreachable", "POST", "/api/nodes/test", json={
        "url": "https://unreachable.invalid", "api_key": "pc_x_y"})
    await recorder.call(http, "fleet:private-address", "POST", "/api/nodes/link", json={
        "display_name": "E", "url": "https://127.0.0.1", "api_key": "pc_x_y"})
    await recorder.call(http, "metrics:live-before-a-sample", "GET", "/api/metrics/live")
    await recorder.call(http, "metrics:history-before-a-sample", "GET", "/api/metrics/history?series=host.cpu")
    await recorder.call(http, "metrics:summary-before-a-sample", "GET", "/api/metrics/summary")
    # the node side of fleet v2 (a node-sync key): warming-up meters and generation conflicts
    from panel.fleet_v2.protocol import GenerationDocument, PushRequest

    key = server.create_api_key("golden-central", "node-sync")
    async with server.http("testserver") as fleet:
        bearer = {"Authorization": f"Bearer {key}"}
        await recorder.call(fleet, "fleet-node:no-key", "GET", "/api/fleet/v2/identity")
        await recorder.call(fleet, "fleet-node:bad-key", "GET", "/api/fleet/v2/identity",
                            headers={"Authorization": "Bearer pc_00000000_nope"})
        identity = await recorder.call(fleet, "fleet-node:identity", "GET", "/api/fleet/v2/identity", headers=bearer)
        guid = identity.json()["guid"]
        await recorder.call(fleet, "fleet-node:metrics-warming-up", "GET", "/api/fleet/v2/metrics", headers=bearer)

        def push(expected, generation, previous, master="central-guid-1"):
            document = GenerationDocument(node_guid=guid, master_guid=master, generation=generation,
                                          previous_generation=previous, created_at=1, created_by="golden", resources=[])
            return PushRequest(expected_guid=expected, generation=document).wire()

        await recorder.call(fleet, "fleet-node:guid-mismatch", "PUT", "/api/fleet/v2/generation",
                            json=push("another-guid", 1, 0), headers=bearer)
        await recorder.call(fleet, "fleet-node:accept", "PUT", "/api/fleet/v2/generation", json=push(guid, 2, 1),
                            headers=bearer)
        await recorder.call(fleet, "fleet-node:stale-generation", "PUT", "/api/fleet/v2/generation",
                            json=push(guid, 1, 0), headers=bearer)
        await recorder.call(fleet, "fleet-node:digest-conflict", "PUT", "/api/fleet/v2/generation",
                            json={**push(guid, 2, 1), "generation": {**push(guid, 2, 1)["generation"],
                                                                     "created_by": "changed"}}, headers=bearer)
        await recorder.call(fleet, "fleet-node:foreign-master", "PUT", "/api/fleet/v2/generation",
                            json=push(guid, 3, 2, master="central-guid-2"), headers=bearer)
        await recorder.call(fleet, "fleet-node:extra-field", "PUT", "/api/fleet/v2/generation",
                            json={**push(guid, 3, 2), "surprise": 1}, headers=bearer)
        await recorder.call(fleet, "fleet-node:observed", "GET", "/api/fleet/v2/observed", headers=bearer)
    await recorder.call(http, "client:not-found", "GET", "/api/clients/nope")
    await recorder.call(http, "operation:not-found", "GET", "/api/operations/nope")
    await http.aclose()
    scenario_dbs["errors"] = server.db_path
    server.close()
    off = start_panel(work, name="metrics-off", metrics_enabled=False)
    off.create_admin("owner", PASSWORD)
    http = await owner_session(off)
    await recorder.call(http, "metrics:disabled", "GET", "/api/metrics/live")
    await http.aclose()
    off.close()
    write_json(out / "error_bodies.json", recorder.items)
    return {"exchanges": len(recorder.items)}


def record_audit(out: Path, scenario_dbs: dict) -> dict:
    found = {}
    for name, path in scenario_dbs.items():
        found[name] = {
            "audit_log": rows(path, "SELECT * FROM audit_log ORDER BY id"),
        }
        with contextlib.suppress(sqlite3.OperationalError):
            found[name]["events"] = rows(path, "SELECT * FROM events ORDER BY id")
    write_json(out / "audit.json", found)
    return {name: len(value["audit_log"]) for name, value in found.items()}


# -- main ----------------------------------------------------------------------------------------------

LAYOUT = {
    "keyring/keyring-N.json": "keyring files as `Keyring.save` writes them (1 key; 2 keys after rotate; narrowed)",
    "keyring/secret_versions.json": "secret_versions rows (base64 nonce/ciphertext, the exact AAD text, the "
                                    "plaintext) under each keyring: a Rust SecretStore must decrypt every row",
    "migrations/migrations.json": "every migration: version, name, checksum, exact statement text",
    "migrations/schema-vNN.json": "sqlite_master (rowid order) and schema_migrations after migrations 1..NN",
    "subscriptions/subscriptions.sqlite3": "database snapshot taken before the first fetch (with its master key "
                                           "subscriptions-master-key.json); open it with that keyring",
    "subscriptions/subscriptions.json": "GET/HEAD /s/{token} exchanges: request (path, query, Accept, User-Agent, "
                                        "If-None-Match, Host) → status, headers in order, body by sha256 in `bodies`",
    "clients/client_cursor.json": "GET /api/clients?limit=… pages following next_cursor, plus invalid cursors",
    "routing/routing.json": "routing preview/put/apply/explain/history/rollback per protocol and policy, and the "
                            "documents each manager double held after the apply",
    "fleet/fleet.json": "desired_generations (document_json, digest, content_digest, canonical wire JSON), "
                        "observed/managed rows on both sides and the central↔node HTTP exchanges",
    "links/tt_links.json": "tt:// deep links: encode_deeplink inputs → link → decode_deeplink",
    "errors/error_bodies.json": "status, headers and body of every error class (framework, auth, validation, "
                                "managers, routing codes, fleet refusals, node-side fleet conflicts, metrics)",
    "audit/audit.json": "audit_log rows (exact detail_json) and events of every scenario database",
}

async def main(out: Path, work: Path, commit: str | None = None) -> dict:
    index: dict = {
        "recorded_at": int(time.time()), "python": platform.python_version(),
        "panel_version": (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else None,
        "commit": commit or subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
                                           text=True).stdout.strip() or None,
        "synthetic": "every key, token, password and id here was generated for this recording in a throwaway "
                     "directory against in-memory manager doubles; none is in use anywhere",
        "sections": {},
        "layout": LAYOUT,
    }
    scenario_dbs: dict = {}

    async def section(name: str, coro_or_value):
        target = out / name
        target.mkdir(parents=True, exist_ok=True)
        try:
            value = await coro_or_value if asyncio.iscoroutine(coro_or_value) else coro_or_value
            index["sections"][name] = {"ok": True, **{k: v for k, v in (value or {}).items() if k != "server"}}
            return value
        except Exception:  # noqa: BLE001 - recorded, the other sections still run
            index["sections"][name] = {"ok": False, "error": traceback.format_exc()}
            return None

    await section("keyring", asyncio.to_thread(record_keyring, out / "keyring", work))
    await section("migrations", asyncio.to_thread(record_migrations, out / "migrations", work))
    subs = await section("subscriptions", record_subscriptions(out / "subscriptions", work, scenario_dbs))
    if subs:
        await section("clients", record_cursor(out / "clients", subs["server"], scenario_dbs))
    await section("routing", record_routing(out / "routing", work, scenario_dbs))
    await section("fleet", record_fleet(out / "fleet", work, scenario_dbs))
    await section("links", asyncio.to_thread(record_links, out / "links"))
    await section("errors", record_errors(out / "errors", work, subs and subs["server"], scenario_dbs))
    await section("audit", asyncio.to_thread(record_audit, out / "audit", scenario_dbs))
    if subs:
        subs["server"].close()
    errors = fake_managers.assertion_failures()
    if errors:
        index["fake_manager_assertions"] = errors
    fake_managers.close_all()
    return index


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "panel" / "tests" / "goldens")
    parser.add_argument("--commit", default=None, help="the source commit to name in index.json (default: git HEAD)")
    args = parser.parse_args()
    out = args.out.resolve()
    for child in ("keyring", "migrations", "subscriptions", "clients", "routing", "fleet", "links", "errors", "audit"):
        shutil.rmtree(out / child, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="panel-goldens-") as work:
        index = asyncio.run(main(out, Path(work), args.commit))
    write_json(out / "index.json", index)
    failed = [name for name, value in index["sections"].items() if not value.get("ok")]
    for name in failed:
        print(f"section {name} failed:\n{index['sections'][name]['error']}", file=sys.stderr)
    print(json.dumps({name: {k: v for k, v in value.items() if k != "error"} for name, value in index["sections"].items()},
                     indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
