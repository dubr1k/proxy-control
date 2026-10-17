"""Issue AmneziaWG accesses through a real panel app against a real awg-manager socket.

Lab helper for `awg-panel-e2e.sh`: the panel runs in-process (ASGI), talks to the manager over its
Unix socket exactly as in production, and the configs it hands out are written to the output
directory for the client side of the test to use.

  python scripts/lab/awg_panel_issue.py issue  <repo> <socket> <token-file> <outdir>
  python scripts/lab/awg_panel_issue.py action <repo> <socket> <token-file> <outdir> <disable|enable|rotate> <version>
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

VERSIONS = ("1.5", "2.0", "3.1")


async def session(repo: str, socket: str, token_file: str, workdir: Path):
    sys.path.insert(0, repo)
    import httpx

    from panel.amneziawg import AmneziawgClient
    from panel.app import Settings, create_app
    from panel.keyring import Keyring
    from panel.mieru import MemoryMieru
    from panel.naive import MemoryNaive
    from panel.telemt import MemoryTelemt
    from panel.versions import VersionClient

    key = workdir / "master-key"
    if not key.exists():
        Keyring.generate().save(key)
    settings = Settings(
        database_path=workdir / "panel.sqlite3", master_key_file=key, session_cookie_secure=False,
        allowed_hosts=("testserver",), reveal_ttl_seconds=120, amneziawg_enabled=True,
        amneziawg_public_host="vpn.lab.example", naive_public_host="vpn.lab.example", vnext_writer="domain",
    )
    app = create_app(settings, telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(),
                     amneziawg=AmneziawgClient(socket, Path(token_file).read_text().strip()),
                     version_client=VersionClient(str(workdir / "none.sock")))
    if not app.state.store.has_admin() if hasattr(app.state.store, "has_admin") else True:
        try:
            app.state.store.create_admin("owner", "lab password for the e2e run", "owner")
        except Exception:  # noqa: BLE001 - the admin already exists on the second call
            pass
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")
    page = await client.get("/login")
    await client.post("/api/auth/login", json={"username": "owner", "password": "lab password for the e2e run"},
                      headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
    return client, {"X-CSRF-Token": client.cookies["panel_csrf"]}


async def config_of(client, headers, client_id: str, grant_id: str) -> str:
    issued = await client.post(f"/api/clients/{client_id}/links?grant_id={grant_id}", headers=headers)
    issued.raise_for_status()
    revealed = await client.get(f"/api/reveal/{issued.json()['reveal_token']}")
    revealed.raise_for_status()
    [artifact] = revealed.json()["grants"][0]["artifacts"]
    assert artifact["media_type"] == "text/x-amneziawg-conf" and artifact["qr"].startswith("data:image/svg+xml")
    return artifact["value"]


async def main() -> int:
    mode, repo, socket, token_file, outdir = sys.argv[1:6]
    out = Path(outdir)
    work = out / "panel"
    work.mkdir(parents=True, exist_ok=True)
    client, headers = await session(repo, socket, token_file, work)
    try:
        if mode == "issue":
            created = await client.post("/api/clients", json={"display_name": "E2E"}, headers=headers)
            client_id = created.json()["id"]
            started = await client.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
                {"protocol": "amneziawg", "runtime_username": f"e2e-awg{v.replace('.', '')}", "options": {"version": v}}
                for v in VERSIONS]})
            assert started.status_code == 200 and started.json()["status"] == "succeeded", started.text
            grants = (await client.get(f"/api/clients/{client_id}")).json()["grants"]
            index = {"client_id": client_id, "grants": {}}
            for grant in grants:
                version = grant["options"]["version"]
                (out / f"{version}.conf").write_text(await config_of(client, headers, client_id, grant["id"]))
                index["grants"][version] = {"id": grant["id"], "username": grant["runtime_username"],
                                            "address": grant["options"]["address"], "port": grant["options"]["port"]}
            (out / "index.json").write_text(json.dumps(index, indent=1))
            print("issued", sorted(index["grants"]))
            return 0
        action, version = sys.argv[6:8]
        index = json.loads((out / "index.json").read_text())
        grant = index["grants"][version]
        answer = await client.post(f"/api/clients/grants/{grant['id']}/{action}", headers=headers)
        answer.raise_for_status()
        if action == "rotate":
            (out / f"{version}.conf").write_text(await config_of(client, headers, index["client_id"], grant["id"]))
        print(action, version, "ok")
        return 0
    finally:
        await client.aclose()


if __name__ == "__main__":
    tempfile.tempdir = None
    raise SystemExit(asyncio.run(main()))
