"""Issue AmneziaWG accesses through a real panel app against a real awg-manager socket.

Lab helper for `awg-panel-e2e.sh`: a native panel process talks to the manager over its
Unix socket exactly as in production. Set `PANEL_RUST_BIN` to the built panel binary;
the issued configs are written to the output directory for the client side of the test.

  python scripts/lab/awg_panel_issue.py issue  <repo> <socket> <token-file> <outdir>
  python scripts/lab/awg_panel_issue.py action <repo> <socket> <token-file> <outdir> <disable|enable|rotate> <version>
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import json
import sys
import tempfile
from contextlib import asynccontextmanager, closing
from pathlib import Path

VERSIONS = ("1.5", "2.0", "3.1")


@asynccontextmanager
async def session(repo: str, socket: str, token_file: str, workdir: Path):
    import httpx

    source = Path(repo).resolve()
    workdir = workdir.resolve()
    binary = Path(os.environ.get("PANEL_RUST_BIN", str(source / "panel/target/debug/panel"))).resolve()
    if not binary.is_file():
        raise RuntimeError(f"build the native panel first or set PANEL_RUST_BIN: {binary}")
    database = workdir / "panel.sqlite3"
    key = workdir / "master-key"
    with tempfile.TemporaryDirectory(prefix="pc-awg-panel-") as temporary:
        listener = Path(temporary) / "panel.sock"
        env = {name: os.environ[name] for name in ("PATH", "HOME", "LANG") if name in os.environ}
        env.update({
            "PANEL_DATABASE": str(database), "PANEL_MASTER_KEY_FILE": str(key),
            "PANEL_LISTEN": f"unix:{listener}", "PANEL_ALLOWED_HOSTS": "testserver",
            "PANEL_COOKIE_SECURE": "false", "PANEL_METRICS_ENABLED": "false",
            "PANEL_STATIC_DIR": str(source / "panel/static"), "PANEL_VERSION_FILE": str(source / "VERSION"),
            "TELEMT_API_URL": "http://127.0.0.1:1", "VERSION_AGENT_SOCKET": str(workdir / "none.sock"),
            "AMNEZIAWG_ENABLED": "true", "AMNEZIAWG_PUBLIC_HOST": "vpn.lab.example",
            "AWG_MANAGER_SOCKET": socket, "AWG_MANAGER_TOKEN_FILE": str(Path(token_file).resolve()),
        })

        def cli(*args: str, stdin: str = "") -> None:
            subprocess.run([str(binary), "cli", "--database", str(database), *args], input=stdin,
                           capture_output=True, text=True, check=True, timeout=60, env=env)

        if not key.exists():
            cli("master-key-init", "--path", str(key))
        owner_exists = False
        if database.is_file():
            with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as stored:
                owner_exists = stored.execute("SELECT 1 FROM admins WHERE username='owner'").fetchone() is not None
        password = "lab password for the e2e run"
        if not owner_exists:
            cli("create-admin", "--username", "owner", "--role", "owner", "--password-stdin", stdin=password + "\n")
        with (workdir / "native-panel.log").open("ab") as log:
            process = subprocess.Popen([str(binary)], env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        client = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(listener)), base_url="http://testserver")
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 30
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"native panel exited with {process.returncode}; see {workdir / 'native-panel.log'}")
                try:
                    if (await client.get("/healthz")).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if loop.time() >= deadline:
                    raise RuntimeError("native panel did not become healthy")
                await asyncio.sleep(0.05)
            page = await client.get("/login")
            logged_in = await client.post("/api/auth/login", json={"username": "owner", "password": password},
                                          headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
            logged_in.raise_for_status()
            yield client, {"X-CSRF-Token": client.cookies["panel_csrf"]}
        finally:
            await client.aclose()
            if process.poll() is None:
                process.terminate()
                try:
                    await asyncio.to_thread(process.wait, timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    await asyncio.to_thread(process.wait)


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
    async with session(repo, socket, token_file, work) as (client, headers):
        if mode == "issue":
            created = await client.post("/api/clients", json={"display_name": "E2E"}, headers=headers)
            client_id = created.json()["id"]
            started = await client.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
                {"protocol": "amneziawg", "runtime_username": f"e2e-awg{v.replace('.', '')}", "options": {"version": v}}
                for v in VERSIONS]})
            assert started.status_code == 200 and started.json()["status"] == "succeeded", (
                started.status_code, started.json().get("status")
            )
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


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
