"""Does a sing-box FORK core load and run the TrustTunnel outbound the panel's feed emits?

Run on the lab node itself (it resolves the gate name to 127.0.0.1), from a checkout, with the
panel's own Python so the renderer under test is the checkout's:

  TT_LIVE_PANEL=<panel domain> TT_LIVE_GATE=<trusttunnel domain> \\
  TT_FORK_CORE=/root/fork-core/hiddify-sing-box TT_FORK_LABEL=hiddify@<commit> \\
  TT_OFFICIAL_CORE=/root/fork-core/official/sing-box-1.14.3-linux-amd64/sing-box \\
  .venv/bin/python scripts/lab/trusttunnel-fork-core-check.py

What it does: makes a throw-away client with a TrustTunnel access on the live panel, takes the access's
`tt://` link from the panel, builds the sing-box feed with the checkout's renderer for the User-Agent
`Throne/1.1.4` and for `?client=hiddify`, wraps the outbounds into a runnable config (a mixed inbound
on 127.0.0.1:19090, `route.final` = the TrustTunnel outbound), then
  1. `check` with the fork core must pass and `check` with the OFFICIAL core must refuse (the reason the
     default feed never carries the outbound for an official User-Agent);
  2. `run` with the fork core, `curl --proxy socks5h://127.0.0.1:19090 https://example.com/` must give 200
     and the gate's overview must count traffic for the access;
  3. the throw-away client is deleted at the end.
Prints PASS/FAIL lines and statuses only; never a password. The cores are downloaded by hand and kept
outside the repository (verify their sha256 against the release).
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from panel.protocols.base import AccessArtifact  # noqa: E402
from panel.subscription_routes import fork_client  # noqa: E402
from panel.subscriptions.models import Manifest, ManifestGrant  # noqa: E402
from panel.subscriptions.renderers.singbox import SingboxRenderer  # noqa: E402

PANEL = "https://" + os.environ["TT_LIVE_PANEL"]
GATE = os.environ["TT_LIVE_GATE"]
FORK = os.environ["TT_FORK_CORE"]
LABEL = os.environ.get("TT_FORK_LABEL", Path(FORK).name)
OFFICIAL = os.environ.get("TT_OFFICIAL_CORE", "")
SECRETS = Path(os.environ.get("TT_LIVE_SECRETS", "/opt/mtproxy-shared443/secrets"))
PORT = 19090
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def version(binary):
    out = subprocess.run([binary, "version"], capture_output=True, text=True)
    return (out.stdout.splitlines() or ["?"])[0]


def feed(link, grant, agent, client=None):
    """The checkout's sing-box feed for one request: the User-Agent decides unless `client` is explicit."""
    manifest = Manifest(client_id="c", client_name="TT fork check", generation=1, grants=[grant])
    artifacts = {grant.grant_id: [AccessArtifact(kind="trusttunnel_link", label="link", media_type="text/uri-list", value=link)]}
    chosen = client or fork_client(agent) or "karing"
    return chosen, json.loads(SingboxRenderer().render(manifest, artifacts, client=chosen))


def config_of(feed_json):
    outbounds = [o for o in feed_json["outbounds"] if o["type"] == "trusttunnel"]
    if os.environ.get("TT_DROP_KEYS"):  # diagnosis only: run the core with some keys removed
        for key in os.environ["TT_DROP_KEYS"].split(","):
            outbounds[0].pop(key, None)
    return {
        "log": {"level": "info"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": PORT}],
        "outbounds": [*outbounds, {"type": "direct", "tag": "direct"}],
        "route": {"final": outbounds[0]["tag"] if outbounds else "direct"},
    }


c = httpx.Client(base_url=PANEL, timeout=30, follow_redirects=False)
c.get("/login")
pw = (SECRETS / "panel-bootstrap-password").read_text().strip()
r = c.post("/api/auth/login", json={"username": "owner", "password": pw}, headers={"X-CSRF-Token": c.cookies.get("panel_csrf")})
check("login", r.status_code in (200, 204), str(r.status_code))
if r.status_code not in (200, 204):
    sys.exit(1)
H = {"X-CSRF-Token": c.cookies.get("panel_csrf")}
cid = c.post("/api/clients", json={"display_name": "TT fork check"}, headers=H).json()["id"]
gid = None
proc = None
try:
    started = c.post(f"/api/clients/{cid}/grants", headers=H, json={"grants": [
        {"protocol": "trusttunnel", "runtime_username": "tt-fork-check", "options": {"name": "fork check"}}]})
    check("access created", started.status_code == 200 and started.json().get("status") == "succeeded", str(started.status_code))
    grant_row = c.get(f"/api/clients/{cid}").json()["grants"][0]
    gid = grant_row["id"]
    issued = c.post(f"/api/clients/{cid}/links?grant_id={gid}", headers=H)
    got = c.get(f"/api/reveal/{issued.json()['reveal_token']}").json()
    link = {a["kind"]: a for a in got["grants"][0]["artifacts"]}["trusttunnel_link"]["value"]
    manifest_grant = ManifestGrant(
        grant_id=gid, protocol="trusttunnel", node_id=grant_row["node_id"], endpoint_id=grant_row["endpoint_id"],
        runtime_username="tt-fork-check", secret_version=1, options=grant_row["options"], enabled=True)
    time.sleep(4)  # the manager restarts the endpoint to read the new client

    print(f"fork core: {LABEL}  {version(FORK)}")
    for title, agent, client in (("User-Agent Throne/1.1.4", "Throne/1.1.4", None), ("?client=hiddify", "sing-box 1.13.0", "hiddify")):
        chosen, body = feed(link, manifest_grant, agent, client)
        types = [o["type"] for o in body["outbounds"]]
        check(f"{title}: the feed carries trusttunnel (cut {chosen})", types == ["trusttunnel"], ",".join(types))
        outbound = body["outbounds"][0]
        check(f"{title}: schema keys", set(outbound) == {"type", "tag", "server", "server_port", "username", "password", "quic", "tls"}
              and outbound["quic"] is False and outbound["tls"]["server_name"] == GATE, ",".join(sorted(outbound)))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(config_of(body), handle)
        done = subprocess.run([FORK, "check", "-c", handle.name], capture_output=True, text=True)
        check(f"{title}: fork core `check`", done.returncode == 0, (done.stderr or done.stdout).strip()[:200].replace(outbound["password"], "***"))
        if OFFICIAL:
            refused = subprocess.run([OFFICIAL, "check", "-c", handle.name], capture_output=True, text=True)
            text = (refused.stderr or refused.stdout).strip().replace(outbound["password"], "***")
            check(f"{title}: OFFICIAL sing-box refuses it ({version(OFFICIAL)})", refused.returncode != 0, text[:200])
        config_path = handle.name

    _, official_agent = feed(link, manifest_grant, "sing-box 1.13.0")
    check("official User-Agent keeps the feed without trusttunnel", official_agent["outbounds"] == []
          and official_agent["proxy_control"]["unsupported"][0]["protocol"] == "trusttunnel")

    core_log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)
    proc = subprocess.Popen([FORK, "run", "-c", config_path], stdout=core_log, stderr=subprocess.STDOUT)
    for _ in range(30):  # the mixed inbound is up when the port accepts
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", PORT)) == 0:
                break
        time.sleep(0.5)
    done = subprocess.run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "25", "--proxy", f"socks5h://127.0.0.1:{PORT}", "https://example.com/"],
        capture_output=True, text=True)
    code = done.stdout.strip()
    core_log.flush()
    tail = Path(core_log.name).read_text()[-600:].replace(outbound["password"], "***")
    check("fork core `run`: example.com through the TrustTunnel outbound -> 200", code == "200", f"{code} {done.stderr.strip()[:120]}" + ("" if code == "200" else f" core: {tail}"))
    row = None
    for _ in range(12):  # the manager's counters are polled, not pushed
        time.sleep(5)
        rows = c.get("/api/trusttunnel/overview").json().get("clients", [])
        row = next((x for x in rows if x.get("username") == "tt-fork-check"), None)
        if row and (row.get("download_bytes") or 0) > 0:
            break
    check("gate overview counts the traffic", bool(row) and (row.get("download_bytes") or 0) > 0 and (row.get("upload_bytes") or 0) > 0,
          f"down={row and row.get('download_bytes')} up={row and row.get('upload_bytes')}")
finally:
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
    if gid:
        deleted = c.post(f"/api/clients/grants/{gid}/delete", headers=H)
        check("throw-away access deleted", deleted.status_code in (200, 204), str(deleted.status_code))
    archived = c.post(f"/api/clients/{cid}/state", headers=H, json={"state": "archived"})
    print("client archived:", archived.status_code)

bad = [n for n, ok, _ in results if not ok]
print(f"\nTOTAL {len(results)} checks, FAILED {len(bad)}: {bad}")
sys.exit(1 if bad else 0)
