"""Does a sing-box FORK core load and run the TrustTunnel outbound the panel's feed emits?

Run on the disposable lab node itself (it resolves the gate name to 127.0.0.1),
with an external lab Python controller and the installed native panel:

  TT_LIVE_PANEL=<panel domain> TT_LIVE_GATE=<trusttunnel domain> \\
  TT_FORK_CORE=/root/fork-core/hiddify-sing-box TT_FORK_LABEL=hiddify@<commit> \\
  TT_OFFICIAL_CORE=/root/fork-core/official/sing-box-1.14.3-linux-amd64/sing-box \\
  .venv/bin/python scripts/lab/trusttunnel-fork-core-check.py

What it does: makes a throw-away client with a TrustTunnel access on the live panel,
requests its actual native HTTP sing-box subscription for the User-Agent
`Throne/1.1.4` and for `?client=hiddify`, wraps the outbounds into a runnable config
(a mixed inbound on 127.0.0.1:19090, `route.final` = the TrustTunnel outbound), then
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


PORT = 19090
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def version(binary):
    out = subprocess.run([binary, "version"], capture_output=True, text=True)
    return (out.stdout.splitlines() or ["?"])[0]


def feed(http, subscription_url, agent, client=None):
    """Request the installed native renderer; never import a production Python module."""
    params = {"format": "singbox"}
    if client:
        params["client"] = client
    response = http.get(subscription_url, params=params, headers={"User-Agent": agent})
    if response.status_code != 200:
        raise RuntimeError(f"native subscription feed failed: HTTP {response.status_code}")
    body = response.json()
    return body["proxy_control"]["client"], body


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


def main():
    panel = "https://" + os.environ["TT_LIVE_PANEL"]
    gate = os.environ["TT_LIVE_GATE"]
    fork = os.environ["TT_FORK_CORE"]
    label = os.environ.get("TT_FORK_LABEL", Path(fork).name)
    official = os.environ.get("TT_OFFICIAL_CORE", "")
    secrets = Path(os.environ.get("TT_LIVE_SECRETS", "/opt/mtproxy-shared443/secrets"))
    with httpx.Client(base_url=panel, timeout=30, follow_redirects=False) as c, tempfile.TemporaryDirectory(prefix="tt-fork-") as directory:
        work = Path(directory)
        c.get("/login")
        password = (secrets / "panel-bootstrap-password").read_text().strip()
        r = c.post("/api/auth/login", json={"username": "owner", "password": password},
                   headers={"X-CSRF-Token": c.cookies["panel_csrf"]})
        check("login", r.status_code in (200, 204), str(r.status_code))
        if r.status_code not in (200, 204):
            return 1
        headers = {"X-CSRF-Token": c.cookies["panel_csrf"]}
        cid = c.post("/api/clients", json={"display_name": "TT fork check", "subscription": False}, headers=headers).json()["id"]
        gid = None
        proc = None
        try:
            started = c.post(f"/api/clients/{cid}/grants", headers=headers, json={"grants": [
                {"protocol": "trusttunnel", "runtime_username": "tt-fork-check", "options": {"name": "fork check"}}]})
            check("access created", started.status_code == 200 and started.json().get("status") == "succeeded", str(started.status_code))
            gid = c.get(f"/api/clients/{cid}").json()["grants"][0]["id"]
            subscription = c.post(f"/api/clients/{cid}/subscription", headers=headers)
            if subscription.status_code != 201:
                raise RuntimeError(f"native subscription creation failed: HTTP {subscription.status_code}")
            revealed = c.get(f"/api/reveal/{subscription.json()['reveal_token']}")
            if revealed.status_code != 200:
                raise RuntimeError(f"native subscription reveal failed: HTTP {revealed.status_code}")
            subscription_url = revealed.json()["url"]
            time.sleep(4)  # the manager restarts the endpoint to read the new client
            print(f"fork core: {label}  {version(fork)}")
            config_path = work / "config.json"
            for title, agent, client in (
                ("User-Agent Throne/1.1.4", "Throne/1.1.4", None),
                ("?client=hiddify", "sing-box 1.13.0", "hiddify"),
            ):
                chosen, body = feed(c, subscription_url, agent, client)
                types = [o["type"] for o in body["outbounds"]]
                check(f"{title}: the feed carries trusttunnel (cut {chosen})", types == ["trusttunnel"], ",".join(types))
                outbound = body["outbounds"][0]
                check(f"{title}: schema keys", set(outbound) == {"type", "tag", "server", "server_port", "username", "password", "quic", "tls"}
                      and outbound["quic"] is False and outbound["tls"]["server_name"] == gate, ",".join(sorted(outbound)))
                config_path.write_text(json.dumps(config_of(body)))
                config_path.chmod(0o600)
                done = subprocess.run([fork, "check", "-c", str(config_path)], capture_output=True, text=True)
                check(f"{title}: fork core `check`", done.returncode == 0, f"exit={done.returncode}")
                if official:
                    refused = subprocess.run([official, "check", "-c", str(config_path)], capture_output=True, text=True)
                    check(f"{title}: OFFICIAL sing-box refuses it ({version(official)})", refused.returncode != 0, f"exit={refused.returncode}")
            _, official_agent = feed(c, subscription_url, "sing-box 1.13.0")
            check("official User-Agent keeps the feed without trusttunnel", official_agent["outbounds"] == []
                  and official_agent["proxy_control"]["unsupported"][0]["protocol"] == "trusttunnel")
            # Native core diagnostics may contain credentials: retain no log payload.
            proc = subprocess.Popen([fork, "run", "-c", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(30):
                with socket.socket() as probe:
                    probe.settimeout(0.5)
                    if probe.connect_ex(("127.0.0.1", PORT)) == 0:
                        break
                time.sleep(0.5)
            done = subprocess.run(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "25", "--proxy", f"socks5h://127.0.0.1:{PORT}", "https://example.com/"],
                capture_output=True, text=True)
            check("fork core `run`: example.com through the TrustTunnel outbound -> 200",
                  done.stdout.strip() == "200", f"curl_exit={done.returncode}")
            row = None
            for _ in range(12):
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
                    proc.wait(5)
            if gid:
                deleted = c.post(f"/api/clients/grants/{gid}/delete", headers=headers)
                check("throw-away access deleted", deleted.status_code in (200, 204), str(deleted.status_code))
            archived = c.post(f"/api/clients/{cid}/state", headers=headers, json={"state": "archived"})
            print("client archived:", archived.status_code)
    bad = [name for name, ok, _ in results if not ok]
    print(f"\nTOTAL {len(results)} checks, FAILED {len(bad)}: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
