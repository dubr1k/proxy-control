"""Live TrustTunnel check (access, subscription and traffic) against an installed node.

Run on the node itself (it resolves the gate name to 127.0.0.1) with the panel's own Python:
  TT_LIVE_PANEL=<panel domain> TT_LIVE_GATE=<trusttunnel domain> python scripts/lab/trusttunnel-live-check.py
Needs a node installed with [trusttunnel] enabled (routing: also [egress] router = true).
Prints statuses only; never passwords.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

PANEL = "https://" + os.environ["TT_LIVE_PANEL"]
GATE = os.environ["TT_LIVE_GATE"]
SECRETS = Path(os.environ.get("TT_LIVE_SECRETS", "/opt/mtproxy-shared443/secrets"))
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def connect_code(user, password):
    out = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15",
         "--resolve", f"{GATE}:443:127.0.0.1", "--proxy", f"https://{GATE}:443",
         "--proxy-user", f"{user}:{password}", "https://example.com/"],
        capture_output=True, text=True)
    return out.stdout.strip()


def toml_creds(toml_text):
    user = re.search(r'^username = "([^"]+)"', toml_text, re.M).group(1)
    password = re.search(r'^password = "([^"]+)"', toml_text, re.M).group(1)
    return user, password


c = httpx.Client(base_url=PANEL, timeout=30, follow_redirects=False)
page = c.get("/login")
csrf = c.cookies.get("panel_csrf")
pw = (SECRETS / "panel-bootstrap-password").read_text().strip()
r = c.post("/api/auth/login", json={"username": "owner", "password": pw}, headers={"X-CSRF-Token": csrf})
check("login", r.status_code in (200, 204), str(r.status_code))
if r.status_code not in (200, 204):
    sys.exit(1)
H = {"X-CSRF-Token": c.cookies.get("panel_csrf")}

me = c.get("/api/auth/me").json()
check("features.trusttunnel", me.get("features", {}).get("trusttunnel") is True)

ov = c.get("/api/trusttunnel/overview")
check("overview 200", ov.status_code == 200, str(ov.status_code))
ovj = ov.json()
check("overview status ok", ovj.get("status") == "ok", str(ovj.get("status")))
check("overview hostname", (ovj.get("endpoint") or {}).get("hostname") == GATE, str((ovj.get("endpoint") or {}).get("hostname")))
check("overview cert trusted", (ovj.get("endpoint") or {}).get("certificate_trusted") is True)
check("overview no placeholder", all(x.get("username") != "proxy-control-idle" for x in ovj.get("clients", [])))

client = c.post("/api/clients", json={"display_name": "TT Check"}, headers=H)
cid = client.json()["id"]
started = c.post(f"/api/clients/{cid}/grants", headers=H, json={"grants": [
    {"protocol": "trusttunnel", "runtime_username": "tt-check", "options": {"name": "Лаб TrustTunnel"}}]})
check("grant created", started.status_code == 200 and started.json().get("status") == "succeeded", started.text[:200])
grant = c.get(f"/api/clients/{cid}").json()["grants"][0]
gid = grant["id"]
check("learned hostname", grant["options"].get("hostname") == GATE, str(grant["options"].get("hostname")))
check("learned port 443", grant["options"].get("port") == 443, str(grant["options"].get("port")))


def reveal():
    issued = c.post(f"/api/clients/{cid}/links?grant_id={gid}", headers=H)
    issued.raise_for_status()
    got = c.get(f"/api/reveal/{issued.json()['reveal_token']}")
    got.raise_for_status()
    return {a["kind"]: a for a in got.json()["grants"][0]["artifacts"]}


arts = reveal()
check("artifact kinds", set(arts) == {"trusttunnel_link", "trusttunnel_toml"}, ",".join(sorted(arts)))
check("link scheme", arts["trusttunnel_link"]["value"].startswith("tt://?"))
check("link has QR", str(arts["trusttunnel_link"].get("qr", "")).startswith("data:image/svg+xml"))
check("toml has no QR", arts["trusttunnel_toml"].get("qr") is None)
user, password = toml_creds(arts["trusttunnel_toml"]["value"])

time.sleep(4)  # the manager restarts the endpoint to read the new client
check("CONNECT with right password -> 200", connect_code(user, password) == "200", connect_code(user, password))
check("CONNECT with wrong password refused", connect_code(user, "wrong-password-123") != "200")
check("CONNECT with idle placeholder name refused", connect_code("proxy-control-idle", "x" * 20) != "200")

d = c.post(f"/api/clients/grants/{gid}/disable", headers=H)
check("disable ok", d.status_code == 200, str(d.status_code))
time.sleep(4)
check("disabled client refused", connect_code(user, password) != "200")
e = c.post(f"/api/clients/grants/{gid}/enable", headers=H)
check("enable ok", e.status_code == 200, str(e.status_code))
time.sleep(4)
check("re-enabled client works", connect_code(user, password) == "200")

old = password
rot = c.post(f"/api/clients/grants/{gid}/rotate", headers=H)
check("rotate ok", rot.status_code == 200, str(rot.status_code))
time.sleep(4)
user2, password2 = toml_creds(reveal()["trusttunnel_toml"]["value"])
check("rotate changed password", password2 != old)
check("old password refused", connect_code(user2, old) != "200")
check("new password works", connect_code(user2, password2) == "200")

ov2 = c.get("/api/trusttunnel/overview").json()
row = next((x for x in ov2.get("clients", []) if x.get("username") == "tt-check"), None)
check("overview lists the access", row is not None)
if row:
    check("overview counts traffic", (row.get("download_bytes") or 0) > 0 and (row.get("upload_bytes") or 0) > 0,
          f"down={row.get('download_bytes')} up={row.get('upload_bytes')}")

# subscription: create for the client and read the clash/mihomo + raw + html feeds
sub = c.post(f"/api/clients/{cid}/subscription", headers=H, json={})
check("subscription exists", sub.status_code in (200, 201, 409), str(sub.status_code))
sub_url = None
try:
    sj = sub.json()
    sub_url = sj.get("url") or (sj.get("subscription") or {}).get("url")
except Exception:
    pass
if not sub_url:
    reveal_sub = c.post(f"/api/clients/{cid}/subscription/reveal", headers=H)
    try:
        rj = reveal_sub.json()
        sub_url = rj.get("url") or (rj.get("subscription") or {}).get("url")
        if not sub_url and rj.get("reveal_token"):
            got = c.get(f"/api/reveal/{rj['reveal_token']}").json()
            sub_url = got.get("url") or (got.get("subscription") or {}).get("url") or got.get("subscription_url")
            if not sub_url:
                print("reveal payload keys:", sorted(got.keys()))
    except Exception:
        sub_url = None
check("subscription url known", bool(sub_url))
if sub_url:
    for fmt, needle in (("clash", "type: 'trusttunnel'"), ("raw", "tt://?"), ("html", "TrustTunnel")):
        resp = httpx.get(sub_url, params={"format": fmt}, timeout=30, headers={"User-Agent": "lab"})
        body = resp.text
        check(f"subscription {fmt} carries trusttunnel", resp.status_code == 200 and (needle in body or needle.replace("'", '"') in body or "trusttunnel" in body.lower()),
              f"{resp.status_code}")
    resp = httpx.get(sub_url, params={"format": "singbox"}, timeout=30)
    check("subscription singbox leaves it out cleanly", resp.status_code == 200 and "trusttunnel" not in resp.text.lower().replace("no trusttunnel outbound", ""), str(resp.status_code))

# cleanup
dele = c.post(f"/api/clients/grants/{gid}/delete", headers=H)
check("delete ok", dele.status_code in (200, 204), str(dele.status_code))
time.sleep(4)
check("deleted client refused", connect_code(user2, password2) != "200")

bad = [n for n, ok, _ in results if not ok]
print(f"\nTOTAL {len(results)} checks, FAILED {len(bad)}: {bad}")
sys.exit(1 if bad else 0)
