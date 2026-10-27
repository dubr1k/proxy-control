"""Live TrustTunnel check (routing through the Xray-router) against an installed node.

Run on the lab node itself (it resolves the gate name to 127.0.0.1), using the external
dev venv installed from panel/requirements-dev.txt, not an installed panel interpreter:
  TT_LIVE_PANEL=<panel domain> TT_LIVE_GATE=<trusttunnel domain> .venv/bin/python scripts/lab/trusttunnel-live-routing.py
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


def code(user, password, url):
    out = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20",
         "--resolve", f"{GATE}:443:127.0.0.1", "--proxy", f"https://{GATE}:443",
         "--proxy-user", f"{user}:{password}", url],
        capture_output=True, text=True)
    return out.stdout.strip()


c = httpx.Client(base_url=PANEL, timeout=60)
c.get("/login")
pw = (SECRETS / "panel-bootstrap-password").read_text().strip()
r = c.post("/api/auth/login", json={"username": "owner", "password": pw}, headers={"X-CSRF-Token": c.cookies.get("panel_csrf")})
check("login", r.status_code in (200, 204), str(r.status_code))
H = {"X-CSRF-Token": c.cookies.get("panel_csrf")}

cid = c.post("/api/clients", json={"display_name": "TT Route"}, headers=H).json()["id"]
started = c.post(f"/api/clients/{cid}/grants", headers=H, json={"grants": [
    {"protocol": "trusttunnel", "runtime_username": "tt-route", "options": {}}]})
check("grant created", started.status_code == 200 and started.json().get("status") == "succeeded", started.text[:160])
gid = c.get(f"/api/clients/{cid}").json()["grants"][0]["id"]
issued = c.post(f"/api/clients/{cid}/links?grant_id={gid}", headers=H).json()["reveal_token"]
toml = {a["kind"]: a for a in c.get(f"/api/reveal/{issued}").json()["grants"][0]["artifacts"]}["trusttunnel_toml"]["value"]
user = re.search(r'^username = "([^"]+)"', toml, re.M).group(1)
password = re.search(r'^password = "([^"]+)"', toml, re.M).group(1)
time.sleep(5)

check("baseline example.com 200", code(user, password, "https://example.com/") == "200", code(user, password, "https://example.com/"))
check("baseline example.org 200", code(user, password, "https://example.org/") == "200")

targets = c.get("/api/routing/targets").json()["items"]
tt = [t for t in targets if t.get("protocol") == "trusttunnel"]
check("targets list trusttunnel", len(tt) == 1, json.dumps(tt)[:200] if tt else "none")
check("trusttunnel not attached yet", tt and tt[0].get("attached_to_router") in (False, None), json.dumps(tt[0])[:300] if tt else "")

att = c.post("/api/routing/targets/local/trusttunnel/attach", headers=H)
check("attach ok", att.status_code == 200, f"{att.status_code} {att.text[:240]}")

policy = {"default_action": "direct", "fallback": "fail_closed", "rules": [
    {"match": {"domains": ["example.com"]}, "action": "block", "note": "live check"}]}
put = c.put("/api/routing/policies/local/trusttunnel", headers=H, json={**policy, "expected_revision": None})
check("policy saved", put.status_code == 200, f"{put.status_code} {put.text[:200]}")
rev = put.json().get("revision") if put.status_code == 200 else None
prev = c.post("/api/routing/policies/local/trusttunnel/preview", headers=H, json=policy)
check("preview ok", prev.status_code == 200, f"{prev.status_code} {prev.text[:200]}")
app = c.post("/api/routing/policies/local/trusttunnel/apply", headers=H, json={"expected_revision": rev})
check("apply ok", app.status_code == 200, f"{app.status_code} {app.text[:300]}")
time.sleep(8)

blocked = code(user, password, "https://example.com/")
other = code(user, password, "https://example.org/")
check("blocked domain refused through the router", blocked != "200", blocked)
check("other domain still works through the router", other == "200", other)

ex = c.post("/api/routing/policies/local/trusttunnel/explain", headers=H, json={"host": "example.com", "port": 443})
check("explain says block", ex.status_code == 200 and "block" in ex.text.lower(), f"{ex.status_code} {ex.text[:160]}")

lane = c.post(f"/api/routing/lanes/{gid}", headers=H, json={"mode": "own"})
check("lane refused with lanes_unsupported", lane.status_code in (409, 422) and "lanes_unsupported" in lane.text, f"{lane.status_code} {lane.text[:160]}")

det = c.post("/api/routing/targets/local/trusttunnel/detach", headers=H)
check("detach ok", det.status_code == 200, f"{det.status_code} {det.text[:200]}")
time.sleep(8)
check("after detach example.com works again", code(user, password, "https://example.com/") == "200", code(user, password, "https://example.com/"))

c.post(f"/api/clients/grants/{gid}/delete", headers=H)
bad = [n for n, ok, _ in results if not ok]
print(f"\nTOTAL {len(results)} checks, FAILED {len(bad)}: {bad}")
sys.exit(1 if bad else 0)
