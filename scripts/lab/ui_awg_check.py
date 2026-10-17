"""Real-browser check of the AmneziaWG screens: the version columns of the placement matrix and the
access window with the config, its QR and the download. Lab helper (headless Chrome, memory manager).

  python scripts/lab/ui_awg_check.py [repo]
"""
# ruff: noqa: E401, E701, E702
import base64, json, subprocess, sys, tempfile, threading, time, urllib.request
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")
from pathlib import Path
import httpx, uvicorn
from panel.amneziawg import MemoryAmneziawg
from panel.app import Settings, create_app
from panel.keyring import Keyring
from panel.naive import MemoryNaive
from panel.mieru import MemoryMieru
from panel.telemt import MemoryTelemt
from panel.versions import VersionClient
from panel.tests.test_mobile_layout import DevTools

tmp = Path(tempfile.mkdtemp())
key = tmp / "key"; Keyring.generate().save(key)
settings = Settings(database_path=tmp / "p.sqlite3", master_key_file=key, session_cookie_secure=False,
                    allowed_hosts=("127.0.0.1", "127.0.0.1:18787"), naive_public_host="naive.example.com",
                    naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True, amneziawg_public_host="vpn.example.com",
                    version_agent_socket=str(tmp / "none.sock"))
app = create_app(settings, telemt=MemoryTelemt(public_host="x.example"), naive=MemoryNaive(), mieru=MemoryMieru(), amneziawg=MemoryAmneziawg(),
                 version_client=VersionClient(str(tmp / "none.sock")))
app.state.store.create_admin("owner", "correct horse battery staple", "owner")
server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=18787, log_level="warning"))
threading.Thread(target=server.run, daemon=True).start()
time.sleep(2)

base = "http://127.0.0.1:18787"
http = httpx.Client(base_url=base)
page = http.get("/login"); csrf = http.cookies["panel_csrf"]
r = http.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"}, headers={"X-CSRF-Token": csrf})
assert r.status_code in (200, 204), (r.status_code, r.text[:200])
csrf = http.cookies["panel_csrf"]; h = {"X-CSRF-Token": csrf}
cid = http.post("/api/clients", json={"display_name": "samsung"}, headers=h).json()["id"]

profile = tmp / "chrome"
proc = subprocess.Popen(["google-chrome", "--headless", "--no-sandbox", "--disable-gpu", "--remote-allow-origins=*",
                         "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    port = None
    for _ in range(600):
        try:
            lines = (profile / "DevToolsActivePort").read_text().splitlines()
            if len(lines) >= 2: port = int(lines[0]); break
        except Exception: pass
        time.sleep(0.1)
    targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list"))
    dt = DevTools(next(t["webSocketDebuggerUrl"] for t in targets if t["type"] == "page"))
    dt.call("Emulation.setDeviceMetricsOverride", {"width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": False})
    dt.call("Network.enable")
    for name in ("panel_session", "panel_csrf"):
        if name in http.cookies:
            dt.call("Network.setCookie", {"name": name, "value": http.cookies[name], "url": base})
    errors = []
    def ev(expr):
        r = dt.call("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in r: errors.append(str(r["exceptionDetails"])[:300])
        return r["result"].get("value")
    def shot(name):
        img = dt.call("Page.captureScreenshot", {"format": "png"})
        Path(f"/root/ui-awg-{name}.png").write_bytes(base64.b64decode(img["data"]))
    def wait(expr, label, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if ev(expr): return
            time.sleep(0.2)
        shot("timeout-" + label); raise SystemExit(f"TIMEOUT waiting for {label}")

    dt.call("Page.navigate", {"url": base + "/#clients"})
    wait("!!document.querySelector('[data-client-id] [data-client-action=placement]')", "client-card")
    ev("document.querySelector('[data-client-id] [data-client-action=placement]').click()")
    wait("!!document.querySelector('#placement-body input[data-protocol]')", "placement-matrix")
    heads = ev("[...document.querySelectorAll('#placement-body thead th')].map(t=>t.textContent.trim())")
    assert heads[1:] == ["MTProxy", "NaiveProxy", "Mieru", "AmneziaWG 1.5", "AmneziaWG 2.0", "AmneziaWG 3.1"], heads
    shot("matrix")
    if ev("!document.querySelector('#placement-username-row').hidden"):
        ev("document.querySelector('#placement-username').value='samsung'")
    ev("document.querySelector('#placement-body input[data-protocol=\"amneziawg:1.5\"]').click()")
    ev("document.querySelector('#placement-body input[data-protocol=\"amneziawg:3.1\"]').click()")
    ev("document.querySelector('#placement-actions button[data-placement-action=apply]').click()")
    end = time.time() + 20
    while time.time() < end:
        grants = http.get(f"/api/clients/{cid}").json()["grants"]
        if len([g for g in grants if g["protocol"] == "amneziawg"]) == 2: break
        time.sleep(0.3)
    awg = {g["options"]["version"]: g for g in http.get(f"/api/clients/{cid}").json()["grants"] if g["protocol"] == "amneziawg"}
    assert sorted(awg) == ["1.5", "3.1"], awg
    assert awg["1.5"]["runtime_username"] == "samsung-awg15" and awg["3.1"]["runtime_username"] == "samsung-awg31"
    assert awg["3.1"]["options"]["port"] == 51822 and awg["3.1"]["observed_state"] == "enabled"
    # the issued-links dialog shows each config as a text area with its QR and a download
    wait("document.querySelector('#bundle-modal')?.open && document.querySelectorAll('#bundle-body textarea.awg-conf').length === 2", "bundle-dialog")
    titles = ev("[...document.querySelectorAll('#bundle-body h3')].map(e=>e.textContent.trim())")
    assert titles == ["AmneziaWG · samsung-awg15", "AmneziaWG · samsung-awg31"], titles
    assert ev("document.querySelectorAll('#bundle-body img.link-qr').length") == 2
    assert ev("[...document.querySelectorAll('#bundle-body a[download]')].map(a=>a.download).sort().join()") == "samsung-awg15.conf,samsung-awg31.conf"
    assert ev("document.querySelector('#bundle-body textarea.awg-conf').value.split('\\n').length") > 10
    shot("bundle")
    ev("document.querySelector('#bundle-modal').close()")
    time.sleep(0.3)
    assert "AmneziaWG выдаётся файлом" in ev("document.querySelector('#subscription-unavailable').textContent"), "wrong subscription hint"
    ev("[...document.querySelectorAll('dialog[open]')].forEach(d => d.close())")
    time.sleep(0.3)
    dt.call("Page.navigate", {"url": base + "/#clients"})
    wait("!!document.querySelector('[data-grant-open]')", "grant-rows")
    rows = ev("[...document.querySelectorAll('.grant-proto')].map(e=>e.textContent.trim())")
    assert "AmneziaWG 1.5" in rows and "AmneziaWG 3.1" in rows, rows
    ev("[...document.querySelectorAll('[data-grant-open]')].find(b=>b.textContent.includes('AmneziaWG 3.1')).click()")
    wait("document.querySelector('#grant-window')?.open && !!document.querySelector('[data-grant-action=show]')", "grant-window")
    facts = ev("document.querySelector('#grant-facts').textContent")
    assert "AmneziaWG 3.1" in facts and "10.66.31." in facts and "51822/udp" in facts and "Название в подписке" not in facts, facts
    assert ev("!document.querySelector('[data-grant-action=label]')") is True
    shot("grant-window")
    ev("document.querySelector('[data-grant-action=show]').click()")
    wait("!!document.querySelector('#grant-link-body textarea.awg-conf')", "config-shown")
    text = ev("document.querySelector('#grant-link-body textarea.awg-conf').value")
    assert text.startswith("[Interface]\nPrivateKey = ") and "Endpoint = vpn.example.com:51822" in text and "HeaderProtectionKey" in text, text[:200]
    assert ev("!!document.querySelector('#grant-link-body img.link-qr')") is True
    href = ev("[...document.querySelectorAll('#grant-link-body a')].find(a=>a.textContent.includes('.conf')).href")
    assert href.startswith("data:text/plain;charset=utf-8,%5BInterface%5D"), href[:60]
    assert ev("[...document.querySelectorAll('#grant-link-body a')].find(a=>a.textContent.includes('.conf')).download") == "samsung-awg31.conf"
    shot("config")
    # rotate asks the AmneziaWG-specific question
    ev("document.querySelector('[data-grant-action=rotate]').click()")
    wait("[...document.querySelectorAll('dialog[open]')].some(d => d.textContent.includes('Ротировать ключи?'))", "rotate-confirm")
    shot("rotate-confirm")
    print("UI_AWG_OK errors=", errors)
finally:
    proc.terminate()
