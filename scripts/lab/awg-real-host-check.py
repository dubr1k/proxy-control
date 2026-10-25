"""AmneziaWG on a REAL installation (lab host, installed by the installer with `[amneziawg]` enabled).

Drives the installed panel's HTTP API on 127.0.0.1:8787, issues one access per version for a test
client, then brings up a real amneziawg-go client in a network namespace per version with the
config the panel handed out. The client dials the host's own PUBLIC address (resolved from the
config's `Endpoint` name) over a veth, so the packets pass the firewall rules the installer
created, and the tunnel is proved by a ping of its gateway and a ping through NAT. Everything it
creates (client, accesses, namespaces, veths, the temporary admin) is removed at the end.

  AWG_REAL_HOST=1 python3 scripts/lab/awg-real-host-check.py <repo> <panel-host-name>
"""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO, PANEL_HOST = sys.argv[1], sys.argv[2]
VERSIONS = ("1.5", "2.0", "3.1")
WORK = Path("/root/awg-real-host")
fails: list[str] = []
pids: list[subprocess.Popen] = []


def say(text):
    print(f"\n== {text}", flush=True)


def ok(text):
    print(f"PASS {text}", flush=True)


def bad(text):
    print(f"FAIL {text}", flush=True)
    fails.append(text)


def sh(*args, check=False, **kw):
    return subprocess.run(args, capture_output=True, text=True, check=check, **kw)


def suffix(version):
    return version.replace(".", "")


assert os.environ.get("AWG_REAL_HOST") == "1" and os.geteuid() == 0, "lab host only: AWG_REAL_HOST=1, root"
WORK.mkdir(exist_ok=True)
password = secrets.token_urlsafe(24)
sh("docker", "exec", "-i", "proxy-control-panel", "python", "-m", "panel.cli", "create-admin", "--username", "awgcheck",
   "--role", "owner", "--password-stdin", input=password + "\n", check=True)
http = httpx.Client(base_url="http://127.0.0.1:8787", headers={"Host": PANEL_HOST}, timeout=30)
page = http.get("/login")
csrf = page.cookies["panel_csrf"]
# The panel's cookies are `Secure`; this check talks plain HTTP to localhost, so the cookies are
# carried by hand instead of by the jar.
login = http.post("/api/auth/login", json={"username": "awgcheck", "password": password},
                  headers={"X-CSRF-Token": csrf, "Cookie": f"panel_csrf={csrf}"})
assert login.status_code in (200, 204), login.text
session = login.cookies.get("panel_session") or next(v.split("panel_session=")[1].split(";")[0]
                                                      for k, v in login.headers.multi_items() if k.lower() == "set-cookie" and "panel_session=" in v)
csrf = login.cookies.get("panel_csrf") or csrf
http.headers["Cookie"] = f"panel_csrf={csrf}; panel_session={session}"
H = {"X-CSRF-Token": csrf}
client_id = None


def cleanup():
    say("cleanup")
    for proc in pids:
        proc.terminate()
    time.sleep(1)
    for version in VERSIONS:
        s = suffix(version)
        sh("ip", "netns", "del", f"rh{s}")
        sh("ip", "link", "del", f"vr{s}")
        Path(f"/var/run/amneziawg/rc{s}.sock").unlink(missing_ok=True)
    if client_id:
        for grant in http.get(f"/api/clients/{client_id}").json()["grants"]:
            http.post(f"/api/clients/grants/{grant['id']}/delete", headers=H)
        http.post(f"/api/clients/{client_id}/state", json={"state": "archived"}, headers=H)
    sh("docker", "exec", "proxy-control-panel", "python", "-c",
       "import sqlite3,os;db=sqlite3.connect(os.environ.get('PANEL_DATABASE','/data/panel.sqlite3'));"
       "db.execute(\"delete from sessions where username='awgcheck'\");db.execute(\"delete from admins where username='awgcheck'\");db.commit()")
    print(f"REAL_HOST_RESULT fails={len(fails)}", flush=True)


try:
    say("the installed panel offers AmneziaWG")
    me = http.get("/api/auth/me").json()
    (ok if me["features"].get("amneziawg") is True else bad)("features.amneziawg is on")
    local = next(n for n in http.get("/api/nodes").json()["items"] if n["node_id"] == "local")
    (ok if local["services"].get("amneziawg") == "ok" else bad)(f"local service state {local['services'].get('amneziawg')}")
    (ok if local["identity"]["awg_versions"] == list(VERSIONS) else bad)(f"versions {local['identity']['awg_versions']}")

    say("issue one access per version through the panel API")
    client_id = http.post("/api/clients", json={"display_name": "AWG live"}, headers=H).json()["id"]
    started = http.post(f"/api/clients/{client_id}/grants", headers=H, json={"grants": [
        {"protocol": "amneziawg", "node_id": "local", "runtime_username": f"live-awg{suffix(v)}", "options": {"version": v}}
        for v in VERSIONS]})
    (ok if started.status_code == 200 and started.json()["status"] == "succeeded" else bad)(f"grants {started.status_code} {started.text[:120]}")
    grants = {g["options"]["version"]: g for g in http.get(f"/api/clients/{client_id}").json()["grants"]}
    configs = {}
    for version, grant in grants.items():
        issued = http.post(f"/api/clients/{client_id}/links?grant_id={grant['id']}", headers=H).json()
        artifact = http.get(f"/api/reveal/{issued['reveal_token']}").json()["grants"][0]["artifacts"][0]
        configs[version] = artifact["value"]
        (WORK / f"{version}.conf").write_text(artifact["value"])
        endpoint = next(line.split(" = ", 1)[1] for line in artifact["value"].splitlines() if line.startswith("Endpoint"))
        (ok if endpoint == f"{PANEL_HOST}:{grant['options']['port']}" else bad)(f"{version}: endpoint {endpoint}")
        (ok if artifact["qr"].startswith("data:image/svg+xml") else bad)(f"{version}: QR present")

    say("a real client per version dials the host's public address")
    public_ip = socket.gethostbyname(PANEL_HOST)
    image = sh("docker", "inspect", "-f", "{{.Image}}", "proxy-control-awg-manager").stdout.strip()
    binary = WORK / "amneziawg-go"
    with binary.open("wb") as handle:
        subprocess.run(["docker", "run", "--rm", "--entrypoint", "cat", image, "/usr/local/bin/amneziawg-go"], stdout=handle, check=True)
    binary.chmod(0o755)
    sys.path.insert(0, f"{REPO}/scripts/lab")
    from awg_lab import uapi_exchange as _uapi_exchange

    for version in VERSIONS:
        s, grant = suffix(version), grants[version]
        ns, host_if, ns_if, iface = f"rh{s}", f"vr{s}", f"vq{s}", f"rc{s}"
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if, check=True)
        sh("ip", "link", "set", ns_if, "netns", ns)
        sh("ip", "addr", "add", f"10.98.{s}.1/30", "dev", host_if)
        sh("ip", "link", "set", host_if, "up")
        sh("ip", "-n", ns, "addr", "add", f"10.98.{s}.2/30", "dev", ns_if)
        for args in (("link", "set", ns_if, "up"), ("link", "set", "lo", "up"), ("route", "add", "default", "via", f"10.98.{s}.1")):
            sh("ip", "-n", ns, *args)
        proc = subprocess.Popen(["ip", "netns", "exec", ns, "env", "LOG_LEVEL=error", str(binary), "-f", iface],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pids.append(proc)
        sock = Path(f"/var/run/amneziawg/{iface}.sock")
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.1)
        converted = sh(sys.executable, f"{REPO}/scripts/lab/awg_conf_to_uapi.py", REPO, str(WORK / f"{version}.conf"),
                       f"{public_ip}:{grant['options']['port']}", check=True)
        _uapi_exchange(str(sock), b"set=1\n" + converted.stdout.encode() + b"\n")
        sh("ip", "-n", ns, "addr", "add", f"{grant['options']['address']}/24", "dev", iface)
        sh("ip", "-n", ns, "link", "set", iface, "mtu", "1280", "up")
        sh("ip", "-n", ns, "route", "replace", "default", "dev", iface)
        # the endpoint is this host's own public address: keep that route on the veth
        sh("ip", "-n", ns, "route", "add", public_ip, "via", f"10.98.{s}.1")
        gateway = f"10.66.{ {'1.5': 15, '2.0': 20, '3.1': 31}[version] }.1"
        ping = sh("ip", "netns", "exec", ns, "ping", "-c3", "-W3", gateway)
        (ok if ping.returncode == 0 else bad)(f"{version}: ping the gateway {gateway} through the tunnel")
        nat = sh("ip", "netns", "exec", ns, "ping", "-c2", "-W3", "1.1.1.1")
        (ok if nat.returncode == 0 else bad)(f"{version}: ping 1.1.1.1 through the tunnel and NAT")
        peers = http.get("/api/dashboard").json()["protocols"]["amneziawg"]
        print(f"   dashboard peers: {peers.get('versions')} traffic: {peers.get('traffic')}")
        proc.terminate()
        pids.remove(proc)
        sh("ip", "netns", "del", ns)
        sh("ip", "link", "del", host_if)
        sock.unlink(missing_ok=True)
    traffic = http.get("/api/dashboard").json()["protocols"]["amneziawg"]["traffic"]
    (ok if (traffic.get("upload_bytes") or 0) > 0 else bad)(f"the dashboard counts the traffic {traffic}")
finally:
    cleanup()
sys.exit(1 if fails else 0)
