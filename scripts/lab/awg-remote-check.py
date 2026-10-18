"""AmneziaWG across hosts: a CENTRAL panel issues accesses on a linked node, a client elsewhere dials it.

Three modes, because the parts run on different machines:

  issue    (inside the central panel container)  python awg-remote-check.py issue <node_id> <panel-host>
           creates a temporary owner, a test client and one access per AmneziaWG version on that node,
           waits until the node confirms them and prints one JSON document with the configs.
  cleanup  (inside the central panel container)  python awg-remote-check.py cleanup <client_id> <panel-host>
           deletes the accesses, archives the client and removes the temporary owner.
  multi    (inside the central panel container)  python awg-remote-check.py multi <node_id> <panel-host>
           like issue, for SEVERAL clients with different version sets (one only 1.5, one 2.0+3.1, one all
           three): proves that versions are chosen per client. Output is read by `connect-multi`.
  cleanup-multi  (inside the panel container)    python awg-remote-check.py cleanup-multi <client_id,client_id,…> <panel-host>
  connect-multi  (on the client host, root, AWG_REMOTE=1) python awg-remote-check.py connect-multi <repo> <multi.json> <amneziawg-go>
           brings ALL tunnels of ALL clients up at the same time and checks each one.
  overview (inside the panel container)          python awg-remote-check.py overview <panel-host>
           prints what the panel's AmneziaWG screen shows (versions, ports, peers), no secrets.
  connect  (on the client host, root, AWG_REMOTE=1) python awg-remote-check.py connect <repo> <issue.json> <amneziawg-go>
           brings up a real amneziawg-go client per version in a network namespace over the real
           network and proves the tunnel by pinging its gateway and the Internet through the node.

The temporary owner's password and the configs (they hold test keys only) never go to the log.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

VERSIONS = ("1.5", "2.0", "3.1")
GATEWAY = {"1.5": "10.66.15.1", "2.0": "10.66.20.1", "3.1": "10.66.31.1"}


def suffix(version):
    return version.replace(".", "")


def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def panel_session(panel_host):
    import httpx

    password = secrets.token_urlsafe(24)
    sh("python", "-m", "panel.cli", "create-admin", "--username", "awgremote", "--role", "owner",
       "--password-stdin", input=password + "\n", check=True)
    http = httpx.Client(base_url="http://127.0.0.1:8787", headers={"Host": panel_host}, timeout=60)
    csrf = http.get("/login").cookies["panel_csrf"]
    login = http.post("/api/auth/login", json={"username": "awgremote", "password": password},
                      headers={"X-CSRF-Token": csrf, "Cookie": f"panel_csrf={csrf}"})
    assert login.status_code in (200, 204), login.text
    session = next(v.split("panel_session=")[1].split(";")[0] for k, v in login.headers.multi_items()
                   if k.lower() == "set-cookie" and "panel_session=" in v)
    csrf = next((v.split("panel_csrf=")[1].split(";")[0] for k, v in login.headers.multi_items()
                 if k.lower() == "set-cookie" and "panel_csrf=" in v), csrf)
    http.headers["Cookie"] = f"panel_csrf={csrf}; panel_session={session}"
    return http, {"X-CSRF-Token": csrf}


def drop_admin():
    from panel.settings import Settings
    from panel.store import Store

    store = Store(Settings().database_path)
    for admin in store.admins():
        if admin["username"] == "awgremote":
            store.delete_admin(admin["id"])


def issue(node_id, panel_host):
    http, headers = panel_session(panel_host)
    try:
        client_id = http.post("/api/clients", json={"display_name": "AWG remote"}, headers=headers).json()["id"]
        started = http.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
            {"protocol": "amneziawg", "node_id": node_id, "runtime_username": f"remote-awg{suffix(v)}",
             "options": {"version": v}} for v in VERSIONS]})
        assert started.status_code == 200, started.text
        grants = {}
        for _ in range(60):
            grants = {g["options"]["version"]: g for g in http.get(f"/api/clients/{client_id}").json()["grants"]}
            if len(grants) == 3 and all(g["observed_state"] == "enabled" and g["options"].get("address") for g in grants.values()):
                break
            time.sleep(3)
        else:
            raise SystemExit("the node did not confirm the accesses: " + json.dumps(
                {v: g["observed_state"] for v, g in grants.items()}))
        out = {"client_id": client_id, "grants": {}}
        for version, grant in grants.items():
            issued = http.post(f"/api/clients/{client_id}/links?grant_id={grant['id']}", headers=headers).json()
            artifact = http.get(f"/api/reveal/{issued['reveal_token']}").json()["grants"][0]["artifacts"][0]
            out["grants"][version] = {"id": grant["id"], "conf": artifact["value"], "address": grant["options"]["address"],
                                      "port": grant["options"]["port"]}
        print(json.dumps(out))
    finally:
        drop_admin()


def cleanup(client_id, panel_host):
    http, headers = panel_session(panel_host)
    try:
        for grant in http.get(f"/api/clients/{client_id}").json()["grants"]:
            http.post(f"/api/clients/grants/{grant['id']}/delete", headers=headers)
        http.post(f"/api/clients/{client_id}/state", json={"state": "archived"}, headers=headers)
        print("cleaned", client_id)
    finally:
        drop_admin()


def connect(repo, issue_json, binary):
    assert os.environ.get("AWG_REMOTE") == "1" and os.geteuid() == 0, "client host only: AWG_REMOTE=1, root"
    sys.path.insert(0, repo)
    from awg_manager.host import _uapi_exchange

    document = json.loads(Path(issue_json).read_text())
    work = Path("/root/awg-remote")
    work.mkdir(exist_ok=True)
    fails = 0
    procs = []
    try:
        for version in VERSIONS:
            grant, s = document["grants"][version], suffix(version)
            conf = work / f"{version}.conf"
            conf.write_text(grant["conf"])
            conf.chmod(0o600)
            host = next(line.split(" = ", 1)[1].rsplit(":", 1)[0] for line in grant["conf"].splitlines() if line.startswith("Endpoint"))
            # AWG_ENDPOINT_IP: dial this address instead of resolving the name (a host behind NAT is
            # tested on its own LAN address, from a namespace on the same machine).
            ip = os.environ.get("AWG_ENDPOINT_IP") or socket.gethostbyname(host)
            ns, hv, nv, iface = f"rm{s}", f"vm{s}", f"vn{s}", f"rm{s}t"
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "add", hv, "type", "veth", "peer", "name", nv, check=True)
            sh("ip", "link", "set", nv, "netns", ns)
            sh("ip", "addr", "add", f"10.97.{s}.1/30", "dev", hv)
            sh("ip", "link", "set", hv, "up")
            sh("ip", "-n", ns, "addr", "add", f"10.97.{s}.2/30", "dev", nv)
            sh("ip", "-n", ns, "link", "set", nv, "up")
            sh("ip", "-n", ns, "link", "set", "lo", "up")
            sh("ip", "-n", ns, "route", "add", "default", "via", f"10.97.{s}.1")
            # the client host forwards the namespace's packets to the real network
            sh("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"10.97.{s}.0/30", "-j", "MASQUERADE")
            sh("iptables", "-I", "FORWARD", "-i", hv, "-j", "ACCEPT")
            sh("iptables", "-I", "FORWARD", "-o", hv, "-j", "ACCEPT")
            proc = subprocess.Popen(["ip", "netns", "exec", ns, "env", "LOG_LEVEL=error", binary, "-f", iface],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(proc)
            sock = Path(f"/var/run/amneziawg/{iface}.sock")
            for _ in range(100):
                if sock.exists():
                    break
                time.sleep(0.1)
            body = sh(sys.executable, f"{repo}/scripts/lab/awg_conf_to_uapi.py", repo, str(conf), f"{ip}:{grant['port']}", check=True)
            _uapi_exchange(str(sock), b"set=1\n" + body.stdout.encode() + b"\n")
            sh("ip", "-n", ns, "addr", "add", f"{grant['address']}/24", "dev", iface)
            sh("ip", "-n", ns, "link", "set", iface, "mtu", "1280", "up")
            sh("ip", "-n", ns, "route", "add", f"{ip}/32", "via", f"10.97.{s}.1")
            sh("ip", "-n", ns, "route", "replace", "default", "dev", iface)
            gateway = sh("ip", "netns", "exec", ns, "ping", "-c3", "-W3", GATEWAY[version])
            ok_gateway = gateway.returncode == 0
            internet = sh("ip", "netns", "exec", ns, "ping", "-c2", "-W3", "1.1.1.1")
            egress = sh("ip", "netns", "exec", ns, "curl", "-s", "-m", "8", "https://1.1.1.1/cdn-cgi/trace")
            exit_ip = next((line.split("=", 1)[1] for line in egress.stdout.splitlines() if line.startswith("ip=")), "")
            print(f"{'PASS' if ok_gateway else 'FAIL'} {version}: gateway {GATEWAY[version]} through {host} ({ip}:{grant['port']})")
            print(f"{'PASS' if internet.returncode == 0 else 'FAIL'} {version}: 1.1.1.1 through the node's NAT")
            print(f"{'PASS' if exit_ip else 'FAIL'} {version}: HTTPS out through the node, exit address {exit_ip or 'none'}")
            fails += (not ok_gateway) + (internet.returncode != 0) + (not exit_ip)
            proc.terminate()
            procs.remove(proc)
            sh("ip", "netns", "del", ns)
            sh("ip", "link", "del", hv)
            sh("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"10.97.{s}.0/30", "-j", "MASQUERADE")
            sh("iptables", "-D", "FORWARD", "-i", hv, "-j", "ACCEPT")
            sh("iptables", "-D", "FORWARD", "-o", hv, "-j", "ACCEPT")
            sock.unlink(missing_ok=True)
    finally:
        for proc in procs:
            proc.terminate()
        for conf in work.glob("*.conf"):
            conf.unlink()
    print(f"REMOTE_RESULT fails={fails}")
    return 1 if fails else 0


PLAN = {"alice": ("1.5",), "bob": ("2.0", "3.1"), "carol": ("1.5", "2.0", "3.1")}


def multi_issue(node_id, panel_host):
    http, headers = panel_session(panel_host)
    try:
        out = {"clients": {}}
        for name, versions in PLAN.items():
            client_id = http.post("/api/clients", json={"display_name": f"AWG multi {name}"}, headers=headers).json()["id"]
            started = http.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
                {"protocol": "amneziawg", "node_id": node_id, "runtime_username": f"multi-{name}-awg{suffix(v)}",
                 "options": {"version": v}} for v in versions]})
            assert started.status_code == 200, started.text
            out["clients"][name] = {"client_id": client_id, "grants": {}}
        for name, versions in PLAN.items():
            client_id = out["clients"][name]["client_id"]
            for _ in range(60):
                grants = {g["options"]["version"]: g for g in http.get(f"/api/clients/{client_id}").json()["grants"]}
                if len(grants) == len(versions) and all(g["observed_state"] == "enabled" and g["options"].get("address") for g in grants.values()):
                    break
                time.sleep(3)
            else:
                raise SystemExit(f"the node did not confirm the accesses of {name}")
            for version, grant in grants.items():
                issued = http.post(f"/api/clients/{client_id}/links?grant_id={grant['id']}", headers=headers).json()
                artifact = http.get(f"/api/reveal/{issued['reveal_token']}").json()["grants"][0]["artifacts"][0]
                out["clients"][name]["grants"][version] = {"conf": artifact["value"], "address": grant["options"]["address"],
                                                          "port": grant["options"]["port"]}
        print(json.dumps(out))
    finally:
        drop_admin()


def cleanup_multi(client_ids, panel_host):
    http, headers = panel_session(panel_host)
    try:
        for client_id in client_ids.split(","):
            for grant in http.get(f"/api/clients/{client_id}").json()["grants"]:
                http.post(f"/api/clients/grants/{grant['id']}/delete", headers=headers)
            http.post(f"/api/clients/{client_id}/state", json={"state": "archived"}, headers=headers)
        print("cleaned", client_ids)
    finally:
        drop_admin()


def connect_multi(repo, multi_json, binary):
    assert os.environ.get("AWG_REMOTE") == "1" and os.geteuid() == 0, "client host only: AWG_REMOTE=1, root"
    sys.path.insert(0, repo)
    from awg_manager.host import _uapi_exchange

    document = json.loads(Path(multi_json).read_text())
    work = Path("/root/awg-multi")
    work.mkdir(exist_ok=True)
    entries = [(name, version, grant) for name, client in document["clients"].items() for version, grant in client["grants"].items()]
    procs, made, fails = [], [], 0
    try:
        for index, (name, version, grant) in enumerate(entries):
            conf = work / f"{name}-{version}.conf"
            conf.write_text(grant["conf"])
            conf.chmod(0o600)
            host = next(line.split(" = ", 1)[1].rsplit(":", 1)[0] for line in grant["conf"].splitlines() if line.startswith("Endpoint"))
            ip = os.environ.get("AWG_ENDPOINT_IP") or socket.gethostbyname(host)
            ns, hv, nv, iface = f"mu{index}", f"mh{index}", f"mn{index}", f"mt{index}"
            base = f"10.96.{index}"
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "add", hv, "type", "veth", "peer", "name", nv, check=True)
            sh("ip", "link", "set", nv, "netns", ns)
            sh("ip", "addr", "add", f"{base}.1/30", "dev", hv)
            sh("ip", "link", "set", hv, "up")
            for args in (("addr", "add", f"{base}.2/30", "dev", nv), ("link", "set", nv, "up"), ("link", "set", "lo", "up"),
                         ("route", "add", "default", "via", f"{base}.1")):
                sh("ip", "-n", ns, *args)
            sh("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{base}.0/30", "-j", "MASQUERADE")
            sh("iptables", "-I", "FORWARD", "-i", hv, "-j", "ACCEPT")
            sh("iptables", "-I", "FORWARD", "-o", hv, "-j", "ACCEPT")
            made.append((ns, hv, base))
            procs.append(subprocess.Popen(["ip", "netns", "exec", ns, "env", "LOG_LEVEL=error", binary, "-f", iface],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            sock = Path(f"/var/run/amneziawg/{iface}.sock")
            for _ in range(100):
                if sock.exists():
                    break
                time.sleep(0.1)
            body = sh(sys.executable, f"{repo}/scripts/lab/awg_conf_to_uapi.py", repo, str(conf), f"{ip}:{grant['port']}", check=True)
            _uapi_exchange(str(sock), b"set=1\n" + body.stdout.encode() + b"\n")
            sh("ip", "-n", ns, "addr", "add", f"{grant['address']}/24", "dev", iface)
            sh("ip", "-n", ns, "link", "set", iface, "mtu", "1280", "up")
            sh("ip", "-n", ns, "route", "add", f"{ip}/32", "via", f"{base}.1")
            sh("ip", "-n", ns, "route", "replace", "default", "dev", iface)
        print(f"{len(entries)} tunnels of {len(document['clients'])} clients are up at the same time")
        addresses = [grant["address"] for _n, _v, grant in entries]
        print(("PASS" if len(set(addresses)) == len(addresses) else "FAIL") + f" every access has its own tunnel address ({len(set(addresses))} distinct)")
        fails += len(set(addresses)) != len(addresses)
        for index, (name, version, grant) in enumerate(entries):
            ns = f"mu{index}"
            gateway = sh("ip", "netns", "exec", ns, "ping", "-c2", "-W3", GATEWAY[version])
            internet = sh("ip", "netns", "exec", ns, "ping", "-c2", "-W3", "1.1.1.1")
            good = gateway.returncode == 0 and internet.returncode == 0
            print(f"{'PASS' if good else 'FAIL'} {name} on {version}: gateway {GATEWAY[version]} and 1.1.1.1 through the tunnel")
            fails += not good
        # a client's config must not work with another client's version: carol's 3.1 key against the 2.0 port
        print("MULTI_RESULT fails=%d" % fails)
    finally:
        for proc in procs:
            proc.terminate()
        time.sleep(1)
        for ns, hv, base in made:
            sh("ip", "netns", "del", ns)
            sh("ip", "link", "del", hv)
            sh("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{base}.0/30", "-j", "MASQUERADE")
            sh("iptables", "-D", "FORWARD", "-i", hv, "-j", "ACCEPT")
            sh("iptables", "-D", "FORWARD", "-o", hv, "-j", "ACCEPT")
        for conf in work.glob("*.conf"):
            conf.unlink()
        for sock in Path("/var/run/amneziawg").glob("mt*.sock"):
            sock.unlink(missing_ok=True)
    return 1 if fails else 0


def overview(panel_host):
    http, _headers = panel_session(panel_host)
    try:
        data = http.get("/api/amneziawg/overview").json()
        print(json.dumps({"status": data.get("status"), "ip_forward": data.get("ip_forward"),
                          "versions": [(v["version"], v["port"], v["running"], v["peers"]) for v in data.get("versions", [])],
                          "peers": len(data.get("peers", [])), "pending": len(data.get("pending", []))}))
    finally:
        drop_admin()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "issue":
        issue(sys.argv[2], sys.argv[3])
    elif mode == "cleanup":
        cleanup(sys.argv[2], sys.argv[3])
    elif mode == "overview":
        overview(sys.argv[2])
    elif mode == "multi":
        multi_issue(sys.argv[2], sys.argv[3])
    elif mode == "cleanup-multi":
        cleanup_multi(sys.argv[2], sys.argv[3])
    elif mode == "connect-multi":
        sys.exit(connect_multi(sys.argv[2], sys.argv[3], sys.argv[4]))
    elif mode == "connect":
        sys.exit(connect(sys.argv[2], sys.argv[3], sys.argv[4]))
    else:
        raise SystemExit("mode: issue | cleanup | connect | multi | cleanup-multi | connect-multi")
