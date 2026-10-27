#!/usr/bin/env python3
"""Live check of the 2.0 monitoring against a REAL installation (lab host only, run as root).

  /root/dev/<lab>/.venv/bin/python scripts/lab/monitoring-live-check.py [--repo DIR] [--mb 36]
        [--phases agent,panel,traffic,sse,history,degraded] [--perf SECONDS]

Needs the installer-managed stack with trusttunnel, naive, mieru, amneziawg and mtproxy, the panel
reachable on https://<panel domain> (default read from the installer's nginx vhost name), the owner's
bootstrap password in /opt/mtproxy-shared443/secrets/panel-bootstrap-password and, for the real
clients, the `mieru` client binary (extracted from the pinned mieru .deb) and the awg-manager image
(for amneziawg-go). It creates one throw-away client and one viewer admin and removes both at the end.

Prints PASS/FAIL/INFO lines; never prints a password, token, link or key.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
import socket
import statistics
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse as up
from pathlib import Path

import httpx

SECRETS = Path("/opt/mtproxy-shared443/secrets")
AGENT_SOCKET = "/run/proxy-control/version-agent.sock"
# Public, fast, ranged download sources tried in this order (the first that answers wins).
SOURCES = ("https://proof.ovh.net/files/100Mb.dat", "http://speedtest.tele2.net/100MB.zip", "https://speed.hetzner.de/100MB.bin")
OVH = SOURCES[0]
SINK = "http://speedtest.tele2.net/upload.php"
PROTOCOLS = ("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel")
WORK = Path("/root/mon-chk")
results: list[tuple[str, bool]] = []
args: argparse.Namespace


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
    return bool(ok)


def info(text: str) -> None:
    print("INFO " + text, flush=True)


def sh(*cmd: str, check_rc: bool = False, timeout: float | None = None, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check_rc, timeout=timeout, **kw)


# --- panel client ----------------------------------------------------------------------------


class Panel:
    def __init__(self, base: str, username: str, password: str):
        self.base = base
        self.http = httpx.Client(base_url=base, timeout=30)
        self.http.get("/login")
        r = self.http.post("/api/auth/login", json={"username": username, "password": password},
                           headers={"X-CSRF-Token": self.http.cookies.get("panel_csrf")})
        r.raise_for_status()

    @property
    def H(self) -> dict:
        return {"X-CSRF-Token": self.http.cookies.get("panel_csrf")}

    def get(self, path: str, **kw):
        return self.http.get(path, **kw)

    def post(self, path: str, **kw):
        return self.http.post(path, headers=self.H, **kw)

    def cookies(self) -> dict:
        return dict(self.http.cookies)

    def live(self, node: str = "local") -> dict | None:
        r = self.http.get("/api/metrics/live", params={"node": node})
        return r.json()["nodes"][0] if r.status_code == 200 else None


def panel_host() -> str:
    for conf in sorted(Path("/etc/nginx/sites-enabled").glob("*")):
        text = conf.read_text(errors="ignore")
        match = re.search(r"server_name\s+(aurora\.[^;\s]+|[^;\s]+)\s*;", text)
        if match and "8787" in text:
            return match.group(1)
    return "aurora.sky.dubr1kkk.uk"


# --- agent -----------------------------------------------------------------------------------


def agent_metrics() -> dict | None:
    class Unix(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect(AGENT_SOCKET)

    try:
        conn = Unix("localhost")
        conn.request("GET", "/v1/metrics")
        resp = conn.getresponse()
        body = resp.read()
        return json.loads(body) if resp.status == 200 else None
    except (OSError, ValueError):
        return None


def phase_agent() -> None:
    print("\n== (1) agent /v1/metrics, nft table, panel route", flush=True)
    m = agent_metrics()
    if not check("agent GET /v1/metrics over the socket", m is not None):
        return
    check("kernel_counters ok", m["kernel_counters"] == "ok", str(m["kernel_counters"]))
    host = m["host"]
    check("cpu_percent within 0..100", 0 <= host["cpu_percent"] <= 100, str(host["cpu_percent"]))
    total = int(sh("free", "-b").stdout.splitlines()[1].split()[1])
    check("mem total within 2 % of free -b", abs(host["mem"]["total"] - total) / total < 0.02,
          f"{host['mem']['total']} vs {total}")
    check("mem percent sane", 0 < host["mem"]["percent"] < 100, str(host["mem"]["percent"]))
    st = os.statvfs("/")
    check("disk total matches statvfs within 2 %", abs(host["disk"]["total"] - st.f_blocks * st.f_frsize) / host["disk"]["total"] < 0.02)
    nic = re.search(r"dev (\S+)", sh("ip", "-o", "route", "get", "1.1.1.1").stdout).group(1)
    names = [i["name"] for i in host["net"]["interfaces"]]
    check("net interfaces = the real NIC only", names == [nic], f"{names} vs {nic}")
    check("containers reported", len(host["containers"]) >= 5, str(len(host["containers"])))
    for proto in ("mtproxy", "naive", "mieru", "trusttunnel", "amneziawg"):
        check(f"protocol {proto} present", proto in m["protocols"], str(m["protocols"].get(proto, {}).get("source")))
    check("amneziawg from interfaces", m["protocols"].get("amneziawg", {}).get("source") == "interface")
    table = sh("nft", "list", "table", "inet", "proxy_control_metrics")
    check("nft table inet proxy_control_metrics exists", table.returncode == 0)
    rules = [line.strip() for line in table.stdout.splitlines() if re.search(r"\b(tcp|udp) (dport|sport)\b", line)]
    verdicts = [r for r in rules if re.search(r"\b(accept|drop|reject|queue|jump|goto|dnat|snat|masquerade|redirect|return|mark|ct)\b", r)]
    check("nft rules only count (no verdict statements)", rules and not verdicts, f"{len(rules)} rules")
    check("every rule is `counter name`", all("counter name" in r for r in rules))
    ss = sh("ss", "-ltn").stdout
    check("ss: panel listens on 8787", ":8787" in ss)


# --- real clients ----------------------------------------------------------------------------


class Rig:
    """One throw-away client with every protocol and a real client program for each."""

    def __init__(self, panel: Panel, repo: str):
        self.panel, self.repo = panel, repo
        self.cid: int | None = None
        self.creds: dict = {}
        self.mieru_home = Path("/root/mieru-chk")
        self.awg_pid: int | None = None
        self.ns = "monchk"

    def create(self) -> None:
        p = self.panel
        tag = os.urandom(2).hex()  # runtime names are not reusable right after a delete
        cid = p.post("/api/clients", json={"display_name": "mon-check"}).json()["id"]
        self.cid = cid
        grants = [{"protocol": proto, "node_id": "local", "runtime_username": f"mon-check-{proto[:4]}-{tag}",
                   "options": ({"quotas": []} if proto == "mieru" else {"version": "2.0"} if proto == "amneziawg"
                               else {"name": "mon-check"} if proto == "trusttunnel" else {})}
                  for proto in PROTOCOLS]
        r = p.post(f"/api/clients/{cid}/grants", json={"grants": grants})
        check("grants for five protocols created", r.status_code == 200 and r.json().get("status") == "succeeded", r.text[:150])
        time.sleep(4)
        for g in p.get(f"/api/clients/{cid}").json()["grants"]:
            iss = p.post(f"/api/clients/{cid}/links?grant_id={g['id']}").json()
            got = p.get(f"/api/reveal/{iss['reveal_token']}").json()
            self.creds[g["protocol"]] = {"grant": g, "art": {a["kind"]: a["value"] for a in got["grants"][0]["artifacts"]}}

    def cleanup(self) -> None:
        sh(str(self.mieru_home / "mieru"), "stop", env={**os.environ, "HOME": str(self.mieru_home)})
        if self.awg_pid:
            sh("kill", str(self.awg_pid))
        sh("ip", "netns", "del", self.ns)
        sh("ip", "link", "del", "vmonchk")
        Path("/var/run/amneziawg/rcchk.sock").unlink(missing_ok=True)
        if self.cid:
            for g in self.panel.get(f"/api/clients/{self.cid}").json().get("grants", []):
                self.panel.post(f"/api/clients/grants/{g['id']}/delete")
            self.panel.post(f"/api/clients/{self.cid}/state", json={"state": "archived"})

    # -- per-protocol client plumbing

    def start_mieru(self) -> bool:
        share = self.creds["mieru"]["art"]["share_url"]
        u = up.urlsplit(share.replace("mierus://", "https://", 1))
        q = up.parse_qs(u.query)
        conf = {"profiles": [{"profileName": "chk", "user": {"name": up.unquote(u.username), "password": up.unquote(u.password)},
                              "servers": [{"domainName": u.hostname, "portBindings": [{"port": int(q["port"][0]), "protocol": q["protocol"][0]}]}],
                              "mtu": 1400}], "activeProfile": "chk", "rpcPort": 8965, "socks5Port": 1081, "loggingLevel": "INFO"}
        self.mieru_home.mkdir(exist_ok=True)
        binary = self.mieru_home / "mieru"
        if not binary.exists():
            src = next(Path("/root").glob("mieru-client/usr/bin/mieru"), None)
            if src is None:
                deb = next(Path("/var/lib/proxy-control").glob("mieru_*_amd64.deb"))
                sh("dpkg-deb", "-x", str(deb), str(self.mieru_home / "x"), check_rc=True)
                src = self.mieru_home / "x/usr/bin/mieru"
            shutil.copy(src, binary)
        (self.mieru_home / "c.json").write_text(json.dumps(conf))
        os.chmod(self.mieru_home / "c.json", 0o600)
        env = {**os.environ, "HOME": str(self.mieru_home)}
        sh(str(binary), "apply", "config", str(self.mieru_home / "c.json"), env=env)
        subprocess.run([str(binary), "start"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       stdin=subprocess.DEVNULL, timeout=30)
        time.sleep(3)
        r = sh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20", "--socks5-hostname", "127.0.0.1:1081", "https://example.com/")
        return r.stdout.strip() == "200"

    def start_awg(self) -> bool:
        conf = self.creds["amneziawg"]
        cfg, opts = conf["art"]["awg_conf"], conf["grant"]["options"]
        WORK.mkdir(exist_ok=True)
        (WORK / "c.conf").write_text(cfg)
        os.chmod(WORK / "c.conf", 0o600)
        host = next(ln.split("=", 1)[1].strip().rsplit(":", 1)[0] for ln in cfg.splitlines() if ln.startswith("Endpoint"))
        ip = socket.gethostbyname(host)
        binary = Path("/root/mon-awg/amneziawg-go")
        if not binary.exists():
            binary.parent.mkdir(exist_ok=True)
            image = sh("docker", "inspect", "-f", "{{.Image}}", "proxy-control-awg-manager").stdout.strip()
            with binary.open("wb") as h:
                subprocess.run(["docker", "run", "--rm", "--entrypoint", "cat", image, "/usr/local/bin/amneziawg-go"], stdout=h, check=True)
            binary.chmod(0o755)
        ns = self.ns
        sh("ip", "netns", "add", ns)
        Path(f"/etc/netns/{ns}").mkdir(parents=True, exist_ok=True)
        Path(f"/etc/netns/{ns}/resolv.conf").write_text("nameserver 1.1.1.1\n")
        sh("ip", "link", "add", "vmonchk", "type", "veth", "peer", "name", "qmonchk", check_rc=True)
        sh("ip", "link", "set", "qmonchk", "netns", ns)
        sh("ip", "addr", "add", "10.98.201.1/30", "dev", "vmonchk")
        sh("ip", "link", "set", "vmonchk", "up")
        sh("ip", "-n", ns, "addr", "add", "10.98.201.2/30", "dev", "qmonchk")
        for a in (("link", "set", "qmonchk", "up"), ("link", "set", "lo", "up"), ("route", "add", "default", "via", "10.98.201.1")):
            sh("ip", "-n", ns, *a)
        proc = subprocess.Popen(["ip", "netns", "exec", ns, "env", "LOG_LEVEL=error", str(binary), "-f", "rcchk"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.awg_pid = proc.pid
        sock = Path("/var/run/amneziawg/rcchk.sock")
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.1)
        sys.path.insert(0, f"{self.repo}/scripts/lab")
        from awg_lab import uapi_exchange as _uapi_exchange  # noqa: PLC0415

        conv = sh(sys.executable, f"{self.repo}/scripts/lab/awg_conf_to_uapi.py", self.repo, str(WORK / "c.conf"),
                  f"{ip}:{opts['port']}", check_rc=True)
        _uapi_exchange(str(sock), b"set=1\n" + conv.stdout.encode() + b"\n")
        sh("ip", "-n", ns, "addr", "add", f"{opts['address']}/24", "dev", "rcchk")
        sh("ip", "-n", ns, "link", "set", "rcchk", "mtu", "1280", "up")
        sh("ip", "-n", ns, "route", "replace", "default", "dev", "rcchk")
        sh("ip", "-n", ns, "route", "add", ip, "via", "10.98.201.1")
        return sh("ip", "netns", "exec", ns, "ping", "-c2", "-W3", "1.1.1.1").returncode == 0

    def curl_prefix(self, proto: str) -> list[str]:
        if proto in ("naive", "trusttunnel"):
            if proto == "naive":
                u = up.urlsplit(self.creds["naive"]["art"]["proxy_url"])
                proxy, user = f"https://{u.hostname}:{u.port or 443}", f"{up.unquote(u.username)}:{up.unquote(u.password)}"
            else:
                t = self.creds["trusttunnel"]["art"]["trusttunnel_toml"]
                o = self.creds["trusttunnel"]["grant"]["options"]
                proxy = f"https://{o['hostname']}:{o.get('port', 443)}"
                user = re.search(r'^username = "([^"]+)"', t, re.M).group(1) + ":" + re.search(r'^password = "([^"]+)"', t, re.M).group(1)
            return ["curl", "-p", "--proxy", proxy, "--proxy-user", user]
        if proto == "mieru":
            return ["curl", "--socks5-hostname", "127.0.0.1:1081"]
        if proto == "amneziawg":
            return ["ip", "netns", "exec", self.ns, "curl"]
        raise ValueError(proto)

    def transfer(self, proto: str, direction: str, nbytes: int, rate: int) -> tuple[int, float]:
        """Moves `nbytes` through the client of `proto`; returns (bytes the client saw, seconds)."""
        base = self.curl_prefix(proto) + ["-s", "-o", "/dev/null", "--max-time", "120", "--limit-rate", str(rate)]
        if direction == "down":
            cmd = base + ["-w", "%{size_download} %{time_total}", "-r", f"0-{nbytes - 1}", OVH]
        else:
            cmd = base + ["-w", "%{size_upload} %{time_total}", "-T", str(WORK / "up.bin"), SINK]
        out = sh(*cmd, timeout=150).stdout.split()
        return (int(float(out[0])), float(out[1])) if len(out) == 2 else (0, 0.0)


# --- sampling --------------------------------------------------------------------------------


class Sampler(threading.Thread):
    """Reads /api/metrics/live every second into a list of (monotonic, protocols, top_clients, host)."""

    def __init__(self, panel_base: str, cookies: dict, interval: float = 1.0):
        super().__init__(daemon=True)
        self.http = httpx.Client(base_url=panel_base, cookies=cookies, timeout=10)
        self.rows: list[tuple[float, dict, list, dict, str, float]] = []
        self.stop = threading.Event()
        self.interval = interval

    def run(self) -> None:
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                n = self.http.get("/api/metrics/live").json()["nodes"][0]
                self.rows.append((t0, n["protocols"], n["top_clients"], n["host"] or {}, n["status"], n["age_seconds"] or 0))
            except Exception:  # noqa: BLE001
                pass
            self.stop.wait(max(0.0, self.interval - (time.monotonic() - t0)))


def cum(row, proto: str, key: str) -> int:
    return (row[1].get(proto) or {}).get(key) or 0


def phase_panel(panel: Panel, base: str) -> None:
    print("\n== (2) panel /api/metrics/live", flush=True)
    n = panel.live()
    check("snapshot status ok", bool(n) and n["status"] == "ok", str(n and n["status"]))
    check("age_seconds small", bool(n) and n["age_seconds"] is not None and n["age_seconds"] < 5, str(n and n["age_seconds"]))
    agent = agent_metrics()
    if n and agent:
        check("cpu/mem same family as the agent", abs(n["host"]["mem"]["total"] - agent["host"]["mem"]["total"]) == 0
              and abs(n["host"]["cpu_percent"] - agent["host"]["cpu_percent"]) < 40)
    check("unauthenticated = 401", httpx.get(base + "/api/metrics/live", timeout=10).status_code == 401)
    pw = "V" + os.urandom(12).hex()
    r = panel.post("/api/admins", json={"username": "mon-viewer", "password": pw, "role": "viewer"})
    if check("viewer admin created", r.status_code == 201, str(r.status_code)):
        try:
            v = Panel(base, "mon-viewer", pw)
            vn = v.live()
            check("viewer role reads /api/metrics/live", bool(vn) and vn["status"] == "ok")
            check("viewer reads history", v.get("/api/metrics/history", params={"series": "host.cpu", "range": "15m"}).status_code == 200)
            check("viewer reads summary", v.get("/api/metrics/summary", params={"range": "1h"}).status_code == 200)
        finally:
            admins = panel.get("/api/admins").json()["items"]
            aid = next((a["id"] for a in admins if a["username"] == "mon-viewer"), None)
            if aid:
                panel.http.request("DELETE", f"/api/admins/{aid}", headers=panel.H)


# --- traffic ---------------------------------------------------------------------------------


def window_stats(rows, t_start: float, t_end: float, proto: str, key: str) -> dict:
    """Every 1 s reading of `key` between t_start and t_end (the panel refreshes every 2 s, so each value
    shows up about twice: that is the time-weighted view a user has of the screen)."""
    vals = [(row[1].get(proto) or {}).get(key) or 0.0 for row in rows if t_start <= row[0] <= t_end]
    return {"vals": vals, "peak": max(vals, default=0.0),
            "steady": statistics.mean(vals[2:-2]) if len(vals) > 6 else (statistics.mean(vals) if vals else 0.0)}


def run_traffic(rig: Rig, panel: Panel, sampler: Sampler, mb: int) -> dict:
    """Per protocol: a download phase, a quiet gap, an upload phase; compares client and monitor."""
    print("\n== (3) real traffic per protocol", flush=True)
    WORK.mkdir(exist_ok=True)
    (WORK / "up.bin").write_bytes(os.urandom(16 * 1024 * 1024))
    moved: dict[str, dict] = {}
    plan = [("trusttunnel", "real client: curl through the TrustTunnel endpoint"),
            ("naive", "real client: curl through NaiveProxy"),
            ("mieru", "real client: mieru client + SOCKS5"),
            ("amneziawg", "real client: amneziawg-go in a netns")]
    for proto, how in plan:
        if args.protos and proto not in args.protos.split(","):
            continue
        info(f"{proto}: {how}")
        for direction, rate, size in (("down", 3_000_000, mb * 1_000_000), ("up", 1_500_000, 16 * 1024 * 1024)):
            time.sleep(16)  # settle: rates back to ~0 and the per-client counters (polled every 5 s) caught up
            before = sampler.rows[-1]
            t0 = time.monotonic()
            got, secs = rig.transfer(proto, direction, size, rate)
            t1 = time.monotonic()
            time.sleep(16)  # let the last ticks (and the lagging per-client counters) fold in
            after = sampler.rows[-1]
            moved.setdefault(proto, {})[direction] = (got, secs)
            key = "down" if direction == "down" else "up"
            counted = cum(after, proto, f"{key}_bytes") - cum(before, proto, f"{key}_bytes")
            other = cum(after, proto, "up_bytes" if key == "down" else "down_bytes") - cum(before, proto, "up_bytes" if key == "down" else "down_bytes")
            ratio = counted / got if got else 0
            check(f"{proto} {direction}: client moved >0 bytes", got > 1_000_000, f"{got / 1e6:.1f} MB in {secs:.1f}s")
            check(f"{proto} {direction}: monitor {key}_bytes within +-15 % of client bytes", got and 0.85 <= ratio <= 1.15,
                  f"monitor {counted / 1e6:.2f} MB / client {got / 1e6:.2f} MB = {ratio:.3f} (reverse dir {other / 1e6:.2f} MB)")
            stats = window_stats(sampler.rows, t0, t1, proto, f"{key}_bps")
            series = [(r[1].get(proto) or {}).get(f"{key}_bps") or 0.0 for r in sampler.rows if t0 - 1 <= r[0] <= t1 + 4]
            info(f"{proto} {direction}: monitor MB/s each second: " + " ".join(f"{v / 1e6:.1f}" for v in series))
            client_rate = got / secs if secs else 0
            rate_ratio = stats["steady"] / client_rate if client_rate else 0
            check(f"{proto} {direction}: steady {key}_bps within +-25 % of client mean rate", client_rate and 0.75 <= rate_ratio <= 1.25,
                  f"monitor {stats['steady'] / 1e6:.2f} MB/s (peak {stats['peak'] / 1e6:.2f}) / client {client_rate / 1e6:.2f} MB/s = {rate_ratio:.2f}")
            idle = window_stats(sampler.rows, t1 + 6, t1 + 10, proto, f"{key}_bps")
            check(f"{proto} {direction}: rate back to ~0 within 10 s", idle["peak"] < max(0.05 * client_rate, 50_000), f"{idle['peak'] / 1e3:.1f} kB/s")
            moved_flat = []
            for other_proto in PROTOCOLS:
                if other_proto == proto:
                    continue
                d = sum(cum(after, other_proto, k) - cum(before, other_proto, k) for k in ("up_bytes", "down_bytes"))
                if d > max(0.02 * got, 300_000):
                    moved_flat.append(f"{other_proto}+{d / 1e6:.2f}MB")
            check(f"{proto} {direction}: the other protocol cards stay flat", not moved_flat, ", ".join(moved_flat))
            tops = {(c["protocol"], c["client_name"]) for row in sampler.rows if t0 <= row[0] <= t1 + 15 for c in row[2]}
            if proto in ("trusttunnel", "amneziawg"):
                check(f"{proto} {direction}: top_clients names the user", (proto, "mon-check") in tops, str(sorted(map(str, tops))))
            sess = max((row[1].get(proto, {}).get("sessions") or 0 for row in sampler.rows if t0 <= row[0] <= t1), default=0)
            info(f"{proto} {direction}: peak sessions={sess}")
            if proto in ("trusttunnel", "amneziawg"):
                seen_at = [row[0] - t0 for row in sampler.rows if t0 <= row[0] <= t1 + 15
                           for c in row[2] if c["protocol"] == proto and c["client_name"] == "mon-check"]
                if seen_at:
                    info(f"{proto} {direction}: per-client row visible from +{min(seen_at):.0f}s to +{max(seen_at):.0f}s "
                         f"(transfer lasted {t1 - t0:.0f}s; managers are polled every 5 s)")
                mon = [c for row in sampler.rows if t0 <= row[0] <= t1 + 15 for c in row[2]
                       if c["protocol"] == proto and c["client_name"] == "mon-check"]
                if mon:
                    d_key, w_key = ("down_bps", "up_bps") if direction == "down" else ("up_bps", "down_bps")
                    peak = max((c.get(d_key) or 0) for c in mon)
                    wrong = max((c.get(w_key) or 0) for c in mon)
                    check(f"{proto} {direction}: top_clients direction is right ({d_key} dominates)", peak > 2 * wrong,
                          f"{d_key}={peak / 1e6:.2f} MB/s vs {w_key}={wrong / 1e6:.2f} MB/s")
    # mtproxy: no real Telegram client is available -> synthetic bytes on the backend port
    info("mtproxy: SYNTHETIC (raw TCP to the backend port 127.0.0.1:8445; no Telegram client)")
    m_before = sampler.rows[-1]
    sent = recv = 0
    t_end = time.monotonic() + 8
    while time.monotonic() < t_end:
        try:
            with socket.create_connection(("127.0.0.1", 8445), timeout=3) as s:
                s.settimeout(2)
                try:
                    for _ in range(16):
                        s.sendall(b"\x16\x03\x01" + os.urandom(60000))
                        sent += 60003
                        try:
                            recv += len(s.recv(65536))
                        except OSError:
                            pass
                except OSError:
                    pass
        except OSError:
            break
    time.sleep(5)
    m_after = sampler.rows[-1]
    up_counted = cum(m_after, "mtproxy", "up_bytes") - cum(m_before, "mtproxy", "up_bytes")
    check("mtproxy (synthetic): up_bytes accounts the raw bytes sent", sent > 0 and 0.7 <= up_counted / sent <= 1.4,
          f"counter {up_counted / 1e6:.2f} MB / sent {sent / 1e6:.2f} MB; received {recv / 1e3:.1f} kB")
    return moved


# --- SSE -------------------------------------------------------------------------------------


def sse_probe(base: str, cookies: dict, seconds: float, node: str = "local") -> dict:
    out = {"status": None, "headers": {}, "events": [], "pings": [], "retry": False, "start": time.monotonic()}
    with httpx.Client(base_url=base, cookies=cookies, timeout=httpx.Timeout(20, read=30)) as c:
        with c.stream("GET", "/api/metrics/stream", params={"node": node}) as r:
            out["status"], out["headers"] = r.status_code, dict(r.headers)
            if r.status_code != 200:
                return out
            deadline = time.monotonic() + seconds
            event = None
            for line in r.iter_lines():
                now = time.monotonic()
                if line.startswith("retry:"):
                    out["retry"] = True
                elif line.startswith("event:"):
                    event = line.split(":", 1)[1].strip()
                    if event == "snapshot":
                        out["events"].append(now - out["start"])
                elif line.startswith(": ping"):
                    out["pings"].append(now - out["start"])
                if now > deadline:
                    break
    return out


def phase_sse(panel: Panel, base: str) -> None:
    print("\n== (4) SSE through the real nginx", flush=True)
    r = sse_probe(base, panel.cookies(), 12)
    check("stream 200", r["status"] == 200, str(r["status"]))
    h = {k.lower(): v for k, v in r["headers"].items()}
    check("Content-Type text/event-stream", "text/event-stream" in h.get("content-type", ""))
    # nginx consumes X-Accel-Buffering, so the header is proven on the origin; the frame timing above proves nginx does not buffer
    with httpx.Client(base_url="http://127.0.0.1:8787", cookies=panel.cookies(), headers={"Host": base.split("//")[1]}, timeout=10) as local:
        with local.stream("GET", "/api/metrics/stream") as origin:
            check("origin sends X-Accel-Buffering: no", origin.headers.get("x-accel-buffering") == "no", str(origin.status_code))
    check("Cache-Control: no-store", "no-store" in h.get("cache-control", ""))
    check("retry: sent", r["retry"])
    ev = r["events"]
    gaps = [b - a for a, b in list(zip(ev, ev[1:]))[1:]]  # the first frame is the immediate one at connect
    check("snapshot frames about every 2 s", len(ev) >= 5 and all(1.0 <= g <= 3.2 for g in gaps),
          f"{len(ev)} frames in 12 s, gaps {min(gaps, default=0):.2f}..{max(gaps, default=0):.2f}")
    r2 = sse_probe(base, panel.cookies(), 17)
    check(": ping within 15 s", bool(r2["pings"]) and r2["pings"][0] <= 16, f"first ping at {r2['pings'][0]:.1f}s" if r2["pings"] else "none")
    # 4 concurrent streams per session, the 5th is refused
    held, stop = [], threading.Event()
    cookies = panel.cookies()

    def hold():
        with httpx.Client(base_url=base, cookies=cookies, timeout=httpx.Timeout(20, read=60)) as c:
            with c.stream("GET", "/api/metrics/stream") as resp:
                held.append(resp.status_code)
                for _ in resp.iter_lines():
                    if stop.is_set():
                        break

    threads = [threading.Thread(target=hold, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(3)
    fifth = httpx.get(base + "/api/metrics/stream", cookies=cookies, timeout=10)
    check("4 streams accepted", held.count(200) == 4, str(held))
    check("5th concurrent stream per session gets 429", fifth.status_code == 429, str(fifth.status_code))
    stop.set()
    time.sleep(3)


# --- history / summary ------------------------------------------------------------------------


def panel_db(sql: str) -> list:
    # SQLite runs in the external controller, never inside the native panel image.
    inspected = sh("docker", "inspect", "proxy-control-panel", check_rc=True)
    container = json.loads(inspected.stdout)[0]
    env = dict(item.split("=", 1) for item in container["Config"]["Env"] if "=" in item)
    database = Path(env.get("PANEL_DATABASE", "/data/panel.sqlite3"))
    for mount in sorted(container["Mounts"], key=lambda item: len(item["Destination"]), reverse=True):
        destination = Path(mount["Destination"])
        if database.is_relative_to(destination):
            host_path = Path(mount["Source"]) / database.relative_to(destination)
            with sqlite3.connect(host_path.as_uri() + "?mode=ro", uri=True) as db:
                return db.execute(sql).fetchall()
    raise RuntimeError("panel database is not exposed by a lab Docker mount")


def phase_history(panel: Panel, rig: Rig | None, moved: dict, t_start_wall: float, summary_before: dict | None) -> None:
    print("\n== (5) history / summary / rollups", flush=True)
    h = panel.get("/api/metrics/history", params={"series": "trusttunnel.down_bps,host.cpu", "range": "15m"}).json()
    tt = [p for p in h["series"]["trusttunnel.down_bps"] if p[2] is not None]
    cpu = [p for p in h["series"]["host.cpu"] if p[2] is not None]
    check("history 15m: trusttunnel.down_bps shows the load peak", bool(tt) and max(p[2] for p in tt) > 1_000_000,
          f"peak {max((p[2] for p in tt), default=0) / 1e6:.2f} MB/s, step {h['step']}s, source {h['source']}")
    check("history 15m: host.cpu has points", len(cpu) > 10, f"{len(cpu)} points, max {max((p[2] for p in cpu), default=0):.1f} %")
    gaps = [p for p in h["series"]["host.cpu"] if p[1] is None]
    info(f"history 15m: {len(gaps)} gap points (null, not zero) of {len(h['series']['host.cpu'])}")
    # a series without any data in the window comes back as pure gaps
    z = panel.get("/api/metrics/history", params={"series": "host.swap", "range": "15m"}).json()
    check("history: an idle series is gaps/zeros but never invented", all(p[1] in (None, 0, 0.0) for p in z["series"]["host.swap"]))
    s = panel.get("/api/metrics/summary", params={"range": "1h"}).json()["nodes"][0]
    shares = sum(p["share_percent"] or 0 for p in s["protocols"].values())
    check("summary 1h: shares add to ~100 %", 99 <= shares <= 101, f"{shares:.1f}")
    for proto in ("trusttunnel", "naive", "mieru", "amneziawg"):
        got = sum(v[0] for v in moved.get(proto, {}).values())
        total = s["protocols"][proto]["total_bytes"]
        # The 1 h window slides: older load ages out while new bytes arrive, so a before/after
        # difference is not comparable. What must hold is a lower bound: the window contains
        # everything this run just moved (headers make the kernel count a little higher).
        check(f"summary 1h: {proto} total covers the bytes moved (>= 85 %)", bool(got) and total >= 0.85 * got,
              f"summary {total / 1e6:.1f} MB vs client {got / 1e6:.1f} MB (sum of both directions)")
    time.sleep(35)  # a flush interval
    for res, bucket_s in ((60, "60 s"), (900, "900 s"), (3600, "3600 s")):
        rows = panel_db(f"select count(*) from metric_rollups where resolution={res}")
        check(f"SQLite metric_rollups rows at {bucket_s}", bool(rows) and rows[0][0] > 0, str(rows))
    r60 = panel_db("select count(*), count(distinct series), min(bucket), max(bucket) from metric_rollups where resolution=60")
    if r60:
        n, nseries, lo, hi = r60[0]
        span_min = max((hi - lo) / 60, 1)
        per_bucket = n / span_min
        page = panel_db("pragma page_size")[0][0]
        bytes_row = 70  # key (3 ints + node + series text) + 4 numbers, measured below when dbstat exists
        db = panel_db("select sum(pgsize) from dbstat where name='metric_rollups'")
        if db and db[0][0]:
            bytes_row = db[0][0] / max(sum(r[0] for r in panel_db("select count(*) from metric_rollups")), 1)
        info(f"rollups: 60 s tier {n} rows over {span_min:.0f} min = {per_bucket:.1f} rows/min ({nseries} series); "
             f"~{per_bucket * 60:.0f} rows/h, ~{per_bucket * 60 * bytes_row / 1024:.0f} KiB/h at {bytes_row:.0f} B/row (page size {page})")


# --- degraded modes ----------------------------------------------------------------------------


def phase_degraded(panel: Panel) -> None:
    print("\n== (6) degraded modes", flush=True)
    t0 = time.monotonic()
    sh("systemctl", "stop", "version-agent")
    first_stale, ages = None, []
    while time.monotonic() - t0 < 40:
        n = panel.live()
        if n and n["status"] == "stale":
            first_stale = first_stale or time.monotonic() - t0
            ages.append(n["age_seconds"])
        if len(ages) >= 5:
            break
        time.sleep(1.5)
    check("agent stopped -> node stale within ~10 s", first_stale is not None and first_stale <= 12,
          f"{first_stale:.1f}s" if first_stale else "never")
    check("stale age grows", len(ages) >= 3 and ages[-1] > ages[0], str([round(a, 1) for a in ages]))
    n = panel.live()
    check("stale entry keeps the last numbers", bool(n and n["host"]))
    time.sleep(max(0, args.outage - 25))  # a real hole in the history: at least one whole 60 s bucket
    t1 = time.monotonic()
    sh("systemctl", "start", "version-agent")
    back = None
    while time.monotonic() - t1 < 60:
        n = panel.live()
        if n and n["status"] == "ok":
            back = time.monotonic() - t1
            break
        time.sleep(1)
    check("agent restarted -> data resumes", back is not None and back <= 30, f"{back:.1f}s" if back else "never")
    hist = panel.get("/api/metrics/history", params={"series": "host.cpu", "range": "15m"}).json()["series"]["host.cpu"]
    nulls = [p for p in hist if p[1] is None]
    check("history shows the outage as a gap (null points, not zeros)", len(nulls) >= 1 and all(p[2] is None for p in nulls),
          f"{len(nulls)} null points, step {hist[1][0] - hist[0][0]} s")
    # the table vanishes: the sampler must rebuild it
    sh("nft", "delete", "table", "inet", "proxy_control_metrics")
    t2 = time.monotonic()
    recovered = None
    while time.monotonic() - t2 < 90:
        m = agent_metrics()
        exists = sh("nft", "list", "table", "inet", "proxy_control_metrics").returncode == 0
        if m and m["kernel_counters"] == "ok" and exists:
            recovered = time.monotonic() - t2
            break
        time.sleep(2)
    check("nft table deleted -> counters recover within 60 s", recovered is not None and recovered <= 60,
          f"{recovered:.1f}s" if recovered else "never")
    time.sleep(6)
    n = panel.live()
    spike = max(((p.get("down_bps") or 0) + (p.get("up_bps") or 0)) for p in n["protocols"].values())
    check("no phantom traffic spike after the table is rebuilt", spike < 200_000, f"{spike / 1e3:.1f} kB/s")
    check("kernel_counters ok again in the panel", n["status"] == "ok" and n["kernel_counters"] == "ok")


# --- performance -----------------------------------------------------------------------------


def cpu_ticks(pids: list[int]) -> int:
    total = 0
    for pid in pids:
        try:
            f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            total += int(f[11]) + int(f[12])
        except OSError:
            pass
    return total


def phase_perf(rig: Rig, panel: Panel, base: str, seconds: int) -> None:
    print(f"\n== (7) performance: 2 SSE clients + moderate load for {seconds} s", flush=True)
    stop = threading.Event()
    cookies = panel.cookies()

    def sse():
        with httpx.Client(base_url=base, cookies=cookies, timeout=httpx.Timeout(20, read=60)) as c:
            with c.stream("GET", "/api/metrics/stream") as r:
                for _ in r.iter_lines():
                    if stop.is_set():
                        break

    def load(proto):
        while not stop.is_set():
            rig.transfer(proto, "down", 12_000_000, 1_500_000)

    ts = [threading.Thread(target=sse, daemon=True) for _ in range(2)]
    ts += [threading.Thread(target=load, args=(p,), daemon=True) for p in ("trusttunnel", "naive")]
    for t in ts:
        t.start()
    agent_pid = int(sh("systemctl", "show", "-p", "MainPID", "--value", "version-agent").stdout.strip())
    nginx = [int(p) for p in sh("pgrep", "-x", "nginx").stdout.split()]
    panel_pid = int(sh("docker", "inspect", "-f", "{{.State.Pid}}", "proxy-control-panel").stdout.strip())
    hz = os.sysconf("SC_CLK_TCK")
    t0 = time.monotonic()
    a0, n0, p0 = cpu_ticks([agent_pid]), cpu_ticks(nginx), cpu_ticks([panel_pid])
    docker_samples = []
    while time.monotonic() - t0 < seconds:
        out = sh("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}", "proxy-control-panel").stdout.split()
        if out:
            docker_samples.append((float(out[0].rstrip("%")), out[1]))
        time.sleep(10)
    wall = time.monotonic() - t0
    a1, n1, p1 = cpu_ticks([agent_pid]), cpu_ticks(nginx), cpu_ticks([panel_pid])
    stop.set()
    agent_cpu, nginx_cpu, panel_cpu = (100 * (b - a) / hz / wall for a, b in ((a0, a1), (n0, n1), (p0, p1)))
    info(f"version-agent: {agent_cpu:.2f} % of one core (pid {agent_pid})")
    info(f"panel container: {panel_cpu:.2f} % of one core by /proc; docker stats samples "
         f"avg {statistics.mean(s[0] for s in docker_samples):.2f} % max {max(s[0] for s in docker_samples):.2f} % mem {docker_samples[-1][1]}")
    info(f"nginx (all workers, includes the proxied load): {nginx_cpu:.2f} % of one core")
    check("version-agent below 2 % of one core under load", agent_cpu < 2.0, f"{agent_cpu:.2f} %")
    check("panel container below 25 % of one core", panel_cpu < 25, f"{panel_cpu:.2f} %")


# --- main ------------------------------------------------------------------------------------


def pick_source() -> None:
    global OVH
    for url in SOURCES:
        r = sh("curl", "-s", "-o", "/dev/null", "--max-time", "6", "-r", "0-100000", "-w", "%{http_code}", url)
        if r.stdout.strip() == "206":
            OVH = url
            info("download source: " + url.split("/")[2])
            return
    info("no public download source answers; traffic checks will fail")


def main() -> int:
    global args
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--mb", type=int, default=36)
    ap.add_argument("--phases", default="agent,panel,traffic,sse,history,degraded")
    ap.add_argument("--perf", type=int, default=0)
    ap.add_argument("--protos", default="", help="comma list to limit the traffic phase, e.g. naive,trusttunnel")
    ap.add_argument("--outage", type=int, default=130, help="seconds the agent stays stopped in the degraded phase")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("run as root on the lab host", file=sys.stderr)
        return 2
    phases = set(args.phases.split(","))
    pick_source()
    host = panel_host()
    base = f"https://{host}"
    panel = Panel(base, "owner", (SECRETS / "panel-bootstrap-password").read_text().strip())
    started_wall = time.time()
    if "agent" in phases:
        phase_agent()
    if "panel" in phases:
        phase_panel(panel, base)
    need_rig = phases & {"traffic", "history"} or args.perf
    rig = Rig(panel, args.repo) if need_rig else None
    sampler = None
    moved: dict = {}
    summary_before = None
    try:
        if rig:
            summary_before = {k: v["total_bytes"] for k, v in panel.get("/api/metrics/summary", params={"range": "1h"}).json()["nodes"][0]["protocols"].items()}
            rig.create()
            check("mieru client up (real mieru client)", rig.start_mieru())
            check("amneziawg client up (amneziawg-go in a netns)", rig.start_awg())
            sampler = Sampler(base, panel.cookies())
            sampler.start()
            time.sleep(4)
        if "traffic" in phases:
            moved = run_traffic(rig, panel, sampler, args.mb)
        if "sse" in phases:
            phase_sse(panel, base)
        if "history" in phases:
            phase_history(panel, rig, moved, started_wall, summary_before)
        if args.perf:
            phase_perf(rig, panel, base, args.perf)
        if "degraded" in phases:
            phase_degraded(panel)
    finally:
        if sampler:
            sampler.stop.set()
        if rig:
            rig.cleanup()
    bad = [n for n, ok in results if not ok]
    print(f"\nTOTAL {len(results)} checks, FAILED {len(bad)}: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
