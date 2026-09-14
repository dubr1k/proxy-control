#!/usr/bin/env python3
"""v0.4 routing spike (Task 30): what the pinned Caddy forwardproxy and mita can enforce natively.

Runs as root on the disposable lab host against the `lab-host` install (live Caddy 2.11.4 +
klzgrad/forwardproxy, live mita 3.36) and a stand-in SOCKS5 egress (`socks5-stub.py`) in
place of WARP. Every probe answers one cell of the capability matrix in
`docs/spikes/VNEXT_ROUTING_ENGINE.md`; the JSON on stdout is copied into that document.

Nothing here is a release path: the Caddy config is swapped through the Admin API and the
mita config through `mita apply`, and both are restored byte-for-byte at the end (the
managers' state files are never touched, so their `config changed outside manager` guard
stays satisfied). Throw-away users are created through the panel and deleted afterwards.

    routing-spike.py --panel https://panel.lab.test --ca /etc/letsencrypt/lab-ca/ca.crt \
        --password-file /opt/mtproxy-shared443/secrets/panel-bootstrap-password --output /root/lab-results/spike
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.cookiejar
import json
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ADMIN = "http://127.0.0.1:2019"
STUB_PORT = 45000
MIHOMO_PORT = 18081
MIHOMO_IMAGE = "metacubex/mihomo:latest"
CADDYFILE = Path("/var/lib/naive-manager/Caddyfile")
TARGET_HOST = "api.ipify.org"
DENY_HOST = "example.com"


class Spike(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(*argv: str, timeout: int = 120, input_text: str | None = None) -> tuple[int, str]:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, input=input_text)
    return completed.returncode, (completed.stdout + completed.stderr)[-4000:]


# --- panel ---------------------------------------------------------------------------

class Panel:
    def __init__(self, base: str, ca: Path | None):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context(cafile=str(ca) if ca else None)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                                  urllib.request.HTTPCookieProcessor(self.jar))

    def _csrf(self) -> str:
        return next((c.value for c in self.jar if c.name == "panel_csrf"), "")

    def request(self, path: str, *, method: str = "GET", payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        if method != "GET":
            headers["X-CSRF-Token"] = self._csrf()
        request = urllib.request.Request(f"{self.base}{path}", data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def json(self, path: str, *, method: str = "GET", payload=None, expect=(200, 201)):
        status, body = self.request(path, method=method, payload=payload)
        if status not in expect:
            raise Spike(f"{method} {path} -> {status} {body[:200]!r}")
        return json.loads(body) if body else {}

    def login(self, password: str) -> None:
        status, _ = self.request("/login")
        if status != 200 or not self._csrf():
            raise Spike("login page did not set the CSRF cookie")
        self.json("/api/auth/login", method="POST", payload={"username": "owner", "password": password}, expect=(200, 204))


# --- Caddy through its Admin API ------------------------------------------------------

def admin(method: str, path: str, data: bytes | None = None, content_type: str = "application/json") -> tuple[int, bytes]:
    request = urllib.request.Request(ADMIN + path, data=data, method=method,
                                     headers={"Content-Type": content_type, "Cache-Control": "must-revalidate"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def adapt(caddyfile: str) -> tuple[int, dict | str]:
    status, body = admin("POST", "/adapt?adapter=caddyfile&validate=true", caddyfile.encode(), "text/caddyfile")
    if status != 200:
        return status, body.decode(errors="replace")[:300]
    payload = json.loads(body)
    return status, payload.get("result", payload)


def rewrite_listener(config: dict) -> dict:
    """What naive_manager.server.command_reload does: the private listener is 4443."""
    for server in config["apps"]["http"]["servers"].values():
        server["listen"] = ["127.0.0.1:4443" if a == "127.0.0.1:443" else ":4443" if a == ":443" else a
                            for a in server["listen"]]
        if any(a in {":4443", "127.0.0.1:4443"} for a in server["listen"]):
            server.setdefault("automatic_https", {})["disable_redirects"] = True
    return config


def forward_proxy_handler(config: dict) -> dict:
    def walk(value):
        if isinstance(value, dict):
            if value.get("handler") == "forward_proxy":
                yield value
            for item in value.values():
                yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)
    handlers = list(walk(config))
    if len(handlers) != 1:
        raise Spike(f"expected one forward_proxy handler, found {len(handlers)}")
    return handlers[0]


def with_egress(caddyfile: str, *, upstream: str | None, deny: list[str] | None, extra: str = "") -> str:
    """Insert the lines a v0.4 naive-manager would own, right after `probe_resistance`."""
    lines = caddyfile.splitlines()
    index = next(i for i, line in enumerate(lines) if re.match(r"^\s*probe_resistance", line))
    indent = re.match(r"^(\s*)", lines[index]).group(1)
    block = ["# BEGIN NAIVE-MANAGER EGRESS"]
    if upstream:
        block.append(f"upstream {upstream}")
    if deny:
        block += ["acl {", f"    deny {' '.join(deny)}", "}"]
    if extra:
        block.append(extra)
    block.append("# END NAIVE-MANAGER EGRESS")
    lines[index + 1:index + 1] = [indent + line for line in block]
    return "\n".join(lines) + "\n"


def load(config: dict) -> None:
    status, body = admin("POST", "/load", json.dumps(config, separators=(",", ":")).encode())
    if status not in (200, 204):
        raise Spike(f"caddy load -> {status} {body[:200]!r}")


# --- probes ---------------------------------------------------------------------------

def naive_connect(share_url: str, ca: Path | None, target: str, *, timeout: int = 25) -> tuple[int, str]:
    """One CONNECT through the NaiveProxy of the lab node (curl as the HTTPS proxy client,
    the credential sent up front — probe resistance answers an unauthenticated CONNECT
    with the cover site, never a 407)."""
    parts = urllib.parse.urlsplit(share_url.replace("naive+https://", "https://", 1))
    token = base64.b64encode(f"{urllib.parse.unquote(parts.username)}:{urllib.parse.unquote(parts.password)}".encode()).decode()
    argv = ["curl", "--silent", "--show-error", "--max-time", str(timeout), "--output", "/dev/null", "--write-out", "%{http_code}",
            "--proxy", f"https://{parts.hostname}:{parts.port or 443}", "--proxy-header", f"Proxy-Authorization: Basic {token}"]
    if ca:
        argv += ["--proxy-cacert", str(ca)]
    argv.append(target)
    return run(*argv, timeout=timeout + 10)


def mihomo_config(share_url: str) -> str:
    """`mierus://user:pass@host?profile=…&port=N&protocol=TCP[&port=M&protocol=UDP]` → a mihomo
    `mieru` proxy on the TCP binding (mihomo's `mieru` outbound is TCP-transport)."""
    parts = urllib.parse.urlsplit(share_url)
    pairs = urllib.parse.parse_qsl(parts.query)
    ports = [int(value) for key, value in pairs if key == "port"]
    protocols = [value for key, value in pairs if key == "protocol"]
    tcp = next((port for port, protocol in zip(ports, protocols) if protocol == "TCP"), ports[0])
    return (f"mixed-port: {MIHOMO_PORT}\nbind-address: '127.0.0.1'\nallow-lan: false\nmode: rule\nlog-level: warning\n"
            f"proxies:\n  - name: lab\n    type: mieru\n    server: {parts.hostname}\n    port: {tcp}\n"
            f"    transport: TCP\n    username: {urllib.parse.unquote(parts.username)}\n"
            f"    password: {urllib.parse.unquote(parts.password)}\n    udp: true\n"
            "proxy-groups: []\nrules:\n  - MATCH,lab\n")


def curl_socks(target: str, *, resolve_locally: bool = False, timeout: int = 25) -> tuple[int, str]:
    scheme = "socks5" if resolve_locally else "socks5h"
    return run("curl", "--silent", "--show-error", "--max-time", str(timeout), "--output", "/dev/null",
               "--write-out", "%{http_code}", "--proxy", f"{scheme}://127.0.0.1:{MIHOMO_PORT}", target, timeout=timeout + 10)


def socks5_udp_dns(port: int, name: str = "cloudflare.com") -> bool:
    import struct

    control = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        control.sendall(b"\x05\x01\x00")
        if control.recv(2) != b"\x05\x00":
            return False
        control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
        reply = control.recv(10)
        if len(reply) < 10 or reply[1] != 0 or reply[3] != 1:
            return False
        relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])
        if relay[0] == "0.0.0.0":
            relay = ("127.0.0.1", relay[1])
        labels = b"".join(bytes((len(part),)) + part.encode() for part in name.split(".")) + b"\x00"
        query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
        header = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(10)
        try:
            udp.sendto(header + query, relay)
            data, _ = udp.recvfrom(1500)
        finally:
            udp.close()
        payload = data[10:]
        return payload[:2] == b"\x12\x34" and bool(payload[2] & 0x80) and payload[3] & 0x0F == 0 and payload[6:8] != b"\x00\x00"
    except OSError:
        return False
    finally:
        control.close()


class StubLog:
    def __init__(self, path: Path):
        self.path = path

    def lines(self) -> list[tuple[str, int]]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text().splitlines():
            _, host, port = line.split("\t")
            rows.append((host, int(port)))
        return rows

    def reset(self) -> None:
        self.path.write_text("")

    def saw(self, host: str) -> bool:
        return any(h == host for h, _ in self.lines())


def socks5_greeting(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.sendall(b"\x05\x01\x00")
            return s.recv(2) == b"\x05\x00"
    except OSError:
        return False


# --- the spike --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--panel", default="https://panel.lab.test")
    parser.add_argument("--ca", type=Path, default=Path("/etc/letsencrypt/lab-ca/ca.crt"))
    parser.add_argument("--password-file", type=Path, default=Path("/opt/mtproxy-shared443/secrets/panel-bootstrap-password"))
    parser.add_argument("--stub", type=Path, default=Path(__file__).with_name("socks5-stub.py"))
    parser.add_argument("--output", type=Path, default=Path("/root/lab-results/spike"))
    parser.add_argument("--mihomo-image", default=MIHOMO_IMAGE)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    result: dict = {"naive_native": {}, "mieru_native": {}, "reachability": {}, "failures": {}, "notes": []}
    suffix = secrets.token_hex(3)
    cleanup = []
    stub_log = StubLog(args.output / "stub-connects.log")
    stub_log.reset()
    stub = subprocess.Popen([sys.executable, str(args.stub), "--listen", f"127.0.0.1:{STUB_PORT}", "--log", str(stub_log.path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cleanup.append(lambda: (stub.terminate(), stub.wait(timeout=5)))
    time.sleep(0.5)
    result["reachability"]["stub_socks5_greeting"] = socks5_greeting(STUB_PORT)
    result["reachability"]["dead_port_refused_fast"] = not socks5_greeting(STUB_PORT + 1)

    panel = Panel(args.panel, args.ca)
    panel.login(args.password_file.read_text().strip())
    try:
        # --- throw-away users ---
        naive_user, mieru_user = f"spike-{suffix}", f"spike-{suffix}"
        created = panel.json("/api/naive/users", method="POST", payload={"username": naive_user})
        cleanup.append(lambda: panel.request(f"/api/naive/users/{naive_user}", method="DELETE"))
        naive_share = panel.json(f"/api/reveal/{created['reveal_token']}")["clients"]["nekobox"]["share_url"]
        revision = panel.json("/api/mieru/users")["service"]["revision"]
        created = panel.json("/api/mieru/users", method="POST",
                             payload={"username": mieru_user, "quotas": [], "expected_revision": revision})
        cleanup.append(lambda: panel.request(f"/api/mieru/users/{mieru_user}", method="DELETE",
                                             payload={"expected_revision": panel.json("/api/mieru/users")["service"]["revision"]}))
        mieru_share = panel.json(f"/api/reveal/{created['reveal_token']}")["clients"]["native"]["simple_share_url"]
        target_ip = socket.gethostbyname(TARGET_HOST)

        # --- Caddy forwardproxy ---
        original_text = CADDYFILE.read_bytes()
        status, original_config = admin("GET", "/config/")
        if status != 200:
            raise Spike("caddy admin unreachable")
        original_config = json.loads(original_config)
        cleanup.append(lambda: load(original_config))
        naive = result["naive_native"]
        base_text = original_text.decode()

        def naive_probe(target: str) -> tuple[int, str]:
            return naive_connect(naive_share, args.ca, target)

        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["baseline_direct_ok"] = code == 0 and out == "200"
        naive["baseline_stub_untouched"] = not stub_log.saw(TARGET_HOST)

        status, adapted = adapt(with_egress(base_text, upstream=f"socks5://127.0.0.1:{STUB_PORT}", deny=None))
        naive["adapt_upstream_socks5"] = status == 200 and forward_proxy_handler(adapted).get("upstream") == f"socks5://127.0.0.1:{STUB_PORT}"
        if status == 200:
            load(rewrite_listener(adapted))
            stub_log.reset()
            code, out = naive_probe(f"https://{TARGET_HOST}")
            naive["whole_warp_via_stub"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)
            naive["whole_warp_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-3:]}"

        status, adapted = adapt(with_egress(base_text, upstream=None, deny=[DENY_HOST, f"*.{DENY_HOST}", "10.0.0.0/8"]))
        handler = forward_proxy_handler(adapted) if status == 200 else {}
        naive["adapt_acl_deny"] = status == 200 and bool(handler.get("acl"))
        naive["adapt_acl_shape"] = json.dumps(handler.get("acl"))[:300]
        if status == 200:
            load(rewrite_listener(adapted))
            code, out = naive_probe(f"http://{DENY_HOST}")
            naive["block_domain"] = out == "403" or (code != 0 and out != "200")
            naive["block_domain_detail"] = f"curl {code} {out}"
            code, out = naive_probe(f"http://www.{DENY_HOST}")
            naive["block_domain_wildcard"] = out == "403" or (code != 0 and out != "200")
            code, out = naive_probe(f"https://{TARGET_HOST}")
            naive["acl_leaves_others_alone"] = code == 0 and out == "200"

        status, adapted = adapt(with_egress(base_text, upstream=None, deny=[f"{target_ip}/32"]))
        if status == 200:
            load(rewrite_listener(adapted))
            code, out = naive_probe(f"https://{TARGET_HOST}")
            naive["block_cidr_one_address_of_a_multihomed_host"] = out == "403" or (code != 0 and out != "200")
            naive["block_cidr_detail"] = f"deny {target_ip}/32, CONNECT {TARGET_HOST}: curl {code} {out}"
            code, out = naive_probe(f"https://{target_ip}")
            naive["block_cidr_matches_literal_ip"] = out == "403" or (code != 0 and out != "200")
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(TARGET_HOST, 443, proto=socket.IPPROTO_TCP)})
        naive["target_addresses"] = addresses
        status, adapted = adapt(with_egress(base_text, upstream=None,
                                            deny=[f"{a}/128" if ":" in a else f"{a}/32" for a in addresses]))
        if status == 200:
            load(rewrite_listener(adapted))
            code, out = naive_probe(f"https://{TARGET_HOST}")
            naive["block_cidr_matches_resolved_hostname"] = out == "403" or (code != 0 and out != "200")
            naive["block_cidr_all_addresses_detail"] = f"deny every address of {TARGET_HOST}: curl {code} {out}"

        status, adapted = adapt(with_egress(base_text, upstream=f"socks5://127.0.0.1:{STUB_PORT}", deny=[DENY_HOST]))
        naive["adapt_acl_with_upstream"] = status == 200
        if status == 200:
            load(rewrite_listener(adapted))
            stub_log.reset()
            code, out = naive_probe(f"http://{DENY_HOST}")
            naive["acl_enforced_with_upstream"] = (out == "403" or (code != 0 and out != "200")) and not stub_log.saw(DENY_HOST)
            naive["acl_with_upstream_detail"] = f"deny {DENY_HOST} + upstream: curl {code} {out}; stub {stub_log.lines()[-2:]}"
            code, out = naive_probe(f"https://{TARGET_HOST}")
            naive["upstream_still_used_with_acl"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)
            # With an upstream the handler hands every CONNECT to it: is the built-in loopback
            # deny still applied, or does the upstream see 127.0.0.1?
            stub_log.reset()
            code, out = naive_probe("http://127.0.0.1:2019/config/")
            naive["loopback_denied_with_upstream"] = (out == "403" or (code != 0 and out != "200")) and not stub_log.saw("127.0.0.1")
            naive["loopback_with_upstream_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-2:]}"
        load(original_config)
        code, out = naive_probe("http://127.0.0.1:2019/config/")
        naive["loopback_denied_by_default"] = out == "403" or (code != 0 and out != "200")
        naive["loopback_detail"] = f"curl {code} {out}"

        status, adapted = adapt(with_egress(base_text, upstream=None, deny=None, extra="ports 443"))
        naive["ports_is_an_allow_list"] = status == 200
        if status == 200:
            load(rewrite_listener(adapted))
            code, out = naive_probe(f"http://{TARGET_HOST}")
            naive["ports_blocks_other_ports"] = out == "403" or (code != 0 and out != "200")
            load(original_config)

        status, _ = adapt(with_egress(base_text, upstream=None, deny=["not a host or cidr !!"]))
        naive["invalid_acl_rejected_by_adapt"] = status != 200
        status, adapted = adapt(with_egress(base_text, upstream=f"socks5://127.0.0.1:{STUB_PORT + 1}", deny=None))
        if status == 200:
            load(rewrite_listener(adapted))
            code, out = naive_probe(f"https://{TARGET_HOST}")
            naive["dead_upstream_fails_closed"] = out != "200"
            naive["dead_upstream_detail"] = f"curl {code} {out}"
        load(original_config)
        status, now = admin("GET", "/config/")
        naive["restored_running_config"] = json.loads(now) == original_config
        naive["caddyfile_untouched"] = CADDYFILE.read_bytes() == original_text
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["restored_direct_ok"] = code == 0 and out == "200"

        # --- mita ---
        mieru = result["mieru_native"]
        code, out = run("mita", "describe", "config")
        if code != 0:
            raise Spike(f"mita describe config: {out}")
        original_mita = json.loads(out)
        work = Path(tempfile.mkdtemp(prefix="spike-mihomo-"))
        cleanup.append(lambda: shutil.rmtree(work, ignore_errors=True))

        def apply_mita(config: dict, *, restart: bool) -> None:
            path = work / "mita.json"
            path.write_text(json.dumps(config))
            code, out = run("mita", "apply", "config", str(path))
            if code != 0:
                raise Spike(f"mita apply: {out}")
            if restart:
                run("mita", "stop")
                code, out = run("mita", "start")
            else:
                code, out = run("mita", "reload")
            if code != 0:
                raise Spike(f"mita {'restart' if restart else 'reload'}: {out}")
            time.sleep(2.5 if restart else 1.5)

        cleanup.append(lambda: apply_mita(original_mita, restart=False))
        (work / "mihomo.yaml").write_text(mihomo_config(mieru_share))
        (work / "mihomo.yaml").chmod(0o644)
        run("docker", "rm", "-f", "pc-spike-mihomo")
        code, out = run("docker", "run", "-d", "--name", "pc-spike-mihomo", "--network", "host", "-v", f"{work}:/cfg",
                        args.mihomo_image, "-d", "/cfg", "-f", "/cfg/mihomo.yaml")
        cleanup.append(lambda: run("docker", "rm", "-f", "pc-spike-mihomo"))
        if code != 0:
            raise Spike(f"mihomo: {out}")
        time.sleep(4)

        def egress(rules: list[dict]) -> dict:
            config = json.loads(json.dumps(original_mita))
            config["egress"] = {"proxies": [{"name": "stub", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": STUB_PORT}],
                                "rules": rules}
            return config

        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["baseline_direct_ok"] = code == 0 and out == "200"
        mieru["baseline_detail"] = f"curl {code} {out}"
        whole = egress([{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["stub"]}])
        apply_mita(whole, restart=False)
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["egress_change_applied_by_reload"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)
        mieru["reload_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-3:]}"
        apply_mita(whole, restart=True)
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["whole_warp_via_stub_after_restart"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)
        mieru["whole_warp_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-3:]}"
        mieru["hostname_reaches_proxy_as_domain"] = any(h == TARGET_HOST for h, _ in stub_log.lines())
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}", resolve_locally=True)
        mieru["client_resolved_ip_reaches_proxy_as_ip"] = code == 0 and out == "200" and any(
            h[0].isdigit() or ":" in h for h, _ in stub_log.lines())
        mieru["client_resolved_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-3:]}"
        mieru["udp_over_proxy"] = socks5_udp_dns(MIHOMO_PORT)

        # Every egress change below is applied the way the reload probe showed it must be.
        restart_needed = not mieru["egress_change_applied_by_reload"]
        apply_mita(egress([{"domainNames": [DENY_HOST], "action": "REJECT"},
                           {"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["stub"]}]), restart=restart_needed)
        stub_log.reset()
        code, out = curl_socks(f"http://{DENY_HOST}")
        mieru["block_domain"] = out != "200" and not stub_log.saw(DENY_HOST)
        mieru["block_domain_detail"] = f"curl {code} {out}"
        code, out = curl_socks(f"http://www.{DENY_HOST}")
        mieru["block_domain_suffix"] = out != "200" and not stub_log.saw(f"www.{DENY_HOST}")
        code, out = curl_socks(f"http://{DENY_HOST}", resolve_locally=True)
        mieru["block_domain_when_client_resolves"] = out != "200"
        mieru["block_domain_when_client_resolves_detail"] = f"curl {code} {out} (IP-only CONNECT never matches a domain rule)"

        apply_mita(egress([{"domainNames": [TARGET_HOST], "action": "DIRECT"},
                           {"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["stub"]}]), restart=restart_needed)
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["selective_domain_direct"] = code == 0 and out == "200" and not stub_log.saw(TARGET_HOST)
        code, out = curl_socks("https://www.cloudflare.com/cdn-cgi/trace")
        mieru["selective_rest_via_stub"] = code == 0 and out == "200" and stub_log.saw("www.cloudflare.com")

        apply_mita(egress([{"ipRanges": [f"{target_ip}/32"], "action": "REJECT"},
                           {"ipRanges": ["*"], "domainNames": ["*"], "action": "DIRECT"}]), restart=restart_needed)
        # A literal-IP CONNECT to the denied address: refused by the rule, or the TLS handshake
        # never happens (an `Empty reply`/reset rather than a certificate error).
        code, out = curl_socks(f"http://{target_ip}")
        mieru["block_cidr_literal_ip"] = out != "200" and out != "301"
        mieru["block_cidr_literal_detail"] = f"curl {code} {out}"
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["block_cidr_matches_resolved_hostname"] = out != "200"
        mieru["block_cidr_detail"] = f"curl {code} {out}"

        # Loopback as a destination through Mieru: the user's own allowLoopbackIP=false is the
        # guard (mita refuses before any egress rule); recorded as what a client sees.
        apply_mita(egress([{"ipRanges": ["*"], "domainNames": ["*"], "action": "DIRECT"}]), restart=restart_needed)
        code, out = curl_socks("http://127.0.0.1:2019/config/")
        mieru["loopback_reachable_direct"] = out == "200"
        mieru["loopback_detail"] = f"curl {code} {out}"
        apply_mita(whole, restart=restart_needed)
        stub_log.reset()
        code, out = curl_socks("http://127.0.0.1:2019/config/")
        mieru["loopback_reachable_via_proxy"] = out == "200" or stub_log.saw("127.0.0.1")
        mieru["loopback_via_proxy_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-2:]}"

        apply_mita(original_mita, restart=restart_needed)
        code, out = run("mita", "describe", "config")
        mieru["restored_config"] = json.loads(out) == original_mita
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["restored_direct_ok"] = code == 0 and out == "200"
        health = panel.json("/api/mieru/users")
        mieru["manager_still_consistent"] = health["service"]["ready"] is True
    except Spike as exc:
        result["failures"]["spike"] = str(exc)
    finally:
        for step in reversed(cleanup):
            with contextlib.suppress(Exception):
                step()
    result["summary"] = {
        "naive_native": {k: v for k, v in result["naive_native"].items() if isinstance(v, bool)},
        "mieru_native": {k: v for k, v in result["mieru_native"].items() if isinstance(v, bool)},
    }
    (args.output / "spike.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["failures"] else 1


if __name__ == "__main__":
    sys.exit(main())
