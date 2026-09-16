#!/usr/bin/env python3
"""v0.5 Xray-router spike (Task 32): what a dedicated Xray egress router can enforce for the
NaiveProxy and Mieru data planes, and how the two attach to it.

Runs as root on the disposable lab host against the `lab-host` install (live Caddy 2.11.4 +
klzgrad/forwardproxy, live mita 3.36) with the pinned Xray-core unpacked into a scratch
directory and `socks5-stub.py` standing in for WARP. Every probe answers one cell of the
table in `docs/spikes/XRAY_EGRESS_ROUTER.md`; the JSON on stdout is copied there.

Nothing here is a release path: Caddy's config is swapped through the Admin API, mita's
through `mita apply`, both restored byte-for-byte at the end; the Xray process, its scratch
config and the throw-away users are gone when the script exits.

    xray-spike.py --output /root/lab-results/spike
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from installer.release import ReleaseManifest, safe_extract_zip, verify_artifact  # noqa: E402

_spec = importlib.util.spec_from_file_location("routing_spike", HERE / "routing-spike.py")
routing_spike = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(routing_spike)
Panel, Spike, StubLog = routing_spike.Panel, routing_spike.Spike, routing_spike.StubLog
admin, adapt, load, rewrite_listener = routing_spike.admin, routing_spike.adapt, routing_spike.load, routing_spike.rewrite_listener
forward_proxy_handler, with_egress = routing_spike.forward_proxy_handler, routing_spike.with_egress
naive_connect, mihomo_config, curl_socks, run = (routing_spike.naive_connect, routing_spike.mihomo_config,
                                                  routing_spike.curl_socks, routing_spike.run)
CADDYFILE, STUB_PORT, MIHOMO_PORT, TARGET_HOST, DENY_HOST = (routing_spike.CADDYFILE, routing_spike.STUB_PORT,
                                                             routing_spike.MIHOMO_PORT, routing_spike.TARGET_HOST,
                                                             routing_spike.DENY_HOST)
PORTS = {"naive": 45101, "mieru": 45102}
ADS_HOST = "doubleclick.net"
# A public name whose A record is 127.0.0.1 — the DNS-rebinding shape the bypass must catch
# (an /etc/hosts entry is not what Xray's `localhost` resolver consults).
REBIND_HOST = "localtest.me"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def stage_xray(cache: Path, work: Path) -> tuple[Path, dict]:
    """The pinned archive (downloaded once into the lab cache, digest-checked every time),
    extracted by the release extractor into `work/xray`."""
    manifest = ReleaseManifest.from_bytes((ROOT / "release" / "external-artifacts.json").read_bytes())
    pin = manifest.external_artifact("xray", "amd64")
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / pin.url.rsplit("/", 1)[1]
    if not archive.exists() or sha256_file(archive) != pin.sha256:
        with urllib.request.urlopen(pin.url, timeout=120) as response, archive.open("wb") as sink:
            shutil.copyfileobj(response, sink)
    verify_artifact(archive, pin.sha256)
    destination = work / "xray"
    safe_extract_zip(archive, destination, dict(pin.members))
    return destination, {"version": pin.version, "archive_sha256": pin.sha256,
                         "members": {name: sha256_file(destination / name) for name in pin.members}}


# --- the router config under test (spec §6) ------------------------------------------

def xray_config(policies: dict[str, dict], credentials: dict[str, tuple[str, str]], *, warp_port: int | None,
                asset_dir: Path, domain_strategy: str = "IPOnDemand", route_only: bool = True) -> dict:
    inbounds = [{"tag": tag, "listen": "127.0.0.1", "port": PORTS[tag], "protocol": "socks",
                 "settings": {"auth": "password", "accounts": [{"user": credentials[tag][0], "pass": credentials[tag][1]}],
                              "udp": False},
                 "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": route_only}}
                for tag in PORTS]
    outbounds = [{"tag": "block", "protocol": "blackhole"},
                 {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}]
    if warp_port is not None:
        outbounds.append({"tag": "warp", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": warp_port}]}})
    rules = []
    for tag in PORTS:
        policy = policies.get(tag, {"default": "direct", "rules": []})
        rules.append({"inboundTag": [tag], "ip": ["geoip:private"], "outboundTag": "block"})
        rules.append({"inboundTag": [tag], "domain": ["domain:localhost", "full:localhost"], "outboundTag": "block"})
        for rule in policy["rules"]:
            entry = {"inboundTag": [tag], "outboundTag": rule["outbound"]}
            for key in ("domain", "ip", "port"):
                if rule.get(key):
                    entry[key] = rule[key]
            rules.append(entry)
        rules.append({"inboundTag": [tag], "outboundTag": policy["default"]})
    return {"log": {"access": "none", "loglevel": "warning"},
            "dns": {"servers": ["localhost"]},
            "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": domain_strategy, "rules": rules}}


class Router:
    """One Xray process under the spike's hand: test, start, swap, kill."""

    def __init__(self, binary: Path, asset_dir: Path, work: Path):
        self.binary, self.asset_dir, self.work = binary, asset_dir, work
        self.process: subprocess.Popen | None = None
        self.env = {**os.environ, "XRAY_LOCATION_ASSET": str(asset_dir)}
        self.config_path = work / "router.json"

    def version(self) -> str:
        code, out = run(str(self.binary), "version")
        return out.splitlines()[0] if code == 0 and out else f"exit {code}"

    def test(self, config: dict) -> tuple[int, str]:
        path = self.work / "candidate.json"
        path.write_text(json.dumps(config))
        completed = subprocess.run([str(self.binary), "run", "-test", "-config", str(path)], capture_output=True,
                                   text=True, timeout=30, check=False, env=self.env)
        return completed.returncode, (completed.stdout + completed.stderr)[-600:]

    def start(self, config: dict) -> None:
        self.config_path.write_text(json.dumps(config))
        self.process = subprocess.Popen([str(self.binary), "run", "-config", str(self.config_path)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env)
        self.wait_ready()

    def wait_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(_port_open(port) for port in PORTS.values()):
                return
            if self.process is not None and self.process.poll() is not None:
                raise Spike(f"xray exited with {self.process.returncode}")
            time.sleep(0.05)
        raise Spike("xray ingress ports did not open")

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None

    def swap(self, config: dict) -> float:
        """`-test` → stop → start; returns the seconds the ingress was closed."""
        code, out = self.test(config)
        if code != 0:
            raise Spike(f"xray -test refused the config: {out}")
        started = time.monotonic()
        self.stop()
        self.start(config)
        return time.monotonic() - started

    def kill9(self) -> None:
        assert self.process is not None
        self.process.kill()
        self.process.wait(timeout=5)
        self.process = None

    def rss_and_cpu(self) -> str:
        assert self.process is not None
        code, out = run("ps", "-o", "rss=,pcpu=", "-p", str(self.process.pid))
        return out.strip()


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def socks_curl(port: int, target: str, *, user: str | None, password: str | None, timeout: int = 20) -> tuple[int, str]:
    auth = f"{user}:{password}@" if user else ""
    return run("curl", "--silent", "--show-error", "--max-time", str(timeout), "--output", "/dev/null", "--write-out",
               "%{http_code}", "--proxy", f"socks5h://{auth}127.0.0.1:{port}", target, timeout=timeout + 10)


def refused(code: int, out: str) -> bool:
    return out != "200" and out != "301"


def resolved_stats() -> str:
    code, out = run("resolvectl", "statistics")
    return out if code == 0 else f"unavailable ({code})"


# --- the spike ----------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--panel", default="https://panel.lab.test")
    parser.add_argument("--ca", type=Path, default=Path("/etc/letsencrypt/lab-ca/ca.crt"))
    parser.add_argument("--password-file", type=Path, default=Path("/opt/mtproxy-shared443/secrets/panel-bootstrap-password"))
    parser.add_argument("--stub", type=Path, default=HERE / "socks5-stub.py")
    parser.add_argument("--artifact-cache", type=Path, default=Path("/root/lab-artifacts"))
    parser.add_argument("--output", type=Path, default=Path("/root/lab-results/spike"))
    parser.add_argument("--mihomo-image", default=routing_spike.MIHOMO_IMAGE)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    result: dict = {"artifact": {}, "router": {}, "naive_via_router": {}, "mieru_via_router": {}, "failures": {}, "notes": []}
    cleanup = []
    work = Path(tempfile.mkdtemp(prefix="xray-spike-"))
    cleanup.append(lambda: shutil.rmtree(work, ignore_errors=True))
    credentials = {"naive": ("naive-spike", secrets.token_urlsafe(24)), "mieru": ("mieru-spike", secrets.token_urlsafe(24))}

    stub_log = StubLog(args.output / "stub-connects.log")
    stub_log.reset()
    stub = subprocess.Popen([sys.executable, str(args.stub), "--listen", f"127.0.0.1:{STUB_PORT}", "--log", str(stub_log.path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cleanup.append(lambda: (stub.terminate(), stub.wait(timeout=5)))
    time.sleep(0.5)

    try:
        asset_dir, artifact = stage_xray(args.artifact_cache, work)
        result["artifact"] = artifact
        router = Router(asset_dir / "xray", asset_dir, work)
        cleanup.append(router.stop)
        result["router"]["version"] = router.version()

        def policies(naive: dict | None = None, mieru: dict | None = None) -> dict:
            return {"naive": naive or {"default": "direct", "rules": []}, "mieru": mieru or {"default": "direct", "rules": []}}

        def config(naive=None, mieru=None, **kwargs) -> dict:
            return xray_config(policies(naive, mieru), credentials, warp_port=STUB_PORT, asset_dir=asset_dir, **kwargs)

        code, out = router.test(config())
        result["router"]["test_accepts_baseline"] = code == 0
        code, out = router.test(config(naive={"default": "direct", "rules": [{"domain": ["geosite:no-such-code-xyz"], "outbound": "block"}]}))
        result["router"]["test_refuses_unknown_geosite"] = code != 0
        result["router"]["test_unknown_geosite_detail"] = out[-200:]
        code, out = router.test(config(naive={"default": "direct", "rules": [{"ip": ["geoip:no-such-code-xyz"], "outbound": "block"}]}))
        result["router"]["test_refuses_unknown_geoip"] = code != 0
        result["router"]["test_unknown_geoip_detail"] = out[-200:]
        router.start(config())
        time.sleep(3)
        result["router"]["idle_rss_kb_cpu"] = router.rss_and_cpu()

        # --- ingress authentication, straight at the router ---
        code, out = socks_curl(PORTS["naive"], f"https://{TARGET_HOST}", user=None, password=None)
        result["router"]["unauthenticated_refused"] = refused(code, out)
        result["router"]["unauthenticated_detail"] = f"curl {code} {out}"
        code, out = socks_curl(PORTS["naive"], f"https://{TARGET_HOST}", user=credentials["mieru"][0], password=credentials["mieru"][1])
        result["router"]["cross_service_credential_refused"] = refused(code, out)
        code, out = socks_curl(PORTS["naive"], f"https://{TARGET_HOST}", user=credentials["naive"][0], password=credentials["naive"][1])
        result["router"]["authenticated_direct_ok"] = code == 0 and out == "200"
        result["router"]["udp_associate_refused"] = not routing_spike.socks5_udp_dns(PORTS["naive"])

        # --- bypass: private destinations, by IP and by a name that rebinds to loopback ---
        naive_ok = (credentials["naive"][0], credentials["naive"][1])
        code, out = socks_curl(PORTS["naive"], "http://127.0.0.1:2019/config/", user=naive_ok[0], password=naive_ok[1])
        result["router"]["bypass_private_literal_ip"] = out.startswith("000")
        result["router"]["bypass_private_literal_detail"] = f"curl {code} {out}"
        result["router"]["rebinding_name_resolves_to"] = sorted({info[4][0] for info in socket.getaddrinfo(REBIND_HOST, 80)})
        # Caddy's Admin API answers 403 to a foreign Host header: a 403 here means the tunnel
        # reached loopback; the bypass must leave the client with no HTTP answer at all.
        code, out = socks_curl(PORTS["naive"], f"http://{REBIND_HOST}:2019/config/", user=naive_ok[0], password=naive_ok[1])
        result["router"]["bypass_private_rebinding_name"] = out.startswith("000")
        result["router"]["bypass_private_rebinding_detail"] = f"curl {code} {out}"
        # The same name with AsIs (no resolution before matching) shows why IPOnDemand is the rule.
        router.swap(config(domain_strategy="AsIs"))
        code, out = socks_curl(PORTS["naive"], f"http://{REBIND_HOST}:2019/config/", user=naive_ok[0], password=naive_ok[1])
        result["router"]["asis_lets_rebinding_name_through"] = out.startswith("403")
        result["router"]["asis_rebinding_detail"] = f"curl {code} {out}"
        router.swap(config())

        # --- panel users and the two data planes ---
        panel = Panel(args.panel, args.ca)
        panel.login(args.password_file.read_text().strip())
        suffix = secrets.token_hex(3)
        naive_user = mieru_user = f"xspike-{suffix}"
        created = panel.json("/api/naive/users", method="POST", payload={"username": naive_user})
        cleanup.append(lambda: panel.request(f"/api/naive/users/{naive_user}", method="DELETE"))
        naive_share = panel.json(f"/api/reveal/{created['reveal_token']}")["clients"]["nekobox"]["share_url"]
        revision = panel.json("/api/mieru/users")["service"]["revision"]
        created = panel.json("/api/mieru/users", method="POST",
                             payload={"username": mieru_user, "quotas": [], "expected_revision": revision})
        cleanup.append(lambda: panel.request(f"/api/mieru/users/{mieru_user}", method="DELETE",
                                             payload={"expected_revision": panel.json("/api/mieru/users")["service"]["revision"]}))
        mieru_share = panel.json(f"/api/reveal/{created['reveal_token']}")["clients"]["native"]["simple_share_url"]
        target_addresses = sorted({info[4][0] for info in socket.getaddrinfo(TARGET_HOST, 443, proto=socket.IPPROTO_TCP)})

        # --- Caddy forwardproxy → authenticated ingress ---
        original_text = CADDYFILE.read_bytes()
        status, body = admin("GET", "/config/")
        if status != 200:
            raise Spike("caddy admin unreachable")
        original_config = json.loads(body)
        cleanup.append(lambda: load(original_config))
        naive = result["naive_via_router"]
        upstream = f"socks5://{credentials['naive'][0]}:{credentials['naive'][1]}@127.0.0.1:{PORTS['naive']}"
        status, adapted = adapt(with_egress(original_text.decode(), upstream=upstream, deny=None))
        naive["caddy_adapts_authenticated_upstream"] = status == 200 and forward_proxy_handler(adapted).get("upstream") == upstream
        if status != 200:
            raise Spike(f"caddy adapt: {adapted}")
        load(rewrite_listener(adapted))

        def naive_probe(target: str) -> tuple[int, str]:
            return naive_connect(naive_share, args.ca, target)

        stub_log.reset()
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["whole_direct"] = code == 0 and out == "200" and not stub_log.saw(TARGET_HOST)
        naive["whole_direct_detail"] = f"curl {code} {out}"

        naive["swap_seconds"] = round(router.swap(config(naive={"default": "warp", "rules": []})), 3)
        stub_log.reset()
        before_stats = resolved_stats()
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["whole_warp"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)
        naive["whole_warp_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-2:]}"
        naive["hostname_reaches_warp_as_domain"] = stub_log.saw(TARGET_HOST)
        naive["dns_statistics_before_after"] = [before_stats[-300:], resolved_stats()[-300:]]

        router.swap(config(naive={"default": "warp", "rules": [{"domain": [f"domain:{DENY_HOST}"], "outbound": "block"}]}))
        stub_log.reset()
        code, out = naive_probe(f"http://{DENY_HOST}")
        naive["block_domain_beside_warp"] = refused(code, out) and not stub_log.saw(DENY_HOST)
        naive["block_domain_beside_warp_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-2:]}"
        code, out = naive_probe(f"http://www.{DENY_HOST}")
        naive["block_domain_suffix"] = refused(code, out) and not stub_log.saw(f"www.{DENY_HOST}")
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["others_still_via_warp"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)

        router.swap(config(naive={"default": "direct", "rules": [
            {"ip": [f"{a}/128" if ":" in a else f"{a}/32" for a in target_addresses], "outbound": "block"}]}))
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["block_cidr_by_hostname_ipondemand"] = refused(code, out)
        naive["block_cidr_detail"] = f"deny {target_addresses}; CONNECT {TARGET_HOST}: curl {code} {out}"
        code, out = naive_probe(f"https://{target_addresses[0]}")
        naive["block_cidr_literal_ip"] = refused(code, out)

        router.swap(config(naive={"default": "direct", "rules": [{"port": "80", "outbound": "block"}]}))
        code, out = naive_probe(f"http://{TARGET_HOST}")
        naive["block_port_80"] = refused(code, out)
        naive["block_port_detail"] = f"curl {code} {out}"
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["port_443_still_open"] = code == 0 and out == "200"

        router.swap(config(naive={"default": "direct", "rules": [{"domain": ["geosite:category-ads-all"], "outbound": "block"}]}))
        code, out = naive_probe(f"http://{ADS_HOST}")
        naive["block_geosite_ads"] = refused(code, out)
        naive["block_geosite_detail"] = f"curl {code} {out}"
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["geosite_leaves_others_alone"] = code == 0 and out == "200"

        router.swap(config(naive={"default": "direct", "rules": [{"ip": ["geoip:cloudflare"], "outbound": "block"}]}))
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["block_geoip_cloudflare_by_hostname"] = refused(code, out)
        naive["block_geoip_detail"] = f"curl {code} {out} ({TARGET_HOST} → {target_addresses})"

        router.swap(config(naive={"default": "warp", "rules": [{"ip": ["geoip:cloudflare"], "outbound": "direct"}]}))
        stub_log.reset()
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["selective_geoip_direct_beside_warp"] = code == 0 and out == "200" and not stub_log.saw(TARGET_HOST)
        code, out = naive_probe("https://www.cloudflare.com/cdn-cgi/trace")
        naive["selective_rest_via_warp_or_geoip"] = code == 0 and out == "200"
        naive["selective_detail"] = f"stub {stub_log.lines()[-3:]}"

        # Dead WARP with a warp default: fail closed, never direct.
        router.swap(xray_config(policies({"default": "warp", "rules": []}), credentials, warp_port=STUB_PORT + 1, asset_dir=asset_dir))
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["dead_warp_fails_closed"] = refused(code, out)
        naive["dead_warp_detail"] = f"curl {code} {out}"

        # kill -9 during service: without a supervisor nothing comes back; the manager owns that.
        router.swap(config())
        router.kill9()
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["after_kill9_without_supervisor"] = f"curl {code} {out} (ingress closed; the manager's watchdog restarts it)"
        router.start(config())
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["after_restart_ok"] = code == 0 and out == "200"

        # Load: ten parallel CONNECTs, then the process footprint.
        procs = [subprocess.Popen(["curl", "--silent", "--max-time", "20", "--output", "/dev/null", "--proxy",
                                   f"socks5h://{naive_ok[0]}:{naive_ok[1]}@127.0.0.1:{PORTS['naive']}", "https://www.cloudflare.com/cdn-cgi/trace"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(10)]
        for proc in procs:
            proc.wait(timeout=40)
        naive["load_rss_kb_cpu"] = router.rss_and_cpu()
        load(original_config)
        naive["caddyfile_untouched"] = CADDYFILE.read_bytes() == original_text
        code, out = naive_probe(f"https://{TARGET_HOST}")
        naive["restored_direct_ok"] = code == 0 and out == "200"

        # --- mita → its own authenticated ingress ---
        mieru = result["mieru_via_router"]
        code, out = run("mita", "describe", "config")
        if code != 0:
            raise Spike(f"mita describe config: {out}")
        original_mita = json.loads(out)

        def apply_mita(cfg: dict) -> None:
            path = work / "mita.json"
            path.write_text(json.dumps(cfg))
            code, out = run("mita", "apply", "config", str(path))
            if code != 0:
                raise Spike(f"mita apply: {out}")
            run("mita", "stop")
            code, out = run("mita", "start")
            if code != 0:
                raise Spike(f"mita start: {out}")
            time.sleep(2.5)

        cleanup.append(lambda: apply_mita(original_mita))
        (work / "mihomo.yaml").write_text(mihomo_config(mieru_share))
        (work / "mihomo.yaml").chmod(0o644)
        run("docker", "rm", "-f", "pc-xspike-mihomo")
        code, out = run("docker", "run", "-d", "--name", "pc-xspike-mihomo", "--network", "host", "-v", f"{work}:/cfg",
                        args.mihomo_image, "-d", "/cfg", "-f", "/cfg/mihomo.yaml")
        cleanup.append(lambda: run("docker", "rm", "-f", "pc-xspike-mihomo"))
        if code != 0:
            raise Spike(f"mihomo: {out}")
        time.sleep(4)
        attached = json.loads(json.dumps(original_mita))
        attached["egress"] = {"proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1",
                                           "port": PORTS["mieru"],
                                           "socks5Authentication": {"user": credentials["mieru"][0], "password": credentials["mieru"][1]}}],
                              "rules": [{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["router"]}]}
        apply_mita(attached)
        code, out = run("mita", "describe", "config")
        mieru["mita_accepts_socks5_authentication"] = code == 0 and "socks5Authentication" in out
        router.swap(config(mieru={"default": "direct", "rules": []}))
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["whole_direct"] = code == 0 and out == "200" and not stub_log.saw(TARGET_HOST)
        mieru["whole_direct_detail"] = f"curl {code} {out}"
        router.swap(config(mieru={"default": "warp", "rules": []}))
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["whole_warp"] = code == 0 and out == "200" and stub_log.saw(TARGET_HOST)
        mieru["whole_warp_detail"] = f"curl {code} {out}; stub {stub_log.lines()[-2:]}"
        mieru["hostname_reaches_warp_as_domain"] = stub_log.saw(TARGET_HOST)
        router.swap(config(mieru={"default": "warp", "rules": [{"domain": [f"domain:{TARGET_HOST}"], "outbound": "direct"}]}))
        stub_log.reset()
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["selective_domain_direct"] = code == 0 and out == "200" and not stub_log.saw(TARGET_HOST)
        code, out = curl_socks("https://www.cloudflare.com/cdn-cgi/trace")
        mieru["selective_rest_via_warp"] = code == 0 and out == "200" and stub_log.saw("www.cloudflare.com")
        # sniffing routeOnly: the client resolves locally and CONNECTs by IP; the TLS SNI
        # still lets the domain rule match.
        router.swap(config(mieru={"default": "direct", "rules": [{"domain": [f"domain:{DENY_HOST}"], "outbound": "block"}]}))
        code, out = curl_socks(f"https://{DENY_HOST}", resolve_locally=True)
        mieru["sniffing_route_only_blocks_ip_connect_by_sni"] = refused(code, out)
        mieru["sniffing_detail"] = f"curl {code} {out} (IP-literal CONNECT, SNI {DENY_HOST})"
        code, out = curl_socks(f"https://{TARGET_HOST}", resolve_locally=True)
        mieru["sniffing_leaves_others_alone"] = code == 0 and out == "200"
        router.swap(config(mieru={"default": "direct", "rules": []}, route_only=False))
        code, out = curl_socks(f"https://{TARGET_HOST}", resolve_locally=True)
        mieru["dest_override_without_route_only_also_works"] = code == 0 and out == "200"
        router.swap(config())
        mieru["udp_via_router"] = routing_spike.socks5_udp_dns(MIHOMO_PORT)
        mieru["loopback_via_router"] = curl_socks("http://127.0.0.1:2019/config/")[1] == "200"
        # A wrong credential on mita's side: the ingress refuses, the client fails closed.
        wrong = json.loads(json.dumps(attached))
        wrong["egress"]["proxies"][0]["socks5Authentication"]["password"] = "not-the-key"
        apply_mita(wrong)
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["wrong_credential_fails_closed"] = refused(code, out)
        mieru["wrong_credential_detail"] = f"curl {code} {out}"
        apply_mita(original_mita)
        code, out = run("mita", "describe", "config")
        mieru["restored_config"] = json.loads(out) == original_mita
        code, out = curl_socks(f"https://{TARGET_HOST}")
        mieru["restored_direct_ok"] = code == 0 and out == "200"
        mieru["manager_still_consistent"] = panel.json("/api/mieru/users")["service"]["ready"] is True
    except Spike as exc:
        result["failures"]["spike"] = str(exc)
    except Exception as exc:  # noqa: BLE001 — the spike reports, the cleanup still runs
        result["failures"]["unexpected"] = f"{type(exc).__name__}: {exc}"
    finally:
        for step in reversed(cleanup):
            with contextlib.suppress(Exception):
                step()
    result["summary"] = {section: {k: v for k, v in result[section].items() if isinstance(v, bool)}
                         for section in ("router", "naive_via_router", "mieru_via_router")}
    (args.output / "xray-spike.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["failures"] else 1


if __name__ == "__main__":
    sys.exit(main())
