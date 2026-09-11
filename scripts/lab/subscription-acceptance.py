#!/usr/bin/env python3
"""Live acceptance of the client subscription on an installed host (v0.2 plan, Task 19A Step 5).

Runs as root on the host itself, against the real panel and subscription domains with
real certificates. Everything it does goes through the public API the UI uses, and
every claim it makes is a status code or a byte it received:

  1. log in as the bootstrap owner;
  2. import every account the managers report, one client per account;
  3. adopt the imported grants (MTProxy and Naive by capture, Mieru by rotation);
  4. create a subscription for one client that holds all three protocols;
  5. GET /s/<token>: 200 + ETag, then 304 on If-None-Match, then 404 on the panel host;
  6. disable one grant through the legacy API: the ETag moves and the line is gone;
  7. save the sing-box and Clash bodies for the core checks;
  8. revoke: 404.

Nothing here prints a token, a credential or a link. The report is a JSON object of
booleans and counts on stdout; a non-zero exit means at least one check failed.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


class Check(Exception):
    pass


class Panel:
    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def _csrf(self) -> str:
        return next((c.value for c in self.jar if c.name == "panel_csrf"), "")

    def request(self, path: str, *, method: str = "GET", payload=None, host: str | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        if method != "GET":
            headers["X-CSRF-Token"] = self._csrf()
        request = urllib.request.Request(
            f"https://{host or self.domain}{path}", data=data, headers=headers, method=method
        )
        # Headers stay an HTTPMessage: lookups are case-insensitive there, and uvicorn
        # sends them in lowercase.
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read()
                return response.status, response.headers, body
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def json(self, path: str, *, method: str = "GET", payload=None, expect=(200, 201)):
        status, _, body = self.request(path, method=method, payload=payload)
        if status not in expect:
            raise Check(f"{method} {path} -> {status}")
        return json.loads(body) if body else {}

    def login(self, password: str) -> None:
        status, _, _ = self.request("/login")
        if status != 200 or not self._csrf():
            raise Check("login page did not set the CSRF cookie")
        self.json("/api/auth/login", method="POST", payload={"username": "owner", "password": password}, expect=(200, 204))
        me = self.json("/api/auth/me")
        if me.get("username") != "owner":
            raise Check("login did not yield the owner session")


def fetch(url: str, *, headers: dict | None = None):
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=30) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


# --- the real cores -------------------------------------------------------------------

SINGBOX_PORT = 18080
MIHOMO_PORT = 18081


def _run(*argv: str, timeout: int = 120) -> tuple[int, str]:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return completed.returncode, (completed.stdout + completed.stderr)[-2000:]


def _ip_through(proxy_port: int | None) -> str:
    """The public address a request lands with — directly, or through a local SOCKS port."""
    argv = ["curl", "--silent", "--show-error", "--max-time", "25", "https://api.ipify.org"]
    if proxy_port is not None:
        argv[1:1] = ["--proxy", f"socks5h://127.0.0.1:{proxy_port}"]
    code, output = _run(*argv, timeout=40)
    return output.strip() if code == 0 else ""


def _socks5_udp_dns(proxy_port: int, name: str = "cloudflare.com") -> bool:
    """One DNS query to 1.1.1.1 over SOCKS5 UDP ASSOCIATE: proves the proxy carries UDP."""
    import socket
    import struct

    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
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
        # Same id, response bit set, rcode 0, at least one answer.
        return payload[:2] == b"\x12\x34" and payload[2] & 0x80 and payload[3] & 0x0F == 0 and payload[6:8] != b"\x00\x00"
    except OSError:
        return False
    finally:
        control.close()


def core_checks(output: Path, *, singbox_image: str, mihomo_image: str) -> dict:
    """Load the rendered feeds into the real cores and push traffic through them."""
    result: dict[str, object] = {}
    direct = _ip_through(None)
    result["direct_ip"] = direct
    work = output / "cores"
    work.mkdir(exist_ok=True)
    work.chmod(0o755)

    if singbox_image:
        feed = json.loads((output / "subscription.singbox-official").read_bytes())
        outbounds = feed["outbounds"]
        result["singbox_outbounds"] = [o["type"] for o in outbounds]
        config = {
            "log": {"level": "warn"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": SINGBOX_PORT}],
            "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
            "route": {"final": outbounds[0]["tag"] if outbounds else "direct"},
        }
        (work / "singbox.json").write_text(json.dumps(config, indent=2))
        (work / "singbox.json").chmod(0o644)
        code, text = _run("docker", "run", "--rm", "-v", f"{work}:/cfg:ro", singbox_image, "check", "-c", "/cfg/singbox.json")
        result["singbox_check"] = code == 0
        if code != 0:
            result["singbox_check_detail"] = text
        else:
            _run("docker", "rm", "-f", "pc-acceptance-singbox")
            _run("docker", "run", "-d", "--name", "pc-acceptance-singbox", "--network", "host",
                 "-v", f"{work}:/cfg:ro", singbox_image, "run", "-c", "/cfg/singbox.json")
            time.sleep(4)
            seen = _ip_through(SINGBOX_PORT)
            result["singbox_naive_ip"] = seen
            result["singbox_naive_traffic"] = bool(direct) and seen == direct
            if not result["singbox_naive_traffic"]:
                result["singbox_naive_traffic_detail"] = _run("docker", "logs", "--tail", "20", "pc-acceptance-singbox")[1]
            _run("docker", "rm", "-f", "pc-acceptance-singbox")

    if mihomo_image:
        feed = (output / "subscription.clash").read_text()
        config = (
            f"mixed-port: {MIHOMO_PORT}\nbind-address: '127.0.0.1'\nallow-lan: false\nmode: rule\n"
            "log-level: warning\n" + feed + "rules:\n  - MATCH,proxy-control\n"
        )
        (work / "mihomo.yaml").write_text(config)
        (work / "mihomo.yaml").chmod(0o644)
        # mihomo keeps its cache next to the config, so the directory is writable for it.
        code, text = _run("docker", "run", "--rm", "-v", f"{work}:/cfg", mihomo_image, "-t", "-d", "/cfg", "-f", "/cfg/mihomo.yaml")
        result["mihomo_check"] = code == 0
        if code != 0:
            result["mihomo_check_detail"] = text
        else:
            _run("docker", "rm", "-f", "pc-acceptance-mihomo")
            _run("docker", "run", "-d", "--name", "pc-acceptance-mihomo", "--network", "host",
                 "-v", f"{work}:/cfg", mihomo_image, "-d", "/cfg", "-f", "/cfg/mihomo.yaml")
            time.sleep(4)
            seen = _ip_through(MIHOMO_PORT)
            result["mihomo_mieru_ip"] = seen
            result["mihomo_mieru_tcp"] = bool(direct) and seen == direct
            result["mihomo_mieru_udp"] = _socks5_udp_dns(MIHOMO_PORT)
            if not (result["mihomo_mieru_tcp"] and result["mihomo_mieru_udp"]):
                result["mihomo_mieru_tcp_detail"] = _run("docker", "logs", "--tail", "20", "pc-acceptance-mihomo")[1]
            _run("docker", "rm", "-f", "pc-acceptance-mihomo")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--panel-domain", required=True)
    parser.add_argument("--subscription-domain", required=True)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="directory for the rendered bodies")
    parser.add_argument("--singbox-image", default="", help="pinned official sing-box image; empty skips the check")
    parser.add_argument("--mihomo-image", default="", help="pinned mihomo image; empty skips the check")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {}

    def check(name: str, condition: bool, detail: str = "") -> None:
        report[name] = bool(condition)
        if not condition:
            report[f"{name}_detail"] = detail

    panel = Panel(args.panel_domain)
    panel.login(args.password_file.read_text().rstrip("\r\n"))

    # 2. import everything the managers hold, one client per account.
    inventory = panel.json("/api/clients/import/inventory")
    proposals = inventory.get("proposals", [])
    decisions = [
        {
            "display_name": proposal["display_name"],
            "client_id": None,
            "items": [[item["protocol"], item["runtime_username"]] for item in proposal["items"]],
        }
        for proposal in proposals
        if all(item.get("imported_grant_id") is None for item in proposal["items"])
    ]
    imported = panel.json("/api/clients/import", method="POST", payload={"decisions": decisions}) if decisions else {}
    report["imported_grants"] = imported.get("created_grants", 0)

    # 3. adopt: capture where the protocol allows it, rotate where it does not.
    adopted = {}
    for protocol, rotation in (("mtproxy", False), ("naive", False), ("mieru", True)):
        result = panel.json(
            "/api/clients/grants/adopt-batch", method="POST",
            payload={"protocol": protocol, "allow_rotation": rotation},
        )
        adopted[protocol] = {"adopted": len(result.get("adopted", [])), "refused": len(result.get("refused", []))}
    report["adopted"] = adopted

    # 4. one client with every protocol: create it if the imports did not produce one.
    clients = panel.json("/api/clients")["items"]
    target = next(
        (entry for entry in clients if {g["protocol"] for g in entry["grants"] if g["secret_ref"]} == {"mtproxy", "naive", "mieru"}),
        None,
    )
    if target is None:
        created = panel.json("/api/clients", method="POST", payload={"display_name": "acceptance"})
        operation = panel.json(
            f"/api/clients/{created['id']}/grants", method="POST",
            payload={"grants": [
                {"protocol": "mtproxy", "runtime_username": "acceptance", "options": {}},
                {"protocol": "naive", "runtime_username": "acceptance", "options": {}},
                {"protocol": "mieru", "runtime_username": "acceptance", "options": {"quotas": []}},
            ]},
        )
        check("provisioning_succeeded", operation.get("status") == "succeeded", str(operation.get("status")))
        target = next(entry for entry in panel.json("/api/clients")["items"] if entry["client"]["id"] == created["id"])
    client_id = target["client"]["id"]
    report["client_grants"] = sorted(g["protocol"] for g in target["grants"])

    overview = panel.json(f"/api/clients/{client_id}/subscription")
    check("subscription_configured", overview.get("configured") is True)
    if overview.get("subscription"):
        panel.json(f"/api/clients/{client_id}/subscription/revoke", method="POST")
    reveal_token = panel.json(f"/api/clients/{client_id}/subscription", method="POST")["reveal_token"]
    reveal = panel.json(f"/api/reveal/{reveal_token}")
    url = reveal["url"]
    check("reveal_is_one_time", panel.request(f"/api/reveal/{reveal_token}")[0] == 410)
    check("url_on_subscription_domain", url.startswith(f"https://{args.subscription_domain}/s/"))
    token = url.rsplit("/", 1)[1]

    # 5. the public endpoint.
    status, headers, raw = fetch(url)
    check("raw_200", status == 200, str(status))
    etag = headers.get("ETag", "")
    check("etag_present", bool(etag))
    check("cache_control", headers.get("Cache-Control") == "private, no-cache", headers.get("Cache-Control", ""))
    check("profile_update_interval", headers.get("Profile-Update-Interval") == "12")
    lines = raw.decode().splitlines()
    report["raw_lines"] = {
        "tg": sum(line.startswith("tg://proxy?") for line in lines),
        "naive": sum(line.startswith("naive+https://") for line in lines),
        "mieru": sum(line.startswith("mierus://") for line in lines),
        "comments": sum(line.startswith("#") for line in lines),
    }
    status, headers, _ = fetch(url, headers={"If-None-Match": etag})
    check("conditional_304", status == 304 and headers.get("ETag") == etag, str(status))
    # The panel's vhost refuses `/s/` in Nginx before the panel sees it, so its answer
    # must not depend on the token; on the subscription host every refusal (unknown,
    # malformed, later revoked) is one and the same 404.
    status, _, panel_body = fetch(f"https://{args.panel_domain}/s/{token}")
    check("panel_host_404", status == 404, str(status))
    panel_unknown = fetch(f"https://{args.panel_domain}/s/{'A' * 43}")
    check("panel_host_token_blind", panel_unknown[0] == 404 and panel_unknown[2] == panel_body)
    unknown = fetch(f"https://{args.subscription_domain}/s/{'A' * 43}")
    malformed = fetch(f"https://{args.subscription_domain}/s/not-a-token")
    check(
        "unknown_token_404_same_body",
        unknown[0] == 404 and malformed[0] == 404 and unknown[2] == malformed[2],
        f"{unknown[0]}/{malformed[0]}",
    )

    for name, query in (
        ("singbox", "?format=singbox"),
        ("singbox-official", "?format=singbox&client=singbox"),
        ("clash", "?format=clash"),
        ("manifest", "?format=manifest"),
        ("html", "?format=html"),
    ):
        status, headers, rendered = fetch(f"{url}{query}")
        check(f"{name}_200", status == 200, str(status))
        (args.output / f"subscription.{name}").write_bytes(rendered)
        report[f"{name}_content_type"] = headers.get("Content-Type", "")

    # 7. the real cores, if asked: the feeds must load and carry traffic, not just parse.
    if args.singbox_image or args.mihomo_image:
        report["cores"] = core_checks(
            args.output, singbox_image=args.singbox_image, mihomo_image=args.mihomo_image
        )
        for name, value in report["cores"].items():
            if isinstance(value, bool):
                check(f"core_{name}", value, str(report["cores"].get(f"{name}_detail", "")))

    # 6. a change moves the ETag. Suspending the client works in both writer modes
    # (legacy and domain) because it never touches a manager: the effective set is
    # empty while the client is suspended, and the raw feed says so line by line.
    naive_user = next(g["runtime_username"] for g in target["grants"] if g["protocol"] == "naive")
    panel.json(f"/api/clients/{client_id}/state", method="POST", payload={"state": "suspended"}, expect=(200,))
    status, headers, changed = fetch(url, headers={"If-None-Match": etag})
    check("etag_moves_after_suspend", status == 200 and headers.get("ETag") != etag, str(status))
    check("disabled_line_present", f"# disabled naive {naive_user}" in changed.decode().splitlines())
    panel.json(f"/api/clients/{client_id}/state", method="POST", payload={"state": "active"}, expect=(200,))
    status, headers, _ = fetch(url)
    check("etag_returns_after_resume", status == 200 and headers.get("ETag") == etag, str(status))
    generation = panel.json(f"/api/clients/{client_id}/subscription")["subscription"]["generation"]
    check("generation_advanced", generation >= 3, str(generation))

    events = panel.json("/api/events?limit=500")["items"]
    names = {event["name"] for event in events}
    check("events_recorded", {"subscription.fetched", "subscription.generation.changed"} <= names, str(sorted(names)))

    # 8. revoke: the URL is gone.
    panel.json(f"/api/clients/{client_id}/subscription/revoke", method="POST")
    revoked = fetch(url)
    check("revoked_404", revoked[0] == 404 and revoked[2] == unknown[2], str(revoked[0]))
    report["client_id"] = client_id

    print(json.dumps(report, sort_keys=True, indent=2))
    failed = [name for name, value in report.items() if value is False]
    if failed:
        print(f"FAILED: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("SUBSCRIPTION_ACCEPTANCE_OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Check as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
