#!/usr/bin/env python3
"""Disposable full-topology differential client probe; no production defaults.

Manifest supplies SHA-256-pinned Xray and Hysteria binaries plus six ephemeral
client configs. Each config must expose a SOCKS5 inbound at its case's port;
positive/negative variants differ only in a deliberately invalid credential.
The gate tests actual proxied HTTP POST/echo around a bad-credential attempt.
Its pass does not assert server-side auth-denial log or inbound-counter evidence.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid

CASES = ("vless-tcp", "xhttp", "hysteria2")
TARGETS = {"vless-tcp": "vless.lab.test", "xhttp": "xhttp.lab.test", "hysteria2": "hy2.lab.test"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
PAYLOAD = b"proxy-control-managed-xui-probe-v1\n"


class ProbeError(RuntimeError):
    pass


def empty_report() -> dict:
    return {"schema": 1, "kind": "controlled-differential-client-probe", "cases": {}, "pass": False,
            "server_auth_log_verified": False}


@dataclass(frozen=True)
class Transfer:
    returncode: int
    payload_echo: bool


def root_private(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise ProbeError("missing root-private file") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
        raise ProbeError("file is not root-private")


def read_manifest(path: Path) -> dict:
    root_private(path)
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ProbeError("invalid manifest")
    return document


def _field(document, dotted: str):
    value = document
    for part in dotted.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _set_field(document, dotted: str, replacement: str) -> None:
    parts = dotted.split(".")
    value = document
    for part in parts[:-1]:
        value = value[int(part)] if isinstance(value, list) else value[part]
    value[int(parts[-1]) if isinstance(value, list) else parts[-1]] = replacement


def validate_config_pair(name: str, positive: Path, negative: Path, port: int, credential_path: str) -> None:
    allowed_path = ("auth" if name == "hysteria2" else "outbounds.0.settings.vnext.0.users.0.id")
    if credential_path != allowed_path:
        raise ProbeError("unsupported credential path")
    try:
        good, bad = json.loads(positive.read_text()), json.loads(negative.read_text())
        if not isinstance(good, dict) or not isinstance(bad, dict):
            raise ValueError("config is not an object")
        credential, wrong = _field(good, credential_path), _field(bad, credential_path)
        if not isinstance(credential, str) or not isinstance(wrong, str) or not credential or not wrong or credential == wrong:
            raise ProbeError("negative credential must differ")
        if name != "hysteria2":
            for value in (credential, wrong):
                try:
                    if str(uuid.UUID(value)) != value:
                        raise ValueError("noncanonical UUID")
                except ValueError as exc:
                    raise ProbeError("invalid VLESS UUID") from exc
        _set_field(bad, credential_path, credential)
        if good != bad:
            raise ProbeError("configs are not credential-only variants")
        if name == "hysteria2":
            if good.get("lazy") is not True:
                raise ProbeError("Hysteria lazy mode required")
            if (set(good) != {"server", "auth", "lazy", "tls", "socks5"} or
                good["server"] != f"{TARGETS[name]}:443" or
                good["tls"] != {"sni": TARGETS[name]}):
                raise ProbeError("target mismatch")
            if good["socks5"] != {"listen": f"127.0.0.1:{port}"}:
                raise ProbeError("SOCKS config mismatch")
        else:
            inbound, outbound = good["inbounds"], good["outbounds"]
            if set(good) != {"inbounds", "outbounds"} or len(inbound) != 1 or len(outbound) != 1:
                raise ProbeError("unrelated route is forbidden")
            if inbound[0] != {"listen": "127.0.0.1", "port": port, "protocol": "socks"}:
                raise ProbeError("SOCKS config mismatch")
            route = outbound[0]
            next_hop = route["settings"]["vnext"]
            stream = route["streamSettings"]
            if (route["protocol"] != "vless" or len(next_hop) != 1 or
                next_hop[0]["address"] != TARGETS[name] or next_hop[0]["port"] != 443 or
                len(next_hop[0]["users"]) != 1 or
                stream["network"] != ("tcp" if name == "vless-tcp" else "xhttp") or
                stream["security"] != "reality" or
                stream["realitySettings"]["serverName"] != TARGETS[name]):
                raise ProbeError("target mismatch")
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ProbeError("invalid client config") from exc


def preflight(manifest: dict, base: Path) -> None:
    if not isinstance(manifest, dict):
        raise ProbeError("invalid manifest")
    for name in ("xray", "hysteria"):
        item = manifest.get(name, {})
        if not isinstance(item, dict):
            raise ProbeError(f"missing executable: {name}")
        path_value = item.get("path", "")
        if not isinstance(path_value, str):
            raise ProbeError(f"missing executable: {name}")
        path = Path(path_value)
        digest = item.get("sha256", "")
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ProbeError(f"missing executable: {name}")
        if not isinstance(digest, str) or not _SHA.fullmatch(digest) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ProbeError(f"digest mismatch: {name}")
    if not shutil_which("curl"):
        raise ProbeError("missing executable: curl")
    cases = manifest.get("cases", {})
    if not isinstance(cases, dict):
        raise ProbeError("invalid cases")
    ports = set()
    for name in CASES:
        case = cases.get(name)
        if not isinstance(case, dict):
            raise ProbeError(f"missing case: {name}")
        port = case.get("socks_port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
            raise ProbeError(f"invalid SOCKS port: {name}")
        if port in ports:
            raise ProbeError("duplicate SOCKS port")
        ports.add(port)
        for variant in ("positive", "negative"):
            value = case.get(variant)
            if not isinstance(value, str) or not value:
                raise ProbeError(f"missing {variant} config: {name}")
            candidate = base / value
            root_private(candidate)  # lstat rejects symlinks before resolution.
            config = candidate.resolve()
            if not config.is_relative_to(base.resolve()) or not config.is_file():
                raise ProbeError(f"missing {variant} config: {name}")
        validate_config_pair(name, base / case["positive"], base / case["negative"],
                             port, case.get("credential_path", ""))


def assert_port_free(port: int) -> None:
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ProbeError("SOCKS port already in use") from exc


def listener_owned_by_group(port: int, group: int) -> bool:
    if not shutil_which("ss"):
        raise ProbeError("missing executable: ss")
    result = subprocess.run(["ss", "-ltnp", f"sport = :{port}"], capture_output=True, timeout=3)
    if result.returncode:
        raise ProbeError("SOCKS listener ownership unavailable")
    pids = [int(value) for value in re.findall(rb"pid=(\d+)", result.stdout)]
    for pid in pids:
        try:
            if os.getpgid(pid) == group:
                return True
        except ProcessLookupError:
            pass
    return False


def classify_case(first: Transfer, negative: Transfer, last: Transfer,
                  hits: tuple[int, int, int, int]) -> dict:
    before, after_first, after_negative, after_last = hits
    first_ok = first.payload_echo and first.returncode == 0 and after_first == before + 1
    last_ok = last.payload_echo and last.returncode == 0 and after_last == after_negative + 1
    if negative.returncode != 0 and after_negative == after_first:
        negative_status = "transfer_failed_no_echo"
    elif after_negative != after_first:
        negative_status = "unexpected_echo_hit"
    else:
        negative_status = "unexpected_transfer_success"
    return {"positive_payload_before": first_ok, "negative_attempt": negative_status,
            "positive_payload_after": last_ok,
            "controlled_differential_denial": first_ok and last_ok and negative_status == "transfer_failed_no_echo"}


def cleanup_group(process) -> None:
    # The leader may have exited after forking a listener. Signal the whole
    # group regardless; waiting for only the leader would leave that child.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        process.poll()  # Reap an exited leader; otherwise its zombie keeps the group visible.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(.05)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def shutil_which(name: str) -> str | None:
    from shutil import which
    return which(name)


class Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/echo":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(min(length, 1024))
        if length != len(PAYLOAD) or body != PAYLOAD:
            self.send_error(400)
            return
        self.server.echo_hits += 1
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def one_probe(binary: Path, config: Path, port: int, target: str, *, hysteria: bool) -> Transfer:
    assert_port_free(port)
    argv = ([str(binary), "client", "-c", str(config)] if hysteria else
            [str(binary), "run", "-config", str(config)])
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ProbeError("client exited before SOCKS readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    if not listener_owned_by_group(port, process.pid):
                        raise ProbeError("SOCKS listener is not owned by client group")
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise ProbeError("client SOCKS readiness timed out")
        result = subprocess.run(
            ["curl", "--silent", "--show-error", "--fail", "--noproxy", "",
             "--max-time", "8", "--socks5-hostname", f"127.0.0.1:{port}",
             "--data-binary", "@-", target], input=PAYLOAD, capture_output=True, timeout=10)
        if process.poll() is not None:
            raise ProbeError("client exited during payload probe")
        if not listener_owned_by_group(port, process.pid):
            raise ProbeError("client SOCKS listener disappeared during payload probe")
        return Transfer(result.returncode, result.returncode == 0 and result.stdout == PAYLOAD)
    finally:
        cleanup_group(process)


def run(manifest: dict, base: Path) -> dict:
    preflight(manifest, base)
    report = empty_report()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    server.echo_hits = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/echo"
    try:
        for name in CASES:
            case = manifest["cases"][name]
            binary = Path(manifest["hysteria" if name == "hysteria2" else "xray"]["path"])
            before = server.echo_hits
            first = one_probe(binary, base / case["positive"], case["socks_port"], target,
                              hysteria=name == "hysteria2")
            after_first = server.echo_hits
            negative = one_probe(binary, base / case["negative"], case["socks_port"], target,
                                 hysteria=name == "hysteria2")
            after_negative = server.echo_hits
            last = one_probe(binary, base / case["positive"], case["socks_port"], target,
                             hysteria=name == "hysteria2")
            report["cases"][name] = classify_case(first, negative, last,
                                                   (before, after_first, after_negative, server.echo_hits))
        report["pass"] = all(item["controlled_differential_denial"] for item in report["cases"].values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = empty_report()
    try:
        manifest = read_manifest(args.manifest)
        report = run(manifest, args.manifest.resolve().parent)
    except (ProbeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        report["error"] = type(exc).__name__  # Never serialize exception text or config paths.
    args.report.write_text(json.dumps(report, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
