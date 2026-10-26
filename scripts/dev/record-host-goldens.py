#!/usr/bin/env python3
"""Record golden fixtures of the Python host side for the Rust port (dev-only, ams-test).

The script runs the *current Python* installer and version-agent code against a throwaway
root directory with fake command runners, fixed clocks and seeded "random" values, and writes
the bytes it produced into ``tests/fixtures/host-golden/``.  Rust packages load those files and
must reproduce them (or round-trip them byte for byte).  See the README in that directory.

It never touches the live installation of the host it runs on: it re-executes itself in a
private mount namespace (``unshare --mount``) and hides every live state directory behind an
empty tmpfs before any installer code is imported.  Run it as root on ams-test:

    python3 scripts/dev/record-host-goldens.py            # write tests/fixtures/host-golden
    python3 scripts/dev/record-host-goldens.py --output /tmp/a --check-against tests/fixtures/host-golden

It changes no production code; every seam is a monkeypatch of this process only.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO / "tests" / "fixtures" / "host-golden"
WORK_BASE = Path("/tmp/proxy-control-host-golden")
NAMESPACE_FLAG = "PC_HOST_GOLDEN_NAMESPACE"

# Live state of a real installation. Inside the private namespace each of these is covered
# by an empty tmpfs, so no code path can read or write the host's own installation.
LIVE_PATHS = (
    "/var/lib/proxy-control",
    "/opt/mtproxy-shared443",
    "/opt/proxy-control",
    "/etc/proxy-control",
    "/etc/letsencrypt",
    "/etc/nginx",
    "/etc/mieru-manager",
    "/var/lib/mita",
    "/var/lib/naive-manager",
    "/var/lib/xray-router",
    "/var/lib/awg-manager",
    "/var/lib/trusttunnel-manager",
    "/var/lib/mieru-manager",
    "/usr/local/x-ui",
    "/etc/x-ui",
    "/run/lock",
)

# One fixed wall clock for every recorded artefact: 2026-01-01T00:00:00Z.
FIXED_EPOCH = 1767225600
FORBIDDEN_SUFFIXES = (".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".pyc")
SCHEMA_NOTE = "proxy-control host goldens, recorded from the Python code"


# --------------------------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------------------------


def _enter_namespace(argv: Sequence[str]) -> None:
    """Re-exec inside a private mount namespace with the live state hidden."""
    if os.environ.get(NAMESPACE_FLAG) == "1":
        for path in LIVE_PATHS:
            if os.path.isdir(path) and not os.path.islink(path):
                subprocess.run(
                    ["mount", "-t", "tmpfs", "-o", "mode=0755,size=64m", "golden", path],
                    check=True,
                )
        return
    if os.geteuid() != 0:
        raise SystemExit("run as root on ams-test (the recorder needs a private mount namespace)")
    if shutil.which("unshare") is None:
        raise SystemExit("unshare(1) is required")
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        NAMESPACE_FLAG: "1",
    }
    os.execvpe(
        "unshare",
        ["unshare", "--mount", "--propagation", "private", "--", sys.executable, "-B", *argv],
        environment,
    )


# --------------------------------------------------------------------------------------------
# Determinism: seeded secrets, uuid4, a fixed clock, no sleeping, stable temp names
# --------------------------------------------------------------------------------------------


class Determinism:
    """Replaces every entropy and clock source the host code reads, per scenario."""

    def __init__(self) -> None:
        self.seed = "unset"
        self.counter = 0
        self.clock = float(FIXED_EPOCH)

    def reset(self, seed: str) -> None:
        self.seed = seed
        self.counter = 0
        self.clock = float(FIXED_EPOCH)

    def random_bytes(self, count: int | None) -> bytes:
        size = 32 if count is None else int(count)
        out = b""
        while len(out) < size:
            self.counter += 1
            out += hashlib.sha256(f"host-golden:{self.seed}:{self.counter}".encode()).digest()
        return out[:size]

    def token_bytes(self, nbytes: int | None = None) -> bytes:
        return self.random_bytes(nbytes)

    def token_hex(self, nbytes: int | None = None) -> str:
        return self.random_bytes(nbytes).hex()

    def token_urlsafe(self, nbytes: int | None = None) -> str:
        return base64.urlsafe_b64encode(self.random_bytes(nbytes)).rstrip(b"=").decode("ascii")

    def uuid4(self) -> uuid.UUID:
        return uuid.UUID(bytes=self.random_bytes(16), version=4)

    def time(self) -> float:
        return self.clock

    def time_ns(self) -> int:
        return int(self.clock * 1_000_000_000)


DET = Determinism()


class _TempNames:
    """Deterministic tempfile candidate names (tempfile._get_candidate_names)."""

    def __iter__(self) -> "_TempNames":
        return self

    def __next__(self) -> str:
        return "golden" + DET.token_hex(4)


def install_determinism(work: Path) -> None:
    import secrets

    secrets.token_bytes = DET.token_bytes  # type: ignore[assignment]
    secrets.token_hex = DET.token_hex  # type: ignore[assignment]
    secrets.token_urlsafe = DET.token_urlsafe  # type: ignore[assignment]
    uuid.uuid4 = DET.uuid4  # type: ignore[assignment]
    time.time = DET.time  # type: ignore[assignment]
    time.time_ns = DET.time_ns  # type: ignore[assignment]
    time.sleep = lambda _seconds: None  # type: ignore[assignment]
    tempdir = work / "tmp"
    tempdir.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(tempdir)
    tempfile._name_sequence = _TempNames()  # type: ignore[attr-defined]
    os.umask(0o022)


# --------------------------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------------------------


class Output:
    """Collects every fixture file; written at the end so a failure leaves nothing half-done."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}

    def bytes(self, relative: str, data: bytes) -> None:
        # release/build.py refuses these names inside the archive; SQLite fixtures are *.db.
        if relative.endswith(FORBIDDEN_SUFFIXES):
            raise RuntimeError(f"fixture name is refused by the release builder: {relative}")
        if relative in self.files:
            raise RuntimeError(f"fixture written twice: {relative}")
        self.files[relative] = data

    def text(self, relative: str, data: str) -> None:
        self.bytes(relative, data.encode("utf-8"))

    def json(self, relative: str, value: object) -> None:
        self.text(relative, pretty(value))

    def write(self, destination: Path) -> None:
        if destination.exists():
            shutil.rmtree(destination)
        for relative, data in sorted(self.files.items()):
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        index = {
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(self.files.items())},
            "note": SCHEMA_NOTE,
            "schema": 1,
        }
        (destination / "INDEX.json").write_text(pretty(index), encoding="utf-8")


def pretty(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def snapshot_tree(root: Path, *, skip: Sequence[str] = ()) -> tuple[dict[str, object], dict[str, bytes]]:
    """Every path under `root`: kind, mode, size, sha256 (files) or target (symlinks)."""
    entries: dict[str, object] = {}
    contents: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        relative = "/" + path.relative_to(root).as_posix()
        if any(relative == prefix or relative.startswith(prefix + "/") for prefix in skip):
            continue
        info = path.lstat()
        mode = f"{stat.S_IMODE(info.st_mode):04o}"
        if stat.S_ISLNK(info.st_mode):
            entries[relative] = {"kind": "symlink", "target": os.readlink(path)}
        elif stat.S_ISDIR(info.st_mode):
            entries[relative] = {"kind": "dir", "mode": mode, "uid": info.st_uid, "gid": info.st_gid}
        elif stat.S_ISREG(info.st_mode):
            data = path.read_bytes()
            entries[relative] = {
                "kind": "file",
                "mode": mode,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            contents[relative] = data
        else:
            entries[relative] = {"kind": "other", "mode": mode}
    return entries, contents


# --------------------------------------------------------------------------------------------
# (8) Configuration errors for a corpus of bad TOML
# --------------------------------------------------------------------------------------------

BASE_TOML = {
    "root": [
        "schema = 1",
        'host_mode = "fresh"',
        'profile = "full"',
        'acme_email = "admin@example.com"',
        'initial_user = "owner"',
    ],
    "domains": [
        'panel = "panel.example.com"',
        'mtproxy = "relay.example.com"',
        'naive = "edge.example.com"',
        'mieru = "mieru.example.com"',
    ],
    "mieru": ["tcp_ports = [46001]", "udp_ports = [46001]"],
    "three_xui": ['mode = "none"'],
    "firewall": ["manage_ufw = true"],
}


def toml_text(
    *,
    root: Sequence[str] | None = None,
    sections: Mapping[str, Sequence[str] | None] | None = None,
    extra: str = "",
) -> str:
    """A configuration built from BASE_TOML: `sections` replaces (list) or drops (None) a table."""
    tables: dict[str, Sequence[str] | None] = {
        name: lines for name, lines in BASE_TOML.items() if name != "root"
    }
    for name, lines in (sections or {}).items():
        tables[name] = lines
    lines = list(BASE_TOML["root"] if root is None else root)
    for name, body in tables.items():
        if body is None:
            continue
        lines.extend(["", f"[{name}]", *body])
    return "\n".join(lines) + "\n" + extra


def _replace(lines: Sequence[str], key: str, value: str | None) -> list[str]:
    """Replace (or drop with None, or append when absent) `key = …` in a table body."""
    result = []
    found = False
    for line in lines:
        if line.split("=", 1)[0].strip() == key:
            found = True
            if value is not None:
                result.append(f"{key} = {value}")
            continue
        result.append(line)
    if not found and value is not None:
        result.append(f"{key} = {value}")
    return result


def root_with(key: str, value: str | None) -> list[str]:
    return _replace(BASE_TOML["root"], key, value)


def table_with(table: str, key: str, value: str | None) -> list[str]:
    return _replace(BASE_TOML.get(table, []), key, value)


CORE_ROOT = root_with("profile", '"core"')
CORE_SECTIONS: dict[str, Sequence[str] | None] = {
    "domains": ['panel = "panel.example.com"', 'mtproxy = "relay.example.com"'],
    "mieru": None,
}


def config_error_corpus() -> list[tuple[str, str]]:
    corpus: list[tuple[str, str]] = []

    def add(name: str, text: str) -> None:
        corpus.append((name, text))

    # tomllib itself (TOML 1.0)
    add("toml-syntax-unterminated-string", 'schema = 1\nhost_mode = "fresh\n')
    add("toml-syntax-missing-value", "schema =\n")
    add("toml-duplicate-key", "schema = 1\nschema = 1\n")
    add("toml-table-redefined", toml_text(extra='\n[domains]\npanel = "x.example.com"\n'))
    add("toml-1.1-escape-e", 'schema = 1\nacme_email = "a\\e@example.com"\n')
    add("toml-1.1-escape-x", 'schema = 1\nacme_email = "a\\x41@example.com"\n')
    add("toml-1.1-inline-table-newline", 'schema = 1\nx = { a = 1,\n b = 2 }\n')
    add("toml-bom", "﻿" + toml_text())
    add("toml-integer-overflow-port", toml_text(sections={"mieru": ["tcp_ports = [99999999999999999999]", "udp_ports = []"]}))
    add("toml-dotted-keys-at-root", "\n".join([
        *BASE_TOML["root"][:1], 'host_mode = "fresh"', 'profile = "core"',
        'acme_email = "admin@example.com"', 'initial_user = "owner"',
        'domains.panel = "panel.example.com"', 'domains.mtproxy = "relay.example.com"',
        'three_xui.mode = "none"', "firewall.manage_ufw = true", "schema_extra = 1",
    ]) + "\n")
    # root keys: unknown first (document order), then missing (sorted)
    add("root-unknown-key", toml_text(root=[*BASE_TOML["root"], "zeta = 1", "alpha = 2"]))
    add("root-missing-keys", toml_text(root=root_with("acme_email", None)[:2], sections={"three_xui": None}))
    add("root-unknown-and-missing", toml_text(root=["zzz = 1", "schema = 1"]))
    add("root-not-a-table-array", "[[domains]]\npanel = 1\n")
    # schema, enums, scalars
    add("schema-bool", toml_text(root=root_with("schema", "true")))
    add("schema-float", toml_text(root=root_with("schema", "1.0")))
    add("schema-string", toml_text(root=root_with("schema", '"1"')))
    add("schema-unsupported", toml_text(root=root_with("schema", "2")))
    add("host-mode-invalid", toml_text(root=root_with("host_mode", '"Fresh"')))
    add("host-mode-not-string", toml_text(root=root_with("host_mode", "1")))
    add("profile-invalid", toml_text(root=root_with("profile", '"everything"')))
    for index, email in enumerate(['"admin"', '"a b@example.com"', '"admin@example"', '" admin@example.com"',
                                   '"admin@@example.com"', '"admin@example.com\\n"', "7"]):
        add(f"acme-email-invalid-{index}", toml_text(root=root_with("acme_email", email)))
    add("acme-email-with-del-accepted", toml_text(root=root_with("acme_email", '"ad\\u007fmin@example.com"')))
    for index, user in enumerate(['""', '"own er"', '"' + "a" * 65 + '"', '"ownér"', '"owner\\n"']):
        add(f"initial-user-unsafe-{index}", toml_text(root=root_with("initial_user", user)))
    # domains
    add("domains-not-a-table", toml_text(root=[*BASE_TOML["root"], "domains = 1"], sections={"domains": None}))
    add("domains-naive-required-first", toml_text(sections={"domains": ['panel = "panel.example.com"']}))
    add("domains-mieru-required", toml_text(sections={"domains": table_with("domains", "mieru", None)}))
    add("domains-unknown-key", toml_text(sections={"domains": [*BASE_TOML["domains"], 'xui = "x.example.com"']}))
    add("domains-missing-mtproxy", toml_text(sections={"domains": table_with("domains", "mtproxy", None)}))
    for index, domain in enumerate(['"PANEL.Example.COM."', '" panel.example.com "', '"panel.example.com.."',
                                    '"panel"', '"a.b"', '"-panel.example.com"', '"panel.example.c0m"',
                                    '"panel.exa_mple.com"', '"xn--80ak6aa92e.com"', '"пример.рф"',
                                    '"' + "a" * 64 + '.example.com"', "42"]):
        add(f"domain-value-{index}", toml_text(sections={"domains": table_with("domains", "panel", domain)}))
    add("domains-duplicate-sni", toml_text(sections={"domains": table_with("domains", "mtproxy", '"panel.example.com"')}))
    add("domains-duplicate-sni-after-normalising", toml_text(sections={"domains": table_with("domains", "mtproxy", '"Panel.Example.com."')}))
    add("domains-mieru-may-equal-panel", toml_text(sections={"domains": table_with("domains", "mieru", '"panel.example.com"')}))
    # mieru
    add("mieru-outside-profile", toml_text(root=CORE_ROOT, sections={**CORE_SECTIONS, "mieru": BASE_TOML["mieru"]}))
    add("mieru-section-required", toml_text(sections={"mieru": None}))
    add("mieru-not-a-table", toml_text(root=[*BASE_TOML["root"], "mieru = 3"], sections={"mieru": None}))
    add("mieru-no-ports", toml_text(sections={"mieru": ["tcp_ports = []", "udp_ports = []"]}))
    add("mieru-ports-not-array", toml_text(sections={"mieru": ["tcp_ports = 46001", "udp_ports = []"]}))
    add("mieru-port-low", toml_text(sections={"mieru": ["tcp_ports = [1023]", "udp_ports = []"]}))
    add("mieru-port-high", toml_text(sections={"mieru": ["tcp_ports = [65536]", "udp_ports = []"]}))
    add("mieru-port-bool", toml_text(sections={"mieru": ["tcp_ports = [true]", "udp_ports = []"]}))
    add("mieru-port-duplicate", toml_text(sections={"mieru": ["tcp_ports = [46001, 46001]", "udp_ports = []"]}))
    add("mieru-port-taken-by-panel", toml_text(sections={"mieru": ["tcp_ports = [8787]", "udp_ports = []"]}))
    add("mieru-port-taken-by-naive", toml_text(sections={"mieru": ["tcp_ports = [4443]", "udp_ports = []"]}))
    add("mieru-port-443", toml_text(sections={"mieru": ["tcp_ports = [443]", "udp_ports = []"]}))
    add("mieru-ports-keep-order", toml_text(sections={"mieru": ["tcp_ports = [46003, 46001]", "udp_ports = [46002]"]}))
    add("mieru-lane-slots-range", toml_text(sections={"mieru": [*BASE_TOML["mieru"], "lane_slots = 9"]}))
    add("mieru-lane-slots-without-router", toml_text(sections={"mieru": [*BASE_TOML["mieru"], "lane_slots = 2"]}))
    add("mieru-lane-slots-collide", toml_text(
        sections={"mieru": ["tcp_ports = [46102]", "udp_ports = []", "lane_slots = 3"],
                  "egress": ["router = true"]}))
    add("mieru-unknown-key", toml_text(sections={"mieru": [*BASE_TOML["mieru"], "slots = 1"]}))
    # three_xui
    add("three-xui-mode-missing", toml_text(sections={"three_xui": ["warp = false"]}))
    add("three-xui-mode-invalid", toml_text(sections={"three_xui": ['mode = "managed"']}))
    add("three-xui-none-domain", toml_text(sections={"three_xui": ['mode = "none"', 'panel_domain = "x.example.com"']}))
    add("three-xui-warp-port-range", toml_text(sections={"three_xui": ['mode = "none"', "warp_port = 80"]}))
    add("three-xui-warp-not-bool", toml_text(sections={"three_xui": ['mode = "none"', 'warp = "yes"']}))
    managed = ['mode = "managed-new"', 'panel_domain = "xui.example.com"', 'vless_tcp_domain = "vless.example.com"',
               'vless_xhttp_domain = "xhttp.example.com"', 'hysteria_domain = "hy2.example.com"']
    add("three-xui-managed-missing-warp", toml_text(sections={"three_xui": [*managed, "warp_domains = []"]}))
    add("three-xui-warp-domains-not-array", toml_text(sections={"three_xui": [*managed, "warp = true", 'warp_domains = "geosite:x"']}))
    add("three-xui-warp-geosite-invalid", toml_text(sections={"three_xui": [*managed, "warp = true", 'warp_domains = ["geosite:Bad"]']}))
    add("three-xui-warp-domain-invalid", toml_text(sections={"three_xui": [*managed, "warp = true", 'warp_domains = ["domain:x"]']}))
    add("three-xui-warp-domains-require-warp", toml_text(sections={"three_xui": [*managed, "warp = false", 'warp_domains = ["example.org"]']}))
    add("three-xui-warp-domains-sorted", toml_text(sections={"three_xui": [*managed, "warp = true",
        'warp_domains = ["geosite:openai", "domain:b.example.org", "a.example.org", "geosite:openai"]']}))
    add("three-xui-managed-on-coexist", toml_text(root=root_with("host_mode", '"coexist"'),
        sections={"three_xui": [*managed, "warp = false", "warp_domains = []"], "firewall": ["manage_ufw = false"]}))
    add("three-xui-sni-duplicate-hysteria-allowed", toml_text(sections={"three_xui": [
        'mode = "existing"', 'hysteria_domain = "panel.example.com"'], "firewall": ["manage_ufw = false"]},
        root=root_with("host_mode", '"coexist"')))
    add("three-xui-sni-duplicate-panel", toml_text(sections={"three_xui": [
        'mode = "existing"', 'panel_domain = "panel.example.com"'], "firewall": ["manage_ufw = false"]},
        root=root_with("host_mode", '"coexist"')))
    # egress
    add("egress-unknown-key", toml_text(sections={"egress": ["proxy = true"]}))
    add("egress-router-without-service", toml_text(root=CORE_ROOT, sections={**CORE_SECTIONS, "egress": ["router = true"]}))
    add("egress-relay-without-router", toml_text(sections={"egress": ["relay_port = 45443"]}))
    add("egress-relay-range", toml_text(sections={"egress": ["router = true", "relay_port = 70000"]}))
    add("egress-relay-collides", toml_text(sections={"egress": ["router = true", "relay_port = 45101"]}))
    add("egress-relay-zero-with-router", toml_text(sections={"egress": ["router = true", "relay_port = 0"]}))
    add("egress-warp-port-range", toml_text(sections={"egress": ["warp = true", "warp_port = 1000"]}))
    add("egress-warp-disagrees", toml_text(sections={"egress": ["warp = true"], "three_xui": ['mode = "none"', "warp = false"]}))
    add("egress-warp-port-disagrees", toml_text(sections={"egress": ["warp = true", "warp_port = 40001"],
                                                          "three_xui": ['mode = "none"', "warp_port = 40002"]}))
    add("egress-naive-outside-profile", toml_text(root=CORE_ROOT, sections={**CORE_SECTIONS, "egress": ['naive = "direct"']}))
    add("egress-naive-needs-warp", toml_text(sections={"egress": ['naive = "warp"']}))
    add("egress-mieru-needs-router", toml_text(sections={"egress": ['mieru = "router"']}))
    add("egress-naive-invalid", toml_text(sections={"egress": ['naive = "socks"']}))
    add("egress-full-router", toml_text(sections={"egress": ["warp = true", "router = true", 'naive = "router"',
                                                             'mieru = "warp"']}))
    add("egress-warp-domains-need-egress-warp", toml_text(sections={"egress": ["warp = false"], "three_xui": [
        *managed, 'warp_domains = ["example.org"]']}))
    # firewall
    add("firewall-missing-manage-ufw", toml_text(sections={"firewall": []}))
    add("firewall-not-bool", toml_text(sections={"firewall": ['manage_ufw = "true"']}))
    add("firewall-coexist-managed", toml_text(root=root_with("host_mode", '"coexist"')))
    # ingress
    coexist = root_with("host_mode", '"coexist"')
    no_ufw = {"firewall": ["manage_ufw = false"]}
    add("ingress-on-fresh", toml_text(sections={"ingress": ['proxy_protocol_bridge = "127.0.0.1:10443"']}))
    add("ingress-bridge-not-loopback", toml_text(root=coexist, sections={**no_ufw, "ingress": ['proxy_protocol_bridge = "0.0.0.0:10443"']}))
    add("ingress-bridge-low-port", toml_text(root=coexist, sections={**no_ufw, "ingress": ['proxy_protocol_bridge = "127.0.0.1:443"']}))
    add("ingress-bridge-missing", toml_text(root=coexist, sections={**no_ufw, "ingress": ["panel_tls_port = 9443"]}))
    add("ingress-panel-port-equals-bridge", toml_text(root=coexist, sections={**no_ufw, "ingress": [
        'proxy_protocol_bridge = "127.0.0.1:10443"', "panel_tls_port = 10443"]}))
    add("ingress-valid", toml_text(root=coexist, sections={**no_ufw, "ingress": [
        'proxy_protocol_bridge = "127.0.0.1:10443"', "panel_tls_port = 9443", "skip_renewal_dry_run = true"]}))
    add("ingress-panel-port-taken-by-mieru", toml_text(root=coexist, sections={
        **no_ufw, "mieru": ["tcp_ports = [9443]", "udp_ports = []"],
        "ingress": ['proxy_protocol_bridge = "127.0.0.1:10443"', "panel_tls_port = 9443"]}))
    # amneziawg
    awg = ["enabled = true"]
    add("awg-disabled-with-settings", toml_text(sections={"amneziawg": ["enabled = false", "mtu = 1300"]}))
    add("awg-disabled-alone", toml_text(sections={"amneziawg": ["enabled = false"]}))
    add("awg-versions-empty", toml_text(sections={"amneziawg": [*awg, "versions = []"]}))
    add("awg-versions-unknown", toml_text(sections={"amneziawg": [*awg, 'versions = ["2.1"]']}))
    add("awg-versions-duplicate", toml_text(sections={"amneziawg": [*awg, 'versions = ["2.0", "2.0"]']}))
    add("awg-versions-canonical-order", toml_text(sections={"amneziawg": [*awg, 'versions = ["3.1", "1.5"]',
                                                                          'ports = { "3.1" = 20031, "1.5" = 20015 }']}))
    for index, host in enumerate(['"192.168.001.1"', '" 203.0.113.7 "', '"Host.Example.COM."', '"2001:db8::1"',
                                  '"256.1.1.1"', '"host"']):
        add(f"awg-host-{index}", toml_text(sections={"amneziawg": [*awg, f"host = {host}", 'ports = { "1.5" = 20015, "2.0" = 20020, "3.1" = 20031 }']}))
    add("awg-ports-not-table", toml_text(sections={"amneziawg": [*awg, "ports = [1]"]}))
    add("awg-ports-unknown-version", toml_text(sections={"amneziawg": [*awg, 'ports = { "9.9" = 20000 }']}))
    add("awg-ports-not-enabled", toml_text(sections={"amneziawg": [*awg, 'versions = ["1.5"]', 'ports = { "2.0" = 20000 }']}))
    add("awg-ports-range", toml_text(sections={"amneziawg": [*awg, 'ports = { "1.5" = 80 }']}))
    add("awg-ports-distinct", toml_text(sections={"amneziawg": [*awg, 'ports = { "1.5" = 20000, "2.0" = 20000 }']}))
    add("awg-ports-taken-by-mieru-udp", toml_text(sections={"amneziawg": [*awg, 'ports = { "1.5" = 46001 }']}))
    add("awg-mtu-range", toml_text(sections={"amneziawg": [*awg, "mtu = 1500"]}))
    add("awg-dns-empty", toml_text(sections={"amneziawg": [*awg, "dns = []"]}))
    add("awg-dns-five", toml_text(sections={"amneziawg": [*awg, 'dns = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]']}))
    add("awg-dns-invalid", toml_text(sections={"amneziawg": [*awg, 'dns = ["one.one.one.one"]']}))
    add("awg-dns-leading-zero", toml_text(sections={"amneziawg": [*awg, 'dns = ["01.1.1.1"]']}))
    add("awg-dns-normalised-duplicate", toml_text(sections={"amneziawg": [*awg, 'dns = ["2001:db8::1", "2001:DB8:0::1"]']}))
    add("awg-dns-scope-id", toml_text(sections={"amneziawg": [*awg, 'dns = ["fe80::1%eth0"]', 'ports = { "1.5" = 20015, "2.0" = 20020, "3.1" = 20031 }']}))
    # trusttunnel
    tt_domains = [*BASE_TOML["domains"], 'trusttunnel = "gate.example.org"']
    add("tt-disabled-with-settings", toml_text(sections={"trusttunnel": ["enabled = false", "listen_port = 5000"]}))
    add("tt-domain-without-section", toml_text(sections={"domains": tt_domains}))
    add("tt-section-without-domain", toml_text(sections={"trusttunnel": ["enabled = true"]}))
    add("tt-listen-range", toml_text(sections={"domains": tt_domains, "trusttunnel": ["enabled = true", "listen_port = 99"]}))
    add("tt-listen-metrics", toml_text(sections={"domains": tt_domains, "trusttunnel": ["enabled = true", "listen_port = 1987"]}))
    add("tt-listen-taken-by-naive", toml_text(sections={"domains": tt_domains, "trusttunnel": ["enabled = true", "listen_port = 4443"]}))
    add("tt-duplicates-panel", toml_text(sections={"domains": table_with("domains", "mieru", None) + ['trusttunnel = "mieru.example.com"', 'mieru = "mieru.example.com"'],
                                                    "trusttunnel": ["enabled = true"]}))
    add("tt-unknown-key", toml_text(sections={"domains": tt_domains, "trusttunnel": ["enabled = true", "port = 1"]}))
    add("tt-router-allowed-on-core", toml_text(root=CORE_ROOT, sections={
        **CORE_SECTIONS, "domains": ['panel = "panel.example.com"', 'mtproxy = "relay.example.com"', 'trusttunnel = "gate.example.org"'],
        "trusttunnel": ["enabled = true"], "egress": ["router = true"]}))
    # valid files, recorded for their parsed canonical form
    add("valid-base", toml_text())
    return corpus


def record_config_errors(out: Output) -> None:
    from installer import cli
    from installer.config import ConfigError, parse_config, render_config

    records = []
    for name, text in config_error_corpus():
        entry: dict[str, object] = {"name": name, "input": text}
        try:
            config = parse_config(text)
        except ConfigError as exc:
            entry["result"] = "error"
            entry["exception"] = type(exc).__name__
            entry["message"] = str(exc)
        else:
            entry["result"] = "ok"
            entry["canonical"] = config.canonical_dict()
            entry["rendered"] = render_config(config)
        records.append(entry)
    out.json("config/errors.json", records)

    # The same failures as an operator sees them: `plan --config F` → `BLOCKED: …`, exit 2.
    cli_records = []
    directory = WORK_BASE / "config-errors"
    directory.mkdir(parents=True, exist_ok=True)
    failing = [str(entry["name"]) for entry in records if entry["result"] == "error"]
    samples = failing[::5] + [name for name in ("toml-bom", "awg-dns-invalid") if name not in failing[::5]]
    corpus = dict(config_error_corpus())
    for name in samples:
        path = directory / f"{name}.toml"
        path.write_text(corpus[name], encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.run(["plan", "--config", str(path)], services=_unused_services(), stdout=stdout, stderr=stderr)
        cli_records.append({
            "name": name,
            "exit": code,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue().replace(str(directory), "<dir>"),
        })
    # File-level failures that are not ConfigError.
    for name, data in (("missing-file", None), ("invalid-utf8", b"schema = 1\nacme_email = \"\xff\"\n")):
        path = directory / f"{name}.toml"
        if data is not None:
            path.write_bytes(data)
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.run(["plan", "--config", str(path)], services=_unused_services(), stdout=stdout, stderr=stderr)
        cli_records.append({
            "name": name,
            "exit": code,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue().replace(str(directory), "<dir>"),
        })
    out.json("config/cli-blocked.json", cli_records)

    # render_config of every example (the wizard's "save" writer) and its round trip.
    renders = {}
    for example in sorted((REPO / "examples" / "installer").glob("*.toml")):
        config = parse_config(example.read_text(encoding="utf-8"))
        rendered = render_config(config)
        out.text(f"config/render/{example.stem}.toml", rendered)
        try:
            reparsed = parse_config(rendered)
            renders[example.name] = {"round_trip_equal": reparsed == config}
        except ConfigError as exc:
            renders[example.name] = {"round_trip_error": str(exc)}
    out.json("config/render/round-trip.json", renders)


def _unused_services():
    """CliServices whose every hook fails: config loading must refuse before any is reached."""
    from installer.cli import CliServices

    def refuse(*_args, **_kwargs):
        raise AssertionError("the configuration should have been refused first")

    return CliServices(audit=refuse, plan=refuse, engine=None, store=None, wizard=refuse)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------
# (9) Python semantics the digest and the validators depend on
# --------------------------------------------------------------------------------------------

UNICODE_SAMPLES = [
    "0", "123", "", " 1", "1 ", "+1", "-1", "1.5", "0x10", "1_000",
    "١٢٣",  # ARABIC-INDIC DIGITS ١٢٣
    "۱",  # EXTENDED ARABIC-INDIC DIGIT ONE
    "१",  # DEVANAGARI DIGIT ONE
    "１２",  # FULLWIDTH ١٢
    "²",  # SUPERSCRIPT TWO (isdigit, not isdecimal)
    "①",  # CIRCLED DIGIT ONE
    "½",  # VULGAR FRACTION ONE HALF (isnumeric only)
    "一",  # CJK ONE (isnumeric only)
    "\U0001d7ce",  # MATHEMATICAL BOLD DIGIT ZERO
    "ᵼe",
    "٣4",
]

WHITESPACE_SAMPLES = [
    " a ", "\ta\t", "\na\n", "\r\na\r\n", "\x0ba\x0c", "\x1ca\x1d", "\x1ea\x1f", "\x85a\x85",
    "\xa0a\xa0", " a", " a ", " a ", " a ", "　a　",
    "​a​", "﻿a﻿", "\x00a\x00", "a", "", "  ",
]

LOWER_SAMPLES = [
    "PANEL.EXAMPLE.COM", "Panel.Example.Com.", "İSTANBUL.example", "ẞ.example", "Σ.example",
    "ΑΣ", "K.example", "Ⅻ.example", "ǅ.example", "ﬀ.example", "PANEL.example.com...", "ÀB.example",
]

IP_SAMPLES = [
    "1.1.1.1", "01.1.1.1", "1.1.1", "1.1.1.1.", "256.0.0.1", "0.0.0.0", "255.255.255.255", " 1.1.1.1",
    "1.1.1.1 ", "١.١.١.١", "2001:db8::1", "2001:DB8:0:0:0:0:0:1", "2001:db8::0:1", "::", "::1",
    "::ffff:1.2.3.4", "::FFFF:102:304", "fe80::1%eth0", "fe80::1%", "2001:db8::1/128", "[2001:db8::1]",
    "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3", "0:0:0:0:0:0:0:0", "2001:0db8:0000:0000:0000:ff00:0042:8329",
    "64:ff9b::192.0.2.33", "1.2.3.04", "127.000.000.001",
]

ROUND_SAMPLES = [
    (0.5, None), (1.5, None), (2.5, None), (-0.5, None), (-1.5, None), (0.125, 2), (0.375, 2), (2.675, 2),
    (1.005, 2), (0.045, 2), (99.995, 2), (12.3456, 1), (12.35, 1), (12.25, 1), (0.05, 1), (0.15, 1),
    (0.25, 1), (100.0, 1), (33.33333333, 1), (66.66666666, 1), (1767225600.1235, 3), (1767225600.0005, 3),
    (1.0e16, 3), (5e-324, 3), (1234567.891, 2), (0.0, 1), (-0.0, 1),
]

FLOAT_REPR_SAMPLES = [
    0.1, 0.2, 0.1 + 0.2, 1.0, 100.0, 1e16, 1e15, 123456789012345680.0, 1e-5, 1e-4, 0.0001234, 5e-324,
    1.7976931348623157e308, -0.0, 12.3, 33.3, 66.7, 1767225600.123, 2.5, 1e22, 1e21, 1e20,
]

JSON_STRING_SAMPLES = [
    "plain", "quote\"back\\slash", "\b\f\n\r\t", "\x00\x01\x1f", "\x7f", "\u0080\u009f", "é", "日本",
    "  ", "😀", "퟿", "/slash", "<script>", " nbsp",
]


def record_vectors(out: Output) -> None:
    import ipaddress
    import math
    import re

    def char_names(text: str) -> list[str]:
        return [f"U+{ord(ch):04X}" for ch in text]

    out.json("vectors/str-digits.json", [
        {
            "codepoints": char_names(sample),
            "input": sample,
            "isascii": sample.isascii(),
            "isdecimal": sample.isdecimal(),
            "isdigit": sample.isdigit(),
            "isnumeric": sample.isnumeric(),
            "int": _try(lambda s=sample: int(s)),
            "re_d_fullmatch": re.fullmatch(r"\d+", sample) is not None,
            "re_09_fullmatch": re.fullmatch(r"[0-9]+", sample) is not None,
        }
        for sample in UNICODE_SAMPLES
    ])
    out.json("vectors/str-strip.json", [
        {
            "codepoints": char_names(sample),
            "input": sample,
            "isspace": [ch.isspace() for ch in sample],
            "split": sample.split(),
            "strip": sample.strip(),
            "strip_codepoints": char_names(sample.strip()),
        }
        for sample in WHITESPACE_SAMPLES
    ])
    out.json("vectors/str-lower.json", [
        {
            "casefold": sample.casefold(),
            "input": sample,
            "lower": sample.lower(),
            "lower_codepoints": char_names(sample.lower()),
            "normalised_domain": sample.strip().lower().rstrip("."),
        }
        for sample in LOWER_SAMPLES
    ])
    ip_records = []
    for sample in IP_SAMPLES:
        record: dict[str, object] = {"input": sample}
        record["ip_address"] = _try(lambda s=sample: str(ipaddress.ip_address(s)))
        record["IPv4Address"] = _try(lambda s=sample: str(ipaddress.IPv4Address(s)))
        record["IPv6Address"] = _try(lambda s=sample: str(ipaddress.IPv6Address(s)))
        record["ip_address_before_percent"] = _try(lambda s=sample: str(ipaddress.ip_address(s.split("%", 1)[0])))
        record["version"] = _try(lambda s=sample: ipaddress.ip_address(s).version)
        ip_records.append(record)
    out.json("vectors/ipaddress.json", ip_records)
    out.json("vectors/str-of-scalars.json", [
        {"python": "str(True)", "value": str(True)},
        {"python": "str(False)", "value": str(False)},
        {"python": "str(None)", "value": str(None)},
        {"python": "str(443)", "value": str(443)},
        {"python": "str(-1)", "value": str(-1)},
        {"python": "str(2**70)", "value": str(2**70)},
        {"python": "str(1.0)", "value": str(1.0)},
        {"python": "str(1e16)", "value": str(1e16)},
        {"python": "str(0.1+0.2)", "value": str(0.1 + 0.2)},
        {"python": "str(('a', 1))", "value": str(("a", 1))},
        {"python": "str({'a': [1, True, None]})", "value": str({"a": [1, True, None]})},
        {"python": "json key from {True: 1, 443: 2, None: 3}",
         "value": json.dumps({True: 1, 443: 2, None: 3}, sort_keys=False)},
        {"python": "planner._freeze key str(True)", "value": _freeze_keys({True: 1, 443: 2, 1.5: 3})},
    ])
    out.json("vectors/round.json", [
        {
            "input_repr": repr(value),
            "ndigits": digits,
            "round": (round(value) if digits is None else round(value, digits)),
            "round_repr": repr(round(value) if digits is None else round(value, digits)),
            "json": json.dumps(round(value) if digits is None else round(value, digits)),
            "rust_f64_round_would_be": repr(
                (math.floor(abs(value) * 10 ** (digits or 0) + 0.5) / 10 ** (digits or 0)) * (1 if value >= 0 else -1)
            ),
        }
        for value, digits in ROUND_SAMPLES
    ])
    out.json("vectors/float-repr.json", [
        {"json": json.dumps(value), "repr": repr(value), "hex": float.hex(value)} for value in FLOAT_REPR_SAMPLES
    ])
    out.json("vectors/json-strings.json", [
        {
            "codepoints": char_names(sample),
            "ensure_ascii_false": json.dumps(sample, ensure_ascii=False),
            "ensure_ascii_true": json.dumps(sample),
        }
        for sample in JSON_STRING_SAMPLES
    ])
    keys = ["b", "a", "B", "_", "é", "z", "日", "😀", "￿", "10", "9", "a b", "a-b", "A"]
    out.json("vectors/json-key-order.json", {
        "compact_sorted": json.dumps({key: 1 for key in keys}, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        "indent2_sorted": json.dumps({key: 1 for key in keys}, ensure_ascii=False, indent=2, sort_keys=True),
        "indent2_sorted_ascii": json.dumps({key: 1 for key in keys}, indent=2, sort_keys=True),
        "keys": keys,
        "set_order_by_compact_json": _set_sort([9, 10, 100, "10", "9", True, None, [1], {"a": 1}]),
        "empty_containers_indent2": json.dumps({"a": {}, "b": [], "c": [{}], "d": [[]]}, indent=2, sort_keys=True),
    })
    record_validator_vectors(out)


def _try(function: Callable[[], object]) -> object:
    try:
        return {"ok": function()}
    except Exception as exc:  # noqa: BLE001 - the class name is the vector
        return {"error": type(exc).__name__, "message": str(exc)}


def _freeze_keys(value: Mapping[object, object]) -> object:
    from installer.planner import _canonical_json_value

    return _try(lambda: json.dumps(_canonical_json_value(value), sort_keys=True))


def _set_sort(items: Sequence[object]) -> object:
    from installer.planner import _sort_key

    return [json.dumps(item) for item in sorted(items, key=_sort_key)]


def record_validator_vectors(out: Output) -> None:
    """Input → accept/reject (and normalised value) for the validators that guard the digest."""
    from installer import config as config_module
    from installer.audit import validate_domain
    from installer.wizard import _domain as wizard_domain  # type: ignore[attr-defined]
    from version_agent import catalog, upstream

    domains = [
        "panel.example.com", "PANEL.Example.COM.", " panel.example.com ", "panel.example.com..", "a.b", "ab.c",
        "a.bc", "x" * 63 + ".example.com", "x" * 64 + ".example.com", "-a.example.com", "a-.example.com",
        "a.example.c0m", "a.example.1com", "xn--d1acufc.xn--p1ai", "пример.рф", "a_b.example.com",
        "a..example.com", ".example.com", "example.com\n", " example.com", "1.2.3.4", "localhost",
        ("a." * 126) + "com", ("a." * 125) + "com", "İ.example.com", "panel.EXAMPLE.com　",
    ]
    records = []
    for value in domains:
        records.append({
            "audit_validate_domain": _try(lambda v=value: validate_domain(v)),
            "config_domain": _try(lambda v=value: config_module._domain(v, "domains.panel")),
            "input": value,
            "wizard_domain": _try(lambda v=value: wizard_domain(v)),
        })
    out.json("vectors/validators-domain.json", records)

    versions = [
        "1.2", "1.2.3", "1.2.3.4", "1.2.3.4.5", "1", "v1.2", "1.2-rc1", "1.2.3-rc.1", "١.٢", "1.2\n", "1.2.3-",
        "26.10.17", "3.10.2", "1.1.0-beta.1+x", "0.0", "01.02",
    ]
    out.json("vectors/validators-version.json", [
        {
            "AMNEZIAWG_VERSION": catalog.AMNEZIAWG_VERSION.fullmatch(value) is not None,
            "AMNEZIAWG_VERSION_match": catalog.AMNEZIAWG_VERSION.match(value) is not None,
            "TELEMT_RELEASE_VERSION": catalog.TELEMT_RELEASE_VERSION.fullmatch(value) is not None,
            "TRUSTTUNNEL_VERSION": catalog.TRUSTTUNNEL_VERSION.fullmatch(value) is not None,
            "TRUSTTUNNEL_VERSION_match": catalog.TRUSTTUNNEL_VERSION.match(value) is not None,
            "_VERSION": catalog._VERSION.fullmatch(value) is not None,  # type: ignore[attr-defined]
            "input": value,
        }
        for value in versions
    ])
    pairs = [
        ("1.2.3", "1.2.4"), ("1.10", "1.9"), ("1.2", "1.2.0"), ("1.2.0", "1.2"), ("1.2-rc1", "1.2"),
        ("1.2-rc1", "1.2-rc2"), ("1.2-rc10", "1.2-rc2"), ("1.2-beta", "1.2-alpha"), ("2", "10"),
        ("1.a", "1.0"), ("١.٢", "1.2"), ("3.3.0", "4.0.0"), ("4.0.0-rc.1", "4.0.0"), ("v1.2", "1.2"),
        ("1.2.3.4", "1.2.3"), ("", "0"),
    ]
    out.json("vectors/compare-versions.json", [
        {"a": left, "b": right, "compare": _try(lambda a=left, b=right: upstream.compare_versions(a, b))}
        for left, right in pairs
    ])


# --------------------------------------------------------------------------------------------
# The simulated host: a root directory plus answers to every command the code runs
# --------------------------------------------------------------------------------------------

HOST_V4 = "203.0.113.10"
HOST_V6 = "2001:db8::10"
MACHINE_ID = "0123456789abcdef0123456789abcdef"
RELEASE_VERSION = "3.3.0"
RELEASE_COMMIT = "0" * 40
RELEASE_MANIFEST_SHA256 = "1" * 64

STOCK_NGINX_CONF = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
\tworker_connections 768;
}

http {
\tsendfile on;
\ttcp_nopush on;
\ttypes_hash_max_size 2048;
\tinclude /etc/nginx/mime.types;
\tdefault_type application/octet-stream;
\tssl_protocols TLSv1.2 TLSv1.3;
\tssl_prefer_server_ciphers off;
\taccess_log /var/log/nginx/access.log;
\tgzip on;
\tinclude /etc/nginx/conf.d/*.conf;
\tinclude /etc/nginx/sites-enabled/*;
}
"""

COEXIST_NGINX_CONF = STOCK_NGINX_CONF + """
stream {
\tinclude /etc/nginx/stream.d/*.conf;
}
"""

COEXIST_ROUTES = """map $ssl_preread_server_name $sni_backend {
    legacy.example.net 127.0.0.1:10443;
    default 127.0.0.1:10443;
}
server {
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_pass $sni_backend;
}
"""

EXISTING_XUI_CONFIG = {
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 8449,
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "sniffing": {"destOverride": ["http", "tls"], "enabled": True},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverNames": ["vless.example.com"]}},
            "tag": "inbound-127.0.0.1:8449",
        },
        {
            "listen": "127.0.0.1",
            "port": 8450,
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "xhttp", "security": "reality",
                               "realitySettings": {"serverNames": ["xhttp.example.com"]}},
            "tag": "inbound-127.0.0.1:8450",
        },
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": []},
}


class SimHost:
    """One host: a root directory and the state of the programs it runs.

    `execute` is an `installer.audit.Executor`: it answers every audit and adapter command the
    Python code issues, mutating the root the way the real program would.  Anything it does not
    know is recorded in `unexpected` and answered with exit 127, so a missing case is visible.
    """

    def __init__(self, root: Path, *, coexist: bool = False, existing_xui: bool = False) -> None:
        self.root = root
        self.coexist = coexist
        self.packages: dict[str, str] = {
            "ca-certificates": "20240203",
            "curl": "8.5.0-2ubuntu10.6",
            "docker-compose-v2": "2.24.6+ds1-0ubuntu1~24.04.1",
            "docker.io": "26.1.3-0ubuntu1~24.04.1",
            "nginx-full": "1.24.0-2ubuntu7.5",
            "openssl": "3.0.13-0ubuntu3.5",
            "python3": "3.12.3-0ubuntu2",
        }
        self.listeners: list[tuple[str, str, int, str]] = [
            ("tcp", "0.0.0.0", 22, "sshd"),
            ("tcp", "[::]", 22, "sshd"),
        ]
        if coexist:
            self.listeners += [("tcp", "0.0.0.0", 443, "nginx"), ("tcp", "0.0.0.0", 80, "nginx")]
        if existing_xui:
            self.listeners += [
                ("tcp", "127.0.0.1", 8449, "xray-linux-amd64"),
                ("tcp", "127.0.0.1", 8450, "xray-linux-amd64"),
                ("tcp", "*", 2053, "x-ui"),
            ]
        self.ufw_active = False
        self.ufw_ipv6 = True
        self.ufw_rules: list[str] = []
        self.certificates: dict[str, tuple[str, ...]] = {}
        self.active_units: set[str] = {"nginx", "ssh", "docker"} | ({"x-ui"} if existing_xui else set())
        self.passwd: dict[int, str] = {}
        self.group: dict[int, str] = {}
        self.unexpected: list[tuple[str, ...]] = []
        self.calls: list[tuple[str, ...]] = []
        self._seed(existing_xui=existing_xui)

    # -- the root --------------------------------------------------------------------------

    def path(self, absolute: str) -> Path:
        """A host path, given either as the host sees it or already joined to the root."""
        if absolute == str(self.root) or absolute.startswith(str(self.root) + "/"):
            return Path(absolute)
        return self.root / absolute.lstrip("/")

    def write(self, absolute: str, data: str | bytes, mode: int = 0o644) -> None:
        path = self.path(absolute)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        path.chmod(mode)

    def _seed(self, *, existing_xui: bool) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.write("/etc/machine-id", MACHINE_ID + "\n")
        self.write("/dev/net/tun", b"")
        self.write("/etc/nginx/nginx.conf", COEXIST_NGINX_CONF if self.coexist else STOCK_NGINX_CONF)
        self.write("/etc/nginx/mime.types", "types {\n    text/html html;\n}\n")
        for directory in ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled", "/etc/nginx/modules-enabled",
                          "/var/www/html", "/etc/letsencrypt/renewal-hooks/deploy", "/etc/systemd/system",
                          "/usr/local/bin", "/usr/local/libexec", "/run/lock"):
            self.path(directory).mkdir(parents=True, exist_ok=True)
        if self.coexist:
            self.write("/etc/nginx/stream.d/routes.conf", COEXIST_ROUTES)
        self.write("/etc/default/ufw", "IPV6=yes\n")
        if existing_xui:
            self.write("/usr/local/x-ui/bin/config.json", json.dumps(EXISTING_XUI_CONFIG, indent=2) + "\n")
            self.write("/usr/local/x-ui/x-ui", b"#!/bin/sh\necho 'x-ui 3.10.2'\n", 0o755)
            self.write("/usr/local/x-ui/bin/xray-linux-amd64", b"#!/bin/sh\nexit 0\n", 0o755)
            self.write("/etc/x-ui/x-ui.db", b"SQLite format 3\x00golden-stand-in\n", 0o600)
            self.write("/etc/systemd/system/x-ui.service", "[Unit]\nDescription=x-ui\n[Service]\nExecStart=/usr/local/x-ui/x-ui\n")

    # -- command dispatch ------------------------------------------------------------------

    def execute(self, argv: Sequence[str], *, timeout: float = 5.0, max_output: int = 1 << 20) -> subprocess.CompletedProcess[str]:
        del timeout, max_output
        command = tuple(str(part) for part in argv)
        self.calls.append(command)
        handler = self._handler(command)
        if handler is None:
            self.unexpected.append(command)
            return subprocess.CompletedProcess(command, 127, "", f"golden host: unexpected command {command[0]}")
        result = handler(command)
        if isinstance(result, subprocess.CompletedProcess):
            return result
        code, stdout, stderr = result
        return subprocess.CompletedProcess(command, code, stdout, stderr)

    def resolver(self, host: str, port: int, *, type: int) -> list[tuple[int, int, int, str, tuple[object, ...]]]:  # noqa: A002
        import socket

        del port, type
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (HOST_V4, 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (HOST_V6, 443, 0, 0)),
        ]

    def command_runner(self, timeout: float = 5.0):
        from installer.audit import CommandRunner

        return CommandRunner(timeout=timeout, executor=self.execute, resolver=self.resolver)

    def _handler(self, command: tuple[str, ...]) -> Callable[[tuple[str, ...]], Any] | None:
        head = command[0]
        table: dict[str, Callable[[tuple[str, ...]], Any]] = {
            "uname": lambda c: (0, "x86_64\n", ""),
            "df": lambda c: (0, "Filesystem     1024-blocks     Used Available Capacity Mounted on\n"
                                "/dev/vda1         81000000 20000000  61000000      25% /\n", ""),
            "free": lambda c: (0, "               total        used        free      shared  buff/cache   available\n"
                                  "Mem:      4105519104   900000000  2000000000     1000000  1200000000  3100000000\n"
                                  "Swap:              0           0           0\n", ""),
            "ip": self._ip,
            "ss": self._ss,
            "systemctl": self._systemctl,
            "nginx": self._nginx,
            "docker": self._docker,
            "ufw": self._ufw,
            "grep": self._grep,
            "getent": self._getent,
            "dig": lambda c: (0, '0 issue "letsencrypt.org"\n', ""),
            "openssl": self._openssl,
            "test": lambda c: (0 if self.path(c[-1]).is_file() else 1, "", ""),
            "cat": self._cat,
            "dpkg-query": self._dpkg_query,
            "apt-get": self._apt_get,
            "certbot": self._certbot,
        }
        return table.get(head)

    def _ip(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("ip", "-j", "address"):
            document = [
                {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"},
                                                {"family": "inet6", "local": "::1", "scope": "host"}]},
                {"ifname": "eth0", "addr_info": [{"family": "inet", "local": HOST_V4, "scope": "global"},
                                                  {"family": "inet6", "local": HOST_V6, "scope": "global"},
                                                  {"family": "inet6", "local": "fe80::1", "scope": "link"}]},
            ]
            return 0, json.dumps(document), ""
        return 1, "", "unsupported"

    def _ss(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        """`ss` prints the Netid column only when it lists more than one protocol."""
        flags = "".join(part.lstrip("-") for part in command[1:] if part.startswith("-") and not part.startswith("--"))
        protocols = [name for name, flag in (("tcp", "t"), ("udp", "u")) if flag in flags] or ["tcp", "udp"]
        with_netid = len(protocols) > 1
        lines = []
        for index, (protocol, address, port, process) in enumerate(self.listeners, start=100):
            if protocol not in protocols:
                continue
            state = "LISTEN" if protocol == "tcp" else "UNCONN"
            users = f' users:(("{process}",pid={index},fd=3))' if "p" in flags else ""
            row = f"{state} 0 4096 {address}:{port} 0.0.0.0:*{users}"
            lines.append(f"{protocol} {row}" if with_netid else row)
        return 0, "".join(line + "\n" for line in lines), ""

    def _systemctl(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        verb = command[1] if len(command) > 1 else ""
        if verb == "show" and "ssh.socket" in command:
            return 0, "[::]:22 (Stream)\n", ""
        if verb == "list-unit-files":
            units = sorted({"nginx.service", "ssh.service", "docker.service", "ufw.service"}
                           | {f"{unit}.service" for unit in self.active_units})
            return 0, "".join(f"{unit} enabled enabled\n" for unit in units), ""
        if verb == "is-active":
            unit = command[-1]
            return (0, "active\n", "") if unit in self.active_units else (3, "inactive\n", "")
        if verb in {"reload", "restart", "start", "daemon-reload"}:
            return 0, "", ""
        if verb == "enable" or verb == "disable":
            return 0, "", ""
        return 0, "", ""

    def _nginx(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("nginx", "-T"):
            return 0, self.effective_nginx(), "nginx: configuration file /etc/nginx/nginx.conf test is successful\n"
        if command == ("nginx", "-t"):
            return 0, "", "nginx: configuration file /etc/nginx/nginx.conf test is successful\n"
        if command == ("nginx", "-V"):
            return 0, "", "nginx version: nginx/1.24.0 (Ubuntu)\nconfigure arguments: --with-stream=dynamic\n"
        return 1, "", "unsupported"

    def effective_nginx(self) -> str:
        """What `nginx -T` prints: every included file once, in inclusion order."""
        import fnmatch
        import re

        seen: list[str] = []

        def visit(absolute: str) -> None:
            if absolute in seen:
                return
            path = self.path(absolute)
            if not path.is_file():
                return
            seen.append(absolute)
            for match in re.finditer(r"^\s*include\s+([^;\s]+)\s*;", path.read_text(), re.MULTILINE):
                pattern = match.group(1)
                directory, _, name = pattern.rpartition("/")
                base = self.path(directory)
                if not base.is_dir():
                    continue
                for candidate in sorted(base.iterdir()):
                    if candidate.is_file() and fnmatch.fnmatch(candidate.name, name):
                        visit(f"{directory}/{candidate.name}")

        visit("/etc/nginx/nginx.conf")
        return "".join(
            f"# configuration file {absolute}:\n{self.path(absolute).read_text()}\n" for absolute in seen
        )

    def _docker(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("docker", "--version"):
            return 0, "Docker version 26.1.3, build 26.1.3-0ubuntu1~24.04.1\n", ""
        if command[:4] == ("docker", "compose", "version", "--short"):
            return 0, "2.24.6+ds1-0ubuntu1~24.04.1\n", ""
        return 1, "", "unsupported"

    def _ufw_status(self) -> str:
        if not self.ufw_active:
            return "Status: inactive\n"
        lines = ["Status: active", "", "     To                         Action      From",
                 "     --                         ------      ----"]
        lines.extend(f"[{index:2}] {rule}" for index, rule in enumerate(self.ufw_rules, 1))
        return "\n".join(lines) + "\n"

    def _ufw(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command == ("ufw", "status", "verbose"):
            if not self.ufw_active:
                return 0, "Status: inactive\n", ""
            return 0, "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\n", ""
        if command == ("ufw", "status", "numbered"):
            return 0, self._ufw_status(), ""
        if command[:3] == ("ufw", "route", "allow"):
            interface, comment = command[command.index("on") + 1], command[command.index("comment") + 1]
            for rule in (f"Anywhere                   ALLOW FWD   Anywhere on {interface}        # {comment}",
                         f"Anywhere (v6)              ALLOW FWD   Anywhere (v6) on {interface}   # {comment}"):
                if rule not in self.ufw_rules:
                    self.ufw_rules.append(rule)
            return 0, "Rule added\nRule added (v6)\n", ""
        if command[:4] == ("ufw", "--force", "route", "delete"):
            interface, comment = command[command.index("on") + 1], command[command.index("comment") + 1]
            self.ufw_rules = [rule for rule in self.ufw_rules
                              if not (f"on {interface}" in rule and rule.endswith(f"# {comment}"))]
            return 0, "Rule deleted\n", ""
        if command[:2] == ("ufw", "allow"):
            protocol = command[command.index("proto") + 1]
            port = command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            for rule in (f"{port}/{protocol} ALLOW IN Anywhere # {comment}",
                         f"{port}/{protocol} (v6) ALLOW IN Anywhere (v6) # {comment}"):
                if rule not in self.ufw_rules:
                    self.ufw_rules.append(rule)
            return 0, "Rule added\nRule added (v6)\n", ""
        if command[:4] == ("ufw", "--force", "delete", "allow"):
            protocol = command[command.index("proto") + 1]
            port = command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            for rule in (f"{port}/{protocol} ALLOW IN Anywhere # {comment}",
                         f"{port}/{protocol} (v6) ALLOW IN Anywhere (v6) # {comment}"):
                if rule in self.ufw_rules:
                    self.ufw_rules.remove(rule)
            return 0, "Rule deleted\n", ""
        if command[:3] == ("ufw", "--force", "enable"):
            self.ufw_active = True
            return 0, "Firewall is active and enabled on system startup\n", ""
        if command[:3] == ("ufw", "--force", "disable"):
            self.ufw_active = False
            return 0, "Firewall stopped and disabled on system startup\n", ""
        return 1, "", "unsupported"

    def _grep(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        from installer.audit import UFW_IPV6_CONFIG_COMMAND

        if command == UFW_IPV6_CONFIG_COMMAND:
            return 0, "IPV6=yes\n" if self.ufw_ipv6 else "IPV6=no\n", ""
        return 1, "", ""

    def _getent(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        database, key = command[1], command[2]
        table = self.passwd if database == "passwd" else self.group
        for identifier, name in table.items():
            if key in {str(identifier), name}:
                if database == "passwd":
                    return 0, f"{name}:x:{identifier}:{identifier}::/nonexistent:/usr/sbin/nologin\n", ""
                return 0, f"{name}:x:{identifier}:\n", ""
        return 2, "", ""

    def _cat(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        path = self.path(command[-1])
        if not path.is_file():
            return 1, "", "No such file or directory"
        return 0, path.read_text(), ""

    def _dpkg_query(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        package = command[-1]
        version = self.packages.get(package)
        if version is None:
            return 1, "", f"dpkg-query: no packages found matching {package}\n"
        if command[1] == "--show":
            return 0, f"{package}\tii \t{version}\n", ""
        fmt = next((part for part in command if part.startswith("-f=")), "-f=")
        if "db:Status-Status" in fmt:
            return 0, "installed", ""
        return 0, version, ""

    def _apt_get(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command[:2] == ("apt-get", "update"):
            return 0, "Reading package lists...\n", ""
        if command[:2] == ("apt-get", "install"):
            for specification in command[2:]:
                if specification.startswith("-"):
                    continue
                if specification.endswith(".deb"):
                    self.packages["cloudflare-warp"] = WARP_VERSION
                    continue
                package, separator, version = specification.partition("=")
                self.packages.setdefault(package, version if separator else GOLDEN_PACKAGE_VERSIONS.get(package, "1.0"))
            return 0, "installed\n", ""
        if command[:2] in {("apt-get", "purge"), ("apt-get", "remove")}:
            for package in command[2:]:
                if not package.startswith("-"):
                    self.packages.pop(package, None)
            return 0, "removed\n", ""
        return 1, "", "unsupported"

    def _certbot(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command[:2] == ("certbot", "certonly"):
            name = command[command.index("--cert-name") + 1]
            names = tuple(command[index + 1] for index, part in enumerate(command) if part == "-d")
            self.certificates[name] = names
            self.issue_certificate(name)
            return 0, "Successfully received certificate.\n", ""
        if command[:2] == ("certbot", "renew"):
            return 0, "Congratulations, all simulated renewals succeeded\n", ""
        return 1, "", "unsupported"

    def issue_certificate(self, name: str) -> None:
        live = f"/etc/letsencrypt/live/{name}"
        self.write(f"{live}/privkey.pem", f"golden stand-in key for {name}\n", 0o600)
        for item in ("cert.pem", "chain.pem", "fullchain.pem"):
            self.write(f"{live}/{item}", f"golden stand-in certificate for {name}\n")
        self.path(f"/etc/letsencrypt/archive/{name}").mkdir(parents=True, exist_ok=True)
        self.write(f"/etc/letsencrypt/renewal/{name}.conf", "authenticator = webroot\n")

    def _openssl(self, command: tuple[str, ...]) -> tuple[int, str, str]:
        if command[:2] == ("openssl", "x509"):
            source = Path(command[command.index("-in") + 1])
            lineage = source.parent.name
            if not self.path(str(source)).is_file():
                return 1, "", "Could not open file"
            if "-checkend" in command:
                return 0, "Certificate will not expire\n", ""
            if "-pubkey" in command:
                return 0, "GOLDEN-PUBLIC-KEY\n", ""
            names = self.certificates.get(lineage, (lineage,))
            sans = ", ".join(f"DNS:{name}" for name in names)
            dates = "notBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Apr  1 00:00:00 2026 GMT\n"
            return 0, f"{dates}X509v3 Subject Alternative Name: \n    {sans}\n", ""
        if command[:2] == ("openssl", "pkey"):
            return 0, "GOLDEN-PUBLIC-KEY\n", ""
        if command[:2] == ("openssl", "verify"):
            return 0, "verified: OK\n", ""
        return 1, "", "unsupported"


WARP_VERSION = "2026.7.1377.0"
GOLDEN_PACKAGE_VERSIONS = {"certbot": "2.9.0-1"}


def source_tree(base: Path, *, stand_in_artifacts: bool) -> Path:
    """A release tree with real top-level files and stand-ins for the big source directories.

    Copied verbatim: the compose files, deploy/, probe/, docker/, the helper scripts and the
    release pins. The panel, the managers and the installer sources become one stand-in file each:
    Core copies them and hashes them, and stand-ins keep those hashes stable across commits.
    """
    tree = base / "source"
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    for name in sorted(REPO.glob("compose*.yaml")):
        shutil.copy2(name, tree / name.name)
    for name in ("uninstall.sh", "install.sh"):
        shutil.copy2(REPO / name, tree / name)
    (tree / "VERSION").write_text(RELEASE_VERSION + "\n")
    for directory in ("deploy", "probe", "docker"):
        shutil.copytree(REPO / directory, tree / directory, ignore=shutil.ignore_patterns("__pycache__", "node_modules"))
    (tree / "scripts").mkdir()
    for path in sorted((REPO / "scripts").iterdir()):
        if path.is_file():
            shutil.copy2(path, tree / "scripts" / path.name)
    (tree / "release").mkdir()
    for name in ("external-artifacts.json", "three-xui-layout-amd64.json"):
        shutil.copy2(REPO / "release" / name, tree / "release" / name)
    for directory in ("installer", "mcp_server", "mieru_manager", "naive_manager", "panel",
                      "xray_router_manager", "awg_manager", "trusttunnel_manager", "pc_common"):
        (tree / directory).mkdir()
        (tree / directory / "GOLDEN-STAND-IN").write_text(f"golden stand-in for {directory}/\n")
    (tree / "version_agent").mkdir()
    for path in sorted((REPO / "version_agent").glob("*.py")):
        (tree / "version_agent" / path.name).write_text(f"# golden stand-in for version_agent/{path.name}\n")
    if stand_in_artifacts:
        install_stand_in_artifacts(tree)
    write_release_identity(tree)
    return tree


def write_release_identity(tree: Path) -> None:
    """`release/release.json` exactly as `release/build.py` stamps it."""
    from release import build

    components, artifacts = build._external_artifacts(tree)  # type: ignore[attr-defined]
    document = build._identity_document(  # type: ignore[attr-defined]
        version=RELEASE_VERSION,
        commit=RELEASE_COMMIT,
        manifest_sha256=RELEASE_MANIFEST_SHA256,
        components=components,
        artifacts=artifacts,
    )
    (tree / "release" / "release.json").write_bytes(build._canonical(document))  # type: ignore[attr-defined]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StandIns:
    """Small stand-in artifacts for the pinned downloads (an install never touches the network).

    The fixtures of an install therefore carry stand-in digests for Xray, mita/mieru and 3x-ui;
    the `plans/` fixtures keep the real pins.
    """

    XRAY_MEMBERS = {
        "xray": b"#!/bin/sh\n# golden stand-in xray\necho 'Xray 26.10.17 (Xray, Penetrates Everything.)'\n",
        "geoip.dat": b"golden stand-in geoip.dat\n",
        "geosite.dat": b"golden stand-in geosite.dat\n",
    }
    MITA_PACKAGE = b"golden stand-in mita_3.38.1_amd64.deb\n"
    MITA_BINARY = b"#!/bin/sh\n# golden stand-in mita\necho 'mita 3.38.1'\n"
    MIERU_PACKAGE = b"golden stand-in mieru_3.38.1_amd64.deb\n"
    MIERU_BINARY = b"#!/bin/sh\n# golden stand-in mieru\n"
    WARP_KEY = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ngolden stand-in key\n-----END PGP PUBLIC KEY BLOCK-----\n"
    WARP_PACKAGE = b"golden stand-in cloudflare-warp.deb\n"
    XUI_FILES = {
        "x-ui/x-ui": (b"#!/bin/sh\necho 'x-ui 3.10.2'\n", 0o755),
        "x-ui/x-ui.sh": (b"#!/bin/sh\n# golden stand-in\n", 0o644),
        "x-ui/x-ui.service.debian": (b"[Unit]\nDescription=x-ui Service\n[Service]\nWorkingDirectory=/usr/local/x-ui/\n"
                                     b"ExecStart=/usr/local/x-ui/x-ui\n[Install]\nWantedBy=multi-user.target\n", 0o644),
        "x-ui/bin/xray-linux-amd64": (b"#!/bin/sh\n# golden stand-in\n", 0o755),
        "x-ui/bin/geoip.dat": (b"golden stand-in geoip\n", 0o644),
        "x-ui/bin/geosite.dat": (b"golden stand-in geosite\n", 0o644),
    }

    @classmethod
    def xray_archive(cls) -> bytes:
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            for name, data in {**cls.XRAY_MEMBERS, "README.md": b"# never extracted\n"}.items():
                bundle.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data)
        return buffer.getvalue()

    @classmethod
    def xui_archive(cls) -> bytes:
        import gzip
        import tarfile

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as handle:
            def add(name: str, payload: bytes | None, mode: int) -> None:
                info = tarfile.TarInfo(name)
                info.mtime = FIXED_EPOCH
                info.mode = mode
                info.uname = info.gname = "root"
                if payload is None:
                    info.type = tarfile.DIRTYPE
                    handle.addfile(info)
                else:
                    info.size = len(payload)
                    handle.addfile(info, io.BytesIO(payload))

            add("x-ui", None, 0o755)
            add("x-ui/bin", None, 0o755)
            for name, (payload, mode) in cls.XUI_FILES.items():
                add(name, payload, mode)
        return gzip.compress(raw.getvalue(), mtime=0)

    @classmethod
    def xui_layout(cls) -> dict[str, object]:
        entries: list[dict[str, object]] = [
            {"kind": "directory", "mode": 0o755, "path": "x-ui"},
            {"kind": "directory", "mode": 0o755, "path": "x-ui/bin"},
        ]
        for name, (payload, mode) in cls.XUI_FILES.items():
            entries.append({"kind": "file", "mode": mode, "path": name, "sha256": _sha(payload)})
        return {"archive_sha256": _sha(cls.xui_archive()), "entries": entries, "version": "3.10.2"}


def install_stand_in_artifacts(tree: Path) -> None:
    """Point the tree's release pins at the stand-ins (and the 3x-ui layout at its archive)."""
    path = tree / "release" / "external-artifacts.json"
    document = json.loads(path.read_text())
    for entry in document["artifacts"]:
        pin = entry["platforms"]["amd64"]
        if entry["name"] == "xray":
            pin["sha256"] = _sha(StandIns.xray_archive())
            for member, data in StandIns.XRAY_MEMBERS.items():
                pin["members"][member]["sha256"] = _sha(data)
                pin["members"][member]["size"] = len(data)
        elif entry["name"] == "mita":
            pin["sha256"] = _sha(StandIns.MITA_PACKAGE)
            pin["executable_sha256"] = _sha(StandIns.MITA_BINARY)
        elif entry["name"] == "mieru":
            pin["sha256"] = _sha(StandIns.MIERU_PACKAGE)
            pin["executable_sha256"] = _sha(StandIns.MIERU_BINARY)
        elif entry["name"] == "three_xui":
            pin["sha256"] = _sha(StandIns.xui_archive())
    path.write_text(json.dumps(document, indent=2) + "\n")
    (tree / "release" / "three-xui-layout-amd64.json").write_text(json.dumps(StandIns.xui_layout(), indent=2) + "\n")


@contextlib.contextmanager
def stand_in_pins() -> Iterator[None]:
    """Patch the adapters' compiled-in pins to the stand-ins for the duration of an install."""
    from types import MappingProxyType

    from installer.adapters import mieru, warp, xray_router
    from installer.release import MemberPin

    saved = (xray_router._XRAY_PINS, mieru._MITA_PINS, mieru._MIERU_CLIENT_PINS, warp.KEY_SHA256, warp.PACKAGE_SHA256)
    url, _digest, _members = xray_router._XRAY_PINS["amd64"]
    xray_router._XRAY_PINS = MappingProxyType({"amd64": (url, _sha(StandIns.xray_archive()), MappingProxyType({
        name: MemberPin(_sha(data), len(data), 0o755 if name == "xray" else 0o644)
        for name, data in StandIns.XRAY_MEMBERS.items()
    }))})
    mieru._MITA_PINS = MappingProxyType({"amd64": (
        mieru._MITA_PINS["amd64"][0], _sha(StandIns.MITA_PACKAGE), _sha(StandIns.MITA_BINARY))})
    mieru._MIERU_CLIENT_PINS = MappingProxyType({"amd64": (
        mieru._MIERU_CLIENT_PINS["amd64"][0], _sha(StandIns.MIERU_PACKAGE), _sha(StandIns.MIERU_BINARY))})
    warp.KEY_SHA256 = _sha(StandIns.WARP_KEY)
    warp.PACKAGE_SHA256 = _sha(StandIns.WARP_PACKAGE)
    try:
        yield
    finally:
        (xray_router._XRAY_PINS, mieru._MITA_PINS, mieru._MIERU_CLIENT_PINS, warp.KEY_SHA256,
         warp.PACKAGE_SHA256) = saved


def facts_for(host: SimHost, config) -> Any:
    from installer.audit import audit_host

    return audit_host(config, host.command_runner())


# --------------------------------------------------------------------------------------------
# (1) plan.json and digest for every example
# --------------------------------------------------------------------------------------------

EXTRA_CONFIGS: dict[str, str] = {
    # Everything at once: WARP, the router with the relay and lane slots, MCP, a subscription
    # domain, AmneziaWG on host-derived ports and TrustTunnel, on a fresh host with UFW.
    "kitchen-sink": "\n".join([
        "schema = 1", 'host_mode = "fresh"', 'profile = "full"', 'acme_email = "admin@example.com"',
        'initial_user = "owner"', "",
        "[domains]", 'panel = "panel.example.com"', 'mtproxy = "relay.example.com"', 'naive = "edge.example.com"',
        'mieru = "mieru.example.com"', 'subscription = "sub.example.com"', 'mcp = "mcp.example.com"',
        'trusttunnel = "gate.example.org"', "",
        "[mieru]", "tcp_ports = [46001, 46003]", "udp_ports = [46002]", "",
        "[egress]", "warp = true", "router = true", 'naive = "router"', 'mieru = "warp"', "",
        "[amneziawg]", "enabled = true", 'versions = ["1.5", "2.0", "3.1"]', "",
        "[trusttunnel]", "enabled = true", "",
        "[three_xui]", 'mode = "none"', "",
        "[firewall]", "manage_ufw = true", "",
    ]),
    # A coexisting host whose frontend speaks PROXY protocol to a loopback bridge.
    "coexist-ingress": "\n".join([
        "schema = 1", 'host_mode = "coexist"', 'profile = "core-naive"', 'acme_email = "admin@example.com"',
        'initial_user = "owner"', "",
        "[domains]", 'panel = "panel.example.com"', 'mtproxy = "relay.example.com"', 'naive = "edge.example.com"', "",
        "[ingress]", 'proxy_protocol_bridge = "127.0.0.1:10444"', "panel_tls_port = 9443", "",
        "[three_xui]", 'mode = "none"', "",
        "[firewall]", "manage_ufw = false", "",
    ]),
}


def example_configs() -> list[tuple[str, str]]:
    found = [(path.stem, path.read_text(encoding="utf-8")) for path in sorted((REPO / "examples/installer").glob("*.toml"))]
    return found + sorted(EXTRA_CONFIGS.items())


def host_for(name: str, text: str, root: Path) -> SimHost:
    coexist = 'host_mode = "coexist"' in text
    existing = 'mode = "existing"' in text
    host = SimHost(root, coexist=coexist, existing_xui=existing)
    if name == "coexist-ingress":
        host.listeners.append(("tcp", "127.0.0.1", 10444, "haproxy"))
    return host


class PlanServices:
    """The CLI composition (`installer.cli.CliServices`) bound to one simulated host."""

    def __init__(self, host: SimHost, tree: Path, runners: Mapping[str, object] | None = None) -> None:
        from installer.transaction import TransactionEngine, TransactionStore

        self.host = host
        self.tree = tree
        self.runners = dict(runners or {})
        self.store = TransactionStore(host.root)
        self.engine = TransactionEngine(self.store, {})

    def adapters(self, config) -> tuple[object, ...]:
        from installer.planner import adapters_for

        return adapters_for(config, **build_adapters(self.host, self.tree, self.runners, config))

    def services(self):
        from installer.cli import CliServices, release_identity
        from installer.planner import build_plan
        from installer.wizard import TerminalWizard

        host = self.host

        def audit(config):
            from installer.planner import AuditFacts

            return AuditFacts() if config is None else facts_for(host, config)

        def plan(config, facts):
            adapters = self.adapters(config)
            self.engine.adapters.update({adapter.name: adapter for adapter in adapters})
            return build_plan(config, facts, adapters, release_identity(self.tree))

        return CliServices(
            audit=audit,
            plan=plan,
            engine=self.engine,
            store=self.store,
            wizard=lambda io_, locale, output: TerminalWizard(
                io_, locale=locale, config_output=output, root=host.root, language_fixed=locale is not None
            ),
        )


def build_adapters(host: SimHost, tree: Path, runners: Mapping[str, object], config) -> dict[str, object]:
    """Every adapter bound to the simulated root; protocol adapters get their fake runners."""
    from installer.adapters.amneziawg import AmneziaWgAdapter
    from installer.adapters.core import CoreAdapter
    from installer.adapters.firewall import FirewallAdapter
    from installer.adapters.mcp import McpAdapter
    from installer.adapters.mieru import MieruAdapter
    from installer.adapters.naive import NaiveAdapter
    from installer.adapters.nginx import CertificatePlan, NginxAdapter
    from installer.adapters.packages import PackagesAdapter
    from installer.adapters.three_xui import ThreeXuiAdapter
    from installer.adapters.trusttunnel import TrustTunnelAdapter
    from installer.adapters.version_agent import VersionAgentAdapter
    from installer.adapters.warp import WarpAdapter
    from installer.adapters.xray_router import XrayRouterAdapter

    root = host.root

    def runner(name: str, default: object) -> object:
        return runners.get(name, default)

    three_xui = ThreeXuiAdapter(
        root=root, source_dir=tree, runner=runner("three_xui", PlanOnlyRunner(host)),
        web_path="/golden-web-path/", api_factory=runners.get("three_xui_api"),
    )
    return {
        "packages": PackagesAdapter(runner=runner("packages", host.command_runner(900.0))),
        "nginx": NginxAdapter(root=root, runner=runner("nginx", host.command_runner()), three_xui=three_xui),
        "certificates": CertificatePlan(root=root, runner=runner("certificates", host.command_runner(600.0))),
        "firewall": FirewallAdapter(runner=runner("firewall", host.command_runner(30.0))),
        "core": CoreAdapter(root=root, source_dir=tree, runner=runner("core", PlanOnlyRunner(host))),
        "warp": WarpAdapter(root=root, runner=runner("warp", host.command_runner(900.0))),
        "xray_router": XrayRouterAdapter(root=root, source_dir=tree, runner=runner("xray_router", PlanOnlyRunner(host))),
        "naive": NaiveAdapter(root=root, source_dir=tree, runner=runner("naive", PlanOnlyRunner(host))),
        "mieru": MieruAdapter(root=root, source_dir=tree, runner=runner("mieru", PlanOnlyRunner(host))),
        "three_xui": three_xui,
        "amneziawg": AmneziaWgAdapter(root=root, runner=runner("amneziawg", PlanOnlyRunner(host))),
        "trusttunnel": TrustTunnelAdapter(root=root, runner=runner("trusttunnel", PlanOnlyRunner(host))),
        "mcp": McpAdapter(root=root, runner=runner("mcp", PlanOnlyRunner(host))),
        "version_agent": VersionAgentAdapter(root=root, source_dir=tree, runner=runner("version_agent", PlanOnlyRunner(host))),
    }


class PlanOnlyRunner:
    """A runner for planning: planning must never run a command, so any call is an error."""

    def __init__(self, host: SimHost) -> None:
        self.host = host

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)

    def run(self, argv, **_kwargs):
        raise AssertionError(f"planning ran a command: {tuple(argv)}")


def record_plans(out: Output) -> None:
    from installer import cli
    from installer.config import parse_config

    tree = source_tree(WORK_BASE / "plans", stand_in_artifacts=False)
    summary = {}
    for name, text in example_configs():
        DET.reset(f"plan:{name}")
        root = WORK_BASE / "plans" / name / "root"
        host = host_for(name, text, root)
        config_path = WORK_BASE / "plans" / name / "config.toml"
        config_path.write_text(text, encoding="utf-8")
        composition = PlanServices(host, tree)
        services = composition.services()
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.run(["--root", str(root), "plan", "--config", str(config_path), "--json"],
                       services=services, stdout=stdout, stderr=stderr)
        if code != 0 or host.unexpected:
            raise RuntimeError(f"plan {name} failed: {stderr.getvalue()} unexpected={host.unexpected}")
        text_out = io.StringIO()
        cli.run(["--root", str(root), "plan", "--config", str(config_path)], services=composition.services(),
                stdout=text_out, stderr=stderr)
        document = json.loads(stdout.getvalue())
        digest = document.pop("digest")
        # The canonical bytes and both digests, straight from the planner.
        config = parse_config(text)
        facts = facts_for(host, config)
        from installer.awg_ports import resolve_awg_ports

        resolved = resolve_awg_ports(config, root=root, listeners=facts.listeners)
        plan = composition.services().plan(resolved, facts)
        if plan.digest != digest:
            raise RuntimeError(f"plan {name}: CLI and planner digests differ")
        base = f"plans/{name}"
        if name in EXTRA_CONFIGS:
            out.text(f"{base}/config.toml", text)
        out.bytes(f"{base}/plan.json", plan.to_canonical_json())
        out.text(f"{base}/plan-cli.json", stdout.getvalue())
        out.text(f"{base}/plan-cli.txt", text_out.getvalue())
        out.text(f"{base}/digest", digest + "\n")
        out.json(f"{base}/digests.json", {
            "intent_digest": plan.intent_digest,
            "plan_digest": plan.digest,
            "sha256_of_plan_json": hashlib.sha256(plan.to_canonical_json()).hexdigest(),
        })
        out.json(f"{base}/audit-commands.json", [list(call) for call in host.calls])
        summary[name] = {"config": f"examples/installer/{name}.toml" if name not in EXTRA_CONFIGS else f"{base}/config.toml",
                         "digest": digest, "actions": [action.id for action in plan.actions]}
    out.json("plans/index.json", {
        "release_json": json.loads((tree / "release" / "release.json").read_text()),
        "host": {"ipv4": HOST_V4, "ipv6": HOST_V6, "machine_id": MACHINE_ID},
        "plans": summary,
    })
    out.bytes("plans/release.json", (tree / "release" / "release.json").read_bytes())


# --------------------------------------------------------------------------------------------
# (2) A fake-runner install of every profile: the installer journal and the host it leaves
# --------------------------------------------------------------------------------------------


def install_runners(host: SimHost) -> dict[str, object]:
    """Fake runners for the protocol adapters, built on the fakes the unit tests use."""
    import socket as socket_module

    from tests import test_installer_amneziawg as awg_tests
    from tests import test_installer_core as core_tests
    from tests import test_installer_mcp as mcp_tests
    from tests import test_installer_mieru as mieru_tests
    from tests import test_installer_naive as naive_tests
    from tests import test_installer_three_xui as xui_tests
    from tests import test_installer_trusttunnel as tt_tests
    from tests import test_installer_version_agent as agent_tests
    from tests import test_installer_xray_router as xray_tests

    class Recording:
        """Mixin: every argv also lands in the host's call log."""

        def _log(self, argv) -> None:
            host.calls.append(tuple(str(part) for part in argv))

    class CoreRunner(core_tests.FakeRunner, Recording):
        def run(self, argv, *, stdin_path=None, env=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path, env=env)

    class NaiveRunner(naive_tests.FakeNaiveRunner, Recording):
        def run(self, argv, *, stdin_path=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path)

    class MieruRunner(mieru_tests.FakeMieruRunner, Recording):
        def run(self, argv, *, stdin_path=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path)

        def fetch_artifact(self, url, destination):
            data = StandIns.MIERU_PACKAGE if "/mieru_" in str(url) else StandIns.MITA_PACKAGE
            Path(destination).write_bytes(data)

        def dpkg_extract(self, package, destination):
            client = Path(package).name.startswith("mieru_")
            binary = Path(destination) / "usr/bin" / ("mieru" if client else "mita")
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(StandIns.MIERU_BINARY if client else StandIns.MITA_BINARY)
            self.extracted.append(str(package))

        def mita_slot_status(self, socket_path):
            from installer.adapters import mieru as mieru_module

            del socket_path
            return mieru_module._IDLE

    class XrayRunner(xray_tests.FakeRunner, Recording):
        def run(self, argv, *, stdin_path=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path)

        def fetch_artifact(self, url, destination):
            del url
            Path(destination).write_bytes(StandIns.xray_archive())

        relay = {"enabled": False, "port": None, "server_name": None, "public_key": None, "short_ids": [],
                 "accounts": 0}

        def router_relay_enable(self, server_name, port):
            self.relay = {**self.relay, "enabled": True, "port": port, "server_name": server_name,
                          "public_key": "golden-stand-in-relay-public-key", "short_ids": ["0123abcd"]}
            return dict(self.relay)

        def router_relay(self):
            return dict(self.relay)

        def public_listener(self, port):
            return port == self.relay["port"]

    class AwgRunner(awg_tests.FakeRunner, Recording):
        def run(self, argv, *, stdin_path=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path)

        def manager_health(self):
            env = host.path("/opt/mtproxy-shared443/.env.amneziawg").read_text()
            values = dict(line.split("=", 1) for line in env.splitlines() if "=" in line)
            ports = dict(item.split("=", 1) for item in values["AWG_PORTS"].split(","))
            return {
                "status": "ok",
                "ip_forward": True,
                "instances": {
                    version: {"interface": "awg" + version.replace(".", ""), "running": True,
                              "port": int(port), "peers": 0}
                    for version, port in ports.items()
                },
            }

    class TrustTunnelRunner(tt_tests.FakeRunner, Recording):
        def run(self, argv, *, stdin_path=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path)

    class McpRunner(mcp_tests.FakeRunner, Recording):
        pass

    class AgentRunner(agent_tests.FakeRunner, Recording):
        listener = None

        def run(self, argv, *, stdin_path=None):
            command = tuple(str(part) for part in argv)
            self._log(command)
            super().run(argv, stdin_path=stdin_path)
            if command[:2] in {("systemctl", "enable"), ("systemctl", "restart")} and "version-agent" in command[-1]:
                path = host.path("/run/proxy-control/version-agent.sock")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.unlink(missing_ok=True)
                listener = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
                listener.bind(str(path))
                os.chmod(path, 0o660)
                AgentRunner.listener = listener

        def capture(self, argv, *, max_chars):
            command = tuple(str(value) for value in argv)
            if command[0] == "curl" and command[-1].endswith("/v1/versions"):
                state = json.loads(host.path("/var/lib/proxy-control/version-agent/state.json").read_text())
                self.versions["components"] = {
                    name: {"current": entry.get("version"), "status": "ready", "available": []}
                    for name, entry in state.get("components", {}).items()
                }
            return super().capture(argv, max_chars=max_chars)

    class XuiRunner(xui_tests.FakeThreeXuiRunner, Recording):
        def run(self, argv, *, stdin_path=None):
            self._log(argv)
            return super().run(argv, stdin_path=stdin_path)

        def fetch_artifact(self, url, destination):
            del url
            Path(destination).write_bytes(StandIns.xui_archive())

        def reality_keypair(self, xray_binary):
            del xray_binary
            return ("golden-stand-in-reality-private-key-0000000", "golden-stand-in-reality-public-key-00000000")

    class XuiApi(xui_tests.RecordingApi):
        def configure_subscription(self, domain, *, certificate, private_key):
            self.subscription = {"domain": domain, "certificate": certificate, "private_key": private_key}

        def configure_warp(self, config):
            self.warp = config.three_xui.warp_domains

    api = XuiApi()
    return {
        "core": CoreRunner(),
        "naive": NaiveRunner(),
        "mieru": MieruRunner(),
        "xray_router": XrayRunner(),
        "amneziawg": AwgRunner(),
        "trusttunnel": TrustTunnelRunner(),
        "mcp": McpRunner(),
        "version_agent": AgentRunner(),
        "three_xui": XuiRunner(),
        "three_xui_api": lambda _port, _path="/": api,
    }


def add_warp_commands(host: SimHost) -> None:
    """WARP's own programs: curl for the key and the package, warp-cli, its listener."""
    original = host._handler
    warp_state = {"registered": False, "connected": False}

    def handler(command):
        found = original(command)
        if command[0] == "curl":
            return lambda c: _warp_curl(host, c)
        if command[0] == "warp-cli":
            def answer(c):
                args = c[2:]
                if args[:2] == ("registration", "show"):
                    return (0, "Account type: Free\n", "") if warp_state["registered"] else (1, "", "Missing registration")
                if args[:2] == ("registration", "new"):
                    warp_state["registered"] = True
                    return 0, "Success\n", ""
                if args[:1] == ("connect",):
                    warp_state["connected"] = True
                    host.listeners.append(("tcp", "127.0.0.1", 40000, "warp-svc"))
                    return 0, "Success\n", ""
                if args[:1] == ("status",):
                    return 0, "Status update: Connected\nNetwork: healthy\n", ""
                return 0, "Success\n", ""
            return answer
        if command[0] == "systemctl" and len(command) > 2 and command[1] == "is-enabled":
            return lambda c: (0, "enabled\n", "")
        if command[0] == "systemctl" and len(command) > 3 and command[1:3] == ("enable", "--now"):
            def enable(c):
                host.active_units.add(c[-1])
                return 0, "", ""
            return enable
        if command[0] == "dpkg":
            return lambda c: (0, "", "")
        return found

    host._handler = handler  # type: ignore[method-assign]


def _warp_curl(host: SimHost, command: tuple[str, ...]) -> tuple[int, str, str]:
    if "--output" in command:
        target = Path(command[command.index("--output") + 1])
        target.write_bytes(StandIns.WARP_KEY if command[-1].endswith("pubkey.gpg") else StandIns.WARP_PACKAGE)
        return 0, "", ""
    if command[-1].endswith("/cdn-cgi/trace"):
        if "--socks5-hostname" in command:
            return 0, "fl=golden\nip=198.51.100.7\nwarp=on\n", ""
        return 0, f"fl=golden\nip={HOST_V4}\nwarp=off\n", ""
    return 1, "", "unsupported"


def snapshot_root(out: Output, base: str, host: SimHost, tree: Path) -> None:
    """Every path the install left under the root; text files up to 64 KiB verbatim."""
    sources = {}
    for path in tree.rglob("*"):
        if path.is_file():
            sources.setdefault(_sha(path.read_bytes()), path.relative_to(tree).as_posix())
    entries, contents = snapshot_tree(host.root, skip=("/dev", "/tmp"))
    for absolute, data in contents.items():
        entry = entries[absolute]
        digest = entry["sha256"]  # type: ignore[index]
        if digest in sources and absolute.startswith(("/opt/", "/usr/", "/etc/systemd", "/etc/tmpfiles.d")):
            entry["copy_of_source"] = sources[digest]  # type: ignore[index]
            continue
        if len(data) > 65536 or b"\x00" in data or absolute.startswith("/var/lib/proxy-control/installer/"):
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        out.bytes(f"{base}/files{absolute}", data)
    out.json(f"{base}/tree.json", entries)


@dataclasses.dataclass
class InstallRun:
    name: str
    work: Path
    tree: Path
    root: Path
    host: SimHost
    composition: PlanServices
    config_path: Path
    digest: str
    code: int | None
    stdout: str
    stderr: str
    error: BaseException | None


class InjectedCrash(BaseException):
    """A process death in the middle of an action (what a kill leaves on disk)."""


def perform_install(
    name: str,
    text: str,
    *,
    seed: str,
    tweak: Callable[[dict[str, object]], None] | None = None,
    version: str = RELEASE_VERSION,
    expect_success: bool = True,
) -> InstallRun:
    """`plan --json` then `install --accept-plan` through the real CLI on a fresh simulated host."""
    from installer import cli

    DET.reset(seed)
    work = WORK_BASE / "runs" / seed.replace(":", "-")
    if work.exists():
        shutil.rmtree(work)
    tree = source_tree(work, stand_in_artifacts=True)
    (tree / "VERSION").write_text(version + "\n")
    root = work / "root"
    host = host_for(name, text, root)
    add_warp_commands(host)
    config_path = work / "config.toml"
    config_path.write_text(text, encoding="utf-8")
    runners = install_runners(host)
    if tweak is not None:
        tweak(runners)
    error: BaseException | None = None
    with stand_in_pins():
        composition = PlanServices(host, tree, runners)
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.run(["--root", str(root), "plan", "--config", str(config_path), "--json"],
                       services=composition.services(), stdout=stdout, stderr=stderr)
        if code != 0:
            raise RuntimeError(f"install plan {name}: {stderr.getvalue()}")
        digest = json.loads(stdout.getvalue())["digest"]
        host.calls.clear()
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            code = cli.run(["--root", str(root), "install", "--config", str(config_path), "--accept-plan", digest,
                            "--json"], services=composition.services(), stdout=stdout, stderr=stderr)
        except (Exception, InjectedCrash) as exc:  # noqa: BLE001 - the failure is the fixture
            if expect_success:
                for call in host.calls[-20:]:
                    print("  call:", " ".join(call), flush=True)
                raise
            code, error = None, exc
    if expect_success and (code != 0 or host.unexpected):
        state = root / "var/lib/proxy-control/installer/state.json"
        raise RuntimeError(
            f"install {name} failed ({code}): {stderr.getvalue()}\nunexpected={host.unexpected}\n"
            + (state.read_text() if state.exists() else "")
        )
    return InstallRun(name, work, tree, root, host, composition, config_path, digest, code, stdout.getvalue(),
                      stderr.getvalue(), error)


def sanitize_paths(value: object, run: InstallRun) -> object:
    """Replace the throwaway root and work paths so the fixture does not depend on them."""
    text = json.dumps(value, ensure_ascii=False)
    text = text.replace(str(run.root), "<root>").replace(str(run.work), "<work>")
    text = text.replace(str(WORK_BASE / "tmp"), "<tmp>")
    return json.loads(text)


def record_journal(out: Output, base: str, root: Path) -> None:
    journal = root / "var/lib/proxy-control/installer"
    for item in ("state.json", "plan.json", "ownership.json", "report.json"):
        path = journal / item
        if path.exists():
            out.bytes(f"{base}/{item}", path.read_bytes())
    out.json(f"{base}/modes.json", {
        (path.relative_to(journal).as_posix() if path != journal else "."): f"{stat.S_IMODE(path.stat().st_mode):04o}"
        for path in sorted([journal, *journal.rglob("*")])
    })


def cli_capture(run: InstallRun, *arguments: str) -> tuple[int | None, str, str]:
    from installer import cli

    stdout, stderr = io.StringIO(), io.StringIO()
    with stand_in_pins():
        try:
            code: int | None = cli.run(["--root", str(run.root), *arguments], services=run.composition.services(),
                                       stdout=stdout, stderr=stderr)
        except (Exception, InjectedCrash) as exc:  # noqa: BLE001
            code = None
            stderr.write(f"{type(exc).__name__}: {exc}\n")
    return code, stdout.getvalue(), stderr.getvalue()


def record_installs(out: Output) -> None:
    for name, text in example_configs():
        if name == "coexist-ingress":
            continue
        run = perform_install(name, text, seed=f"install:{name}")
        base = f"installs/{name}"
        record_journal(out, f"{base}/journal", run.root)
        out.text(f"{base}/install-stdout.json", run.stdout)
        out.text(f"{base}/digest", run.digest + "\n")
        _code, status, _ = cli_capture(run, "status", "--json")
        out.text(f"{base}/status.json", status)
        _code, status_text, _ = cli_capture(run, "status")
        out.text(f"{base}/status.txt", status_text)
        report_dir = run.work / "report"
        code, report_out, report_err = cli_capture(run, "report", "--config", str(run.config_path), "--output",
                                                   str(report_dir), "--json")
        if code != 0:
            raise RuntimeError(f"report {name} failed: {report_err}")
        out.text(f"{base}/report/stdout.json", report_out.replace(str(report_dir), "<output>"))
        for produced in sorted(report_dir.rglob("*")):
            if produced.is_file():
                out.bytes(f"{base}/report/{produced.relative_to(report_dir).as_posix()}", produced.read_bytes())
        out.json(f"{base}/report/modes.json", {
            produced.relative_to(report_dir).as_posix(): f"{stat.S_IMODE(produced.stat().st_mode):04o}"
            for produced in sorted(report_dir.rglob("*"))
        })
        out.json(f"{base}/commands.json", sanitize_paths([list(call) for call in run.host.calls], run))
        snapshot_root(out, f"{base}/root", run.host, run.tree)


# --------------------------------------------------------------------------------------------
# (3) a handoff-committed journal, (10) a journal shaped like `home`, and the other lifecycles
# --------------------------------------------------------------------------------------------

PANEL_SYNC_STAND_INS = ("panel", "installer", "pc_common", "compose.yaml", "VERSION")


def panel_update(run: InstallRun, version: str, generation: int) -> dict[str, object]:
    """What a version-agent panel update does to the installer journal (service.py:1111-1182).

    The staged tree is a release whose stand-in sources changed; the files are moved and copied
    exactly as `_sync_and_restart_panel_locked` does, and `PanelOwnershipHandoff` rebases Core's
    and the agent's ownership. Docker steps are irrelevant to the journal and are skipped.
    """
    from installer import transaction

    staging = run.work / f"staging-{generation}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for name in PANEL_SYNC_STAND_INS:
        source = run.tree / name
        if source.is_dir():
            shutil.copytree(source, staging / name)
        else:
            shutil.copy2(source, staging / name)
    (staging / "VERSION").write_text(version + "\n")
    (staging / "panel" / "GOLDEN-STAND-IN").write_text(f"golden stand-in for panel/ (release {version})\n")
    (staging / "panel" / f"added-in-{version}.txt").write_text(f"a file new in {version}\n")
    shutil.copytree(run.tree / "version_agent", staging / "version_agent")
    (staging / "version_agent" / "service.py").write_text(f"# golden stand-in for version_agent/service.py ({version})\n")
    project = run.root / "opt/mtproxy-shared443"
    agent_dir = run.root / "opt/proxy-control"
    names = tuple(name for name in PANEL_SYNC_STAND_INS)
    store = transaction.TransactionStore(run.root)
    with transaction.operation_lock(run.root):
        handoff = transaction.PanelOwnershipHandoff(store, project, staging, names, agent_dir=agent_dir)
        handoff.prepare()
        backup = run.work / f"panel.previous-{generation}"
        backup.mkdir()
        targets = {name: project / name for name in names}
        targets["version_agent"] = agent_dir / "version_agent"
        for name, target in targets.items():
            if target.exists():
                shutil.move(str(target), str(backup / name))
            source = staging / name
            if source.is_dir():
                shutil.copytree(source, target, symlinks=False)
            else:
                shutil.copy2(source, target)
        handoff.commit()
    return {"names": [*names, "version_agent"], "version": version}


def record_journals(out: Output) -> None:
    from installer import transaction

    texts = dict(example_configs())

    # (3) handoff: the kitchen-sink host after one panel update.
    run = perform_install("kitchen-sink", texts["kitchen-sink"], seed="journal:handoff")
    record_journal(out, "journals/handoff/before", run.root)
    performed = panel_update(run, "3.3.1", 1)
    record_journal(out, "journals/handoff/after", run.root)
    out.json("journals/handoff/update.json", performed)

    # (10) shaped like the `home` production host: a fresh `full` install (NaiveProxy, Mieru and
    # AmneziaWG, no router, no WARP, UFW managed) made by an older release, then rebased by two
    # panel updates. Inferred from the code only; see the README for the assumptions.
    home = "\n".join([
        "schema = 1", 'host_mode = "fresh"', 'profile = "full"', 'acme_email = "admin@example.com"',
        'initial_user = "owner"', "",
        "[domains]", 'panel = "panel.example.com"', 'mtproxy = "relay.example.com"', 'naive = "edge.example.com"',
        'mieru = "mieru.example.com"', "",
        "[mieru]", "tcp_ports = [46001]", "udp_ports = [46001]", "",
        "[amneziawg]", "enabled = true", "",
        "[three_xui]", 'mode = "none"', "",
        "[firewall]", "manage_ufw = true", "",
    ])
    run = perform_install("home-like", home, seed="journal:home", version="3.2.0")
    out.text("journals/home-like/config.toml", home)
    record_journal(out, "journals/home-like/installed", run.root)
    panel_update(run, "3.2.1", 1)
    panel_update(run, "3.3.0", 2)
    record_journal(out, "journals/home-like/journal", run.root)
    state = json.loads((run.root / "var/lib/proxy-control/installer/state.json").read_text())
    out.json("journals/home-like/summary.json", {
        "checkpoints": [[item["action_id"], item["phase"]] for item in state["checkpoints"]],
        "origin": state["origin"],
        "schema": state["schema"],
        "status": state["status"],
    })

    # A failed verification: the engine rolls the whole install back and purges (status rolled_back).
    def failing_core(runners: dict[str, object]) -> None:
        runners["core"].respq = False  # type: ignore[attr-defined]

    run = perform_install("core", texts["core"], seed="journal:failed", tweak=failing_core, expect_success=False)
    record_journal(out, "journals/rolled-back", run.root)
    out.json("journals/rolled-back/outcome.json", {"exception": type(run.error).__name__, "message": str(run.error),
                                                   "stderr": run.stderr})

    # A crash in the middle of an action: state `applying`, then `resume` finishes it.
    def crashing_mieru(runners: dict[str, object]) -> None:
        mieru_runner = runners["mieru"]
        original = mieru_runner.run  # type: ignore[attr-defined]
        crashed = {"done": False}

        def run_once(argv, *, stdin_path=None):
            if not crashed["done"] and tuple(str(part) for part in argv[:3]) == ("systemctl", "enable", "--now"):
                crashed["done"] = True
                raise InjectedCrash("injected crash")
            return original(argv, stdin_path=stdin_path)

        mieru_runner.run = run_once  # type: ignore[attr-defined]

    run = perform_install("core-mieru", texts["core-mieru"], seed="journal:interrupted", tweak=crashing_mieru,
                          expect_success=False)
    record_journal(out, "journals/interrupted/applying", run.root)
    code, stdout, stderr = cli_capture(run, "resume", "--json")
    out.json("journals/interrupted/resume.json", {"exit": code, "stdout": stdout, "stderr": stderr})
    record_journal(out, "journals/interrupted/resumed", run.root)

    # Repair of an active install, then uninstall (keeping data); a second install's uninstall --purge-data.
    run = perform_install("core-naive", texts["core-naive"], seed="journal:lifecycle")
    code, stdout, stderr = cli_capture(run, "repair", "--json")
    out.json("journals/repaired/repair.json", {"exit": code, "stdout": stdout, "stderr": stderr})
    record_journal(out, "journals/repaired", run.root)
    code, stdout, stderr = cli_capture(run, "uninstall", "--json")
    out.json("journals/uninstalled/uninstall.json", {"exit": code, "stdout": stdout, "stderr": stderr})
    record_journal(out, "journals/uninstalled", run.root)
    entries, _ = snapshot_tree(run.root, skip=("/dev", "/tmp"))
    out.json("journals/uninstalled/tree-after.json", entries)

    run = perform_install("core", texts["core"], seed="journal:purge")
    code, stdout, stderr = cli_capture(run, "uninstall", "--purge-data", "--json")
    out.json("journals/uninstalled-purged/uninstall.json", {"exit": code, "stdout": stdout, "stderr": stderr})
    record_journal(out, "journals/uninstalled-purged", run.root)

    # The lock file and the busy message of a second holder.
    with transaction.operation_lock(run.root):
        try:
            with transaction.operation_lock(run.root):
                busy = "not busy"
        except transaction.TransactionError as exc:
            busy = f"{type(exc).__name__}: {exc}"
    lock = run.root / "run/lock/proxy-control.lock"
    out.json("journals/lock.json", {"busy": busy, "mode": f"{stat.S_IMODE(lock.stat().st_mode):04o}",
                                    "size": lock.stat().st_size})


# --------------------------------------------------------------------------------------------
# (4) every render, called directly: nginx, ACME, Core, protocol envs, agent env merge, 3x-ui
# --------------------------------------------------------------------------------------------

RENDER_CONFIGS: dict[str, str] = {
    "kitchen-sink": EXTRA_CONFIGS["kitchen-sink"],
    # The other egress assignment: NaiveProxy through WARP on a custom port, Mieru through the
    # router, the relay switched off, two lane slots.
    "egress-swapped": "\n".join([
        "schema = 1", 'host_mode = "fresh"', 'profile = "full"', 'acme_email = "admin@example.com"',
        'initial_user = "owner"', "",
        "[domains]", 'panel = "panel.example.com"', 'mtproxy = "relay.example.com"', 'naive = "edge.example.com"',
        'mieru = "mieru.example.com"', 'mcp = "mcp.example.com"', "",
        "[mieru]", "tcp_ports = [46001]", "udp_ports = [46002, 46003]", "lane_slots = 2", "",
        "[egress]", "warp = true", "warp_port = 40001", "router = true", "relay_port = 0", 'naive = "warp"',
        'mieru = "router"', "",
        "[amneziawg]", "enabled = true", 'versions = ["2.0"]', 'host = "203.0.113.10"', 'ports = { "2.0" = 20020 }',
        "mtu = 1420", 'dns = ["9.9.9.9", "2620:fe::fe"]', "",
        "[trusttunnel]", "enabled = true", "listen_port = 5443", "",
        "[three_xui]", 'mode = "none"', "",
        "[firewall]", "manage_ufw = false", "",
    ]).replace('mcp = "mcp.example.com"', 'mcp = "mcp.example.com"\ntrusttunnel = "gate.example.org"'),
    # Everything direct, nothing optional.
    "direct": "\n".join([
        "schema = 1", 'host_mode = "fresh"', 'profile = "full"', 'acme_email = "admin@example.com"',
        'initial_user = "owner"', "",
        "[domains]", 'panel = "panel.example.com"', 'mtproxy = "relay.example.com"', 'naive = "edge.example.com"',
        'mieru = "mieru.example.com"', "",
        "[mieru]", "tcp_ports = [46001]", "udp_ports = []", "",
        "[three_xui]", 'mode = "none"', "",
        "[firewall]", "manage_ufw = false", "",
    ]),
    "managed-three-xui": (REPO / "examples/installer/managed-three-xui.toml").read_text(encoding="utf-8"),
    "managed-three-xui-warp": (REPO / "examples/installer/managed-three-xui.toml").read_text(encoding="utf-8")
    .replace("warp = false", "warp = true").replace("warp_domains = []",
                                                   'warp_domains = ["geosite:openai", "domain:chat.example.org"]'),
    "existing-three-xui": (REPO / "examples/installer/existing-three-xui.toml").read_text(encoding="utf-8"),
    "coexist-ingress": EXTRA_CONFIGS["coexist-ingress"],
}


def planned(name: str, text: str) -> tuple[Any, dict[str, object], SimHost]:
    """The real-pin plan of one configuration and the adapters that made it."""
    from installer.awg_ports import resolve_awg_ports
    from installer.config import parse_config

    root = WORK_BASE / "renders" / name / "root"
    if root.exists():
        shutil.rmtree(root)
    host = host_for(name, text, root)
    tree = source_tree(WORK_BASE / "renders" / name, stand_in_artifacts=False)
    composition = PlanServices(host, tree)
    config = parse_config(text)
    facts = facts_for(host, config)
    config = resolve_awg_ports(config, root=root, listeners=facts.listeners)
    adapters = {adapter.name: adapter for adapter in composition.adapters(config)}
    plan = composition.services().plan(config, facts)
    return plan, adapters, host


def dataclass_strings(value: object) -> dict[str, object]:
    result: dict[str, object] = {}
    for field in dataclasses.fields(value):  # type: ignore[arg-type]
        item = getattr(value, field.name)
        if isinstance(item, Mapping):
            item = {str(key): (f"{val:04o}" if isinstance(val, int) else val) for key, val in item.items()}
        result[field.name] = item
    return result


def record_renders(out: Output) -> None:
    from installer.adapters import naive as naive_module
    from installer.adapters import nginx as nginx_module
    from installer.adapters.core import _mcp_vhost_text, _panel_vhost_text, _subscription_vhost_text

    for name, text in RENDER_CONFIGS.items():
        DET.reset(f"render:{name}")
        plan, adapters, _host = planned(name, text)
        base = f"renders/{name}"
        out.json(f"{base}/actions.json", [action.to_dict() for action in plan.actions])
        for action in plan.actions:
            adapter = adapters.get(action.adapter)
            if action.adapter == "nginx":
                specification = nginx_module._action_specification(action)
                out.json(f"{base}/nginx/specification.json", specification)
                if specification["mode"] == "fresh":
                    out.bytes(f"{base}/nginx/stream-router.conf", nginx_module._render_fresh(specification))
                    legacy = {key: value for key, value in specification.items() if key != "client_ip"}
                    out.bytes(f"{base}/nginx/stream-router.legacy.conf", nginx_module._render_fresh(legacy))
            elif action.adapter == "certificates":
                specification = nginx_module._certificate_action(action)
                out.bytes(f"{base}/acme/{specification['service']}.conf",
                          nginx_module._render_certificate_vhost(action, specification))
            elif action.adapter == "core":
                rendered = adapter.render(action)  # type: ignore[union-attr]
                fields = dataclass_strings(rendered)
                out.text(f"{base}/core/compose.yaml", str(fields.pop("compose_yaml")))
                out.text(f"{base}/core/env", str(fields.pop("env_text")))
                out.text(f"{base}/core/panel-vhost.conf", str(fields.pop("panel_vhost")))
                out.json(f"{base}/core/file-modes.json", fields["file_modes"])
            elif action.adapter == "naive":
                rendered = adapter.render(action)  # type: ignore[union-attr]
                fields = dataclass_strings(rendered)
                out.text(f"{base}/naive/Caddyfile.template", str(fields.pop("caddyfile_template")))
                out.text(f"{base}/naive/env", str(fields.pop("env_text")))
                out.text(f"{base}/naive/caddy-naive.service", str(fields.pop("unit_text")))
                out.text(f"{base}/naive/caddy-naive.pin", str(fields.pop("pin_text")))
                out.json(f"{base}/naive/file-modes.json", fields["file_modes"])
                selected = adapter._selection(action)  # type: ignore[union-attr]
                out.text(f"{base}/naive/deploy-hook", naive_module._deploy_hook_text(str(selected["naive_domain"])))
            elif action.adapter == "mieru":
                selected = adapter._selection(action)  # type: ignore[union-attr]
                out.text(f"{base}/mieru/env", adapter.env_text(selected, mita_gid=998))  # type: ignore[union-attr]
                document = adapter.bootstrap_config(  # type: ignore[union-attr]
                    selected, password="golden-bootstrap-password",
                    router_credential=("mieru-0011aabb", "golden-router-password"),
                )
                out.text(f"{base}/mieru/bootstrap-input.json", json.dumps(document, separators=(",", ":")) + "\n")
            elif action.adapter in {"trusttunnel", "amneziawg", "xray_router"}:
                selected = adapter._selection(action)  # type: ignore[union-attr]
                out.text(f"{base}/{action.adapter}/env", adapter.env_text(selected))  # type: ignore[union-attr]
            elif action.adapter == "version_agent":
                selected = adapter._selection(action)  # type: ignore[union-attr]
                for variant, existing in AGENT_ENV_EXISTING.items():
                    out.text(f"{base}/version-agent/env.{variant}", adapter.env_text(selected, existing))  # type: ignore[union-attr]
            elif action.adapter == "three_xui" and action.id == "three_xui.runtime":
                record_three_xui_bodies(out, f"{base}/three-xui", action, adapter)

    # Core vhosts with every argument the ingress upgrade feeds them.
    vhosts = {
        "panel": _panel_vhost_text(panel_domain="panel.example.com", certificate="relay.example.com", app_port=8787),
        "panel-tls-9443": _panel_vhost_text(panel_domain="panel.example.com", certificate="relay.example.com",
                                            app_port=8787, tls_port=9443),
        "subscription": _subscription_vhost_text(subscription_domain="sub.example.com",
                                                 certificate="relay.example.com", app_port=8787),
        "mcp": _mcp_vhost_text(mcp_domain="mcp.example.com", certificate="relay.example.com"),
        "mcp-port-9000": _mcp_vhost_text(mcp_domain="mcp.example.com", certificate="relay.example.com",
                                         mcp_port=9000, tls_port=9443),
    }
    for key, value in vhosts.items():
        out.text(f"renders/core-vhosts/{key}.conf", value)
    record_nginx_text_vectors(out)
    record_ingress_upgrade(out)


AGENT_ENV_EXISTING: dict[str, str] = {
    "fresh": "",
    # An operator's own keys survive; the installer's keys are reset; comments are dropped.
    "operator-keys": "\n".join([
        "# my notes",
        "PROXY_CONTROL_UPSTREAM_CHECK=off",
        "PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL=3600",
        "OPERATOR_EXTRA=value with spaces",
        "  INDENTED_KEY = spaced  ",
        "OPERATOR_EXTRA=second value",
        "#PROXY_CONTROL_PANEL_IMAGE=custom-image",
        "PROXY_CONTROL_PANEL_IMAGE=custom-image",
        "not an assignment",
        "",
    ]),
    "crlf": "OPERATOR_KEY=1\r\nPROXY_CONTROL_XRAY_ROUTER=on\r\n",
    "router-flag-only": "PROXY_CONTROL_XRAY_ROUTER=on\n",
}


def record_three_xui_bodies(out: Output, base: str, action: object, adapter: object) -> None:
    """The managed inbounds the adapter would add, as request bodies (secrets are seeded fakes)."""
    from installer.three_xui_api import SystemSecrets, build_managed_clients, build_managed_inbounds, warp_routing

    config = adapter._managed_config(action)  # type: ignore[attr-defined]
    generator = SystemSecrets(keypair=("golden-stand-in-reality-private-key-0000000",
                                       "golden-stand-in-reality-public-key-00000000"))
    templates = build_managed_inbounds(config, generator=generator)
    persistent = build_managed_clients(templates, generator=generator, prefix="initial",
                                       subscription_id="golden-subscription-id" if config.three_xui.subscription_domain else None)
    acceptance = build_managed_clients(templates, generator=generator, prefix="acceptance", acceptance=True)
    bodies = [
        inbound.with_clients([*inbound.clients, *extra.clients]).request_body()
        for inbound, extra in zip(persistent, acceptance, strict=True)
    ]
    out.json(f"{base}/add-inbound-bodies.json", bodies)
    out.json(f"{base}/managed-config.json", config.canonical_dict())
    out.json(f"{base}/warp-routing.json", warp_routing(config, existing_rules=[{"network": "tcp,udp", "outboundTag": "direct"}]))


def record_nginx_text_vectors(out: Output) -> None:
    from installer.adapters.nginx import TopologyError, ensure_stream_context, patch_owned_map, remove_owned_map_block

    work = WORK_BASE / "renders" / "stream-context"
    work.mkdir(parents=True, exist_ok=True)
    cases = {
        "stock": STOCK_NGINX_CONF,
        "no-trailing-newline": STOCK_NGINX_CONF.rstrip("\n"),
        "many-trailing-newlines": STOCK_NGINX_CONF + "\n\n\n",
        "already-streams": COEXIST_NGINX_CONF,
        "commented-stream": STOCK_NGINX_CONF + "# stream {\n",
        "indented-stream": STOCK_NGINX_CONF + "  stream{\n  }\n",
    }
    results = {}
    for key, text in cases.items():
        path = work / f"{key}.conf"
        path.write_text(text, encoding="utf-8")
        changed = ensure_stream_context(path, "/etc/nginx/stream.d/proxy-control.conf")
        results[key] = {"changed": changed, "input": text, "output": path.read_text(encoding="utf-8")}
    out.json("renders/nginx/ensure-stream-context.json", results)

    routes = (("panel.example.com", "127.0.0.1:8443"), ("relay.example.com", "127.0.0.1:8445"))
    maps = {
        "spaces": COEXIST_ROUTES,
        "tabs": COEXIST_ROUTES.replace("    ", "\t"),
        "default-first": "map $ssl_preread_server_name $sni_backend {\n  default 127.0.0.1:10443;\n  a.example.net 127.0.0.1:1;\n}\n",
        "inline-default": "map $ssl_preread_server_name $sni_backend { a.example.net 127.0.0.1:1; default 127.0.0.1:2; }\n",
        "conflict": COEXIST_ROUTES.replace("legacy.example.net", "panel.example.com"),
        "no-default": "map $ssl_preread_server_name $sni_backend {\n    a.example.net 127.0.0.1:1;\n}\n",
        "two-maps": COEXIST_ROUTES + "map $ssl_preread_server_name $sni_backend {\n    default 127.0.0.1:1;\n}\n",
    }
    patched = {}
    for key, text in maps.items():
        entry: dict[str, object] = {"input": text}
        try:
            result = patch_owned_map(text, variable="$sni_backend", routes=routes, ownership_id="nginx.routes")
            entry["output"] = result
            entry["idempotent"] = patch_owned_map(result, variable="$sni_backend", routes=routes,
                                                  ownership_id="nginx.routes") == result
            entry["removed"] = remove_owned_map_block(result.encode(), routes=routes,
                                                      ownership_id="nginx.routes").decode()
        except (TopologyError, ValueError) as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        patched[key] = entry
    out.json("renders/nginx/patch-owned-map.json", patched)


def record_ingress_upgrade(out: Output) -> None:
    """`installer.ingress_upgrade`: the old (pre-client-IP) forms and what they become."""
    from installer import ingress_upgrade
    from installer.adapters.nginx import _render_fresh

    root = WORK_BASE / "renders" / "ingress" / "root"
    if root.exists():
        shutil.rmtree(root)
    project = root / "opt/mtproxy-shared443"
    project.mkdir(parents=True)
    (project / ".mtproxy-owned").write_text("0" * 32 + "\n")
    (project / ".mtproxy-owned").chmod(0o600)
    (root / ingress_upgrade.STATE).mkdir(parents=True)
    routes = (("relay.example.com", "127.0.0.1:8445"), ("panel.example.com", "127.0.0.1:8443"),
              ("sub.example.com", "127.0.0.1:8443"), ("mcp.example.com", "127.0.0.1:8443"),
              ("edge.example.com", "127.0.0.1:4443"))
    legacy_stream = _render_fresh({"routes": routes, "panel_tls_backend": "127.0.0.1:8443"})
    current_panel, _backend = ingress_upgrade._panel_template(_legacy_panel_lines())
    legacy_panel = _legacy_panel_lines()
    stream = root / ingress_upgrade.STREAM
    panel = root / ingress_upgrade.PANEL
    stream.parent.mkdir(parents=True)
    panel.parent.mkdir(parents=True)
    stream.write_bytes(legacy_stream)
    panel.write_bytes(legacy_panel)
    calls: list[list[str]] = []
    pending = ingress_upgrade.upgrade(project, root=root, apply=False)
    applied = ingress_upgrade._upgrade(project, root=root, apply=True, run=lambda command: calls.append(list(command)),
                                       reload=lambda run: calls.append(["<reload>"]))
    out.bytes("renders/ingress-upgrade/legacy/stream.conf", legacy_stream)
    out.bytes("renders/ingress-upgrade/legacy/panel.conf", legacy_panel)
    out.bytes("renders/ingress-upgrade/upgraded/stream.conf", stream.read_bytes())
    out.bytes("renders/ingress-upgrade/upgraded/panel.conf", panel.read_bytes())
    current = ingress_upgrade.upgrade(project, root=root, apply=False)
    backup = Path(str(applied.get("backup", "")))
    out.json("renders/ingress-upgrade/outcome.json", {
        "after": current,
        "applied": {**applied, "backup": "<backup>"} if "backup" in applied else applied,
        "backup_files": sorted(path.name for path in backup.iterdir()) if backup.is_dir() else [],
        "backup_metadata": json.loads((backup / "metadata.json").read_text().replace(str(root), "<root>"))
        if backup.is_dir() else None,
        "calls": calls,
        "pending": pending,
        "panel_template_of_legacy": current_panel.decode(),
    })


def _legacy_panel_lines() -> bytes:
    """The panel file as releases before the client-IP change wrote it."""
    from installer import ingress_upgrade
    from installer.adapters.core import _mcp_vhost_text, _panel_vhost_text, _subscription_vhost_text

    kwargs = {"certificate": "relay.example.com", "tls_port": 8443}
    panel = _panel_vhost_text(panel_domain="panel.example.com", app_port=8787, **kwargs)
    subscription = _subscription_vhost_text(subscription_domain="sub.example.com", app_port=8787, **kwargs)
    mcp = _mcp_vhost_text(mcp_domain="mcp.example.com", mcp_port=8793, **kwargs)
    legacy = [
        text.replace(ingress_upgrade.PROXY_LISTENER, "").replace(
            "X-Forwarded-For $remote_addr;", "X-Forwarded-For $proxy_add_x_forwarded_for;")
        for text in (panel, subscription)
    ] + [mcp.replace(ingress_upgrade.PROXY_LISTENER, "").replace("proxy_set_header X-Forwarded-For $remote_addr; ", "")]
    return "".join(legacy).encode()


# --------------------------------------------------------------------------------------------
# (5) version-agent state: the installer's seed, then updates driven through VersionAgent
# --------------------------------------------------------------------------------------------

TELEMT_IMAGE_NEW = "ghcr.io/samnet-dev/mtproxymax-telemt@sha256:" + "a" * 64
TELEMT_IMAGE_OLD = "ghcr.io/samnet-dev/mtproxymax-telemt@sha256:" + "b" * 64


def _targz(members: Mapping[str, bytes]) -> bytes:
    import gzip
    import tarfile

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as handle:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o755
            info.mtime = FIXED_EPOCH
            handle.addfile(info, io.BytesIO(payload))
    return gzip.compress(raw.getvalue(), mtime=0)


def _zip(members: Mapping[str, bytes]) -> bytes:
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, payload in members.items():
            bundle.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), payload)
    return buffer.getvalue()


class AgentHost:
    """The commands a version-agent runs, answered for one simulated host."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.calls: list[list[str]] = []
        self.fail_restart: set[str] = set()
        self.xray_version = "26.10.17"

    def __call__(self, command, *, env=None, cwd=None, timeout=None) -> str:
        del env, cwd, timeout
        argv = [str(part) for part in command]
        self.calls.append([part.replace(str(self.work), "<work>") for part in argv])
        if argv[:2] == ["systemctl", "restart"] and argv[2] in self.fail_restart:
            self.fail_restart.discard(argv[2])  # the rollback restart succeeds
            raise subprocess.CalledProcessError(1, argv, "", "Job for mita.service failed")
        if argv[:2] == ["systemctl", "is-active"]:
            return "active"
        if argv[:3] == ["systemctl", "list-units", "--plain"]:
            return "mita@1.service loaded active running\nmita@2.service loaded active running"
        if "{{.Config.Image}}" in argv:
            override = self.work / "project" / "version-overrides" / "compose.versions.yaml"
            if override.exists() and TELEMT_IMAGE_NEW in override.read_text():
                return TELEMT_IMAGE_NEW
            return TELEMT_IMAGE_OLD
        if "{{.State.Health.Status}}" in argv:
            return "healthy"
        if argv[:2] == ["docker", "exec"] and "--status" in " ".join(argv):
            return json.dumps({"xray_version": f"Xray {self.xray_version} (Xray, Penetrates Everything.) Custom",
                               "phase": "idle", "running": {"generation": 2}})
        if argv[:2] == ["docker", "inspect"] and "com.docker.compose.project" in " ".join(argv):
            return "proxy_panel_by_dubr1k"
        return ""


def record_agent(out: Output) -> None:
    from version_agent.service import RolledBackError, VersionAgent

    run = perform_install("kitchen-sink", EXTRA_CONFIGS["kitchen-sink"], seed="agent:seed")
    seed_path = run.root / "var/lib/proxy-control/version-agent/state.json"
    catalog_seed = run.root / "etc/proxy-control/versions.json"
    out.bytes("agent/seed/state.json", seed_path.read_bytes())
    out.bytes("agent/seed/versions.json", catalog_seed.read_bytes())
    core_run = perform_install("core", (REPO / "examples/installer/core.toml").read_text(), seed="agent:seed-core")
    out.bytes("agent/seed/state.core.json",
              (core_run.root / "var/lib/proxy-control/version-agent/state.json").read_bytes())

    DET.reset("agent:updates")
    work = WORK_BASE / "agent"
    if work.exists():
        shutil.rmtree(work)
    project = work / "project"
    project.mkdir(parents=True)
    for name in ("compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml"):
        shutil.copy2(run.tree / name, project / name)
    for name in (".env", ".env.naive", ".env.mieru", ".env.xray-router"):
        shutil.copy2(run.root / "opt/mtproxy-shared443" / name, project / name)
    state_path = work / "state" / "state.json"
    state_path.parent.mkdir(parents=True)
    shutil.copy2(seed_path, state_path)
    bin_dir = work / "bin"
    bin_dir.mkdir()
    shutil.copy2(run.root / "usr/bin/mita", bin_dir / "mita")
    shutil.copy2(run.root / "usr/local/bin/caddy", bin_dir / "caddy")
    xray_dir = work / "xray-router"
    shutil.copytree(run.root / "usr/local/lib/proxy-control/xray-router", xray_dir)
    pin = work / "caddy-naive.pin"
    shutil.copy2(run.root / "etc/proxy-control/caddy-naive.pin", pin)

    mita_new = b"#!/bin/sh\n# golden stand-in mita 3.39.0\n"
    mita_archive = _targz({"mita": mita_new})
    xray_members = {"xray": b"golden stand-in xray 26.11.1\n", "geoip.dat": b"geoip 26.11.1\n",
                    "geosite.dat": b"geosite 26.11.1\n"}
    xray_archive = _zip({**xray_members, "README.md": b"# not extracted\n"})
    caddy_new = b"#!/bin/sh\n# golden stand-in caddy 2.11.8\n"
    downloads = {
        "https://github.com/enfein/mieru/releases/download/v3.39.0/mita_3.39.0_linux_amd64.tar.gz": mita_archive,
        "https://github.com/XTLS/Xray-core/releases/download/v26.11.1/Xray-linux-64.zip": xray_archive,
        "https://artifacts.example.com/caddy-2.11.8": caddy_new,
    }
    # The downloaded bytes themselves: a replay must pass the same SHA-256 checks.
    for url, payload in downloads.items():
        out.bytes(f"agent/updates/downloads/{url.rsplit('/', 1)[1]}", payload)
    catalog = work / "versions.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {
        "telemt": [{"version": "3.5.15", "kind": "image", "image": TELEMT_IMAGE_NEW}],
        "xray": [{"version": "26.11.1", "kind": "binary",
                  "url": "https://github.com/XTLS/Xray-core/releases/download/v26.11.1/Xray-linux-64.zip",
                  "sha256": _sha(xray_archive),
                  "archive": {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat",
                                                           "geosite.dat": "geosite.dat"}}}],
        "naive": [{"version": "2.11.8", "kind": "binary", "url": "https://artifacts.example.com/caddy-2.11.8",
                   "sha256": _sha(caddy_new), "runtime_version": "v2.11.8 h1:golden"}],
    }}, indent=2) + "\n")
    host = AgentHost(work)
    agent = VersionAgent(
        catalog_path=catalog, state_path=state_path, compose_dir=project,
        compose_files=("compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml"),
        binary_paths={"naive": bin_dir / "caddy", "mita": bin_dir / "mita"},
        service_names={"naive": "caddy-naive", "mita": "mita"},
        version_pins={"naive": pin},
        consumer_overlays={"mita": (project / ".env.mieru", "MIERU_MITA_SHA256", "mieru-manager")},
        downloader=lambda url: downloads[url], runner=host, health_timeout=5, router_enabled=True,
        clock=DET.time, xray_bin_dir=xray_dir, xray_overlay=project / ".env.xray-router",
        caddy_build_dir=work / "caddy-build", agent_dir=work / "agent", synchronous=True,
        sleep=lambda _seconds: None,
    )
    steps: list[dict[str, object]] = []

    def record(step: str, result: object) -> None:
        out.bytes(f"agent/updates/{len(steps):02d}-{step}/state.json", state_path.read_bytes())
        out.json(f"agent/updates/{len(steps):02d}-{step}/versions.json",
                 json.loads(json.dumps(agent.list_versions()).replace(str(work), "<work>")))
        steps.append({"step": step, "result": result, "calls": host.calls[:]})
        host.calls.clear()

    record("seed", None)
    agent.check_all = lambda current, *, fetcher, router_enabled: {  # type: ignore[method-assign]
        "telemt": {"latest": None, "installable": False, "reason": "no_releases", "candidates": []},
        "naive": {"latest": None, "installable": False, "reason": None, "candidates": [],
                  "last_error": "upstream answered 403 for /repos/caddyserver/caddy/releases"},
        "mita": {"latest": "3.39.0", "installable": True, "reason": None, "candidates": [{
            "version": "3.39.0", "tag": "v3.39.0", "kind": "binary", "source": "upstream",
            "url": "https://github.com/enfein/mieru/releases/download/v3.39.0/mita_3.39.0_linux_amd64.tar.gz",
            "sha256": _sha(mita_archive), "archive": {"format": "tar.gz", "member": "mita"},
            "published_at": "2026-01-01T00:00:00Z"}]},
        "xray": {"latest": "26.11.1", "installable": True, "reason": None, "candidates": []},
        "panel": {"latest": None, "installable": False, "reason": "no_releases", "candidates": []},
    }
    record("check-upstream", json.loads(json.dumps(agent.check_upstream(force=True)).replace(str(work), "<work>")))
    record("update-telemt", agent.update("telemt", "3.5.15", expected_current=None))
    out.text("agent/updates/compose.versions.yaml",
             (project / "version-overrides" / "compose.versions.yaml").read_text())
    record("update-mita", agent.update("mita", "3.39.0", expected_current="3.38.1"))
    out.text("agent/updates/env.mieru", (project / ".env.mieru").read_text())
    host.xray_version = "26.11.1"
    record("update-xray", agent.update("xray", "26.11.1", expected_current=None))
    out.text("agent/updates/env.xray-router", (project / ".env.xray-router").read_text().replace(str(work), "<work>"))
    host.fail_restart.add("caddy-naive")
    try:
        agent.update("naive", "2.11.8", expected_current=None)
        outcome: object = "unexpected success"
    except RolledBackError as exc:
        outcome = {"exception": type(exc).__name__, "message": str(exc).replace(str(work), "<work>")}
    record("update-naive-rolled-back", outcome)
    out.json("agent/updates/steps.json", steps)


# --------------------------------------------------------------------------------------------
# (6) the nft ruleset, the metrics port map and the sampler's JSON
# --------------------------------------------------------------------------------------------

CONTAINER_IDS = {
    "proxy-control-panel": "1" * 64,
    "proxy-control-mtproxy": "2" * 64,
    "proxy-control-awg-manager": "3" * 64,
}


def _write_proc(proc: Path, tick: int) -> None:
    """Two readings of a host one second apart; the numbers exercise Python's round()."""
    files = {
        "stat": ["cpu  1000 0 500 8000 100 0 0 0 0 0", "cpu  1333 0 667 8889 112 0 0 0 0 0"][tick] + "\ncpu0 1 2 3 4 5\n",
        "meminfo": ("MemTotal:        4009296 kB\nMemFree:          500000 kB\nMemAvailable:    2672864 kB\n"
                    "SwapTotal:       1048572 kB\nSwapFree:         699048 kB\n"),
        "loadavg": ["0.125 0.375 2.675 1/200 3000\n", "0.135 0.385 2.665 2/200 3001\n"][tick],
        "uptime": ["12345.67 23456.78\n", "12346.67 23457.78\n"][tick],
        "self/mountinfo": "22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n",
        "diskstats": ["   8       0 vda1 100 0 2000 50 300 0 4000 60 0 1000 110\n",
                      "   8       0 vda1 110 0 2333 55 310 0 4777 66 0 1333 121\n"][tick],
        "net/dev": (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            + ["    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n"
               "  eth0: 5000000 100 0 0 0 0 0 0 7000000 100 0 0 0 0 0 0\n"
               " awg15: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n"
               "veth12: 900 1 0 0 0 0 0 0 900 1 0 0 0 0 0 0\n"
               "docker0: 50 1 0 0 0 0 0 0 50 1 0 0 0 0 0 0\n"
               "virt0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n",
               "    lo: 2000 10 0 0 0 0 0 0 2000 10 0 0 0 0 0 0\n"
               "  eth0: 5123457 100 0 0 0 0 0 0 7333333 100 0 0 0 0 0 0\n"
               " awg15: 1100 1 0 0 0 0 0 0 1700 1 0 0 0 0 0 0\n"
               "veth12: 1900 1 0 0 0 0 0 0 1900 1 0 0 0 0 0 0\n"
               "docker0: 50 1 0 0 0 0 0 0 50 1 0 0 0 0 0 0\n"
               "virt0: 2 1 0 0 0 0 0 0 2 1 0 0 0 0 0 0\n"][tick]
        ),
        "net/tcp": ("  sl  local_address rem_address   st\n"
                    "   0: 0100007F:20FD 0100007F:A000 01 0\n"
                    "   1: 00000000:01BB 00000000:0000 0A 0\n"
                    "   2: 0100007F:115B 0100007F:A001 01 0\n"
                    "   3: 0100007F:115B 0100007F:A002 01 0\n"),
        "net/tcp6": ("  sl  local_address rem_address   st\n"
                     "   0: 00000000000000000000000001000000:B3B1 00000000000000000000000001000000:A003 01 0\n"),
    }
    for relative, text in files.items():
        path = proc / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def record_metrics(out: Output) -> None:
    from version_agent import hostmetrics, metrics_ports

    run = perform_install("kitchen-sink", EXTRA_CONFIGS["kitchen-sink"], seed="metrics:host")
    mita = run.root / "var/lib/mita/server_config.json"
    mita.parent.mkdir(parents=True, exist_ok=True)
    mita.write_text(json.dumps({"portBindings": [
        {"port": 46001, "protocol": "TCP"}, {"port": 46003, "protocol": "TCP"},
        {"portRange": "46010-46012", "protocol": "UDP"}, {"port": 46002, "protocol": "UDP"},
    ]}))
    compose_files = ("compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml",
                     "compose.amneziawg.yaml", "compose.trusttunnel.yaml", "compose.mcp.yaml")
    override = run.root / "etc/proxy-control/metrics-ports.json"
    project = run.root / "opt/mtproxy-shared443"
    discovered = metrics_ports.discover_ports(project, compose_files, override_path=override, mita_config=mita)
    override_cases = {
        "valid": {"naive": {"tcp": [4443, 14443], "udp": []}, "trusttunnel": {"tcp": [5443], "udp": []}},
        "unknown-protocol": {"telnet": {"tcp": [23], "udp": []}},
        "bad-port": {"naive": {"tcp": [70000], "udp": []}},
        "not-an-object": [1, 2, 3],
    }
    discoveries: dict[str, object] = {"no-override": discovered}
    for key, document in override_cases.items():
        override.write_text(json.dumps(document))
        discoveries[f"override-{key}"] = metrics_ports.discover_ports(project, compose_files,
                                                                      override_path=override, mita_config=mita)
    override.unlink()
    discoveries["core-only"] = metrics_ports.discover_ports(project, ("compose.yaml",), override_path=override,
                                                            mita_config=mita)
    out.json("metrics/port-maps.json", discoveries)
    out.json("metrics/inputs.json", {
        "compose_files": list(compose_files),
        "env": (project / ".env").read_text(),
        "env.mieru": (project / ".env.mieru").read_text(),
        "env.trusttunnel": (project / ".env.trusttunnel").read_text(),
        "mita_server_config": json.loads(mita.read_text()),
        "overrides": override_cases,
    })
    rulesets = {
        "discovered": discovered,
        "empty": {},
        "mtproxy-only": {"mtproxy": {"tcp": [8445], "udp": []}},
        "skips-bad-protocol-names": {"Bad-Name": {"tcp": [1]}, "naive": {"tcp": [4443]}},
    }
    for key, port_map in rulesets.items():
        out.text(f"metrics/nft/{key}.nft", hostmetrics.render_ruleset(port_map))
    counters_json = json.dumps({"nftables": [
        {"metainfo": {"version": "1.0.9"}},
        {"counter": {"family": "inet", "name": "up_mtproxy_tcp_8445", "table": "proxy_control_metrics",
                     "handle": 1, "packets": 10, "bytes": 12345}},
        {"counter": {"family": "inet", "name": "down_mtproxy_tcp_8445", "table": "proxy_control_metrics",
                     "handle": 2, "packets": 10, "bytes": 67890}},
        {"counter": {"family": "inet", "name": "foreign", "table": "proxy_control_metrics", "handle": 3,
                     "packets": 1, "bytes": True}},
    ]})
    out.json("metrics/parse-counters.json", {"input": counters_json, "parsed": hostmetrics.parse_counters(counters_json)})

    # Two sampler ticks over a fake /proc, cgroup tree, docker and nft.
    base = WORK_BASE / "metrics"
    proc, cgroup, virtual = base / "proc", base / "cgroup", base / "virtual-net"
    virtual.mkdir(parents=True, exist_ok=True)
    (virtual / "virt0").mkdir(exist_ok=True)
    counters = {0: {"up_mtproxy_tcp_8445": 1000, "down_mtproxy_tcp_8445": 5000, "up_naive_tcp_4443": 0,
                    "down_naive_tcp_4443": 0, "up_mieru_udp_46002": 7},
                1: {"up_mtproxy_tcp_8445": 2500, "down_mtproxy_tcp_8445": 4000, "up_naive_tcp_4443": 333,
                    "down_naive_tcp_4443": 777, "up_mieru_udp_46002": 9}}
    tick = {"index": 0}
    nft_calls: list[object] = []

    def nft(args, stdin=None):
        nft_calls.append({"args": list(args), "stdin": stdin})
        if args[:2] == ["-j", "list"]:
            return json.dumps({"nftables": [{"counter": {"name": name, "bytes": value}}
                                            for name, value in counters[tick["index"]].items()]})
        return ""

    def docker(command, *, timeout=10):
        del timeout
        return "\n".join(f"{cid} {name}" for name, cid in CONTAINER_IDS.items()) + "\n"

    port_map = {"mtproxy": {"tcp": [8445], "udp": []}, "naive": {"tcp": [4443], "udp": []},
                "mieru": {"tcp": [46001], "udp": [46002]}}
    clocks = iter([100.0, 101.0])
    walls = iter([FIXED_EPOCH + 0.1234, FIXED_EPOCH + 1.2346])
    statvfs = os.statvfs_result((4096, 4096, 20_000_000, 15_000_000, 14_000_000, 5_000_000, 4_000_000, 4_000_000, 0, 255))
    sampler = hostmetrics.MetricsSampler(
        ports=lambda: port_map, runner=docker, nft=nft, clock=lambda: next(clocks), wall=lambda: next(walls),
        proc=proc, cgroup=cgroup, virtual_net=virtual, statvfs=lambda _path: statvfs, cores=2,
    )
    samples = []
    for index in (0, 1):
        tick["index"] = index
        _write_proc(proc, index)
        for offset, cid in enumerate(CONTAINER_IDS.values()):
            scope = cgroup / "system.slice" / f"docker-{cid}.scope"
            scope.mkdir(parents=True, exist_ok=True)
            (scope / "cpu.stat").write_text(f"usage_usec {1_000_000 * (offset + 1) + index * 123_457 * (offset + 1)}\n"
                                            "user_usec 1\n")
            (scope / "memory.current").write_text(f"{(offset + 1) * 50_000_000}\n")
        samples.append(sampler.tick())
    out.json("metrics/sampler.json", {"nft_calls": nft_calls, "port_map": port_map, "samples": samples})


# --------------------------------------------------------------------------------------------
# (7) wizard transcripts in both languages
# --------------------------------------------------------------------------------------------

# Each scenario: the answers, line by line ("<DIGEST12>" is replaced by the plan digest prefix
# the same scenario printed when it was first run with "quit" there), and whether `--lang` is given.
WIZARD_SCENARIOS: dict[str, dict[str, object]] = {
    "core-save": {"lang": True, "answers": [
        "", "core", "", "Panel.Example.com.", "relay.example.com", "", "", "n", "n",
        "admin@example.com", "owner", "", "", "save",
    ]},
    "core-apply-install": {"lang": True, "answers": [
        "", "core", "", "panel.example.com", "relay.example.com", "", "", "n", "n",
        "admin@example.com", "owner", "", "", "apply", "<DIGEST12>",
    ]},
    "full-quit-at-digest": {"lang": False, "answers": [
        "<LANG>", "fresh", "full", "none", "panel.example.com", "relay.example.com", "sub.example.com", "",
        "edge.example.com", "mieru.example.com", "46001,46003", "", "y", "y", "y", "n", "y",
        "y", "", "", "", "y", "gate.example.org", "admin@example.com", "owner",
        "correct-horse-battery", "correct-horse-battery", "", "apply", "quit",
    ]},
    "managed-three-xui-save": {"lang": True, "answers": [
        "fresh", "full", "managed-new", "panel.example.com", "relay.example.com", "", "",
        "edge.example.com", "mieru.example.com", "", "", "xui.example.com", "vless.example.com",
        "xhttp.example.com", "hy2.example.com", "y", "geosite:openai, domain:chat.example.org",
        "n", "n", "n", "n", "n", "admin@example.com", "owner", "", "xuiadmin", "", "n", "save",
    ]},
    "invalid-inputs": {"lang": False, "answers": [
        "<LANG>", "maybe", "coexist", "core", "managed-new", "existing", "not a domain", "panel.example.com",
        "relay.example.com", "", "", "", "", "vless.example.com", "", "n", "n", "nope", "admin@example.com",
        "bad user", "owner", "aaaaaaaaaaaa", "bbbbbbbbbbbb", "short", "short", "", "edit", "domains.naive",
        "domains.mtproxy", "", "back", "", "quit",
    ]},
    "invalid-config": {"lang": True, "answers": [
        "", "core", "", "panel.example.com", "relay.example.com", "", "", "y", "1.5,3.1", "", "70000",
        "20015,20031", "y", "panel.example.com", "n", "admin@example.com", "owner", "", "",
        "trusttunnel", "y", "gate.example.org", "n", "edit", "acme_email", "", "quit",
    ]},
    "eof": {"lang": True, "answers": ["", "core"]},
}


def run_wizard(name: str, locale: str, answers: Sequence[str], *, lang_flag: bool, installed: bool = False) -> dict[str, object]:
    from installer import cli
    from installer.wizard import TerminalIO

    seed = f"wizard:{name}:{locale}"
    DET.reset(seed)
    work = WORK_BASE / "wizard" / f"{name}-{locale}"
    if work.exists():
        shutil.rmtree(work)
    tree = source_tree(work, stand_in_artifacts=True)
    root = work / "root"
    host = SimHost(root)
    add_warp_commands(host)
    if installed:
        host.write("/opt/mtproxy-shared443/VERSION", "3.2.1\n")
    runners = install_runners(host)
    output = work / "proxy-control.toml"
    stdin = io.StringIO("".join(f"{line}\n" for line in answers))
    stdout, stderr = io.StringIO(), io.StringIO()
    argv = ["--root", str(root), "wizard", "--config-output", str(output)]
    if lang_flag:
        argv += ["--lang", locale]
    environment = {"LANG": "ru_RU.UTF-8" if locale == "ru" else "en_US.UTF-8", "LC_ALL": ""}
    saved_environment = {key: os.environ.get(key) for key in environment}
    os.environ.update(environment)
    try:
        with stand_in_pins():
            composition = PlanServices(host, tree, runners)
            try:
                code: int | None = cli.run(argv, services=composition.services(), io=TerminalIO(stdin, stdout),
                                           stdout=stdout, stderr=stderr)
            except SystemExit as exc:
                code = int(exc.code or 0)
    finally:
        for key, value in saved_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    result: dict[str, object] = {
        "argv": [part.replace(str(work), "<work>") for part in argv[2:]],
        "environment": environment,
        "exit": code,
        "stdin": stdin.getvalue(),
        "stdout": stdout.getvalue().replace(str(work), "<work>"),
        "stderr": stderr.getvalue().replace(str(work), "<work>"),
    }
    if output.exists():
        result["config_output"] = output.read_text()
    credentials = output.with_suffix(".credentials")
    if credentials.exists():
        result["credentials_output_mode"] = f"{stat.S_IMODE(credentials.stat().st_mode):04o}"
        result["credentials_output_keys"] = sorted(
            line.split("=", 1)[0].strip() for line in credentials.read_text().splitlines() if "=" in line
        )
    state = root / "var/lib/proxy-control/installer/state.json"
    if state.exists():
        result["installed_status"] = json.loads(state.read_text())["status"]
    return result


def record_wizard(out: Output) -> None:
    import re

    from installer.i18n import Locale

    for locale in ("en", "ru"):
        for name, scenario in WIZARD_SCENARIOS.items():
            answers = [locale if answer == "<LANG>" else answer for answer in scenario["answers"]]  # type: ignore[union-attr]
            if "<DIGEST12>" in answers:
                probe = run_wizard(name, locale, [a if a != "<DIGEST12>" else "quit" for a in answers],
                                   lang_flag=bool(scenario["lang"]))
                match = re.search(r"^digest \| ([0-9a-f]{64})$", str(probe["stdout"]), re.MULTILINE)
                if match is None:
                    raise RuntimeError(f"wizard {name}/{locale} printed no digest")
                answers = [match.group(1)[:12] if a == "<DIGEST12>" else a for a in answers]
            result = run_wizard(name, locale, answers, lang_flag=bool(scenario["lang"]))
            out.json(f"wizard/{locale}/{name}.json", result)
            out.text(f"wizard/{locale}/{name}.stdout.txt", str(result["stdout"]))
        for name, answers in (("already-installed", []), ("already-installed-continue", ["continue", "quit"])):
            result = run_wizard(name, locale, answers, lang_flag=True, installed=True)
            out.json(f"wizard/{locale}/{name}.json", result)
            out.text(f"wizard/{locale}/{name}.stdout.txt", str(result["stdout"]))
    # The message catalogue itself (both languages), so texts can be checked one by one.
    from installer import i18n

    catalogue = {}
    for locale in (Locale.EN, Locale.RU):
        catalogue[locale.value] = dict(sorted(i18n._CATALOG[locale].items()))
    out.json("wizard/i18n-catalogue.json", catalogue)


README_TEXT = """\
# Host-side golden fixtures (Python → Rust port, WP0)

Recorded from the **Python** installer and version-agent by `scripts/dev/record-host-goldens.py`.
Every Rust host package (`pc_host`, `installer`, `version_agent`) loads these files and must
reproduce them byte for byte, or read them and write them back unchanged. Do not edit them by hand:
regenerate them on ams-test.

    # as root on ams-test, from a checkout (never against the stand's own installation)
    python3 scripts/dev/record-host-goldens.py
    python3 scripts/dev/record-host-goldens.py --output /tmp/again --check-against tests/fixtures/host-golden

The recorder re-executes itself in a private mount namespace and covers every live state directory
(`/var/lib/proxy-control`, `/opt/mtproxy-shared443`, `/etc/proxy-control`, …) with an empty tmpfs,
then drives the real CLI (`installer.cli.run`) and the real adapters against a throwaway root under
`/tmp/proxy-control-host-golden`. Commands are answered by a simulated host (`SimHost`) and by the
unit tests' fake runners. `INDEX.json` lists every file with its SHA-256.

## Determinism

- Clock: `time.time()` is fixed at 1767225600 (2026-01-01T00:00:00Z); `time.sleep` is a no-op.
- Entropy: `secrets.token_bytes/hex/urlsafe`, `uuid.uuid4` and tempfile names come from
  `sha256("host-golden:<scenario>:<n>")`, reset per scenario. **No value here is a real secret**:
  every token, password, key and certificate is a seeded or labelled stand-in.
- Host: IPv4 203.0.113.10, IPv6 2001:db8::10, machine-id `0123456789abcdef0123456789abcdef`,
  Ubuntu-like package versions, `nginx-full` installed with the stock `nginx.conf`, UFW inactive
  (IPV6=yes), sshd on 22.
- Release tree: real compose files, `deploy/`, `probe/`, `docker/`, `scripts/` and release pins;
  the panel, manager, installer and pc_common sources are one `GOLDEN-STAND-IN` file each and the
  `version_agent/*.py` files are one-line stand-ins, so ownership hashes do not move with every commit.
  `release/release.json` is stamped by `release/build.py` for version 3.3.0, commit `000…0`.
- Running the recorder twice gives byte-identical output (`--check-against`).

## Layout

| Path | What | Python source |
|---|---|---|
| `config/errors.json` | 150-odd TOML inputs: `parse_config` result, exact `ConfigError` text, canonical dict and `render_config` for the valid ones | `installer/config.py` |
| `config/cli-blocked.json` | the same failures through `plan --config`: `BLOCKED: …` on stderr, exit 2 (plus a missing file and invalid UTF-8) | `installer/cli.py` |
| `config/render/` | `render_config` of every example and the round-trip result | `config.py:139` |
| `vectors/` | Python semantics the digest and validators rely on: `isdigit`/`isdecimal`/`\\d`, `strip`, `lower`, `ipaddress`, `str()` of scalars and keys, `round()`, float `repr`, JSON escaping and key order; validator outcomes (domains, version regexes) and `compare_versions` | stdlib, `audit.py`, `config.py`, `wizard.py`, `version_agent/{catalog,upstream}.py` |
| `plans/<name>/` | for every `examples/installer/*.toml` and two extra configs (`kitchen-sink`, `coexist-ingress`): canonical `plan.json` bytes, `digest`, `digests.json` (plan + intent digest), `plan --json` and text output, the audit commands; **real release pins** | `planner.py`, `audit.py` |
| `plans/index.json`, `plans/release.json` | the host facts and release identity the plans were made with | |
| `installs/<name>/journal/` | `state.json`, `plan.json`, `ownership.json`, `report.json` (+ modes) after `install --accept-plan` | `transaction.py` |
| `installs/<name>/root/tree.json` | every path the install left: kind, mode, uid/gid, size, sha256 (copies of release files are marked `copy_of_source`) | all adapters |
| `installs/<name>/root/files/…` | the bytes of every text file the install wrote (rendered vhosts, stream router, ACME vhosts, `.env*`, master key, `users.conf`, markers, WARP owner marker, version-agent env/state/catalog, units, …) | all adapters |
| `installs/<name>/commands.json` | every command the install ran, in order (`<root>`/`<work>`/`<tmp>` replace the throwaway paths) | |
| `installs/<name>/{status.json,status.txt,install-stdout.json,report/}` | CLI `status`, `install --json` output, `report` (public report + root-only handoff, modes) | `cli.py`, `report.py` |
| `journals/handoff/{before,after}` | a panel update's `PanelOwnershipHandoff` prepare/commit on the kitchen-sink host (`report.json` stays stale: Python bug) | `transaction.py:483` |
| `journals/home-like/` | shaped like the `home` host (see below) | |
| `journals/rolled-back` | a failed verification rolled the whole install back (`error: "AcceptanceError"`) | |
| `journals/interrupted/{applying,resumed}` | a crash inside `mieru.runtime` (`applying` checkpoint), then `resume` | |
| `journals/{repaired,uninstalled,uninstalled-purged}` | `repair`, `uninstall`, `uninstall --purge-data` | |
| `journals/lock.json` | the lock file mode and the busy message | `transaction.py:187` |
| `renders/<config>/` | render functions called directly: stream router (current and pre-client-IP forms), ACME vhosts, Core compose/env/panel vhost, Naive Caddyfile template/env/unit/pin/deploy hook, Mieru env and bootstrap input, TrustTunnel/AmneziaWG/Xray-router env, version-agent env merge against several existing files (`env.operator-keys` keeps operator keys), managed 3x-ui add-inbound bodies and WARP routing | adapters |
| `renders/nginx/` | `ensure_stream_context` and `patch_owned_map`/`remove_owned_map_block` edge cases | `nginx.py` |
| `renders/ingress-upgrade/` | the old panel/stream forms, what `ingress_upgrade` turns them into, its result and backup metadata | `ingress_upgrade.py` |
| `renders/core-vhosts/` | panel, subscription and MCP vhost texts with non-default ports | `core.py:2771` |
| `agent/seed/` | the installer's agent `state.json` (indent 2, sorted, trailing newline) and catalog seed | `adapters/version_agent.py:460` |
| `agent/updates/NN-step/` | agent `state.json` (indent 2, sorted, ASCII, **no** trailing newline) and the `/v1/versions` body after: upstream check, telemt image update, mita upstream update, xray update, a naive update rolled back; plus the override file, overlays, every command and (`downloads/`) the artifacts the steps download | `version_agent/service.py` |
| `metrics/` | nft rulesets, the discovered port map (with override variants), `parse_counters`, and two sampler ticks over a fake `/proc` (Python `round`) | `version_agent/{hostmetrics,metrics_ports}.py` |
| `wizard/{en,ru}/<scenario>.json` | stdin, stdout, stderr, exit code and the saved TOML/credentials of wizard runs (`--lang` given or the language asked); `core-apply-install` goes on to a full install | `wizard.py`, `i18n.py`, `cli.py` |
| `wizard/i18n-catalogue.json` | the message catalogue in both languages | `i18n.py` |

## Stand-ins that differ from a real host

- **Installs use stand-in artifacts.** Xray, mita/mieru `.deb`, the 3x-ui archive and the WARP key and
  package are small stand-ins; the adapters' compiled-in pins and the tree's
  `release/external-artifacts.json` are patched to their digests. So the plan digests under
  `installs/` and `journals/` differ from `plans/` for profiles with Mieru, the router or 3x-ui;
  `plans/` uses the real pins.
- Fake runners stand in for Docker, systemd, the panel acceptance and the 3x-ui API (see
  `install_runners`). Their answers are the "healthy" ones; the journal shapes are the code's own.
- `journals/home-like` is inferred from the code, never read from that host: a fresh `full` install
  (NaiveProxy, Mieru, AmneziaWG; no router, no WARP; UFW managed) at 3.2.0 rebased by two panel
  updates (3.2.1, 3.3.0). The real `home` journal may have been written by an older installer, so
  adapter `data` keys can differ; treat checkpoint `data` as opaque JSON.
"""


SECTIONS: list[tuple[str, Callable[[Output], None]]] = [
    ("config-errors", record_config_errors),
    ("vectors", record_vectors),
    ("plans", record_plans),
    ("installs", record_installs),
    ("journals", record_journals),
    ("renders", record_renders),
    ("agent", record_agent),
    ("metrics", record_metrics),
    ("wizard", record_wizard),
]


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check-against",
        type=Path,
        help="after writing, compare the output tree byte for byte with this directory",
    )
    parser.add_argument("--only", action="append", default=[], help="record only these sections")
    options = parser.parse_args(arguments)
    options.output = options.output.resolve()
    if options.check_against is not None:
        options.check_against = options.check_against.resolve()
    _enter_namespace([str(Path(__file__).resolve()), *arguments])

    if WORK_BASE.exists():
        shutil.rmtree(WORK_BASE)
    WORK_BASE.mkdir(parents=True)
    install_determinism(WORK_BASE)
    sys.path.insert(0, str(REPO))
    os.chdir(WORK_BASE)

    output = Output()
    output.text("README.md", README_TEXT)
    selected = [name for name, _ in SECTIONS if not options.only or name in options.only]
    for name, function in SECTIONS:
        if name not in selected:
            continue
        print(f"recording {name}", flush=True)
        DET.reset(name)
        function(output)
    output.write(options.output)
    print(f"wrote {len(output.files)} fixture files into {options.output}", flush=True)
    if options.check_against is not None:
        return compare_trees(options.output, options.check_against)
    return 0


def compare_trees(first: Path, second: Path) -> int:
    def listing(base: Path) -> dict[str, bytes]:
        return {
            path.relative_to(base).as_posix(): path.read_bytes()
            for path in sorted(base.rglob("*"))
            if path.is_file()
        }

    left, right = listing(first), listing(second)
    differences = sorted(
        name for name in set(left) | set(right) if left.get(name) != right.get(name)
    )
    for name in differences[:50]:
        print(f"DIFFERS: {name}", flush=True)
    print(
        f"compared {len(left)} files with {len(right)}: "
        + ("byte-identical" if not differences else f"{len(differences)} differ"),
        flush=True,
    )
    return 0 if not differences else 1


if __name__ == "__main__":
    raise SystemExit(main())
