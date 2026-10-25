"""Golden vectors for `panel_core::settings`: what `panel.settings.Settings()` makes of an environment.

Run with the panel image's interpreter and this checkout mounted at /src, e.g.:

    docker run --rm --network none -v "$PWD:/src:ro" -v "$OUT:/out" --entrypoint python \
        proxy_panel_by_dubr1k-panel:latest -I /src/panel/crates/core/tests/fixtures/generators/gen_settings.py /out

Every case runs in a fresh interpreter (the module reads most variables at import time) with only
the listed variables set. Token files are written under /tmp/pc-settings/ inside the container;
the Rust test recreates them from `files`.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

FILES = {
    "/tmp/pc-settings/telemt-token": "  telemt-secret\r\n",
    "/tmp/pc-settings/naive-token": "naive-secret\n",
    "/tmp/pc-settings/crlf-token": "\ufeffa\r\nb\rc\u00a0\n",
    "/tmp/pc-settings/empty-token": "",
}

PROBE = r"""
import dataclasses, json, sys
sys.path.insert(0, "/src")
try:
    from panel.settings import Settings
    settings = Settings()
except Exception as exc:
    print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
    raise SystemExit(0)
out = {}
for field in dataclasses.fields(settings):
    value = getattr(settings, field.name)
    if isinstance(value, tuple):
        value = list(value)
    elif isinstance(value, float):
        value = repr(value)
    elif value is not None and not isinstance(value, (str, int, bool)):
        value = str(value)
    out[field.name] = value
out["mtproxy_host"] = settings.mtproxy_host
problem = None
if settings.naive_enabled and not settings.naive_public_host.strip():
    problem = "NAIVE_PUBLIC_HOST is required when NaiveProxy is enabled"
elif settings.login_verify_concurrency < 1:
    problem = "login_verify_concurrency must be positive"
elif settings.fleet_heartbeat_seconds < 1:
    problem = "PANEL_FLEET_HEARTBEAT_SECONDS must be positive"
out["validate"] = problem
print(json.dumps(out))
"""

CASES = [
    {},
    {"PANEL_DATABASE": "/var/lib/panel/db.sqlite3", "TELEMT_API_URL": "http://telemt:1", "TELEMT_API_TOKEN": "t1",
     "NAIVE_MANAGER_SOCKET": "/n.sock", "NAIVE_MANAGER_TOKEN": "n1", "NAIVE_PUBLIC_HOST": "naive.example",
     "MTPROXY_DOMAIN": "mt.example", "NAIVE_ENABLED": "true", "MIERU_MANAGER_SOCKET": "/m.sock",
     "MIERU_MANAGER_TOKEN": "m1", "MIERU_ENABLED": "TRUE", "AWG_MANAGER_SOCKET": "/a.sock", "AWG_MANAGER_TOKEN": "a1",
     "AMNEZIAWG_ENABLED": "True", "AMNEZIAWG_PUBLIC_HOST": "awg.example", "TRUSTTUNNEL_MANAGER_SOCKET": "/t.sock",
     "TRUSTTUNNEL_MANAGER_TOKEN": "tt1", "TRUSTTUNNEL_ENABLED": "true", "TRUSTTUNNEL_PUBLIC_HOST": "tt.example",
     "XRAY_ROUTER_ENABLED": "true", "XRAY_ROUTER_MANAGER_SOCKET": "/x.sock", "XRAY_ROUTER_MANAGER_TOKEN": "x1",
     "PANEL_SUBSCRIPTION_URL": "https://Sub.Example.com:8443/base", "PANEL_SINGBOX_FORK_CLIENTS": "karing,Streisand",
     "VERSION_AGENT_SOCKET": "/v.sock", "PANEL_VERSION_FILE": "/app/VERSION", "PANEL_MASTER_KEY_FILE": "/run/k",
     "PANEL_COOKIE_SECURE": "false", "PANEL_ALLOWED_HOSTS": "panel.example,127.0.0.1",
     "PANEL_FLEET_HEARTBEAT_SECONDS": "30", "PANEL_METRICS_ENABLED": "off", "PANEL_METRICS_INTERVAL_SECONDS": "1.5",
     "PANEL_METRICS_RING_POINTS": "100", "PANEL_VNEXT_WRITER": "legacy"},
    {"NAIVE_ENABLED": "1"}, {"NAIVE_ENABLED": "yes"}, {"NAIVE_ENABLED": " true"}, {"NAIVE_ENABLED": ""},
    {"NAIVE_ENABLED": "true"}, {"NAIVE_ENABLED": "true", "NAIVE_PUBLIC_HOST": " \u3000"},
    {"NAIVE_ENABLED": "tRuE", "NAIVE_PUBLIC_HOST": "h"},
    {"PANEL_COOKIE_SECURE": "FALSE"}, {"PANEL_COOKIE_SECURE": ""}, {"PANEL_COOKIE_SECURE": "True"},
    {"PANEL_METRICS_ENABLED": "0"}, {"PANEL_METRICS_ENABLED": "false"}, {"PANEL_METRICS_ENABLED": "no"},
    {"PANEL_METRICS_ENABLED": " OFF "}, {"PANEL_METRICS_ENABLED": "n"}, {"PANEL_METRICS_ENABLED": ""},
    {"PANEL_METRICS_ENABLED": "False\n"}, {"PANEL_METRICS_ENABLED": "\u00a0no\u2003"},
    {"PANEL_METRICS_INTERVAL_SECONDS": "0.1"}, {"PANEL_METRICS_INTERVAL_SECONDS": "nan"},
    {"PANEL_METRICS_INTERVAL_SECONDS": "inf"}, {"PANEL_METRICS_INTERVAL_SECONDS": "x"},
    {"PANEL_METRICS_INTERVAL_SECONDS": ""}, {"METRICS_INTERVAL_SECONDS": "5"},
    {"METRICS_INTERVAL_SECONDS": "5", "PANEL_METRICS_INTERVAL_SECONDS": "3"},
    {"PANEL_METRICS_INTERVAL_SECONDS": " 1_5e-1 "}, {"PANEL_METRICS_INTERVAL_SECONDS": "1e400"},
    {"PANEL_FLEET_HEARTBEAT_SECONDS": "0"}, {"PANEL_FLEET_HEARTBEAT_SECONDS": "-5"},
    {"PANEL_FLEET_HEARTBEAT_SECONDS": "x"}, {"PANEL_FLEET_HEARTBEAT_SECONDS": " 20 "},
    {"PANEL_FLEET_HEARTBEAT_SECONDS": "1_0"}, {"PANEL_FLEET_HEARTBEAT_SECONDS": "1.0"},
    {"PANEL_FLEET_HEARTBEAT_SECONDS": "١٥"}, {"PANEL_METRICS_RING_POINTS": "x"},
    {"PANEL_METRICS_RING_POINTS": "+42"},
    {"PANEL_ALLOWED_HOSTS": "a,,b, c,"}, {"PANEL_ALLOWED_HOSTS": ""}, {"PANEL_ALLOWED_HOSTS": ","},
    {"PANEL_ALLOWED_HOSTS": "Panel.Example"},
    {"PANEL_SUBSCRIPTION_URL": "https://SUB.example.com"}, {"PANEL_SUBSCRIPTION_URL": "sub.example.com"},
    {"PANEL_SUBSCRIPTION_URL": "https://user:pw@[2001:DB8::1]:8443/"},
    {"PANEL_SUBSCRIPTION_URL": "https://a.example", "PANEL_SUBSCRIPTION_HOST": "SUB.Example.com"},
    {"PANEL_SUBSCRIPTION_HOST": "Only.Host"}, {"PANEL_SUBSCRIPTION_URL": "https://[::1"},
    {"PANEL_SUBSCRIPTION_URL": "https://"},
    {"TELEMT_API_TOKEN_FILE": "/tmp/pc-settings/telemt-token", "TELEMT_API_TOKEN": "ignored"},
    {"TELEMT_API_TOKEN_FILE": "", "TELEMT_API_TOKEN": "used"},
    {"NAIVE_MANAGER_TOKEN_FILE": "/tmp/pc-settings/naive-token"},
    {"MIERU_MANAGER_TOKEN_FILE": "/tmp/pc-settings/crlf-token"},
    {"AWG_MANAGER_TOKEN_FILE": "/tmp/pc-settings/empty-token", "AWG_MANAGER_TOKEN": "env"},
    {"TRUSTTUNNEL_MANAGER_TOKEN_FILE": "/tmp/pc-settings/missing"},
    {"XRAY_ROUTER_MANAGER_TOKEN": "  spaced  "},
    {"PANEL_MASTER_KEY_FILE": ""}, {"PANEL_MASTER_KEY_FILE": "/run/panel/master-key"},
    {"PANEL_DATABASE": ""}, {"PANEL_DATABASE": "/data//x/./panel.sqlite3/"}, {"PANEL_DATABASE": "rel/db"},
    {"PANEL_DATABASE": "./db"}, {"PANEL_VERSION_FILE": ""},
    {"MTPROXY_DOMAIN": "", "PANEL_ALLOWED_HOSTS": "first.example,second"}, {"MTPROXY_DOMAIN": "mt", "PANEL_ALLOWED_HOSTS": ""},
    {"PANEL_ALLOWED_HOSTS": ",,"},
]


def main(out: Path) -> None:
    for path, content in FILES.items():
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8", newline="")
    results = []
    for env in CASES:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", PROBE], env={"PATH": os.environ.get("PATH", "/usr/bin"), **env},
            capture_output=True, text=True, check=True,
        )
        results.append({"env": env, "result": json.loads(completed.stdout)})
    payload = {"python": sys.version, "files": FILES, "cases": results}
    (out / "settings.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
