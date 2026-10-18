#!/usr/bin/env python3
"""Development stub for the monitoring screen: the static panel plus synthetic metrics.

    python3 scripts/dev/monitoring-stub-server.py [--port 18900] [--host 127.0.0.1]

Serves `panel/static` (the real UI) and answers `/api/auth/me`, the navigation counters and
`/api/metrics/{live,stream,history,summary}` in the JSON shapes of the monitoring plan, with
believable random-walk traffic: three nodes (one fresh, one fresh without Mieru, one stale),
five protocols, one of them (`naive`) not live. Every value is a pure function of
(node, series, time), so the live feed, the history and the summary agree with each other.

Standard library only. It is a lab tool: no authentication, never put it on a real host.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

STATIC = Path(__file__).resolve().parents[2] / "panel" / "static"
PROTOCOLS = ("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel")
INTERVAL = 2
RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000}
STALE_AGE = 140

NODES = {
    "local": {"name": "Этот сервер", "cores": 4, "mem": 8 << 30, "disk": 80 << 30, "scale": 1.0, "stale": False,
              "missing": (), "live_off": ("naive",)},
    "fra-1": {"name": "Frankfurt", "cores": 2, "mem": 4 << 30, "disk": 40 << 30, "scale": 0.55, "stale": False,
              "missing": ("mieru",), "live_off": ("naive",)},
    "ams-2": {"name": "Amsterdam", "cores": 2, "mem": 2 << 30, "disk": 25 << 30, "scale": 0.3, "stale": True,
              "missing": ("trusttunnel",), "live_off": ("naive",)},
}

BASE_RATE = {  # bytes per second at scale 1, (up, down)
    "mtproxy": (180_000, 1_400_000),
    "naive": (90_000, 700_000),
    "mieru": (60_000, 380_000),
    "amneziawg": (320_000, 2_600_000),
    "trusttunnel": (140_000, 1_100_000),
}
CLIENT_NAMES = ["alice", "bob", "carol-phone", "dave", "erin-laptop", "frank", "grace", "heidi-tv", "ivan", "judy"]
CONTAINERS = [("mtproxy-telemt", 6, 90), ("mtproxy-panel", 3, 140), ("mtproxy-naive", 4, 70), ("mtproxy-mieru", 2, 55),
              ("mtproxy-xray-router", 5, 110), ("mtproxy-trusttunnel", 7, 160), ("mtproxy-version-agent", 1, 30)]


def noise(key: str, bucket: int) -> float:
    digest = hashlib.blake2b(f"{key}:{bucket}".encode(), digest_size=4).digest()
    return int.from_bytes(digest, "big") / 0xFFFFFFFF


def smooth(key: str, t: float, period: float) -> float:
    """Value noise in [0, 1]: linear blend of hashed lattice points, so it wanders."""
    bucket = math.floor(t / period)
    fraction = t / period - bucket
    fraction = fraction * fraction * (3 - 2 * fraction)
    return noise(key, bucket) * (1 - fraction) + noise(key, bucket + 1) * fraction


def day_factor(t: float) -> float:
    hour = (t % 86400) / 3600
    return 0.62 + 0.38 * math.sin((hour - 9) / 24 * 2 * math.pi)


def effective_time(node: str, t: float) -> float:
    return t - STALE_AGE if NODES[node]["stale"] else t


def rate(node: str, proto: str, direction: int, t: float) -> float:
    base = BASE_RATE[proto][direction] * NODES[node]["scale"]
    key = f"{node}{proto}{direction}"
    wander = 0.25 + 1.5 * (0.55 * smooth(key, t, 45) + 0.3 * smooth(key + "m", t, 9) + 0.15 * smooth(key + "f", t, 2.5))
    spike = 3.2 if smooth(key + "s", t, 600) > 0.93 else 1.0
    return max(0.0, base * day_factor(t) * wander * spike)


def pct(node: str, series: str, t: float, low: float, high: float) -> float:
    key = f"{node}{series}"
    return low + (high - low) * (0.6 * smooth(key, t, 60) + 0.3 * smooth(key + "m", t, 11) + 0.1 * smooth(key + "f", t, 2.5))


def series_value(node: str, series: str, t: float) -> float | None:
    t = effective_time(node, t)
    spec = NODES[node]
    if series == "host.cpu":
        base = 38 if node == "fra-1" else 14
        return min(99.0, pct(node, series, t, base * 0.4, base * 2.4 + (35 if node == "fra-1" else 8)) * (0.8 + 0.4 * day_factor(t)))
    if series == "host.mem":
        return pct(node, series, t, 38, 62) if node != "fra-1" else pct(node, series, t, 72, 91)
    if series == "host.swap":
        return pct(node, series, t, 2, 12) if node == "fra-1" else 0.0
    if series == "host.disk":
        return 41.0 + 0.0004 * ((t % 1_000_000) / 10)
    if series == "host.disk_read_bps":
        return 40_000 + 900_000 * smooth(node + "dr", t, 20) ** 3
    if series == "host.disk_write_bps":
        return 120_000 + 1_800_000 * smooth(node + "dw", t, 15) ** 3
    if series == "host.load1":
        return spec["cores"] * pct(node, series, t, 0.08, 0.7)
    if series in ("net.rx_bps", "net.tx_bps"):
        direction = 0 if series == "net.rx_bps" else 1
        return sum(rate(node, p, direction, t) for p in PROTOCOLS if p not in spec["missing"]) * 1.04 + 8_000
    proto, _, metric = series.partition(".")
    if proto in PROTOCOLS and proto not in spec["missing"]:
        if metric == "up_bps":
            return rate(node, proto, 0, t)
        if metric == "down_bps":
            return rate(node, proto, 1, t)
        if metric == "sessions":
            return round(3 + 40 * smooth(node + proto + "s", t, 90) * NODES[node]["scale"] * day_factor(t) * 2)
        if metric == "clients":
            return round(1 + 9 * smooth(node + proto + "c", t, 300) * NODES[node]["scale"] * 1.5)
    return None


def cumulative(node: str, proto: str, direction: int, t: float) -> int:
    start = 1_792_000_000  # a fixed origin: counters only grow
    average = BASE_RATE[proto][direction] * NODES[node]["scale"] * 0.9
    return int(average * (t - start) % (1 << 52)) if t > start else 0


def node_snapshot(node: str, now: float) -> dict:
    spec = NODES[node]
    stale = spec["stale"]
    t = effective_time(node, now)
    value = lambda s: series_value(node, s, now)  # noqa: E731
    cpu, mem, swap = value("host.cpu"), value("host.mem"), value("host.swap")
    protocols = {}
    for proto in PROTOCOLS:
        if proto in spec["missing"]:
            protocols[proto] = {"available": False, "live": False, "source": None, "up_bps": None, "down_bps": None,
                                "up_bytes": None, "down_bytes": None, "sessions": None, "clients": None}
            continue
        live = proto not in spec["live_off"]
        protocols[proto] = {
            "available": True, "live": live, "source": "kernel" if live else "manager",
            "up_bps": round(value(f"{proto}.up_bps")) if live else None,
            "down_bps": round(value(f"{proto}.down_bps")) if live else None,
            "up_bytes": cumulative(node, proto, 0, t), "down_bytes": cumulative(node, proto, 1, t),
            "sessions": value(f"{proto}.sessions"), "clients": value(f"{proto}.clients"),
        }
    clients = []
    for index, name in enumerate(CLIENT_NAMES):
        proto = PROTOCOLS[index % 3 + (1 if index % 5 == 4 else 0)]
        if proto in spec["missing"]:
            continue
        weight = 1.0 / (index + 1.4)
        down = rate(node, proto, 1, t) * weight * 0.6 * (0.5 + smooth(name + node, t, 12))
        up = rate(node, proto, 0, t) * weight * 0.6 * (0.5 + smooth(name + node + "u", t, 12))
        combined = proto == "mtproxy"  # Telemt reports one combined counter
        clients.append({"protocol": proto, "username": name, "client_name": name.replace("-", " ").title(),
                        "up_bps": None if combined else round(up), "down_bps": None if combined else round(down),
                        "total_bps": round(up + down)})
    clients.sort(key=lambda row: -row["total_bps"])
    containers = [{"name": name, "cpu_percent": round(cpu_base * (0.4 + 1.2 * smooth(name + node, t, 20)), 1),
                   "mem_bytes": int(mem_mb * (1 << 20) * (0.92 + 0.16 * smooth(name + node + "m", t, 120)))}
                  for name, cpu_base, mem_mb in CONTAINERS]
    rx, tx = value("net.rx_bps"), value("net.tx_bps")
    return {
        "node_id": node, "name": spec["name"], "status": "stale" if stale else "ok", "age_seconds": STALE_AGE if stale else 0,
        "host": {
            "cpu_percent": round(cpu, 1), "cores": spec["cores"],
            "load": [round(value("host.load1"), 2), round(value("host.load1") * 0.9, 2), round(value("host.load1") * 0.75, 2)],
            "mem": {"used": int(spec["mem"] * mem / 100), "total": spec["mem"], "percent": round(mem, 1),
                    "available": int(spec["mem"] * (1 - mem / 100))},
            "swap": {"used": int((2 << 30) * swap / 100), "total": 2 << 30 if node == "fra-1" else 0, "percent": round(swap, 1)},
            "disk": {"used": int(spec["disk"] * value("host.disk") / 100), "total": spec["disk"], "percent": round(value("host.disk"), 1),
                     "read_bps": round(value("host.disk_read_bps")), "write_bps": round(value("host.disk_write_bps")),
                     "busy_percent": round(min(100, value("host.disk_write_bps") / 25_000), 1)},
            "net": {"rx_bps": round(rx), "tx_bps": round(tx),
                    "interfaces": [{"name": "eth0", "rx_bps": round(rx), "tx_bps": round(tx), "rx_bytes": int(t * 900), "tx_bytes": int(t * 4200)}]},
            "uptime_seconds": int(t % 4_000_000) + 86400 * 12,
            "containers": containers,
        },
        "protocols": protocols, "top_clients": clients[:10], "kernel_counters": "ok",
    }


def snapshot(node: str) -> dict:
    now = time.time()
    if node == "all":
        nodes = [node_snapshot(name, now) for name in NODES]
    elif node in NODES:
        nodes = [node_snapshot(node, now)]
    else:
        nodes = [{"node_id": node, "name": node, "status": "unsupported", "age_seconds": None}]
    return {"ts": int(now), "interval": INTERVAL, "nodes": nodes}


def history(node: str, series: list[str], range_name: str, points: int) -> dict:
    span = RANGES.get(range_name, 3600)
    now = int(time.time())
    step = max(INTERVAL, span // max(points, 2))
    # long ranges come from coarser rollups: snap the step to 60 s / 900 s / 3600 s
    for native in (INTERVAL, 60, 900, 3600):
        if step <= native:
            step = native
            break
    else:
        step = 3600
    start = now - now % step - span
    out: dict[str, list] = {}
    nodes = list(NODES) if node == "all" else [node]
    for name in series:
        rows = []
        for stamp in range(start, now, step):
            subs = (0.15, 0.5, 0.85) if step >= 30 else (0.5,)
            values = [sum(series_value(n, name, stamp + step * f) or 0 for f in subs) / len(subs) for n in nodes if n in NODES and series_value(n, name, stamp) is not None]
            if not values or any(v is None for v in values):
                continue
            if node != "all" and NODES[node]["stale"] and stamp > now - 600:
                continue  # the stale node left a gap
            if 0.2 < smooth("hole" + node, stamp, 5000) < 0.205:
                continue  # a deliberate hole: gaps stay gaps
            average = sum(values) if name.endswith("_bps") or name.endswith("sessions") else sum(values) / len(values)
            rows.append([stamp, round(average, 2), round(average * 1.25 + 1, 2)])
        out[name] = rows
    return {"node_id": node, "range": range_name, "step": step, "from": start, "to": now, "series": out}


def stats(values: list[float], stamps: list[int]) -> dict:
    ordered = sorted(values)
    peak = max(range(len(values)), key=values.__getitem__)
    return {"avg": round(sum(values) / len(values), 2), "p95": round(ordered[int(len(ordered) * 0.95) - 1], 2),
            "max": round(values[peak], 2), "max_at": stamps[peak]}


def node_summary(node: str, range_name: str) -> dict:
    span = RANGES.get(range_name, 86400)
    now = int(time.time())
    count = 200
    stamps = [now - span + int(span * i / count) for i in range(count)]
    spec = NODES[node]
    grab = lambda s: [series_value(node, s, t) or 0.0 for t in stamps]  # noqa: E731
    host = {"cpu": stats(grab("host.cpu"), stamps), "mem": stats(grab("host.mem"), stamps), "disk": stats(grab("host.disk"), stamps),
            "net_rx_bps": stats(grab("net.rx_bps"), stamps), "net_tx_bps": stats(grab("net.tx_bps"), stamps)}
    protocols = {}
    totals = {}
    for proto in PROTOCOLS:
        if proto in spec["missing"]:
            continue
        up, down = grab(f"{proto}.up_bps"), grab(f"{proto}.down_bps")
        totals[proto] = (sum(up) * span / count, sum(down) * span / count)
        both = [a + b for a, b in zip(up, down)]
        peak = stats(both, stamps)
        protocols[proto] = {"up_bytes": int(totals[proto][0]), "down_bytes": int(totals[proto][1]),
                            "total_bytes": int(sum(totals[proto])), "avg_bps": peak["avg"], "peak_bps": peak["max"],
                            "peak_at": peak["max_at"], "sessions_peak": int(max(grab(f"{proto}.sessions")))}
    grand = sum(sum(v) for v in totals.values()) or 1
    for proto, row in protocols.items():
        row["share_percent"] = round(100 * row["total_bytes"] / grand, 1)
    hours = {proto: [round(rate(node, proto, 1, 86400 * 3 + h * 3600 + 1800) + rate(node, proto, 0, 86400 * 3 + h * 3600 + 1800))
                     for h in range(24)] for proto in protocols}
    alerts = []
    if spec["stale"]:
        alerts.append({"kind": "stale", "severity": "critical", "since": now - STALE_AGE, "detail": f"нет данных {STALE_AGE} с"})
    if node == "fra-1":
        alerts.append({"kind": "mem", "severity": "warn", "since": now - 1800, "detail": "память > 90 % уже 30 минут"})
        alerts.append({"kind": "cpu", "severity": "warn", "since": now - 600, "detail": "CPU > 85 % 5 минут"})
    return {"node_id": node, "name": spec["name"], "status": "stale" if spec["stale"] else "ok", "age_seconds": STALE_AGE if spec["stale"] else 0,
            "range": range_name, "host": host, "protocols": protocols, "hours_of_day": hours if span >= 604800 else {},
            "alerts": alerts, "total_bytes": int(grand) if protocols else 0}


def summary(node: str, range_name: str) -> dict:
    """The panel's shape: {range, nodes: [full summaries], compare: [slim ranking] (node=all only)}."""
    names = list(NODES) if node == "all" else [node]
    rows = [node_summary(name, range_name) if name in NODES else {"node_id": name, "name": name, "status": "unsupported", "host": None,
                                                                 "protocols": {}, "hours_of_day": {}, "alerts": []} for name in names]
    body = {"range": range_name, "nodes": rows}
    if node == "all":
        body["compare"] = sorted(({"node_id": r["node_id"], "name": r["name"], "status": r["status"], "total_bytes": r.get("total_bytes"),
                                   "alerts": len(r["alerts"])} for r in rows), key=lambda r: -(r["total_bytes"] or 0))
    return body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # quiet
        pass

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def static(self, name: str) -> None:
        path = (STATIC / name.lstrip("/")).resolve()
        if STATIC not in path.parents and path != STATIC / "index.html" or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        kind = {".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".json": "application/json",
                ".png": "image/png", ".svg": "image/svg+xml"}.get(path.suffix, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{kind}; charset=utf-8" if kind.startswith("text") else kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # the real panel's policy: the stub must not hide a CSP violation
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        args = {key: values[0] for key, values in parse_qs(url.query).items()}
        path = url.path
        if path == "/api/auth/me":
            return self.send_json({"username": "owner", "role": args.get("role", "owner"), "panel_version": "2.0.0-stub",
                                   "features": {"naive": True, "mieru": True, "amneziawg": True, "trusttunnel": True}})
        if path in ("/api/fleet/nodes", "/api/clients", "/api/users"):
            return self.send_json({"items": []})
        if path == "/api/dashboard":
            return self.send_json({"protocols": {}, "host": {"available": False}})
        if path == "/api/metrics/live":
            return self.send_json(snapshot(args.get("node", "local")))
        if path == "/api/metrics/history":
            series = [item for item in args.get("series", "host.cpu").split(",") if item]
            return self.send_json(history(args.get("node", "local"), series, args.get("range", "1h"), int(args.get("points", 240))))
        if path == "/api/metrics/summary":
            return self.send_json(summary(args.get("node", "local"), args.get("range", "24h")))
        if path == "/api/metrics/stream":
            return self.stream(args.get("node", "local"))
        if path in ("/", "/index.html"):
            return self.static("index.html")
        if path.startswith("/static/"):
            return self.static(path[len("/static/"):])
        self.send_error(HTTPStatus.NOT_FOUND)

    def stream(self, node: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            while True:
                self.wfile.write(f"event: snapshot\ndata: {json.dumps(snapshot(node), ensure_ascii=False)}\n\n".encode())
                self.wfile.flush()
                time.sleep(INTERVAL)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18900)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"monitoring stub on http://{args.host}:{args.port}/#monitoring")
    server.serve_forever()


if __name__ == "__main__":
    main()
