"""Live host telemetry sampler behind `GET /v1/metrics`.

A daemon thread reads /proc, cgroup v2 and an nftables counter table once a second and keeps the
latest sample in memory; the HTTP handler only returns that cached dict. Everything is read-only
toward the protocols: the nft rules only count and never decide a verdict.

Bytes in the sample (`rx_bytes`, `up_bytes`, ...) are cumulative since the sampler started
counting (a counter that goes down — table recreated, interface reset — is a reset: the new
reading is the delta). Rates are computed here from `time.monotonic()`. Direction is the
client's point of view: up = from clients (dport, input hook), down = to clients (sport, output
hook). nft figures are L3 bytes, headers included.

Clean-up of the kernel side, should the agent be removed: `nft delete table inet proxy_control_metrics`.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path

LOG = logging.getLogger("version_agent.metrics")

TABLE = "proxy_control_metrics"
INTERVAL = 1.0
DISCOVERY_INTERVAL = 60.0
CONTAINER_NAMES_TTL = 30.0
NFT_RETRY_SECONDS = 30.0
_SKIP_PREFIXES = ("lo", "veth", "br-", "docker", "awg", "tun", "wg")
_COUNTER_NAME = re.compile(r"^(up|down)_([a-z0-9]+)_(tcp|udp)_([0-9]{1,5})$")
_PROTOCOL_NAME = re.compile(r"^[a-z0-9]+$")


class NftUnavailable(RuntimeError):
    pass


def _nft(args: list[str], stdin: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["nft", *args], input=stdin, text=True, capture_output=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NftUnavailable(type(exc).__name__) from exc
    if result.returncode != 0:
        raise NftUnavailable(result.stderr.strip().splitlines()[-1][:200] if result.stderr.strip() else "nft failed")
    return result.stdout


def _run(command: list[str], *, timeout: float = 10) -> str:
    return subprocess.run(
        command, text=True, capture_output=True, timeout=timeout, check=True
    ).stdout.strip()


def render_ruleset(port_map: Mapping[str, Mapping[str, list[int]]]) -> str:
    """One transaction: drop our table if present, define it again. Nothing else is touched."""
    counters, inputs, outputs = [], [], []
    for protocol in sorted(port_map):
        if not _PROTOCOL_NAME.match(protocol):
            continue
        for transport in ("tcp", "udp"):
            for port in port_map[protocol].get(transport, []):
                for direction, rules, key in (("up", inputs, "dport"), ("down", outputs, "sport")):
                    name = f"{direction}_{protocol}_{transport}_{port}"
                    counters.append(f"    counter {name} {{ }}")
                    rules.append(f'    {transport} {key} {port} counter name "{name}"')
    lines = [f"add table inet {TABLE}", f"delete table inet {TABLE}", f"table inet {TABLE} {{", *counters]
    for chain, hook, rules in (("input", "input", inputs), ("output", "output", outputs)):
        lines.append(f"  chain {chain} {{")
        lines.append(f"    type filter hook {hook} priority -300; policy accept;")
        lines.extend(rules)
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def parse_counters(output: str) -> dict[str, int]:
    """Bytes per named counter of our table from `nft -j list counters table ...`."""
    try:
        items = json.loads(output).get("nftables", [])
    except (ValueError, AttributeError) as exc:
        raise NftUnavailable("unparseable nft output") from exc
    found = {}
    for item in items:
        counter = item.get("counter") if isinstance(item, dict) else None
        if isinstance(counter, dict) and isinstance(counter.get("name"), str) and isinstance(counter.get("bytes"), int):
            found[counter["name"]] = counter["bytes"]
    return found


class Deltas:
    """Reset-aware deltas and running totals for named monotonic counters."""

    def __init__(self) -> None:
        self.previous: dict[str, int] = {}
        self.totals: dict[str, int] = {}

    def update(self, key: str, value: int) -> int:
        before = self.previous.get(key)
        self.previous[key] = value
        if before is None:
            delta = 0  # baseline: a first reading says nothing about a period
        else:
            delta = value if value < before else value - before
        self.totals[key] = self.totals.get(key, 0) + delta
        return delta

    def forget_missing(self, keys) -> None:
        for key in set(self.previous) - set(keys):
            self.previous.pop(key, None)


def _round(value: float, digits: int = 1) -> float:
    return round(value, digits)


class MetricsSampler:
    def __init__(
        self,
        *,
        ports: Callable[[], Mapping[str, Mapping[str, list[int]]]] = lambda: {},
        runner: Callable[..., str] | None = None,
        nft: Callable[..., str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        proc: Path = Path("/proc"),
        cgroup: Path = Path("/sys/fs/cgroup"),
        virtual_net: Path = Path("/sys/devices/virtual/net"),
        root_path: str = "/",
        root_device: str | None = None,
        statvfs: Callable[[str], os.statvfs_result] = os.statvfs,
        cores: int | None = None,
        interval: float = INTERVAL,
    ) -> None:
        self._ports = ports
        self._runner = runner or _run
        self._nft = nft or _nft
        self._clock = clock
        self._wall = wall
        self._proc = Path(proc)
        self._cgroup = Path(cgroup)
        self._virtual_net = Path(virtual_net)
        self._root_path = root_path
        self._root_device = root_device
        self._statvfs = statvfs
        self._cores = cores if cores is not None else os.cpu_count()
        self.interval = interval
        self._lock = threading.Lock()
        self._latest: dict | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # state between ticks
        self._last_clock: float | None = None
        self._cpu_prev: tuple[int, int] | None = None
        self._net = Deltas()
        self._disk = Deltas()
        self._containers = Deltas()
        self._kernel = Deltas()
        self._net_delta: dict[str, tuple[int, int]] = {}
        self._proto_totals: dict[tuple[str, str], int] = {}
        self._port_map: dict[str, dict[str, list[int]]] = {}
        self._ports_checked: float | None = None
        self._applied: dict[str, dict[str, list[int]]] | None = None
        self._nft_failed_at: float | None = None
        self._nft_state = "ok"
        self._names: dict[str, str] = {}
        self._names_at: float | None = None
        self._device_resolved = root_device is not None

    # --- public ---------------------------------------------------------------------------

    def latest(self) -> dict | None:
        with self._lock:
            return self._latest

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="host-metrics", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def tick(self) -> dict | None:
        """One sampling pass. The first call only primes the baselines and publishes nothing."""
        now = self._clock()
        elapsed = None if self._last_clock is None else now - self._last_clock
        self._last_clock = now
        host = self._host(now, elapsed)
        protocols, kernel = self._protocols(now, elapsed)
        if elapsed is None or elapsed <= 0:
            return None
        sample = {
            "ts": round(self._wall(), 3),
            "interval": self.interval,
            "host": host,
            "protocols": protocols,
            "kernel_counters": kernel,
        }
        with self._lock:
            self._latest = sample
        return sample

    # --- loop -----------------------------------------------------------------------------

    def _loop(self) -> None:
        next_at = time.monotonic()
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - the sampler must outlive any bad reading
                LOG.warning("metrics tick failed: %s: %s", type(exc).__name__, str(exc)[:200])
            next_at += self.interval
            delay = next_at - time.monotonic()
            if delay < -5 * self.interval:  # stalled (suspend): do not burst to catch up
                next_at = time.monotonic()
                delay = 0
            if self._stop.wait(max(0.0, delay)):
                return

    # --- host -----------------------------------------------------------------------------

    def _read(self, relative: str) -> str | None:
        try:
            return (self._proc / relative).read_text()
        except OSError:
            return None

    def _cpu_percent(self) -> float | None:
        text = self._read("stat")
        if not text:
            return None
        fields = text.split("\n", 1)[0].split()
        if len(fields) < 6 or fields[0] != "cpu":
            return None
        try:
            values = [int(v) for v in fields[1:]]
        except ValueError:
            return None
        current = (sum(values), values[3] + values[4])
        previous, self._cpu_prev = self._cpu_prev, current
        if previous is None:
            return None
        total, idle = current[0] - previous[0], current[1] - previous[1]
        if total <= 0:
            return None
        return _round(min(100.0, max(0.0, 100.0 * (total - idle) / total)))

    def _meminfo(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for line in (self._read("meminfo") or "").splitlines():
            key, _, rest = line.partition(":")
            fields = rest.split()
            if fields and fields[0].isdigit():
                values[key] = int(fields[0]) * 1024
        return values

    @staticmethod
    def _used(total: int | None, available: int | None) -> dict | None:
        if not total or available is None:
            return None
        available = min(available, total)
        used = total - available
        return {"used": used, "total": total, "percent": _round(100.0 * used / total), "available": available}

    def _disk_usage(self) -> dict:
        try:
            st = self._statvfs(self._root_path)
        except OSError:
            return {}
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            return {}
        used = total - st.f_bfree * st.f_frsize
        return {"used": used, "total": total, "percent": _round(100.0 * used / total)}

    def _resolve_root_device(self) -> str | None:
        if self._device_resolved:
            return self._root_device
        self._device_resolved = True
        text = self._read("self/mountinfo")
        for line in (text or "").splitlines():
            head, _, tail = line.partition(" - ")
            fields = head.split()
            if len(fields) > 4 and fields[4] == "/" and tail:
                source = tail.split()[1] if len(tail.split()) > 1 else ""
                if source.startswith("/dev/"):
                    self._root_device = os.path.basename(os.path.realpath(source))
        return self._root_device

    def _disk_io(self, now: float, elapsed: float | None) -> dict:
        empty = {"read_bps": None, "write_bps": None, "busy_percent": None}
        device = self._resolve_root_device()
        if not device:
            return empty
        for line in (self._read("diskstats") or "").splitlines():
            parts = line.split()
            if len(parts) > 12 and parts[2] == device:
                try:
                    read_b, write_b, ticks = int(parts[5]) * 512, int(parts[9]) * 512, int(parts[12])
                except ValueError:
                    return empty
                dr = self._disk.update("read", read_b)
                dw = self._disk.update("write", write_b)
                dt = self._disk.update("ticks", ticks)
                if not elapsed or elapsed <= 0:
                    return empty
                return {
                    "read_bps": _round(dr / elapsed),
                    "write_bps": _round(dw / elapsed),
                    "busy_percent": _round(min(100.0, 100.0 * dt / (elapsed * 1000.0))),
                }
        return empty

    def _net_dev(self) -> dict[str, tuple[int, int]]:
        found = {}
        for line in (self._read("net/dev") or "").splitlines()[2:]:
            name, _, rest = line.partition(":")
            fields = rest.split()
            if len(fields) >= 9 and fields[0].isdigit() and fields[8].isdigit():
                found[name.strip()] = (int(fields[0]), int(fields[8]))
        return found

    def _host(self, now: float, elapsed: float | None) -> dict:
        info = self._meminfo()
        swap_total = info.get("SwapTotal")
        swap = None
        if swap_total is not None and "SwapFree" in info:
            swap = {"used": 0, "total": 0, "percent": None, "available": 0}
            if swap_total:
                free = min(info["SwapFree"], swap_total)
                swap = {
                    "used": swap_total - free, "total": swap_total,
                    "percent": _round(100.0 * (swap_total - free) / swap_total), "available": free,
                }
        loadavg = (self._read("loadavg") or "").split()[:3]
        try:
            load = [round(float(v), 2) for v in loadavg] if len(loadavg) == 3 else None
        except ValueError:
            load = None
        uptime_text = (self._read("uptime") or "").split()
        try:
            uptime = int(float(uptime_text[0])) if uptime_text else None
        except ValueError:
            uptime = None
        disk = self._disk_usage()
        disk.update(self._disk_io(now, elapsed))
        return {
            "cpu_percent": self._cpu_percent(),
            "cores": self._cores,
            "load": load,
            "mem": self._used(info.get("MemTotal"), info.get("MemAvailable")),
            "swap": swap,
            "disk": disk,
            "net": self._network(elapsed),
            "uptime_seconds": uptime,
            "containers": self._container_stats(now, elapsed),
        }

    def _network(self, elapsed: float | None) -> dict:
        interfaces = []
        rx_total = tx_total = 0.0
        readings = self._net_dev()
        self._net_delta = {}
        self._net.forget_missing([f"{n}:{d}" for n in readings for d in ("rx", "tx")])
        for name, (rx, tx) in sorted(readings.items()):
            drx, dtx = self._net.update(f"{name}:rx", rx), self._net.update(f"{name}:tx", tx)
            self._net_delta[name] = drx, dtx
            # Virtual devices (veth, tap, bridges, tunnels under any name) would double-count the NIC.
            if name.startswith(_SKIP_PREFIXES) or (self._virtual_net / name).exists():
                continue
            rx_bps = _round(drx / elapsed) if elapsed else None
            tx_bps = _round(dtx / elapsed) if elapsed else None
            rx_total += rx_bps or 0
            tx_total += tx_bps or 0
            interfaces.append({
                "name": name, "rx_bps": rx_bps, "tx_bps": tx_bps,
                "rx_bytes": self._net.totals[f"{name}:rx"], "tx_bytes": self._net.totals[f"{name}:tx"],
            })
        return {"rx_bps": _round(rx_total), "tx_bps": _round(tx_total), "interfaces": interfaces}

    # --- containers -----------------------------------------------------------------------

    def _container_names(self, now: float) -> dict[str, str]:
        if self._names_at is not None and now - self._names_at < CONTAINER_NAMES_TTL:
            return self._names
        self._names_at = now
        try:
            listing = self._runner(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"], timeout=5)
        except Exception as exc:  # noqa: BLE001 - docker absent or slow: no container section
            _log_once("docker-ps", "container names unavailable: %s", type(exc).__name__)
            self._names = {}
            return self._names
        names = {}
        for line in listing.splitlines():
            container_id, _, name = line.strip().partition(" ")
            if re.fullmatch(r"[0-9a-f]{64}", container_id) and name:
                names[container_id] = name
        self._names = names
        return names

    def _container_stats(self, now: float, elapsed: float | None) -> list[dict]:
        names = self._container_names(now)
        stats = []
        seen = []
        for container_id, name in names.items():
            scope = self._cgroup / "system.slice" / f"docker-{container_id}.scope"
            try:
                cpu_text = (scope / "cpu.stat").read_text()
                mem = int((scope / "memory.current").read_text().strip())
                usage = next(int(line.split()[1]) for line in cpu_text.splitlines() if line.startswith("usage_usec "))
            except (OSError, ValueError, StopIteration):
                continue
            seen.append(name)
            delta = self._containers.update(name, usage)
            percent = _round(100.0 * delta / (elapsed * 1_000_000.0)) if elapsed else None
            stats.append({"name": name, "cpu_percent": percent, "mem_bytes": mem})
        self._containers.forget_missing(seen)
        return sorted(stats, key=lambda item: item["name"])

    # --- protocols ------------------------------------------------------------------------

    def _discover(self, now: float) -> None:
        if self._ports_checked is not None and now - self._ports_checked < DISCOVERY_INTERVAL:
            return
        self._ports_checked = now
        try:
            found = {
                protocol: {t: sorted(set(transports.get(t, []))) for t in ("tcp", "udp")}
                for protocol, transports in self._ports().items()
            }
        except Exception as exc:  # noqa: BLE001 - keep the last known map
            _log_once("discover", "port discovery failed: %s", type(exc).__name__)
            return
        self._port_map = {p: t for p, t in found.items() if t["tcp"] or t["udp"]}

    def _read_kernel(self, now: float) -> dict[str, int] | None:
        """Counters of our table, (re)creating it when the port map changed. None = unavailable."""
        if self._nft_failed_at is not None and now - self._nft_failed_at < NFT_RETRY_SECONDS:
            return None
        try:
            if self._applied != self._port_map:
                self._nft(["-f", "-"], stdin=render_ruleset(self._port_map))
                self._applied = {p: {t: list(v) for t, v in m.items()} for p, m in self._port_map.items()}
            counters = parse_counters(self._nft(["-j", "list", "counters", "table", "inet", TABLE]))
        except NftUnavailable as exc:
            self._nft_failed_at = now
            self._applied = None
            if self._nft_state != "unavailable":
                LOG.warning("kernel counters unavailable: %s", exc)
            self._nft_state = "unavailable"
            return None
        self._nft_failed_at = None
        if self._nft_state != "ok":
            LOG.info("kernel counters available again")
        self._nft_state = "ok"
        return counters

    def _established(self) -> dict[int, int] | None:
        """Established TCP connections per LOCAL port from /proc/net/tcp{,6}; None = unreadable."""
        counts: dict[int, int] = {}
        readable = False
        for name in ("net/tcp", "net/tcp6"):
            text = self._read(name)
            if text is None:
                continue
            readable = True
            for line in text.splitlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and fields[3] == "01":
                    _, _, port = fields[1].rpartition(":")
                    try:
                        key = int(port, 16)
                    except ValueError:
                        continue
                    counts[key] = counts.get(key, 0) + 1
        return counts if readable else None

    def _connections(self, protocols: dict) -> None:
        """`connections` of every protocol entry: established TCP on the protocol's TCP ports."""
        wanted = {port for m in self._port_map.values() for port in m["tcp"]}
        counts = self._established() if wanted else None
        for protocol, entry in protocols.items():
            tcp = self._port_map.get(protocol, {}).get("tcp") or []
            entry["connections"] = sum(counts.get(p, 0) for p in tcp) if counts is not None and tcp else None

    def _protocols(self, now: float, elapsed: float | None) -> tuple[dict, str]:
        protocols, kernel = self._protocol_rates(now, elapsed)
        self._connections(protocols)
        return protocols, kernel

    def _protocol_rates(self, now: float, elapsed: float | None) -> tuple[dict, str]:
        self._discover(now)
        protocols: dict[str, dict] = {}
        counters = self._read_kernel(now) if self._port_map else None
        if self._port_map and counters is None:
            kernel = "unavailable"
        else:
            kernel = "ok"
        if counters is not None:
            totals: dict[str, dict[str, list[int]]] = {}
            for name, value in counters.items():
                match = _COUNTER_NAME.match(name)
                if not match:
                    continue
                direction, protocol, _transport, _port = match.groups()
                delta = self._kernel.update(name, value)
                key = (protocol, direction)
                self._proto_totals[key] = self._proto_totals.get(key, 0) + delta
                bucket = totals.setdefault(protocol, {"up": [0, 0], "down": [0, 0]})[direction]
                bucket[0] += delta
                bucket[1] = self._proto_totals[key]
            self._kernel.forget_missing(counters)
            for protocol, sums in totals.items():
                if protocol not in self._port_map:
                    continue
                protocols[protocol] = {
                    "up_bps": _round(sums["up"][0] / elapsed) if elapsed else None,
                    "down_bps": _round(sums["down"][0] / elapsed) if elapsed else None,
                    "up_bytes": sums["up"][1],
                    "down_bytes": sums["down"][1],
                    "source": "kernel",
                }
        awg = [n for n in self._net_delta if n.startswith("awg")]
        if awg:
            up = sum(self._net_delta[n][0] for n in awg)
            down = sum(self._net_delta[n][1] for n in awg)
            protocols["amneziawg"] = {
                "up_bps": _round(up / elapsed) if elapsed else None,
                "down_bps": _round(down / elapsed) if elapsed else None,
                "up_bytes": sum(self._net.totals[f"{n}:rx"] for n in awg),
                "down_bytes": sum(self._net.totals[f"{n}:tx"] for n in awg),
                "source": "interface",
            }
        return protocols, kernel


_logged: set[str] = set()


def _log_once(key: str, message: str, *args) -> None:
    if key not in _logged:
        _logged.add(key)
        LOG.warning(message, *args)


# --- process-wide instance used by the HTTP handler ---------------------------------------

_sampler: MetricsSampler | None = None


def install(sampler: MetricsSampler) -> MetricsSampler:
    global _sampler
    _sampler = sampler
    return sampler


def metrics_response() -> tuple[int, dict]:
    """Status and body for `GET /v1/metrics`: the cached sample, never a blocking read."""
    sample = _sampler.latest() if _sampler is not None else None
    if sample is None:
        return 503, {"detail": "metrics_warming_up"}
    return 200, sample
