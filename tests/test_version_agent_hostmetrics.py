from __future__ import annotations

import json
import threading

from version_agent import hostmetrics
from version_agent.hostmetrics import MetricsSampler, NftUnavailable, Deltas, parse_counters, render_ruleset


class FakeHost:
    """A tmp-dir /proc and cgroup tree that tests rewrite between ticks."""

    def __init__(self, tmp_path):
        self.proc = tmp_path / "proc"
        self.cg = tmp_path / "cg"
        (self.proc / "net").mkdir(parents=True)
        (self.proc / "self").mkdir()
        self.cpu = [100, 0, 100, 800, 0, 0, 0, 0]
        self.net = {"ens3": (1000, 500), "lo": (5, 5), "docker0": (7, 7), "awg15": (0, 0)}
        self.disk = (0, 0, 0)  # read sectors, write sectors, io ticks ms
        self.write()

    def write(self):
        (self.proc / "stat").write_text("cpu  " + " ".join(map(str, self.cpu)) + "\ncpu0 1 1 1 1\n")
        (self.proc / "loadavg").write_text("0.50 0.25 0.10 1/100 1234\n")
        (self.proc / "uptime").write_text("1234.56 99.0\n")
        (self.proc / "meminfo").write_text(
            "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 400 kB\nSwapFree: 300 kB\n")
        lines = ["Inter-|   Receive\n", " face |bytes\n"]
        for name, (rx, tx) in self.net.items():
            lines.append(f"{name:>6}: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n")
        (self.proc / "net" / "dev").write_text("".join(lines))
        r, w, t = self.disk
        (self.proc / "diskstats").write_text(f"   8  1 vda1 1 0 {r} 0 1 0 {w} 0 0 {t} 0\n")

    def container(self, cid, usage, mem):
        scope = self.cg / "system.slice" / f"docker-{cid}.scope"
        scope.mkdir(parents=True, exist_ok=True)
        (scope / "cpu.stat").write_text(f"usage_usec {usage}\nuser_usec 1\n")
        (scope / "memory.current").write_text(f"{mem}\n")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeStat:
    f_blocks, f_frsize, f_bfree, f_bavail = 1000, 4096, 400, 400


def make(tmp_path, host, clock, *, ports=None, nft=None, runner=None, **extra):
    return MetricsSampler(
        ports=(lambda: ports if ports is not None else {}), nft=nft, runner=runner or (lambda *a, **k: ""),
        clock=clock, wall=lambda: 1_700_000_000.0, proc=host.proc, cgroup=host.cg,
        root_device="vda1", statvfs=lambda _p: FakeStat(), cores=4, **extra,
    )


def test_first_tick_primes_and_publishes_nothing(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    sampler = make(tmp_path, host, clock)
    assert sampler.tick() is None
    assert sampler.latest() is None
    assert hostmetrics.metrics_response() == (503, {"detail": "metrics_warming_up"})


def test_host_rates_from_deltas(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    sampler = make(tmp_path, host, clock)
    sampler.tick()
    clock.now += 2.0
    host.cpu = [200, 0, 200, 900, 0, 0, 0, 0]
    host.net["ens3"] = (3000, 1500)
    host.net["lo"] = (999999, 999999)
    host.disk = (100, 200, 500)  # sectors of 512 B, 500 ms busy in 2 s
    host.write()
    sample = sampler.tick()
    h = sample["host"]
    assert h["cpu_percent"] == 66.7
    assert h["cores"] == 4 and h["load"] == [0.5, 0.25, 0.1] and h["uptime_seconds"] == 1234
    assert h["mem"] == {"used": 750 * 1024, "total": 1000 * 1024, "percent": 75.0, "available": 250 * 1024}
    assert h["swap"]["percent"] == 25.0
    assert h["disk"]["percent"] == 60.0
    assert h["disk"]["read_bps"] == 100 * 512 / 2 and h["disk"]["write_bps"] == 200 * 512 / 2
    assert h["disk"]["busy_percent"] == 25.0
    assert h["net"]["rx_bps"] == 1000.0 and h["net"]["tx_bps"] == 500.0
    assert [i["name"] for i in h["net"]["interfaces"]] == ["ens3"]
    assert h["net"]["interfaces"][0]["rx_bytes"] == 2000
    assert sample["interval"] == 1.0 and sample["ts"] == 1_700_000_000.0


def test_virtual_interfaces_of_any_name_stay_out_of_the_host_totals(tmp_path):
    """A veth/tap/bridge that a tool named freely (here `vmonawg`) is virtual in sysfs: it must not double-count."""
    host, clock = FakeHost(tmp_path), Clock()
    host.net["vmonawg"] = (10, 10)
    host.write()
    virtual = tmp_path / "sys-virtual-net"
    (virtual / "vmonawg").mkdir(parents=True)
    sampler = make(tmp_path, host, clock, virtual_net=virtual)
    sampler.tick()
    clock.now += 1
    host.net["vmonawg"] = (5_000_010, 5_000_010)
    host.net["ens3"] = (2000, 1000)
    host.write()
    net = sampler.tick()["host"]["net"]
    assert [i["name"] for i in net["interfaces"]] == ["ens3"]
    assert net["rx_bps"] == 1000.0


def test_cpu_percent_exact(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    sampler = make(tmp_path, host, clock)
    sampler.tick()
    clock.now += 1
    host.cpu = [175, 0, 100, 850, 0, 0, 0, 0]  # +75 busy, +50 idle
    host.write()
    assert sampler.tick()["host"]["cpu_percent"] == 60.0


def test_interface_counter_reset_uses_new_reading(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    sampler = make(tmp_path, host, clock)
    sampler.tick()
    clock.now += 1
    host.net["ens3"] = (5000, 500)
    host.write()
    sampler.tick()
    clock.now += 1
    host.net["ens3"] = (300, 500)  # interface reset: counter went down
    host.write()
    net = sampler.tick()["host"]["net"]
    assert net["interfaces"][0]["rx_bps"] == 300.0
    assert net["interfaces"][0]["rx_bytes"] == 4000 + 300


def test_amneziawg_from_interface_counters(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    sampler = make(tmp_path, host, clock)
    sampler.tick()
    clock.now += 2
    host.net["awg15"] = (4000, 2000)
    host.write()
    awg = sampler.tick()["protocols"]["amneziawg"]
    assert awg == {"up_bps": 2000.0, "down_bps": 1000.0, "up_bytes": 4000, "down_bytes": 2000,
                   "source": "interface", "connections": None}
    assert all(i["name"] != "awg15" for i in sampler.latest()["host"]["net"]["interfaces"])


def test_containers_from_cgroup_and_docker_ps(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    cid = "a" * 64
    host.container(cid, 1_000_000, 4096)
    calls = []

    def runner(command, **kw):
        calls.append(command)
        return f"{cid} proxy-control-panel\n{'b' * 64} not-in-cgroup\nnoise\n"

    sampler = make(tmp_path, host, clock, runner=runner)
    sampler.tick()
    clock.now += 2
    host.container(cid, 2_000_000, 8192)  # +1 s CPU over 2 s = 50 % of one core
    sampler.tick()
    sample = sampler.latest()
    assert sample["host"]["containers"] == [{"name": "proxy-control-panel", "cpu_percent": 50.0, "mem_bytes": 8192}]
    assert len(calls) == 1  # names cached for 30 s


def test_docker_failure_gives_empty_containers(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()

    def runner(command, **kw):
        raise OSError("no docker")

    sampler = make(tmp_path, host, clock, runner=runner)
    sampler.tick()
    clock.now += 1
    assert sampler.tick()["host"]["containers"] == []


NFT_JSON = {"nftables": [
    {"metainfo": {"version": "1.0.9"}},
    {"counter": {"family": "inet", "name": "up_naive_tcp_4443", "table": "proxy_control_metrics", "bytes": 1000, "packets": 5}},
    {"counter": {"family": "inet", "name": "down_naive_tcp_4443", "table": "proxy_control_metrics", "bytes": 4000, "packets": 5}},
]}


def test_parse_counters():
    assert parse_counters(json.dumps(NFT_JSON)) == {"up_naive_tcp_4443": 1000, "down_naive_tcp_4443": 4000}


def test_render_ruleset_is_one_atomic_script_for_our_table_only():
    text = render_ruleset({"naive": {"tcp": [4443], "udp": []}, "mieru": {"tcp": [], "udp": [9000]}})
    lines = text.splitlines()
    assert lines[0] == "add table inet proxy_control_metrics"
    assert lines[1] == "delete table inet proxy_control_metrics"
    assert 'tcp dport 4443 counter name "up_naive_tcp_4443"' in text
    assert 'tcp sport 4443 counter name "down_naive_tcp_4443"' in text
    assert 'udp dport 9000 counter name "up_mieru_udp_9000"' in text
    assert "hook input priority -300; policy accept;" in text
    assert "hook output priority -300; policy accept;" in text
    assert "flush ruleset" not in text and "accept\n    udp" not in text
    assert "verdict" not in text and " drop" not in text


class FakeNft:
    def __init__(self):
        self.counters = {"up_naive_tcp_4443": 1000, "down_naive_tcp_4443": 4000}
        self.scripts = []
        self.fail = None

    def __call__(self, args, stdin=None):
        if self.fail:
            raise NftUnavailable(self.fail)
        if stdin is not None:
            self.scripts.append(stdin)
            return ""
        return json.dumps({"nftables": [
            {"counter": {"name": n, "bytes": b}} for n, b in self.counters.items()]})


def test_kernel_counters_become_protocol_rates_and_totals(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    sampler = make(tmp_path, host, clock, ports={"naive": {"tcp": [4443], "udp": []}}, nft=nft)
    sampler.tick()
    assert len(nft.scripts) == 1
    clock.now += 2
    nft.counters = {"up_naive_tcp_4443": 3000, "down_naive_tcp_4443": 10000}
    sample = sampler.tick()
    assert sample["kernel_counters"] == "ok"
    assert sample["protocols"]["naive"] == {
        "up_bps": 1000.0, "down_bps": 3000.0, "up_bytes": 2000, "down_bytes": 6000, "source": "kernel",
        "connections": None}  # no /proc/net/tcp in the fake tree: unknown, not zero
    assert len(nft.scripts) == 1  # same map: not recreated


def test_kernel_counter_reset_is_a_reset_not_negative(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    sampler = make(tmp_path, host, clock, ports={"naive": {"tcp": [4443], "udp": []}}, nft=nft)
    sampler.tick()
    clock.now += 1
    nft.counters = {"up_naive_tcp_4443": 5000, "down_naive_tcp_4443": 5000}
    sampler.tick()
    clock.now += 1
    nft.counters = {"up_naive_tcp_4443": 200, "down_naive_tcp_4443": 100}  # table recreated
    p = sampler.tick()["protocols"]["naive"]
    assert p["up_bps"] == 200.0 and p["down_bps"] == 100.0
    assert p["up_bytes"] == 4000 + 200


def test_port_map_change_recreates_table_atomically(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    ports = {"naive": {"tcp": [4443], "udp": []}}
    sampler = MetricsSampler(
        ports=lambda: ports, nft=nft, runner=lambda *a, **k: "", clock=clock, wall=lambda: 1.0,
        proc=host.proc, cgroup=host.cg, root_device="vda1", statvfs=lambda _p: FakeStat())
    sampler.tick()
    ports = {"naive": {"tcp": [4443], "udp": []}, "mieru": {"tcp": [8443], "udp": []}}
    clock.now += hostmetrics.DISCOVERY_INTERVAL + 1
    sampler.tick()
    assert len(nft.scripts) == 2
    assert "mieru_tcp_8443" in nft.scripts[1] and nft.scripts[1].startswith("add table inet proxy_control_metrics")


def test_nft_failure_is_unavailable_without_protocol_numbers_and_logged_once(tmp_path, caplog):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    nft.fail = "nft: command not found"
    sampler = make(tmp_path, host, clock, ports={"naive": {"tcp": [4443], "udp": []}}, nft=nft)
    sampler.tick()
    for _ in range(3):
        clock.now += hostmetrics.NFT_RETRY_SECONDS + 1
        sample = sampler.tick()
    assert sample["kernel_counters"] == "unavailable"
    assert "naive" not in sample["protocols"]
    assert len([r for r in caplog.records if "kernel counters unavailable" in r.getMessage()]) == 1
    # recovers by itself
    nft.fail = None
    clock.now += hostmetrics.NFT_RETRY_SECONDS + 1
    assert sampler.tick()["kernel_counters"] == "ok"


def test_no_ports_means_no_nft_calls(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    sampler = make(tmp_path, host, clock, nft=nft)
    sampler.tick()
    clock.now += 1
    assert set(sampler.tick()["protocols"]) == {"amneziawg"}
    assert nft.scripts == []


def test_endpoint_shape_and_thread_safety(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    sampler = hostmetrics.install(make(tmp_path, host, clock))
    sampler.tick()
    clock.now += 1
    sampler.tick()
    status, body = hostmetrics.metrics_response()
    assert status == 200
    assert set(body) == {"ts", "interval", "host", "protocols", "kernel_counters"}
    assert set(body["host"]) == {
        "cpu_percent", "cores", "load", "mem", "swap", "disk", "net", "uptime_seconds", "containers"}
    assert set(body["host"]["net"]) == {"rx_bps", "tx_bps", "interfaces"}
    assert {"used", "total", "percent", "read_bps", "write_bps", "busy_percent"} <= set(body["host"]["disk"])
    json.dumps(body)
    errors = []

    def reader():
        try:
            for _ in range(200):
                hostmetrics.metrics_response()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    [t.start() for t in threads]
    for _ in range(50):
        clock.now += 1
        sampler.tick()
    [t.join() for t in threads]
    assert not errors
    hostmetrics.install(None)


def test_deltas_baseline_then_reset():
    d = Deltas()
    assert d.update("a", 100) == 0
    assert d.update("a", 150) == 50
    assert d.update("a", 20) == 20
    assert d.totals["a"] == 70


def test_route_over_the_agent_socket_warming_then_sample(tmp_path):
    import os

    import httpx

    from version_agent.server import Handler, UnixHTTPServer

    host, clock = FakeHost(tmp_path), Clock()
    sampler = hostmetrics.install(make(tmp_path, host, clock))
    server = UnixHTTPServer(str(tmp_path / "a.sock"), Handler, gid=os.getgid())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(tmp_path / "a.sock"))
        with httpx.Client(base_url="http://agent", transport=transport) as client:
            cold = client.get("/v1/metrics")
            assert cold.status_code == 503 and cold.json() == {"detail": "metrics_warming_up"}
            sampler.tick()
            clock.now += 1
            sampler.tick()
            warm = client.get("/v1/metrics")
            assert warm.status_code == 200 and warm.headers["cache-control"] == "no-store"
            assert warm.json()["host"]["cores"] == 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        hostmetrics.install(None)


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _row(local, state):
    return f"   0: {local} 0100007F:9C40 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1\n"


def test_connections_count_established_on_protocol_ports_only(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    nft.counters = {"up_naive_tcp_4443": 0, "down_naive_tcp_4443": 0, "up_trusttunnel_tcp_4453": 0,
                    "down_trusttunnel_tcp_4453": 0}
    (host.proc / "net" / "tcp").write_text(
        HEADER + _row("0100007F:115B", "01") * 2      # 4443 established x2
        + _row("0100007F:115B", "06")                  # TIME_WAIT: ignored
        + _row("00000000:115B", "0A")                  # LISTEN: ignored
        + _row("0100007F:1165", "01")                  # 4453 established
        + _row("0100007F:1F90", "01"))                 # unrelated 8080: ignored
    (host.proc / "net" / "tcp6").write_text(
        HEADER + _row("00000000000000000000000001000000:115B", "01")  # 4443 over ipv6
        + _row("00000000000000000000000001000000:1165", "08"))        # CLOSE_WAIT: ignored
    sampler = make(tmp_path, host, clock, nft=nft, ports={
        "naive": {"tcp": [4443], "udp": []}, "trusttunnel": {"tcp": [4453], "udp": []}})
    sampler.tick()
    clock.now += 1
    protocols = sampler.tick()["protocols"]
    assert protocols["naive"]["connections"] == 3
    assert protocols["trusttunnel"]["connections"] == 1


def test_connections_tolerate_missing_ipv6_and_garbage(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    (host.proc / "net" / "tcp").write_text(HEADER + _row("0100007F:115B", "01") + "garbage\n" + "0: x y\n")
    sampler = make(tmp_path, host, clock, nft=nft, ports={"naive": {"tcp": [4443], "udp": []}})
    sampler.tick()
    clock.now += 1
    assert sampler.tick()["protocols"]["naive"]["connections"] == 1


def test_connections_zero_when_files_readable_and_null_without_tcp_ports_or_files(tmp_path):
    host, clock = FakeHost(tmp_path), Clock()
    (host.proc / "net" / "tcp").write_text(HEADER)
    host.net["awg15"] = (10, 10)
    nft = FakeNft()
    sampler = make(tmp_path, host, clock, nft=nft, ports={"naive": {"tcp": [4443], "udp": []}})
    sampler.tick()
    clock.now += 1
    host.net["awg15"] = (20, 30)
    host.write()
    protocols = sampler.tick()["protocols"]
    assert protocols["naive"]["connections"] == 0
    assert protocols["amneziawg"]["connections"] is None  # peer based, not port based
    (host.proc / "net" / "tcp").unlink()
    clock.now += 1
    assert sampler.tick()["protocols"]["naive"]["connections"] is None


def test_mieru_counts_tcp_ports_only(tmp_path):
    host, clock, nft = FakeHost(tmp_path), Clock(), FakeNft()
    nft.counters = {"up_mieru_tcp_8443": 0, "down_mieru_tcp_8443": 0}
    (host.proc / "net" / "tcp").write_text(HEADER + _row("0100007F:20FB", "01") + _row("0100007F:20FC", "01"))
    sampler = make(tmp_path, host, clock, nft=nft, ports={"mieru": {"tcp": [8443], "udp": [8444]}})
    sampler.tick()
    clock.now += 1
    assert sampler.tick()["protocols"]["mieru"]["connections"] == 1
