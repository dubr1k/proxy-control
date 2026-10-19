"""The monitor's sampler: counter arithmetic, the node snapshot, manager fallback and cadence."""
from __future__ import annotations

import pytest

from panel.metrics.fakes import MetricsRig as Rig
from panel.metrics.rates import ClientRates, fold

pytestmark = pytest.mark.anyio


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path, trusttunnel_enabled=True, amneziawg_enabled=True, naive_enabled=True, mieru_enabled=True)


def test_fold_treats_a_lower_reading_as_a_reset_and_first_sight_as_baseline():
    assert fold(None, 500) is None
    assert fold(100, 160) == 60
    assert fold(1000, 40) == 40


def test_a_windowed_rate_spreads_a_burst_over_the_window_and_decays_to_zero():
    rates = ClientRates()
    assert rates.update("naive", "nina", 0.0, up=0, down=0, window=60.0) is None
    quiet = rates.update("naive", "nina", 15.0, up=0, down=0, window=60.0)
    assert (quiet.up_bps, quiet.down_bps) == (0.0, 0.0)
    burst = rates.update("naive", "nina", 30.0, up=3000, down=60000, window=60.0)  # a connection closed
    assert (burst.up_bps, burst.down_bps) == (100.0, 2000.0)  # 30 s of history so far, not one 30 s slice
    later = rates.update("naive", "nina", 45.0, up=3000, down=60000, window=60.0)
    assert (later.up_bps, later.down_bps) == (3000 / 45, 60000 / 45)  # still there, flattening out
    gone = rates.update("naive", "nina", 100.0, up=3000, down=60000, window=60.0)
    assert (gone.up_bps, gone.down_bps) == (0.0, 0.0)  # the burst left the window
    assert gone.up_delta == 0.0  # the poll's own growth (for the byte counters) is unaffected by the window


def test_client_rates_baseline_reset_and_forgetting():
    rates = ClientRates(forget_after=600)
    assert rates.update("trusttunnel", "alice", 0.0, up=1000, down=5000) is None  # baseline: no spike
    rate = rates.update("trusttunnel", "alice", 2.0, up=1400, down=5800)
    assert (rate.up_bps, rate.down_bps, rate.total_bps) == (200.0, 400.0, 600.0)
    reset = rates.update("trusttunnel", "alice", 4.0, up=100, down=200)  # counters restarted
    assert (reset.up_delta, reset.down_delta) == (100, 200)
    combined = rates.update("mtproxy", "bob", 0.0, total=10)
    assert combined is None
    assert rates.update("mtproxy", "bob", 5.0, total=60).up_bps is None
    assert len(rates) == 2
    rates.prune(5.0 + 601)
    assert len(rates) == 0  # unseen for 10 minutes: dropped


async def test_snapshot_shape_from_kernel_counters_and_managers(rig):
    rig.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    rig.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    rig.agent.set_protocol("mtproxy", 10.0, 20.0)
    rig.tt.rows = [{"username": "alice", "tx": 0, "rx": 0, "sessions": 2}, {"username": "bob", "tx": 0, "rx": 0, "sessions": 0}]
    rig.awg.rows = [{"username": "carol", "rx": 0, "tx": 0, "latest_handshake": int(rig.clock.time()) - 30},
                    {"username": "dave", "rx": 0, "tx": 0, "latest_handshake": int(rig.clock.time()) - 900}]
    rig.telemt.rows = [{"username": "erin", "total_octets": 0, "current_connections": 3}]
    await rig.step()
    # the endpoint's inbound (tx) is the CLIENT'S DOWNLOAD, its outbound (rx) the client's upload
    rig.tt.rows = [{"username": "alice", "tx": 45000, "rx": 15000, "sessions": 2},
                   {"username": "bob", "tx": 0, "rx": 0, "sessions": 0}]
    rig.telemt.rows = [{"username": "erin", "total_octets": 18000, "current_connections": 3}]
    await rig.step(15.0)  # Telemt is asked every 15 s
    snap = rig.collector.snapshot()
    assert set(snap) == {"ts", "interval", "nodes"} and snap["interval"] == 2.0
    node = snap["nodes"][0]
    assert node["node_id"] == "local" and node["status"] == "ok" and node["age_seconds"] == 0.0
    assert node["kernel_counters"] == "ok" and node["host"]["cpu_percent"] == 12.5
    assert set(node["protocols"]) == {"mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"}
    tt = node["protocols"]["trusttunnel"]
    assert (tt["available"], tt["live"], tt["source"], tt["up_bps"], tt["down_bps"]) == (True, True, "kernel", 1000.0, 3000.0)
    assert (tt["sessions"], tt["clients"]) == (2, 1)
    awg = node["protocols"]["amneziawg"]
    assert awg["source"] == "interface" and awg["sessions"] == 1  # only the fresh handshake counts
    assert node["protocols"]["mtproxy"]["sessions"] == 3
    # the agent does not count mieru here: mita's own per-user counters make the meter (no users yet: zero)
    assert node["protocols"]["mieru"] == {**node["protocols"]["mieru"], "available": True, "live": True, "source": "manager",
                                           "up_bps": 0.0}
    top = node["top_clients"]
    assert [row["username"] for row in top] == ["alice", "erin"]
    assert top[0] == {"protocol": "trusttunnel", "username": "alice", "client_name": None, "up_bps": 1000.0,
                      "down_bps": 3000.0, "total_bps": 4000.0, "live": True}
    assert top[1]["up_bps"] is None and top[1]["total_bps"] == 1200.0  # Telemt reports one combined counter


async def test_kernel_rates_are_averaged_over_the_panel_tick_not_the_agents_last_second(rig):
    """The agent's 1 s rate is a single, bursty second; the panel reads every 2 s, so it derives the rate
    from the cumulative bytes between its own two reads (every byte counted once, no aliasing)."""
    rig.agent.set_protocol("naive", 0.0, 0.0)
    await rig.step()
    rig.agent.protocols["naive"].update(up_bytes=1000, down_bytes=6000, up_bps=5000.0, down_bps=90000.0)  # a burst second
    rig.agent._at = rig.clock.now + 2.0  # the double must not add its own growth on top
    await rig.step()
    naive = rig.collector.latest["protocols"]["naive"]
    assert (naive["up_bps"], naive["down_bps"]) == (500.0, 3000.0)  # 1000 B / 2 s, 6000 B / 2 s
    assert naive["total_bps"] == 3500.0 and (naive["up_bytes"], naive["down_bytes"]) == (1000, 6000)
    rig.agent.protocols["naive"].update(up_bytes=10, down_bytes=20, up_bps=0.0, down_bps=0.0)  # the agent restarted
    rig.agent._at = rig.clock.now + 2.0
    await rig.step()
    naive = rig.collector.latest["protocols"]["naive"]
    assert (naive["up_bps"], naive["down_bps"]) == (5.0, 10.0)  # a reset counts the reading, never a negative delta


async def test_top_clients_are_named_through_the_client_store_and_capped_at_ten(rig):
    with rig.database.transaction() as db:
        db.execute("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('c1','Alice Doe','active',1,1)")
        db.execute("INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,"
                   "created_at,updated_at) VALUES('g1','c1','trusttunnel','local','u0','enabled','provisioned',1,1)")
    rig.tt.rows = [{"username": f"u{i}", "tx": 0, "rx": 0, "sessions": 1} for i in range(14)]
    await rig.step()
    rig.tt.rows = [{"username": f"u{i}", "tx": 100 * (i + 1), "rx": 0, "sessions": 1} for i in range(14)]
    await rig.step(5.0)
    top = rig.collector.latest["top_clients"]
    assert len(top) == 10 and top[0]["username"] == "u13"
    rig.tt.rows[0]["tx"] = 10_000
    await rig.step(5.0)
    named = [row for row in rig.collector.latest["top_clients"] if row["username"] == "u0"]
    assert named[0]["client_name"] == "Alice Doe"


async def test_without_kernel_counters_rates_come_from_manager_deltas(rig):
    rig.agent.kernel_counters = "unavailable"
    rig.tt.rows = [{"username": "alice", "tx": 1000, "rx": 1000, "sessions": 1}]
    await rig.step()
    rig.tt.rows = [{"username": "alice", "tx": 1000 + 10000, "rx": 1000 + 5000, "sessions": 1}]
    await rig.step(5.0)
    tt = rig.collector.latest["protocols"]["trusttunnel"]
    assert (tt["source"], tt["live"], tt["up_bps"], tt["down_bps"]) == ("manager", True, 1000.0, 2000.0)
    assert rig.collector.latest["kernel_counters"] == "unavailable"
    # naive has no kernel numbers here: its scan runs, and it is flagged not live
    rig.naive.rows = [{"username": "alice", "upload_bytes": 0, "download_bytes": 0}]
    await rig.step(30.0)
    rig.naive.rows = [{"username": "alice", "upload_bytes": 3000, "download_bytes": 27000}]
    await rig.step(30.0)
    naive = rig.collector.latest["protocols"]["naive"]
    assert naive["source"] == "manager" and naive["live"] is False and naive["down_bps"] == 900.0


async def test_naive_is_polled_every_15_seconds_even_when_the_kernel_counts_it(tmp_path, rig):
    for _ in range(46):  # 92 s at a 2 s tick
        await rig.step()
        rig.agent.set_protocol("naive", 1.0, 1.0)  # from the second tick on, the kernel counts naive
    assert 5 <= rig.naive.calls <= 7  # the kernel counts the port, only the manager knows the users
    other = Rig(tmp_path / "b", naive_enabled=True)
    other.agent.kernel_counters = "unavailable"
    for _ in range(46):
        await other.step()
    assert 5 <= other.naive.calls <= 7
    assert other.tt.calls == 0 and other.mieru.calls == 0  # not enabled there: never asked


async def test_naive_and_mieru_clients_get_their_own_rows_while_the_kernel_keeps_the_node_totals(rig):
    rig.agent.set_protocol("naive", 4000.0, 9000.0)
    rig.agent.set_protocol("mieru", 2000.0, 7000.0)
    rig.naive.rows = [{"username": "nina", "upload_bytes": 0, "download_bytes": 0}]
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 100, "download_bytes": 1000}]
    await rig.step()
    rig.naive.rows = [{"username": "nina", "upload_bytes": 1500, "download_bytes": 15000}]
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 100 + 4000, "download_bytes": 1000 + 20000}]
    await rig.step(20.0)
    protocols = rig.collector.latest["protocols"]
    assert protocols["naive"]["source"] == "kernel" and protocols["mieru"]["source"] == "kernel"
    rows = {(row["protocol"], row["username"]): row for row in rig.collector.latest["top_clients"]}
    mia, nina = rows[("mieru", "mia")], rows[("naive", "nina")]
    assert (mia["up_bps"], mia["down_bps"], mia["live"]) == (200.0, 1000.0, True)
    # naive's access log is written when a CONNECT closes: the row is real but not a live meter
    assert (nina["up_bps"], nina["down_bps"], nina["live"]) == (75.0, 750.0, False)


async def test_mieru_rates_fall_back_to_the_manager_counters_without_the_kernel(rig):
    rig.agent.kernel_counters = "unavailable"
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 0, "download_bytes": 0}]
    await rig.step()
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 500, "download_bytes": 5000}]
    await rig.step(5.0)
    mieru = rig.collector.latest["protocols"]["mieru"]
    assert (mieru["source"], mieru["live"], mieru["up_bps"], mieru["down_bps"]) == ("manager", True, 100.0, 1000.0)
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 20, "download_bytes": 40}]  # mita restarted
    await rig.step(5.0)
    mieru = rig.collector.latest["protocols"]["mieru"]
    assert (mieru["up_bps"], mieru["down_bps"]) == (4.0, 8.0)  # a reset counts the reading, never a negative delta


async def test_an_old_mieru_manager_without_the_route_leaves_the_rest_untouched(rig):
    rig.agent.set_protocol("mieru", 1000.0, 1000.0)
    rig.mieru.broken = True
    await rig.step()
    await rig.step(5.0)
    mieru = rig.collector.latest["protocols"]["mieru"]
    assert mieru["source"] == "kernel" and mieru["live"] is True
    assert [row for row in rig.collector.latest["top_clients"] if row["protocol"] == "mieru"] == []


async def test_a_failing_manager_marks_only_its_protocol_unavailable(rig):
    rig.agent.kernel_counters = "unavailable"
    rig.tt.rows = [{"username": "alice", "tx": 1, "rx": 1, "sessions": 1}]
    rig.awg.rows = [{"username": "carol", "rx": 1, "tx": 1, "latest_handshake": None}]
    await rig.step()
    await rig.step(5.0)
    assert rig.collector.latest["protocols"]["trusttunnel"]["available"] is True
    rig.tt.broken = True
    await rig.step(5.0)
    await rig.step(5.0)
    protocols = rig.collector.latest["protocols"]
    assert protocols["trusttunnel"]["available"] is False and protocols["trusttunnel"]["reason"] == "manager_unavailable"
    assert protocols["amneziawg"]["available"] is True
    assert rig.collector.latest["status"] == "ok"


async def test_an_unreachable_agent_makes_the_node_stale_with_its_age_and_records_nothing(rig):
    await rig.step()
    count = len(rig.ring.points_of("host.cpu"))
    rig.agent.broken = True
    await rig.step(10.0)
    node = rig.collector.latest
    assert node["status"] == "stale" and node["age_seconds"] == 10.0 and node["host"]["cpu_percent"] == 12.5
    assert len(rig.ring.points_of("host.cpu")) == count  # a gap, not an invented point
    fresh = Rig(rig.state.database.path.parent / "x", trusttunnel_enabled=False)
    fresh.agent.broken = True
    await fresh.step()
    assert fresh.collector.latest["status"] == "unavailable" and fresh.collector.latest["host"] is None


async def test_kernel_counter_reset_adds_the_reading_not_a_negative_spike(rig):
    rig.agent.set_protocol("trusttunnel", 100.0, 100.0)
    await rig.step()
    await rig.step()
    rig.agent.reset_counters("trusttunnel")
    await rig.step()
    values = [value for _ts, value in rig.ring.points_of("trusttunnel.up_bytes")]
    assert all(value >= 0 for value in values) and len(values) == 2
    assert values[-1] == 200  # the counters restarted: the reading (2 s at 100 B/s) is the growth


async def test_connections_come_from_the_agent_next_to_the_manager_sessions(rig):
    rig.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    rig.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    rig.agent.protocols["trusttunnel"]["connections"] = 5
    rig.agent.protocols["amneziawg"]["connections"] = None
    rig.tt.rows = [{"username": "alice", "tx": 0, "rx": 0, "sessions": 0}]  # the manager's own figure stays 0
    await rig.step()
    await rig.step()
    protocols = rig.collector.snapshot()["nodes"][0]["protocols"]
    assert protocols["trusttunnel"]["connections"] == 5 and protocols["trusttunnel"]["sessions"] == 0
    assert protocols["amneziawg"]["connections"] is None
    assert protocols["mieru"]["connections"] is None  # unavailable protocols carry the key too
    assert [v for _ts, v in rig.ring.points_of("trusttunnel.connections")][-1] == 5
