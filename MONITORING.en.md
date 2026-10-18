# Monitoring

[Русский](MONITORING.ru.md) · **English**

The «Мониторинг» (Monitoring) screen shows live how the server is doing and how much traffic each
protocol carries, and keeps a history for analysis by day, month and node. It **only reads**: it
changes nothing in the protocols or the managers, and a source that cannot be read becomes «no
data», never a wrong number. Every role can see it; there is nothing to configure and nothing extra
to install.

## What is measured and how

```
host kernel ── version-agent (root, host) ──UDS── panel (collector, ring + SQLite, API/SSE) ── browser
 /proc, nft, cgroup    GET /v1/metrics                    ▲ polled only while someone watches
                                                          └── linked panels: /api/fleet/v2/metrics
```

The **host agent** (`version-agent`) samples once a second in a thread of its own and keeps the
latest sample in memory; `GET /v1/metrics` returns that ready sample and computes nothing on
request. The panel's collector takes the sample every 2 seconds (`PANEL_METRICS_INTERVAL_SECONDS`),
computes rates and writes them to an in-memory ring (900 points, about 30 minutes) and, every 30
seconds, to the database.

Host figures:

- **CPU** from `/proc/stat` (the difference between samples), the core count, load average 1/5/15;
- **memory and swap** from `MemAvailable`: «used» is everything that cannot be handed back without eviction;
- **disk**: used space of the root file system, read and write speed and device busy time
  (`busy`) from `/proc/diskstats`;
- **host network**: the sum over physical interfaces; `lo`, `veth*`, `br-*`, `docker*`, `awg*`,
  `tun*` and `wg*` are left out so traffic is not counted twice;
- **containers**: each container's CPU (in percent of one core, so it can exceed 100) and memory from
  cgroup v2; names come from `docker ps` every 30 seconds;
- **uptime**.

### Traffic by protocol

| Protocol | Where the bytes come from | Live rate |
|---|---|---|
| MTProxy (Telemt) | kernel counters on the backend port (`8445/tcp` behind Nginx SNI) | yes |
| NaiveProxy | kernel counters on `4443/tcp` (loopback behind the SNI router; a direct listener is counted too) | yes |
| Mieru | kernel counters on the TCP/UDP ports of mita's `portBindings` and of the Mieru lanes | yes |
| TrustTunnel | kernel counters on the endpoint port (`TT_LISTEN`, `4453/tcp` by default) | yes |
| AmneziaWG | interface counters `awg15`, `awg20`, `awg31` from `/proc/net/dev` | yes |

The kernel counters live in **a nftables table of their own**, `inet proxy_control_metrics`. The
agent creates it itself, idempotently and in one transaction, and recreates it when the set of
ports changes. It has two chains (`input` and `output`, priority `-300`, policy `accept`); the rules
only count (`counter`) and never decide a packet's fate. No other nftables table, Docker or ufw rule
is touched.

- **Direction is the client's point of view.** `↑` is from clients to the server (destination port,
  `input` hook), `↓` is to clients (source port, `output` hook). Each loopback hop is counted once.
- **These are network-layer (L3) bytes, packet headers included.** The figures are therefore a bit
  larger than the «payload», and the interface labels them as network traffic.
- **The agent discovers the ports itself**; the operator is never asked. It reads what the
  installer wrote: the list of Compose files, `.env` (`MTPROXY_BACKEND_PORT`), `.env.trusttunnel`
  (`TT_LISTEN`), the mita configuration `/var/lib/mita/server_config.json` and `MIERU_LANE_SLOTS`. A
  protocol that is not enabled on the host is simply absent and shows as «unavailable», not as zero
  traffic. The port map is re-read every minute; at most 64 ports are taken per protocol.
- **The override file** `/etc/proxy-control/metrics-ports.json` is only needed for non-standard ports.
  It replaces the discovered ports of the protocols it names, as a whole:

  ```json
  { "naive": { "tcp": [4443] }, "mieru": { "tcp": [8443], "udp": [8443] } }
  ```

  Keys are `mtproxy`, `naive`, `mieru`, `trusttunnel`; ports are numbers 1–65535. A file with an error
  is ignored as a whole and one line goes to the agent's log. Edits are picked up within a minute.
- **Clean-up.** The agent removes nothing it did not create and leaves the table in place when it
  stops (the counters are harmless). To remove it by hand: `sudo nft delete table inet proxy_control_metrics`;
  the agent creates it again while it runs.

### What each protocol shows live

- **TrustTunnel, AmneziaWG** — ↑/↓ rates from the kernel, sessions and clients from the manager,
  per-client rates (every 5 seconds) split into ↑ and ↓.
- **MTProxy** — ↑/↓ rates from the kernel. The manager path (Telemt) has **only a combined counter**,
  `total_octets`, with no ↑/↓ split: per client you see the total rate, and connections come from
  `current_connections` (polled every 15 seconds).
- **NaiveProxy** — the total live rate from the kernel. While the kernel counts NaiveProxy the
  manager is not polled (its counter arrives only when a tunnel closes, and the query is expensive).
  There is no live **per-client** rate for NaiveProxy; see its per-client volumes in the traffic
  accounting (period totals).
- **Mieru** — the total rate from the kernel (UDP too). Mieru has no counters in the manager or in
  mita: there is no per-client or session data. When the kernel counters are unavailable Mieru shows
  «no counters».

If `nft` is missing or fails, the agent reports `kernel_counters: "unavailable"` and retries every 30
seconds. The panel then falls back to sums over the managers (`source: "manager"`): TrustTunnel and
AmneziaWG work as usual, MTProxy gives only a total rate, NaiveProxy is flagged not live
(`live: false`, a 30-second cadence or slower) and Mieru has no data.

## The three screens

**Сейчас (Now)** is the live feed. A node selector (including «Все узлы», all nodes); tiles for CPU,
RAM, disk, network and load with gauge rings and sparklines; protocol cards with ↑↓ rates, sessions and
a sparkline; an ↑/↓ chart for the last 5 minutes; a «who is transferring now» table (up to 10 clients) and
a containers table. The state badge reads «в эфире» (live), «пауза» (paused) or «нет связи» (no
connection). The pause button freezes the picture; a tab hidden for over a minute drops the feed and
resumes it on return.

**Трафик (Traffic)** is history by protocol: a stacked area chart, a period from 15 minutes to 90 days,
an ↑/↓/total toggle, volumes and the share of each protocol.

**Узлы (Nodes)** compares all nodes in one table (state, CPU, RAM, disk, network, traffic volume,
alerts) and drills into a chosen node: resource history, volumes by protocol, the average load by hour
of day (periods of 7 days and longer) and peaks.

Periods: 15 min, 1 h, 6 h, 24 h, 7 d, 30 d, 90 d. Gaps in the data stay gaps, not zeros. The resources
card on the overview keeps working and links to this screen.

## Retention

| Resolution | Kept for | Used for |
|---|---|---|
| in memory: a point every 2 s (about 30 min) | until the panel restarts | «Now», the 15 min and 1 h periods |
| 60 s | 3 days | periods up to 3 days |
| 15 min | 35 days | periods up to 35 days |
| 1 h | 400 days | periods up to a year |

Every point lands in all three resolutions (table `metric_rollups`, migration 25: the sum, the sample
count, the maximum and the last value per bucket). A flush is one transaction every 30 seconds, and
expired buckets are deleted at most once an hour. The volume per bucket is stored as a sum (`*_bytes`),
rates as an average and a maximum. The metrics tables grow to roughly 40 MB at the end of the retention
with all five protocols, and less with fewer protocols (an estimate from the row count, not a
measurement on live data). Only `node_id` `local` is stored: the history of linked nodes stays on the
nodes and is requested from them on demand.

## Alerts

Alerts are computed from the same series and shown on the «Nodes» screen and in the MCP overview.

| Kind | Warning | Critical |
|---|---|---|
| `cpu` | 5-minute average above 85 % | above 95 % |
| `mem` | above 90 % | above 97 % |
| `disk` | above 90 % | above 95 % |
| `swap` | above 50 % | above 80 % |
| `stale` (no host sample) | longer than 60 s | longer than 300 s |
| `net_spike` | total rate above 3× the p95 of the last 24 h (and at least 256 KiB/s) | above 6× |

`net_spike` needs at least an hour of collected data. Alerts send nothing out; they are only shown.

## Transport: SSE and fallback polling

The browser receives snapshots from `GET /api/metrics/stream` (Server-Sent Events): a `snapshot` event
every 2 seconds, a `: ping` comment every 15 seconds when quiet, `retry: 3000`. The response carries
`X-Accel-Buffering: no`, so Nginx does not buffer the stream. If the stream is unavailable the interface
switches to polling `GET /api/metrics/live` every 3 seconds on its own (the badge reads «в эфире ·
опрос раз в 3 с») and reconnects with a growing pause.

Stream limits: **4 streams per session, 24 in total** (the fifth and later get `429` with
`Retry-After: 5`); a stream closes after **55 minutes** with a `bye` event (the browser reconnects, which
also re-checks that the session is alive); closing the tab frees the slot at once. An API key (Bearer)
can read `live`, `history` and `summary`; `EventSource` cannot send headers, so a script is better off
polling `live`.

## HTTP API

All routes are `GET`, open to every signed-in role (and to API keys, `monitor` included), answer with
`Cache-Control: no-store`, contain no secrets and name clients only by account names.
`PANEL_METRICS_ENABLED=0` switches the collector and the routes off (the answer is
`404 metrics_disabled`). The `node` parameter is `local` (the default), the id of a linked node, or
`all` (this panel and every linked node).

| Route | Parameters | Answer |
|---|---|---|
| `/api/metrics/live` | `node` | one snapshot |
| `/api/metrics/stream` | `node` | SSE: `snapshot`, `bye` |
| `/api/metrics/history` | `node` (one node), `series` (up to 40, comma-separated), `range`, `points` (10–2000, default 240) | series of `[ts, average, maximum]` |
| `/api/metrics/summary` | `node`, `range` (default `24h`) | period totals, alerts, node comparison |

`range` is one of `15m 1h 6h 24h 7d 30d 90d`; any other value gives `422`. Series ids: `host.cpu`,
`host.mem`, `host.swap`, `host.disk`, `host.disk_read_bps`, `host.disk_write_bps`, `host.load1`,
`net.rx_bps`, `net.tx_bps` and, for each protocol (`mtproxy`, `naive`, `mieru`, `amneziawg`,
`trusttunnel`), `<protocol>.up_bps`, `.down_bps`, `.sessions`, `.clients`, `.up_bytes`, `.down_bytes`.

An example `GET /api/metrics/live?node=local` (abridged):

```json
{
  "ts": 1760780000.5, "interval": 2.0,
  "nodes": [{
    "node_id": "local", "name": "central", "status": "ok", "age_seconds": 0.0, "kernel_counters": "ok",
    "host": {
      "cpu_percent": 12.5, "cores": 4, "load": [0.5, 0.4, 0.3], "uptime_seconds": 864000,
      "mem": {"used": 1717986918, "total": 4294967296, "percent": 40.0, "available": 2576980378},
      "disk": {"used": 10737418240, "total": 53687091200, "percent": 20.0,
               "read_bps": 0.0, "write_bps": 20480.0, "busy_percent": 1.2},
      "net": {"rx_bps": 184320.0, "tx_bps": 921600.0, "interfaces": [{"name": "eth0", "rx_bps": 184320.0, "tx_bps": 921600.0}]},
      "containers": [{"name": "proxy-control-panel", "cpu_percent": 1.4, "mem_bytes": 188743680}]
    },
    "protocols": {
      "trusttunnel": {"available": true, "live": true, "source": "kernel", "up_bps": 51200.0, "down_bps": 307200.0,
                      "total_bps": 358400.0, "up_bytes": 5242880, "down_bytes": 31457280, "sessions": 3, "clients": 2},
      "mieru": {"available": true, "live": false, "reason": "no_counters"},
      "naive": {"available": false, "reason": "disabled"}
    },
    "top_clients": [{"protocol": "trusttunnel", "username": "alice", "client_name": "Alice", "up_bps": 40960.0,
                     "down_bps": 262144.0, "total_bps": 303104.0, "live": true}],
    "alerts": []
  }]
}
```

A node's `status` is `ok`, `stale` (the agent did not answer; the last sample is shown with its
`age_seconds`), `unavailable` (there has been no sample yet) or `unsupported` (a node without the
`metrics.v1` capability). A protocol's `source` is `kernel`, `interface` (AmneziaWG) or `manager`.

An example `GET /api/metrics/history?series=host.cpu,trusttunnel.down_bytes&range=24h&points=96`:

```json
{
  "status": "ok", "node_id": "local", "range": "24h", "step": 900, "from": 1760693600, "to": 1760780000,
  "source": "rollup", "resolution": 60,
  "series": {
    "host.cpu": [[1760693400, 11.2, 40.5], [1760694300, null, null]],
    "trusttunnel.down_bytes": [[1760693400, 73400320, 20971520]]
  }
}
```

In `*_bytes` series the second number is the volume of the bucket (a sum), in the others the average;
the third is the maximum inside the bucket. `null` means there is no data in that interval.

`GET /api/metrics/summary?range=7d` returns for every node `host` (for CPU, memory, disk and network:
`avg`, `p95`, `max`, `max_at`), `protocols` (`up_bytes`, `down_bytes`, `total_bytes`, `avg_bps`,
`peak_bps`, `peak_at`, `share_percent`, `sessions_peak`), `hours_of_day` (24 averages per protocol,
from 7 days up) and `alerts`. With `node=all` it adds `compare`, one row per node ordered by traffic.

## Nodes

Linked panels serve their own samples to the central one through `GET /api/fleet/v2/metrics`,
`/api/fleet/v2/metrics/history` and `/api/fleet/v2/metrics/summary` (the `node-sync` key, capability
`metrics.v1`). The central polls the nodes **only while someone watches** the screen (with no viewer nothing is
polled; a node's fleet status is still refreshed by the usual 15-second heartbeat), at most 8 nodes at a time,
with a 3-second timeout per call and a 2-second cache per node; a node's history and totals are requested from
the node itself at the moment of viewing (a 10-second timeout for history). An unreachable node shows as `stale`
with its last known sample and its age for 120 seconds, then as `unavailable`; a node
without `metrics.v1` (older than 2.0) is `unsupported`. Update the nodes first, the central last. More
on the fleet: [FLEET.en.md](FLEET.en.md).

## MCP

The `live`, `history` and `summary` routes become MCP tools automatically (`get_metrics_live`,
`get_metrics_history`, `get_metrics_summary`); `/api/metrics/stream` is **excluded** from MCP, because
a tool call waits for a finished answer and the stream never finishes. The `overview` tool has a
compact `metrics` section: per node the status, CPU, RAM and disk percent, network rates, per-protocol
↑/↓ rates and session counts, and alerts (`null` when monitoring is unavailable). See
[MCP.en.md](docs/MCP.en.md).

## When something is unavailable

- **The agent does not answer.** The collector marks the node `stale` and shows the last sample with
  its age; after 60 seconds a `stale` alert appears. History does not break: the gap simply has no data.
- **No `nft`.** The protocol series are built from the managers (see above), NaiveProxy is not live,
  Mieru has no data; the host figures keep working.
- **No Docker** or cgroup v2 means only that there is no containers table.
- **The panel restarted.** The in-memory ring fills up again; the history in the database is intact
  (at most the last 30 seconds of points may not have been written).

## Privacy

The metrics contain no traffic payload, destination addresses, client IPs or secrets: only rates,
volumes, session counts and protocol account names (`runtime_username`) and client names. The nftables
rules count bytes per port and never look into packets.

## Cost

The agent's sampler is one thread that reads a few `/proc` files and calls `nft` for the counters once
a second; measured on a test host it takes about **0.3 %** of one core. The panel's collector tick takes
a fraction of a second and blocks nothing; the SQLite write is one small transaction every 30 seconds.
To check the sampler live on a host, run `scripts/lab/agent-metrics-check.py` (as root, from the
release directory).

## Troubleshooting

| Symptom | What to check |
|---|---|
| «нет связи» on the screen | open `/api/metrics/live` from the browser; the proxy in front of the panel must not buffer SSE (the panel sets `X-Accel-Buffering: no` itself); when the stream fails the interface falls back to polling |
| `429` on the stream | more than 4 streams in the session or 24 in total: close extra tabs |
| All protocols «no data» while the host shows | `kernel_counters` in `/api/metrics/live`; `sudo nft list table inet proxy_control_metrics`; `journalctl -u version-agent` (the «kernel counters unavailable» line) |
| A protocol shows zero rate under live traffic | the port was not guessed: compare `sudo nft list counters table inet proxy_control_metrics` with the real port and, if needed, set `/etc/proxy-control/metrics-ports.json` |
| A node is `stale` | `sudo systemctl status version-agent`; `sudo curl --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/metrics` (`503 metrics_warming_up` means the agent has just started) |
| A node is `unsupported` | the node is older than 2.0: update it |
| The screen answers `404 metrics_disabled` | `PANEL_METRICS_ENABLED=0` in the panel's environment |
| You want the rules gone | `sudo nft delete table inet proxy_control_metrics` |
