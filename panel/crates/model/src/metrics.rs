//! Names and limits shared by the metrics modules: series ids, ranges, resolutions
//! (`metrics/model.py`), and the source the fleet plugs in for linked nodes' meters.

use serde_json::Value;

use crate::protocols::BoxFuture;

pub const LOCAL_NODE: &str = "local";
pub const PROTOCOLS: &[&str] = &["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];
pub const HOST_SERIES: &[&str] = &[
    "host.cpu",
    "host.mem",
    "host.swap",
    "host.disk",
    "host.disk_read_bps",
    "host.disk_write_bps",
    "host.load1",
    "net.rx_bps",
    "net.tx_bps",
];
pub const PROTOCOL_SERIES: &[&str] =
    &["up_bps", "down_bps", "sessions", "clients", "connections", "up_bytes", "down_bytes"];

/// Every series id: the host's, then `<protocol>.<series>` for each protocol in order.
pub fn all_series() -> Vec<String> {
    let mut out: Vec<String> = HOST_SERIES.iter().map(|name| name.to_string()).collect();
    for protocol in PROTOCOLS {
        for series in PROTOCOL_SERIES {
            out.push(format!("{protocol}.{series}"));
        }
    }
    out
}

/// Whether `name` is a series id.
pub fn is_series(name: &str) -> bool {
    HOST_SERIES.contains(&name)
        || name
            .split_once('.')
            .is_some_and(|(protocol, series)| PROTOCOLS.contains(&protocol) && PROTOCOL_SERIES.contains(&series))
}

/// The named ranges and their length in seconds, in the Python order.
pub const RANGES: &[(&str, i64)] =
    &[("15m", 900), ("1h", 3600), ("6h", 21600), ("24h", 86400), ("7d", 604800), ("30d", 2592000), ("90d", 7776000)];

/// The length of a named range.
pub fn range_seconds(name: &str) -> Option<i64> {
    RANGES.iter().find(|(range, _)| *range == name).map(|(_, seconds)| *seconds)
}

/// Rollup resolution (seconds) → how long its buckets are kept (seconds).
pub const RETENTION: &[(i64, i64)] = &[(60, 3 * 86400), (900, 35 * 86400), (3600, 400 * 86400)];
pub const POINTS_MIN: i64 = 10;
pub const POINTS_MAX: i64 = 2000;
pub const POINTS_DEFAULT: i64 = 240;

/// A protocol counter that only grows is a "bytes" series: its rollup `sum` is the volume.
pub fn is_bytes_series(series: &str) -> bool {
    series.ends_with("_bytes")
}

/// The rollup resolution that serves a range: 60 s up to 3 d, 900 s up to 35 d, 3600 s beyond.
pub fn resolution_for(range_seconds: i64) -> i64 {
    if range_seconds <= 3 * 86400 {
        60
    } else if range_seconds <= 35 * 86400 {
        900
    } else {
        3600
    }
}

/// A node the source can serve: `{node_id, name}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsNode {
    pub node_id: String,
    pub name: String,
}

/// What the fleet plugs in to serve the linked nodes' meters (`NodeMetricsSource`). Every method
/// answers `None` (or nothing) when the node cannot be served; the caller then reports it as
/// `unavailable`/`unsupported`.
pub trait NodeMetricsSource: Send + Sync {
    /// One node entry of the live snapshot (`nodes[i]` of `/api/metrics/live`).
    fn live<'a>(&'a self, node_id: &'a str) -> BoxFuture<'a, Option<Value>>;
    /// The body of `/api/metrics/history` for that node.
    fn history<'a>(
        &'a self,
        node_id: &'a str,
        series: &'a [String],
        range: &'a str,
        points: i64,
    ) -> BoxFuture<'a, Option<Value>>;
    /// The summary row of that node (a `nodes[i]` of `/api/metrics/summary`).
    fn summary<'a>(&'a self, node_id: &'a str, range: &'a str) -> BoxFuture<'a, Option<Value>>;
    /// The nodes this source can serve.
    fn nodes(&self) -> BoxFuture<'_, Vec<MetricsNode>>;
}
