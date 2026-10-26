//! The Proxy Control version-agent (the Rust port of `version_agent/`): a root service on the
//! host that lists the installed and available versions of the protocol runtimes and the panel,
//! checks upstream for new releases, applies approved updates, and serves host telemetry to the
//! panel over a Unix socket.
//!
//! | Module | What | Python |
//! |---|---|---|
//! | [`server`] | the HTTP routes on the socket, the automatic upstream check | `server.py` |
//! | [`service`] | state and lock, listing, upstream cache, update plumbing, `pending_rebuild`, configuration | `service.py` (the generic part) |
//! | [`updater`] | per-component updates and rollbacks, the panel self-update, the manager rebuild, the agent restart ([`service::Updater`]) | `service.py` (`_update_*`, `_build_caddy`, `_panel_worker`, `rebuild_managers`) |
//! | [`catalog`] | the approved-artifact catalog and candidate validation | `catalog.py` |
//! | [`upstream`] | GitHub / registry probes, `compare_versions`, artifact downloads | `upstream.py`, `service._download` |
//! | [`artifacts`] | one member out of a verified zip or tar.gz | `artifacts.py` |
//! | [`host`] | `GET /v1/host` | `host.py` |
//! | [`hostmetrics`] | the 1 Hz sampler behind `GET /v1/metrics` | `hostmetrics.py` |
//! | [`metrics_ports`] | the protocol port map for the kernel counters | `metrics_ports.py` |
//! | [`runner`] | commands (`_run`) | `service._run` |
//! | [`py`] | Python string/number semantics the formats rely on | — |

pub mod artifacts;
pub mod catalog;
pub mod errors;
pub mod host;
pub mod hostmetrics;
pub mod logging;
pub mod metrics_ports;
pub mod py;
pub mod runner;
pub mod server;
pub mod service;
pub mod updater;
pub mod upstream;

#[cfg(test)]
mod testutil;

pub use errors::{AgentError, CatalogError, UpdateError, UpdateState};
pub use service::{AgentConfig, Applied, NotPorted, Updater, VersionAgent};
pub use updater::HostUpdater;
