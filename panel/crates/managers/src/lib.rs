//! The panel's outbound clients (work package WP5): the five protocol managers on Unix sockets,
//! Telemt's HTTP API and the host's version-agent, plus the Telemt egress journal file.
//!
//! Every client mirrors its Python twin (`panel/naive.py`, `mieru.py`, `amneziawg.py`,
//! `trusttunnel.py`, `xray_router.py`, `telemt.py`, `versions.py`; the in-memory `Memory*` fakes
//! stay Python test tooling): same method names, paths, bodies (httpx's compact `json=`), token
//! headers, per-call timeouts, status pass-through (404/409/422, plus 503 for the router; anything
//! else 502), refusal-code filters and error messages. Methods answer the decoded JSON
//! (`Value::Null` where Python answers `None`).
//!
//! Unix-socket calls run `pc_common::client::request` on tokio's blocking pool; Telemt goes
//! through `reqwest` with rustls (ring, Mozilla roots). Inventory: §6.0–6.3, §2.6, §4.10.

pub mod amneziawg;
pub mod error;
pub mod mieru;
pub mod naive;
pub mod pyvalue;
pub mod telemt;
pub mod telemt_journal;
pub mod trusttunnel;
pub mod uds;
pub mod versions;
pub mod xray_router;

pub use amneziawg::AmneziawgClient;
pub use error::{Manager, ManagerError, TelemtError, VersionAgentError, EGRESS_REASON_CODES};
pub use mieru::{LifecycleAction, MieruClient};
pub use naive::NaiveClient;
pub use telemt::{access_from_user, api_secret, TelemtAccess, TelemtBatch, TelemtClient};
pub use telemt_journal::{JournalUnreadable, TelemtEgressJournal};
pub use trusttunnel::TrusttunnelClient;
pub use uds::ManagerClient;
pub use versions::VersionClient;
pub use xray_router::XrayRouterClient;
