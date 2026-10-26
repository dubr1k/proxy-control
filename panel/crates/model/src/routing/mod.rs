//! Routing: the policy model (`routing/models.py`) and the egress document helpers
//! (`routing/document.py`). The compiler, the store and the services are WP10's.

pub mod document;
pub mod idna;
pub mod models;
pub mod net;
mod tables;

pub use models::*;
