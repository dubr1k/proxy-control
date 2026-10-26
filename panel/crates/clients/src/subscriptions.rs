//! What `POST /api/clients` needs of the subscriptions package (WP9): `subscriptions.public_base`
//! and `create_with_client`. Until WP9 wires an implementation, a client is created without a
//! subscription.

use panel_model::clients::Client;
use serde_json::Value;

use crate::{AuditContext, ClientsError};

/// `SubscriptionService` as the client API uses it.
pub trait SubscriptionIssuer: Send + Sync {
    /// `bool(subscriptions.public_base)`: a subscription domain is configured.
    fn enabled(&self) -> bool;

    /// `create_with_client(display_name, …)` and `subscription_reveal_payload(…)`: the new client
    /// and the payload of its one-time reveal. Blocking (run it in `spawn_blocking`).
    fn create_with_client(&self, display_name: &str, context: &AuditContext) -> Result<(Client, Value), ClientsError>;
}
