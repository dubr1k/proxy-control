//! The panel's protocol adapters (work package WP6): one contract
//! ([`panel_model::protocols::ProtocolAdapter`]) over five unlike data planes, the links and configs
//! a client gets, the TrustTunnel deep link and the QR codes (`panel/protocols/*.py`,
//! `panel/trusttunnel_link.py`, `panel/reveals.py`).
//!
//! - [`telemt`] — MTProxy through Telemt: the manager owns the secret, the live link carries it; the
//!   upstream handed to the node's Xray-router through the SOCKS5 bridge, with the egress journal;
//! - [`naive`], [`mieru`] — the caller chooses the password; Mieru cannot hand one back;
//! - [`amneziawg`] — the panel's client keys (x25519 public keys from escrowed private keys) and the
//!   `.conf` the client imports;
//! - [`trusttunnel`] — the panel's password, the `tt://` link, the TOML and the manual fields;
//! - [`xray_router`] — the node's Xray-router per service (not a grant adapter);
//! - [`trusttunnel_link`] — the `tt://?` TLV deep link;
//! - [`reveals`] and [`qr`] — QR codes byte-identical to python-qrcode's SVG path image, the Karing
//!   import link.
//!
//! Each adapter is generic over the client trait of [`api`] with the real `panel_managers` client
//! as its default, so tests (and the transcript replays recorded from the Python unit tests) hand
//! it another one. Failures Python let escape untranslated are encoded as described in [`error`].
//! The in-memory `Memory*` twins of the Python clients stay Python test tooling.

pub mod amneziawg;
pub mod api;
pub mod error;
pub mod mieru;
pub mod naive;
pub mod qr;
pub mod reveals;
pub mod telemt;
pub mod trusttunnel;
pub mod trusttunnel_link;
pub(crate) mod util;
pub mod xray_router;

pub use amneziawg::AmneziawgAdapter;
pub use mieru::MieruAdapter;
pub use naive::NaiveAdapter;
pub use telemt::TelemtAdapter;
pub use trusttunnel::TrusttunnelAdapter;
pub use xray_router::RouterAdapter;

/// The [`ProtocolAdapter`](panel_model::protocols::ProtocolAdapter) impl of an adapter whose
/// inherent methods carry the Python names and signatures: every trait method boxes the inherent
/// one.
macro_rules! protocol_adapter {
    (
        impl<$($param:ident: $bound:path),+> for $ty:ty;
        protocol: $protocol:expr,
        origin: $origin:expr,
        capture: $capture:expr,
        accepts_caller: $accepts:expr $(,)?
    ) => {
        impl<$($param: $bound),+> panel_model::protocols::ProtocolAdapter for $ty {
            fn protocol(&self) -> panel_model::Protocol {
                $protocol
            }

            fn credential_origin(&self) -> panel_model::fleet::CredentialOrigin {
                $origin
            }

            fn capture_supported(&self) -> bool {
                $capture
            }

            fn accepts_caller_credential(&self) -> bool {
                $accepts
            }

            fn discover(
                &self,
            ) -> panel_model::protocols::BoxFuture<
                '_,
                Result<panel_model::protocols::ObservedInventory, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::discover(self))
            }

            fn preflight<'a>(
                &'a self,
                intent: &'a panel_model::clients::GrantIntent,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::Preflight, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::preflight(self, intent))
            }

            fn create<'a>(
                &'a self,
                operation_id: &'a str,
                intent: &'a panel_model::clients::GrantIntent,
                credential: &'a panel_model::protocols::CredentialPlan,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::AppliedGrant, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::create(self, operation_id, intent, credential))
            }

            fn enable<'a>(
                &'a self,
                grant: &'a panel_model::protocols::GrantRef,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::AppliedGrant, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::enable(self, grant))
            }

            fn disable<'a>(
                &'a self,
                grant: &'a panel_model::protocols::GrantRef,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::AppliedGrant, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::disable(self, grant))
            }

            fn rotate<'a>(
                &'a self,
                operation_id: &'a str,
                grant: &'a panel_model::protocols::GrantRef,
                credential: &'a panel_model::protocols::CredentialPlan,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::AppliedGrant, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::rotate(self, operation_id, grant, credential))
            }

            fn delete<'a>(
                &'a self,
                grant: &'a panel_model::protocols::GrantRef,
            ) -> panel_model::protocols::BoxFuture<'a, Result<(), panel_model::protocols::AdapterError>> {
                Box::pin(<$ty>::delete(self, grant))
            }

            fn capture<'a>(
                &'a self,
                grant: &'a panel_model::protocols::GrantRef,
            ) -> panel_model::protocols::BoxFuture<'a, Result<Option<Vec<u8>>, panel_model::protocols::AdapterError>>
            {
                Box::pin(<$ty>::capture(self, grant))
            }

            fn update_options<'a>(
                &'a self,
                grant: &'a panel_model::protocols::GrantRef,
                options: &'a serde_json::Map<String, serde_json::Value>,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<Option<panel_model::protocols::AppliedGrant>, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::update_options(self, grant, options))
            }

            fn render_artifacts(
                &self,
                grant: &panel_model::clients::AccessGrant,
                credential: &[u8],
                public_host: &str,
            ) -> Result<Vec<panel_model::protocols::AccessArtifact>, panel_model::protocols::AdapterError> {
                <$ty>::render_artifacts(self, grant, credential, public_host)
            }

            fn egress_target(
                &self,
            ) -> panel_model::protocols::BoxFuture<
                '_,
                Result<Option<panel_model::protocols::EgressTarget>, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::egress_target(self))
            }

            fn plan_egress<'a>(
                &'a self,
                document: &'a serde_json::Map<String, serde_json::Value>,
                expected_revision: &'a str,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<serde_json::Map<String, serde_json::Value>, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::plan_egress(self, document, expected_revision))
            }

            fn apply_egress<'a>(
                &'a self,
                document: &'a serde_json::Map<String, serde_json::Value>,
                expected_revision: &'a str,
                operation_id: &'a str,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::AppliedEgress, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::apply_egress(self, document, expected_revision, operation_id))
            }

            fn rollback_egress<'a>(
                &'a self,
                expected_revision: &'a str,
            ) -> panel_model::protocols::BoxFuture<
                'a,
                Result<panel_model::protocols::AppliedEgress, panel_model::protocols::AdapterError>,
            > {
                Box::pin(<$ty>::rollback_egress(self, expected_revision))
            }
        }
    };
}
pub(crate) use protocol_adapter;
