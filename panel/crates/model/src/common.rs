//! Names shared by several model modules: the five data planes, the egress backends, a secret
//! version reference.

use panel_core::errors::LocItem;
use serde_json::{json, Value};

use crate::validate::{literal, Cx};

/// A closed set of wire strings (a Python `Literal[...]`).
pub trait WireEnum: Sized + Copy + 'static {
    /// Every value, in the order the Python module declares them.
    const ALL: &'static [Self];

    /// The value as it travels.
    fn as_str(self) -> &'static str;

    /// The value for its wire text.
    fn from_wire(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|item| item.as_str() == text)
    }
}

/// Validates a `Literal[...]` field whose choices are `expected` (in the field's own declaration
/// order, which the issue message lists) into the enum.
pub fn literal_enum<E: WireEnum>(input: &Value, loc: &[LocItem], cx: &mut Cx, expected: &[&str]) -> Option<E> {
    literal(input, loc, cx, expected).map(|text| E::from_wire(text).expect("every expected choice is a variant"))
}

macro_rules! wire_enum {
    ($(#[$meta:meta])* pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
        }

        impl $crate::common::WireEnum for $name {
            const ALL: &'static [Self] = &[$($name::$variant,)*];

            fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)*
                }
            }
        }

        impl $name {
            /// The value as it travels.
            pub fn as_str(self) -> &'static str {
                <Self as $crate::common::WireEnum>::as_str(self)
            }

            /// The value for its wire text.
            pub fn from_wire(text: &str) -> Option<Self> {
                <Self as $crate::common::WireEnum>::from_wire(text)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<$name> for serde_json::Value {
            fn from(value: $name) -> Self {
                serde_json::Value::String(value.as_str().to_string())
            }
        }
    };
}
pub(crate) use wire_enum;

wire_enum! {
    /// One of the five data planes (`clients.models.PROTOCOLS`, in that order).
    pub enum Protocol {
        Mtproxy => "mtproxy",
        Naive => "naive",
        Mieru => "mieru",
        Amneziawg => "amneziawg",
        Trusttunnel => "trusttunnel",
    }
}

wire_enum! {
    /// Where a protocol's egress runs: its native manager, or the node's Xray-router.
    pub enum Backend {
        NaiveNative => "naive_native",
        MieruNative => "mieru_native",
        MtproxyNative => "mtproxy_native",
        TrusttunnelNative => "trusttunnel_native",
        AmneziawgNative => "amneziawg_native",
        XrayRouter => "xray_router",
    }
}

/// The choices of a `Literal` of backends, in the panel's declaration order.
pub const BACKENDS: &[&str] =
    &["naive_native", "mieru_native", "mtproxy_native", "trusttunnel_native", "amneziawg_native", "xray_router"];

/// `secrets_store.SecretRef`: a secret by id and version (the value lives encrypted in
/// `secret_versions`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    pub secret_id: String,
    pub version: i64,
}

impl SecretRef {
    pub fn new(secret_id: impl Into<String>, version: i64) -> Self {
        Self { secret_id: secret_id.into(), version }
    }

    /// The dataclass as pydantic dumps it.
    pub fn dump(&self) -> Value {
        json!({"secret_id": self.secret_id, "version": self.version})
    }

    /// `"<secret_id>:<version>"`, the form a fleet resource's `credential_ref` takes.
    pub fn credential_ref(&self) -> String {
        format!("{}:{}", self.secret_id, self.version)
    }
}
