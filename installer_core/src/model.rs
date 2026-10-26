//! The typed installer configuration (`installer/model.py`): enums, sections, constants and the
//! canonical dictionary that enters the plan digest.

use serde_json::{json, Map, Value};

/// `HostMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMode {
    Fresh,
    Coexist,
}

impl HostMode {
    pub const ALL: [HostMode; 2] = [HostMode::Fresh, HostMode::Coexist];

    pub fn value(self) -> &'static str {
        match self {
            HostMode::Fresh => "fresh",
            HostMode::Coexist => "coexist",
        }
    }
}

/// `Profile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Core,
    CoreNaive,
    CoreMieru,
    Full,
}

impl Profile {
    pub const ALL: [Profile; 4] = [Profile::Core, Profile::CoreNaive, Profile::CoreMieru, Profile::Full];

    pub fn value(self) -> &'static str {
        match self {
            Profile::Core => "core",
            Profile::CoreNaive => "core-naive",
            Profile::CoreMieru => "core-mieru",
            Profile::Full => "full",
        }
    }

    pub fn includes_naive(self) -> bool {
        matches!(self, Profile::CoreNaive | Profile::Full)
    }

    pub fn includes_mieru(self) -> bool {
        matches!(self, Profile::CoreMieru | Profile::Full)
    }
}

/// `ThreeXuiMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeXuiMode {
    None,
    Existing,
    ManagedNew,
}

impl ThreeXuiMode {
    pub const ALL: [ThreeXuiMode; 3] = [ThreeXuiMode::None, ThreeXuiMode::Existing, ThreeXuiMode::ManagedNew];

    pub fn value(self) -> &'static str {
        match self {
            ThreeXuiMode::None => "none",
            ThreeXuiMode::Existing => "existing",
            ThreeXuiMode::ManagedNew => "managed-new",
        }
    }
}

/// `EgressChoice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressChoice {
    Direct,
    Warp,
    /// The service is handed to the node's Xray egress-router.
    Router,
}

impl EgressChoice {
    pub const ALL: [EgressChoice; 3] = [EgressChoice::Direct, EgressChoice::Warp, EgressChoice::Router];

    pub fn value(self) -> &'static str {
        match self {
            EgressChoice::Direct => "direct",
            EgressChoice::Warp => "warp",
            EgressChoice::Router => "router",
        }
    }
}

/// Lane slots: extra mita daemons, `mita@N` on `LANE_SLOT_BASE_PORT + N`.
pub const LANE_SLOT_BASE_PORT: u16 = 46100;
pub const MAX_LANE_SLOTS: u32 = 8;
pub const DEFAULT_LANE_SLOTS: u32 = 4;

pub fn lane_slot_port(index: u32) -> u16 {
    LANE_SLOT_BASE_PORT + index as u16
}

/// The router's per-service SOCKS5 ingress on the host loopback (`ROUTER_PORTS`), in order.
pub const ROUTER_PORTS: [(&str, u16); 2] = [("naive", 45101), ("mieru", 45102)];
/// TrustTunnel's no-auth SOCKS5 ingress of the router.
pub const TRUSTTUNNEL_ROUTER_PORT: u16 = 45104;
/// The relay inbound's default public port.
pub const DEFAULT_RELAY_PORT: u16 = 45443;

pub const AWG_VERSIONS: [&str; 3] = ["1.5", "2.0", "3.1"];
pub const AWG_DEFAULT_SUBNETS: [(&str, &str); 3] =
    [("1.5", "10.66.15.0/24"), ("2.0", "10.66.20.0/24"), ("3.1", "10.66.31.0/24")];
pub const AWG_DEFAULT_DNS: [&str; 2] = ["1.1.1.1", "1.0.0.1"];
pub const AWG_DEFAULT_MTU: u32 = 1280;

/// `awg15`, `awg20`, `awg31`.
pub fn awg_interface(version: &str) -> String {
    format!("awg{}", version.replace('.', ""))
}

pub const TT_DEFAULT_LISTEN_PORT: u16 = 4453;
pub const TT_METRICS_PORT: u16 = 1987;

/// `DomainConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    pub panel: String,
    pub mtproxy: String,
    pub naive: Option<String>,
    pub mieru: Option<String>,
    pub subscription: Option<String>,
    pub mcp: Option<String>,
    pub trusttunnel: Option<String>,
}

impl DomainConfig {
    pub fn new(panel: &str, mtproxy: &str) -> DomainConfig {
        DomainConfig {
            panel: panel.into(),
            mtproxy: mtproxy.into(),
            naive: None,
            mieru: None,
            subscription: None,
            mcp: None,
            trusttunnel: None,
        }
    }
}

/// `MieruConfig`; `lane_slots` is resolved by the parser (0 without a router).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruConfig {
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
    pub lane_slots: u32,
}

impl MieruConfig {
    pub fn slot_ports(&self) -> Vec<u16> {
        (1..=self.lane_slots).map(lane_slot_port).collect()
    }
}

/// `ThreeXuiConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeXuiConfig {
    pub mode: ThreeXuiMode,
    pub panel_domain: Option<String>,
    pub vless_tcp_domain: Option<String>,
    pub vless_xhttp_domain: Option<String>,
    pub hysteria_domain: Option<String>,
    pub warp: bool,
    pub warp_domains: Vec<String>,
    pub warp_port: u16,
    pub subscription_domain: Option<String>,
}

impl ThreeXuiConfig {
    pub fn new(mode: ThreeXuiMode) -> ThreeXuiConfig {
        ThreeXuiConfig {
            mode,
            panel_domain: None,
            vless_tcp_domain: None,
            vless_xhttp_domain: None,
            hysteria_domain: None,
            warp: false,
            warp_domains: Vec::new(),
            warp_port: 40000,
            subscription_domain: None,
        }
    }
}

/// `EgressConfig` (`[egress]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressConfig {
    pub warp: bool,
    pub warp_port: u16,
    pub naive: EgressChoice,
    pub mieru: EgressChoice,
    pub router: bool,
    /// 0 keeps the relay off.
    pub relay_port: u16,
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            warp: false,
            warp_port: 40000,
            naive: EgressChoice::Direct,
            mieru: EgressChoice::Direct,
            router: false,
            relay_port: 0,
        }
    }
}

impl EgressConfig {
    /// The WARP proxy-mode endpoint, or `None` without WARP.
    pub fn provider_url(&self) -> Option<String> {
        self.warp.then(|| format!("socks5://127.0.0.1:{}", self.warp_port))
    }

    /// The router ingress of `service` (`naive`/`mieru`), or `None` without a router.
    pub fn router_url(&self, service: &str) -> Option<String> {
        let port = ROUTER_PORTS.iter().find(|(name, _)| *name == service)?.1;
        self.router.then(|| format!("socks5://127.0.0.1:{port}"))
    }

    /// `EgressConfig.derived`: what the pre-v0.4 `[three_xui].warp*` keys meant.
    pub fn derived(three_xui: &ThreeXuiConfig) -> EgressConfig {
        let whole = three_xui.warp && three_xui.warp_domains.is_empty();
        let choice = if whole { EgressChoice::Warp } else { EgressChoice::Direct };
        EgressConfig {
            warp: three_xui.warp,
            warp_port: three_xui.warp_port,
            naive: choice,
            mieru: choice,
            ..Default::default()
        }
    }
}

/// `AmneziaWgConfig`; `ports` runs parallel to `versions` (0 = not yet assigned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmneziaWgConfig {
    pub host: String,
    pub versions: Vec<String>,
    pub ports: Vec<u16>,
    pub mtu: u32,
    pub dns: Vec<String>,
}

impl AmneziaWgConfig {
    /// `port_map()` in version order.
    pub fn port_map(&self) -> Vec<(String, u16)> {
        self.versions.iter().cloned().zip(self.ports.iter().copied()).collect()
    }

    pub fn interfaces(&self) -> Vec<String> {
        self.versions.iter().map(|version| awg_interface(version)).collect()
    }
}

/// `TrustTunnelConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustTunnelConfig {
    pub hostname: String,
    pub listen_port: u16,
}

/// `FirewallConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallConfig {
    pub manage_ufw: bool,
}

/// `IngressConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressConfig {
    pub proxy_protocol_bridge: Option<String>,
    pub panel_tls_port: u16,
    pub skip_renewal_dry_run: bool,
}

/// `InstallerConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerConfig {
    pub schema: i64,
    pub host_mode: HostMode,
    pub profile: Profile,
    pub acme_email: String,
    pub initial_user: String,
    pub domains: DomainConfig,
    pub mieru: Option<MieruConfig>,
    pub three_xui: ThreeXuiConfig,
    pub firewall: FirewallConfig,
    /// The written `[egress]` section (`None` for a configuration from before it existed).
    pub egress: Option<EgressConfig>,
    pub ingress: Option<IngressConfig>,
    pub amneziawg: Option<AmneziaWgConfig>,
    pub trusttunnel: Option<TrustTunnelConfig>,
}

impl InstallerConfig {
    /// `effective_egress`: the written section, else derived from `[three_xui]`.
    pub fn effective_egress(&self) -> EgressConfig {
        self.egress.clone().unwrap_or_else(|| EgressConfig::derived(&self.three_xui))
    }

    /// The private Nginx TLS listener of the Core panel.
    pub fn panel_tls_port(&self) -> u16 {
        self.ingress.as_ref().map_or(8443, |ingress| ingress.panel_tls_port)
    }

    /// Every name the installation serves, sorted and unique.
    pub fn required_domains(&self) -> Vec<String> {
        let d = &self.domains;
        let x = &self.three_xui;
        let mut values: Vec<String> = [
            Some(&d.panel),
            Some(&d.mtproxy),
            d.naive.as_ref(),
            d.mieru.as_ref(),
            d.subscription.as_ref(),
            d.mcp.as_ref(),
            d.trusttunnel.as_ref(),
            x.panel_domain.as_ref(),
            x.vless_tcp_domain.as_ref(),
            x.vless_xhttp_domain.as_ref(),
            x.hysteria_domain.as_ref(),
            x.subscription_domain.as_ref(),
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
        values.sort();
        values.dedup();
        values
    }

    /// `canonical_dict()`: every field (absent = `null`), enums as values, tuples as arrays.
    pub fn canonical_dict(&self) -> Value {
        let d = &self.domains;
        let x = &self.three_xui;
        let mut root = Map::new();
        root.insert("schema".into(), json!(self.schema));
        root.insert("host_mode".into(), json!(self.host_mode.value()));
        root.insert("profile".into(), json!(self.profile.value()));
        root.insert("acme_email".into(), json!(self.acme_email));
        root.insert("initial_user".into(), json!(self.initial_user));
        root.insert(
            "domains".into(),
            json!({
                "panel": d.panel, "mtproxy": d.mtproxy, "naive": d.naive, "mieru": d.mieru,
                "subscription": d.subscription, "mcp": d.mcp, "trusttunnel": d.trusttunnel,
            }),
        );
        root.insert(
            "mieru".into(),
            match &self.mieru {
                Some(m) => json!({"tcp_ports": m.tcp_ports, "udp_ports": m.udp_ports, "lane_slots": m.lane_slots}),
                None => Value::Null,
            },
        );
        root.insert(
            "three_xui".into(),
            json!({
                "mode": x.mode.value(), "panel_domain": x.panel_domain, "vless_tcp_domain": x.vless_tcp_domain,
                "vless_xhttp_domain": x.vless_xhttp_domain, "hysteria_domain": x.hysteria_domain, "warp": x.warp,
                "warp_domains": x.warp_domains, "warp_port": x.warp_port, "subscription_domain": x.subscription_domain,
            }),
        );
        root.insert("firewall".into(), json!({"manage_ufw": self.firewall.manage_ufw}));
        root.insert(
            "egress".into(),
            match &self.egress {
                Some(e) => json!({
                    "warp": e.warp, "warp_port": e.warp_port, "naive": e.naive.value(), "mieru": e.mieru.value(),
                    "router": e.router, "relay_port": e.relay_port,
                }),
                None => Value::Null,
            },
        );
        root.insert(
            "ingress".into(),
            match &self.ingress {
                Some(i) => json!({
                    "proxy_protocol_bridge": i.proxy_protocol_bridge, "panel_tls_port": i.panel_tls_port,
                    "skip_renewal_dry_run": i.skip_renewal_dry_run,
                }),
                None => Value::Null,
            },
        );
        root.insert(
            "amneziawg".into(),
            match &self.amneziawg {
                Some(a) => {
                    json!({"host": a.host, "versions": a.versions, "ports": a.ports, "mtu": a.mtu, "dns": a.dns})
                }
                None => Value::Null,
            },
        );
        root.insert(
            "trusttunnel".into(),
            match &self.trusttunnel {
                Some(t) => json!({"hostname": t.hostname, "listen_port": t.listen_port}),
                None => Value::Null,
            },
        );
        Value::Object(root)
    }
}
