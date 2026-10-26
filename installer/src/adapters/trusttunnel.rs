//! Installer-owned TrustTunnel host-network runtime.
use super::{
    vpn::{domain, hex, Runtime, PROJECT},
    AdapterContext,
};
use crate::{
    adapter::Adapter,
    error::Error,
    journal::{CheckpointData, RollbackTarget},
};
use installer_core::model::{InstallerConfig, TT_METRICS_PORT};
use installer_core::planner::{Action, AuditFacts, Evidence};
use serde_json::json;
pub const TT_VERSION: &str = "1.1.0";
pub const TT_SHA256: &str = "91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7";
pub const TT_SHA256_AARCH64: &str = "c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686";
pub struct TrustTunnelAdapter {
    runtime: Runtime,
}
struct Selection {
    hostname: String,
    listen: String,
    port: u16,
    version: String,
    sha256: String,
}
impl TrustTunnelAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { runtime: Runtime { context: context.clone(), awg: false } }
    }
    fn selection(&self, action: &Action) -> Result<Selection, Error> {
        let r = &self.runtime;
        let v = r.values(
            action,
            &[
                "project",
                "state-dir",
                "letsencrypt-dir",
                "hostname",
                "listen",
                "metrics",
                "version",
                "sha256",
                "socket-gid",
                "container",
            ],
        )?;
        if v["letsencrypt-dir"] != "/etc/letsencrypt"
            || v["metrics"] != format!("127.0.0.1:{TT_METRICS_PORT}")
            || v["version"].split('.').count() != 3
            || !v["version"].split('.').all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            || !hex(v["sha256"], 64)
        {
            return Err(r.invalid());
        }
        if !domain(v["hostname"]) {
            return Err(r.error("invalid TrustTunnel host name"));
        }
        let port = v["listen"]
            .strip_prefix("127.0.0.1:")
            .filter(|s| !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p >= 1024 && *p != TT_METRICS_PORT)
            .ok_or_else(|| r.error("invalid TrustTunnel listen address"))?;
        Ok(Selection {
            hostname: v["hostname"].into(),
            listen: v["listen"].into(),
            port,
            version: v["version"].into(),
            sha256: v["sha256"].into(),
        })
    }
    fn env_text(&self, s: &Selection) -> String {
        format!("TRUSTTUNNEL_MANAGER_TOKEN_FILE={PROJECT}/secrets/trusttunnel-manager-token\nTT_MANAGER_STATE_DIR=/var/lib/trusttunnel-manager\nTT_CERT_DIR=/etc/letsencrypt\nTT_HOSTNAME={}\nTT_LISTEN={}\nTT_VERSION=v{}\nTT_SHA256_X86_64={}\nTT_SHA256_AARCH64={TT_SHA256_AARCH64}\nTRUSTTUNNEL_MANAGER_SOCKET_GID=10008\nTRUSTTUNNEL_PUBLIC_HOST={}\n",s.hostname,s.listen,s.version,s.sha256,s.hostname)
    }
}
impl Adapter for TrustTunnelAdapter {
    fn name(&self) -> &str {
        "trusttunnel"
    }
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        let Some(tt) = &config.trusttunnel else { return Ok(vec![]) };
        super::amneziawg::assert_free(
            facts,
            "tcp",
            &[tt.listen_port],
            &["trusttunnel_endpoint", "trusttunnel_end"],
            "TrustTunnel",
        )?;
        Ok(vec![Action{id:"trusttunnel.runtime".into(),adapter:self.name().into(),owner:"proxy-control:trusttunnel".into(),mutations:vec![format!("project={PROJECT}"),"state-dir=/var/lib/trusttunnel-manager".into(),"letsencrypt-dir=/etc/letsencrypt".into(),format!("hostname={}",tt.hostname),format!("listen=127.0.0.1:{}",tt.listen_port),format!("metrics=127.0.0.1:{TT_METRICS_PORT}"),format!("version={TT_VERSION}"),format!("sha256={TT_SHA256}"),"socket-gid=10008".into(),"container=proxy-control-trusttunnel-manager".into()],preconditions:strings(&["the Core runtime is verified","the certificate of the TrustTunnel host name is issued by the certificates step and mounted read-only","the TrustTunnel host name has an A record to this server and is not proxied by a CDN","TCP/443 is shared with the other services through the Nginx SNI router (TCP only: no UDP port and no firewall rule are added)"]),verification:strings(&["the trusttunnel-manager container is healthy","the manager answers /v1/health over its Unix socket and the endpoint is running","the endpoint listens on its loopback TCP port","the host name's certificate lineage is present and readable"]),inverse:strings(&["stop and remove only the trusttunnel-manager Compose service","remove only the owned env overlay and marker","preserve the state directory (credentials) and the manager secret unless purge is explicit"]),credentials_required:true}])
    }
    fn prepare(&self, a: &Action) -> Result<CheckpointData, Error> {
        self.selection(a)?;
        self.runtime.prepare(a)
    }
    fn apply(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        let s = self.selection(a)?;
        self.runtime.apply(a, d, &self.env_text(&s), Some(&s.hostname), false)
    }
    fn reconcile_apply(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(a, d)
    }
    fn repair(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        let s = self.selection(a)?;
        self.runtime.apply(a, d, &self.env_text(&s), Some(&s.hostname), true)
    }
    fn verify(&self, a: &Action) -> Result<Evidence, Error> {
        let s = self.selection(a)?;
        let r = &self.runtime;
        r.verify_state()?;
        r.certificate(&s.hostname)?;
        let report = r.health()?;
        if report["status"] != "ok" || report["endpoint"]["running"] != true {
            return Err(r.error("the TrustTunnel manager does not report a healthy endpoint"));
        }
        if !r.listener(s.port) {
            return Err(r.error(format!("the TrustTunnel endpoint does not listen on 127.0.0.1:{}", s.port)));
        }
        Ok(Evidence {
            action_id: a.id.clone(),
            success: true,
            observations: strings(&[
                "the trusttunnel-manager container is healthy and answers over its Unix socket",
                "the TrustTunnel endpoint is running and bound to its loopback TCP port",
                "TrustTunnel shares TCP/443 through the SNI router: no UDP port was opened and no firewall rule added",
                "the host name needs an A record to this server and must not be proxied by a CDN",
            ]),
            details: json!({"hostname":s.hostname,"listen":format!("127.0.0.1:{}",s.port),"version":s.version})
                .as_object()
                .unwrap()
                .clone(),
        })
    }
    fn rollback(&self, a: &Action, d: CheckpointData, p: bool, t: RollbackTarget) -> Result<Evidence, Error> {
        self.selection(a)?;
        self.runtime.rollback(a, d, p, t)
    }
    fn reconcile_rollback(&self, a: &Action, d: CheckpointData, p: bool, t: RollbackTarget) -> Result<Evidence, Error> {
        self.rollback(a, d, p, t)
    }
}
pub(super) fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
