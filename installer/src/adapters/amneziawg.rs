//! Installer-owned AmneziaWG runtime and reversible IPv4 forwarding.
use super::{
    trusttunnel::strings,
    vpn::{domain, Runtime, PROJECT, SYSCTL, SYSCTL_TEXT},
    AdapterContext,
};
use crate::{
    adapter::Adapter,
    error::Error,
    journal::{CheckpointData, RollbackTarget},
};
use installer_core::model::{awg_interface, HostMode, InstallerConfig, AWG_DEFAULT_SUBNETS, AWG_VERSIONS};
use installer_core::planner::{Action, AuditFacts, Evidence, PlanError};
use serde_json::{json, Value};
use std::collections::BTreeSet;
pub struct AmneziaWgAdapter {
    runtime: Runtime,
}
struct Selection {
    versions: Vec<String>,
    ports: Vec<u16>,
    host: String,
    mtu: u16,
    dns: Vec<String>,
}
impl AmneziaWgAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { runtime: Runtime { context: context.clone(), awg: true } }
    }
    fn selection(&self, action: &Action) -> Result<Selection, Error> {
        let r = &self.runtime;
        let v = r.values(
            action,
            &[
                "project",
                "state-dir",
                "sysctl-file",
                "ip-forward",
                "versions",
                "ports",
                "interfaces",
                "host",
                "mtu",
                "dns",
                "socket-gid",
                "container",
            ],
        )?;
        if v["sysctl-file"] != SYSCTL || v["ip-forward"] != "1" {
            return Err(r.invalid());
        }
        let versions: Vec<String> = v["versions"].split(',').map(str::to_string).collect();
        if versions.iter().any(|s| !AWG_VERSIONS.contains(&s.as_str()))
            || versions.iter().collect::<BTreeSet<_>>().len() != versions.len()
        {
            return Err(r.invalid());
        }
        let mut ports = Vec::new();
        for (i, entry) in v["ports"].split(',').enumerate() {
            let (version, port) = entry.split_once(':').ok_or_else(|| r.invalid())?;
            if versions.get(i).map(String::as_str) != Some(version)
                || port.is_empty()
                || !port.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(r.invalid());
            }
            ports.push(port.parse::<u16>().ok().filter(|p| *p >= 1024).ok_or_else(|| r.invalid())?);
        }
        if ports.len() != versions.len()
            || ports.iter().collect::<BTreeSet<_>>().len() != ports.len()
            || v["interfaces"] != versions.iter().map(|v| awg_interface(v)).collect::<Vec<_>>().join(",")
        {
            return Err(r.invalid());
        }
        if !domain(v["host"]) && v["host"].parse::<std::net::Ipv4Addr>().is_err() {
            return Err(r.error("invalid AmneziaWG public host"));
        }
        let mtu = v["mtu"]
            .parse::<u16>()
            .ok()
            .filter(|m| (1280..=1420).contains(m))
            .ok_or_else(|| r.error("invalid AmneziaWG MTU"))?;
        let dns: Vec<String> = v["dns"].split(',').map(str::to_string).collect();
        if !(1..=4).contains(&dns.len()) || dns.iter().any(|s| installer_core::ipaddr::ip_address(s).is_err()) {
            return Err(r.error("invalid AmneziaWG DNS list"));
        }
        Ok(Selection { versions, ports, host: v["host"].into(), mtu, dns })
    }
    fn env_text(&self, s: &Selection) -> String {
        let ports = s.versions.iter().zip(&s.ports).map(|(v, p)| format!("{v}={p}")).collect::<Vec<_>>().join(",");
        let subnets = s
            .versions
            .iter()
            .map(|v| format!("{v}={}", AWG_DEFAULT_SUBNETS.iter().find(|(version, _)| *version == v).unwrap().1))
            .collect::<Vec<_>>()
            .join(",");
        format!("AWG_MANAGER_TOKEN_FILE={PROJECT}/secrets/awg-manager-token\nAWG_MANAGER_STATE_DIR=/var/lib/awg-manager\nAWG_VERSIONS={}\nAWG_PORTS={ports}\nAWG_SUBNETS={subnets}\nAWG_MTU={}\nAWG_DNS={}\nAWG_MANAGER_SOCKET_GID=10007\nAMNEZIAWG_PUBLIC_HOST={}\n",s.versions.join(","),s.mtu,s.dns.join(","),s.host)
    }
}
pub(super) fn assert_free(
    facts: &AuditFacts,
    protocol: &str,
    ports: &[u16],
    allowed: &[&str],
    title: &str,
) -> Result<(), Error> {
    let Some(observed) = facts.listeners.get(protocol).and_then(Value::as_array) else { return Ok(()) };
    for port in ports {
        if !observed.iter().any(|v| v.as_u64() == Some(u64::from(*port))) {
            continue;
        }
        let owners = facts.listeners.get("owners").and_then(|v| v.get(port.to_string())).and_then(Value::as_array);
        if owners.is_some_and(|owners| {
            !owners.is_empty() && owners.iter().all(|v| v.as_str().is_some_and(|name| allowed.contains(&name)))
        }) {
            continue;
        }
        return Err(
            PlanError::new(format!("{title} port {port}/{protocol} is already claimed by another listener")).into()
        );
    }
    Ok(())
}
impl Adapter for AmneziaWgAdapter {
    fn name(&self) -> &str {
        "amneziawg"
    }
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        let Some(awg) = &config.amneziawg else { return Ok(vec![]) };
        if self.runtime.tun().is_err() {
            return Err(PlanError::new("AmneziaWG needs /dev/net/tun on the host (load the kernel module: modprobe tun) or a kernel/container platform that provides it").into());
        }
        if awg.ports.contains(&0) {
            return Err(self
                .runtime
                .error("AmneziaWG ports are not assigned (resolve them with installer.awg_ports first)"));
        }
        assert_free(facts, "udp", &awg.ports, &["amneziawg-go"], "AmneziaWG")?;
        Ok(vec![Action {
            id: "amneziawg.runtime".into(),
            adapter: self.name().into(),
            owner: "proxy-control:amneziawg".into(),
            mutations: vec![
                format!("project={PROJECT}"),
                "state-dir=/var/lib/awg-manager".into(),
                format!("sysctl-file={SYSCTL}"),
                "ip-forward=1".into(),
                format!("versions={}", awg.versions.join(",")),
                format!(
                    "ports={}",
                    awg.versions.iter().zip(&awg.ports).map(|(v, p)| format!("{v}:{p}")).collect::<Vec<_>>().join(",")
                ),
                format!("interfaces={}", awg.versions.iter().map(|v| awg_interface(v)).collect::<Vec<_>>().join(",")),
                format!("host={}", awg.host),
                format!("mtu={}", awg.mtu),
                format!("dns={}", awg.dns.join(",")),
                "socket-gid=10007".into(),
                "container=proxy-control-awg-manager".into(),
            ],
            preconditions: strings(&[
                "the Core runtime is verified",
                "/dev/net/tun exists on the host",
                "the selected UDP ports are free or held by the owned manager",
                if config.host_mode == HostMode::Fresh && config.firewall.manage_ufw {
                    "the host firewall allows the selected UDP ports and forwarding on the awg interfaces (managed by this installer through UFW)"
                } else {
                    "the operator opens the selected UDP ports and allows forwarding on the awg interfaces in the host firewall (the installer does not manage it here)"
                },
                "the host name clients dial points straight at this server and is not proxied",
            ]),
            verification: strings(&[
                "the awg-manager container is healthy",
                "the manager answers /v1/health over its Unix socket and every enabled version is running",
                "every selected UDP port is bound on the host",
                "IPv4 forwarding is enabled",
            ]),
            inverse: strings(&[
                "stop and remove only the awg-manager Compose service",
                "remove only the owned env overlay, sysctl file and marker",
                "preserve the state directory (server keys) and the manager secret unless purge is explicit",
            ]),
            credentials_required: true,
        }])
    }
    fn prepare(&self, a: &Action) -> Result<CheckpointData, Error> {
        self.selection(a)?;
        self.runtime.prepare(a)
    }
    fn apply(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        let s = self.selection(a)?;
        self.runtime.apply(a, d, &self.env_text(&s), None, false)
    }
    fn reconcile_apply(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(a, d)
    }
    fn repair(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        let s = self.selection(a)?;
        self.runtime.apply(a, d, &self.env_text(&s), None, true)
    }
    fn verify(&self, a: &Action) -> Result<Evidence, Error> {
        let s = self.selection(a)?;
        let r = &self.runtime;
        let path = r.host(SYSCTL)?;
        if path.is_symlink() || !path.is_file() || std::fs::read_to_string(path)? != SYSCTL_TEXT {
            return Err(r.error("the AmneziaWG sysctl file is missing or changed"));
        }
        r.verify_state()?;
        let report = r.health()?;
        let instances = report.get("instances").and_then(Value::as_object);
        if report["status"] != "ok"
            || report["ip_forward"] != true
            || instances.is_none_or(|m| m.keys().collect::<BTreeSet<_>>() != s.versions.iter().collect())
        {
            return Err(r.error("the AmneziaWG manager does not report a healthy state"));
        }
        for (v, p) in s.versions.iter().zip(&s.ports) {
            if report["instances"][v]["running"] != true {
                return Err(r.error(format!("AmneziaWG {v} is not running")));
            }
            if report["instances"][v]["port"] != *p {
                return Err(r.error(format!("AmneziaWG {v} does not run on its planned port")));
            }
            if !r.listener(*p) {
                return Err(r.error(format!("AmneziaWG {v} does not listen on {p}/udp")));
            }
        }
        let ports: serde_json::Map<String, Value> =
            s.versions.iter().zip(&s.ports).map(|(v, p)| (v.clone(), json!(p))).collect();
        Ok(Evidence{action_id:a.id.clone(),success:true,observations:strings(&["the awg-manager container is healthy and answers over its Unix socket","every enabled AmneziaWG version is running and bound to its UDP port","IPv4 forwarding is enabled","the operator must keep the UDP ports open and forwarding allowed on the awg interfaces in any firewall the installer does not manage"]),details:json!({"versions":s.versions,"ports":ports,"interfaces":s.versions.iter().map(|v|awg_interface(v)).collect::<Vec<_>>()}).as_object().unwrap().clone()})
    }
    fn rollback(&self, a: &Action, d: CheckpointData, p: bool, t: RollbackTarget) -> Result<Evidence, Error> {
        self.selection(a)?;
        self.runtime.rollback(a, d, p, t)
    }
    fn reconcile_rollback(&self, a: &Action, d: CheckpointData, p: bool, t: RollbackTarget) -> Result<Evidence, Error> {
        self.rollback(a, d, p, t)
    }
}
