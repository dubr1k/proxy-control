//! HTTP-01 routing and Certbot lineage lifecycle (`CertificatePlan` in
//! `installer/adapters/nginx.py`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pc_host::fs::{atomic_write, durable_remove, sha256_hex};
use pc_host::runner::{Bounded, BoundedOutput, HostRunner};
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::adapters::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::{InstallerConfig, ThreeXuiMode};
use crate::planner::{Action, AuditFacts, Evidence};

use super::nginx::{
    current_uid_gid, effective_source_sections, reload_nginx, safe_host_path, sanitize_diagnostic, topology,
    valid_domain, Result,
};

#[derive(Debug, Clone)]
struct CertificateSpec {
    certificate: String,
    email: String,
    names: Vec<String>,
    service: String,
    skip_renewal_dry_run: bool,
    webroots: Vec<String>,
}

#[derive(Debug, Clone)]
struct SavedCheckpoint {
    created_webroots: Vec<String>,
    lineage_preexisting: bool,
    vhost: String,
    vhost_sha256: Option<String>,
}

/// Own HTTP-01 routing and verify service-scoped Certbot lineages.
pub struct CertificatePlan {
    root: PathBuf,
    runner: Arc<dyn HostRunner>,
    expected_key_owner: (u32, u32),
    renewal_evidence: Mutex<BTreeMap<String, (String, String)>>,
}

impl CertificatePlan {
    pub fn new(context: &AdapterContext) -> CertificatePlan {
        CertificatePlan {
            root: fs::canonicalize(&context.root).unwrap_or_else(|_| context.root.clone()),
            runner: context.runner.clone(),
            expected_key_owner: current_uid_gid(),
            renewal_evidence: Mutex::new(BTreeMap::new()),
        }
    }

    /// Test/lab equivalent of Python's `expected_key_owner` constructor argument.
    pub fn with_expected_key_owner(mut self, uid: u32, gid: u32) -> CertificatePlan {
        self.expected_key_owner = (uid, gid);
        self
    }

    fn contained_path(&self, host_path: &str, allow_missing: bool) -> Result<PathBuf> {
        let normalized = safe_host_path(host_path)?;
        let path = self.root.join(normalized.trim_start_matches('/'));
        let mut nearest = path.clone();
        while !path_exists(&nearest) {
            if nearest == self.root {
                if !allow_missing && !path.exists() {
                    return topology("certificate path is missing");
                }
                return Ok(path);
            }
            nearest = nearest
                .parent()
                .ok_or_else(|| Error::other("TopologyError", "certificate path cannot be resolved"))?
                .to_path_buf();
        }
        let resolved = fs::canonicalize(&nearest)
            .map_err(|_| Error::other("TopologyError", "certificate path cannot be resolved"))?;
        self.assert_contained(&resolved)?;
        if !allow_missing && !path.exists() {
            return topology("certificate path is missing");
        }
        Ok(path)
    }

    fn assert_contained(&self, path: &Path) -> Result<()> {
        if path.strip_prefix(&self.root).is_err() {
            return topology("certificate path escapes the supplied root");
        }
        Ok(())
    }

    fn ensure_webroot(&self, host_path: &str) -> Result<Vec<String>> {
        let challenge = format!("{host_path}/.well-known/acme-challenge");
        let path = self.contained_path(&challenge, true)?;
        let mut created = Vec::new();
        let mut cursor = self.root.clone();
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| Error::other("TopologyError", "certificate path escapes the supplied root"))?
            .to_path_buf();
        for part in relative.components() {
            cursor.push(part.as_os_str());
            if path_exists(&cursor) {
                if cursor.is_symlink() || !cursor.is_dir() {
                    return topology("certificate webroot is not a real directory");
                }
                continue;
            }
            fs::DirBuilder::new().mode(0o755).create(&cursor)?;
            fs::set_permissions(&cursor, fs::Permissions::from_mode(0o755))?;
            created.push(format!("/{}", cursor.strip_prefix(&self.root).expect("contained").display()));
        }
        for required in [
            self.contained_path(host_path, false)?,
            self.contained_path(&format!("{host_path}/.well-known"), false)?,
            path,
        ] {
            if fs::metadata(required)?.mode() & 0o7777 != 0o755 {
                return topology("certificate webroot permissions are invalid");
            }
        }
        Ok(created)
    }

    fn ensure_vhost(&self, host_path: &str, desired: &[u8]) -> Result<()> {
        let vhost = self.contained_path(host_path, true)?;
        if path_exists(&vhost) {
            if vhost.is_symlink() || !vhost.is_file() || fs::read(&vhost)? != desired {
                return topology("owned certificate HTTP-01 vhost has drifted");
            }
            return Ok(());
        }
        atomic_write(&vhost, desired, 0o644, Some(current_uid_gid()))?;
        Ok(())
    }

    fn vhost_valid(&self, action: &Action, spec: &CertificateSpec) -> bool {
        let Ok(path) = self.contained_path(&certificate_vhost_path(spec), true) else { return false };
        !path.is_symlink()
            && path.is_file()
            && fs::read(&path).is_ok_and(|content| content == render_certificate_vhost(action, spec))
    }

    fn assert_vhost_effective(&self, host_path: &str, desired: &[u8]) -> Result<()> {
        let result = self.runner.bounded(&["nginx", "-T"], Bounded::CERTIFICATES)?;
        if result.returncode != 0 {
            return topology("effective Nginx HTTP-01 inspection failed");
        }
        let Ok(rendered) = std::str::from_utf8(desired) else { return topology("owned HTTP-01 vhost is not UTF-8") };
        let sections = effective_source_sections(&result.stdout);
        if sections.get(host_path).is_none_or(|sections| {
            sections.len() != 1 || (sections[0] != rendered && sections[0] != format!("{rendered}\n"))
        }) {
            return topology("owned HTTP-01 vhost is absent from effective Nginx");
        }
        Ok(())
    }

    fn assert_vhost_absent(&self, host_path: &str) -> Result<()> {
        let result = self.runner.bounded(&["nginx", "-T"], Bounded::CERTIFICATES)?;
        if result.returncode != 0 {
            return topology("effective Nginx HTTP-01 inspection failed");
        }
        if effective_source_sections(&result.stdout).contains_key(host_path) {
            return topology("owned HTTP-01 vhost remains in effective Nginx");
        }
        Ok(())
    }

    fn lineage_state(&self, spec: &CertificateSpec) -> Result<&'static str> {
        let live = self.contained_path(&format!("/etc/letsencrypt/live/{}", spec.certificate), true)?;
        let archive = self.contained_path(&format!("/etc/letsencrypt/archive/{}", spec.certificate), true)?;
        let renewal = self.contained_path(&format!("/etc/letsencrypt/renewal/{}.conf", spec.certificate), true)?;
        let paths = [&live, &archive, &renewal];
        let present: Vec<bool> = paths.iter().map(|path| path_exists(path)).collect();
        if !present.iter().any(|present| *present) {
            return Ok("absent");
        }
        if !present.iter().all(|present| *present) {
            return Ok("incomplete");
        }
        if live.is_symlink()
            || !live.is_dir()
            || archive.is_symlink()
            || !archive.is_dir()
            || renewal.is_symlink()
            || !renewal.is_file()
        {
            return Ok("incomplete");
        }
        Ok("complete")
    }

    fn remove_action_lineage(&self, spec: &CertificateSpec) -> Result<()> {
        let paths = [
            (self.contained_path(&format!("/etc/letsencrypt/renewal/{}.conf", spec.certificate), true)?, "file"),
            (self.contained_path(&format!("/etc/letsencrypt/live/{}", spec.certificate), true)?, "directory"),
            (self.contained_path(&format!("/etc/letsencrypt/archive/{}", spec.certificate), true)?, "directory"),
        ];
        for (path, kind) in &paths {
            if !path_exists(path) {
                continue;
            }
            if path.is_symlink() || (*kind == "file" && !path.is_file()) || (*kind == "directory" && !path.is_dir()) {
                return topology("action-created certificate lineage has unsafe path types");
            }
        }
        for (path, _) in paths {
            durable_remove(&path, true)?;
        }
        Ok(())
    }

    fn certificate_valid(&self, spec: &CertificateSpec) -> bool {
        (|| -> Result<bool> {
            let live = self.contained_path(&format!("/etc/letsencrypt/live/{}", spec.certificate), true)?;
            let paths: BTreeMap<&str, PathBuf> = ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"]
                .into_iter()
                .map(|name| (name, live.join(name)))
                .collect();
            for path in paths.values() {
                let resolved = fs::canonicalize(path).map_err(Error::from)?;
                self.assert_contained(&resolved)?;
                if !resolved.is_file() {
                    return Ok(false);
                }
            }
            let key = fs::canonicalize(&paths["privkey.pem"])?;
            let metadata = fs::metadata(key)?;
            if !metadata.file_type().is_file()
                || metadata.mode() & 0o7777 != 0o600
                || (metadata.uid(), metadata.gid()) != self.expected_key_owner
            {
                return Ok(false);
            }
            let key_public = self.openssl(&["pkey", "-in", &paths["privkey.pem"].to_string_lossy(), "-pubout"])?;
            let leaf_public =
                self.openssl(&["x509", "-in", &paths["cert.pem"].to_string_lossy(), "-pubkey", "-noout"])?;
            if key_public.returncode != 0
                || leaf_public.returncode != 0
                || key_public.stdout.trim().is_empty()
                || key_public.stdout.trim() != leaf_public.stdout.trim()
            {
                return Ok(false);
            }
            if self
                .openssl(&["x509", "-in", &paths["cert.pem"].to_string_lossy(), "-noout", "-checkend", "0"])?
                .returncode
                != 0
            {
                return Ok(false);
            }
            if self
                .openssl(&[
                    "verify",
                    "-CApath",
                    "/etc/ssl/certs",
                    "-untrusted",
                    &paths["chain.pem"].to_string_lossy(),
                    &paths["cert.pem"].to_string_lossy(),
                ])?
                .returncode
                != 0
            {
                return Ok(false);
            }
            let sans = self.openssl(&[
                "x509",
                "-in",
                &paths["cert.pem"].to_string_lossy(),
                "-noout",
                "-ext",
                "subjectAltName",
            ])?;
            Ok(sans.returncode == 0 && certificate_sans(&sans.stdout) == spec.names.iter().cloned().collect())
        })()
        .unwrap_or(false)
    }

    fn openssl(&self, arguments: &[&str]) -> Result<BoundedOutput> {
        let mut argv = vec!["openssl"];
        argv.extend(arguments);
        Ok(self.runner.bounded(&argv, Bounded::CERTIFICATES)?)
    }

    fn issue_certificate(&self, spec: &CertificateSpec) -> Result<()> {
        let mut argv = vec![
            "certbot".to_string(),
            "certonly".into(),
            "--non-interactive".into(),
            "--agree-tos".into(),
            "--email".into(),
            spec.email.clone(),
            "--cert-name".into(),
            spec.certificate.clone(),
            "--webroot".into(),
        ];
        for (name, webroot) in spec.names.iter().zip(&spec.webroots) {
            argv.extend(["-w".into(), webroot.clone(), "-d".into(), name.clone()]);
        }
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.run_checked(&refs, "certificate issuance failed", false)
    }

    fn renewal_identity(&self, certificate: &str) -> Option<(String, String)> {
        let renewal = self.root.join("etc/letsencrypt/renewal").join(format!("{certificate}.conf"));
        let fullchain = self.root.join("etc/letsencrypt/live").join(certificate).join("fullchain.pem");
        if !renewal.is_file() || !fullchain.is_file() {
            return None;
        }
        Some((sha256_hex(&fs::read(renewal).ok()?), sha256_hex(&fs::read(fullchain).ok()?)))
    }

    fn run_renewal(&self, spec: &CertificateSpec) -> Result<()> {
        let identity = self.renewal_identity(&spec.certificate);
        if let Some(identity) = &identity {
            let cached = self.renewal_evidence.lock().unwrap_or_else(|error| error.into_inner()).get(&spec.certificate)
                == Some(identity);
            if cached {
                self.renewal_evidence.lock().unwrap_or_else(|error| error.into_inner()).remove(&spec.certificate);
                return Ok(());
            }
        }
        self.run_checked(
            &["certbot", "renew", "--cert-name", &spec.certificate, "--dry-run", "--no-random-sleep-on-renew"],
            "certificate renewal dry run failed",
            false,
        )?;
        if let Some(identity) = identity {
            self.renewal_evidence
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(spec.certificate.clone(), identity);
        }
        Ok(())
    }

    fn ensure_lineage(
        &self,
        spec: &CertificateSpec,
        preexisting: bool,
        repair_renewal: bool,
        skip_renewal_dry_run: bool,
    ) -> Result<()> {
        let mut state = self.lineage_state(spec)?;
        let mut valid = self.certificate_valid(spec);
        if preexisting {
            if state != "complete" || !valid {
                return topology("pre-existing certificate lineage identity changed or is invalid");
            }
        } else if state != "complete" || !valid {
            if state != "absent" {
                self.remove_action_lineage(spec)?;
            }
            self.issue_certificate(spec)?;
            state = self.lineage_state(spec)?;
            valid = self.certificate_valid(spec);
            if state != "complete" || !valid {
                return topology("certificate validity, trust, SANs, or private key are invalid");
            }
        }
        if preexisting && skip_renewal_dry_run {
            return Ok(());
        }
        match self.run_renewal(spec) {
            Ok(()) => Ok(()),
            Err(error)
                if !preexisting
                    && repair_renewal
                    && matches!(&error, Error::Other { class, .. } if class.as_ref() == "TopologyError") =>
            {
                self.remove_action_lineage(spec)?;
                self.issue_certificate(spec)?;
                if self.lineage_state(spec)? != "complete" || !self.certificate_valid(spec) {
                    return topology("certificate validity, trust, SANs, or private key are invalid");
                }
                self.run_renewal(spec)
            }
            Err(error) => Err(error),
        }
    }

    fn activate(&self, action: &Action, checkpoint: CheckpointData, repair_renewal: bool) -> Result<CheckpointData> {
        let spec = certificate_action(action)?;
        let saved = certificate_checkpoint(&checkpoint, &spec)?;
        let desired_vhost = render_certificate_vhost(action, &spec);
        if !saved.lineage_preexisting
            && saved.vhost_sha256.is_none()
            && self.lineage_state(&spec)? != "absent"
            && !self.vhost_valid(action, &spec)
        {
            return topology("certificate lineage appeared after prepare");
        }
        let mut created: BTreeSet<String> = saved.created_webroots.iter().cloned().collect();
        for webroot in &spec.webroots {
            created.extend(self.ensure_webroot(webroot)?);
        }
        let desired_hash = sha256_hex(&desired_vhost);
        self.ensure_vhost(&saved.vhost, &desired_vhost)?;
        self.run_checked(&["nginx", "-t"], "Nginx HTTP-01 vhost test failed", true)?;
        reload_nginx(self.runner.as_ref(), Bounded::CERTIFICATES, "Nginx HTTP-01 vhost reload failed")?;
        self.assert_vhost_effective(&saved.vhost, &desired_vhost)?;
        self.ensure_lineage(&spec, saved.lineage_preexisting, repair_renewal, spec.skip_renewal_dry_run)?;
        Ok(Map::from_iter([
            ("certificate".into(), json!(spec.certificate)),
            ("created_webroots".into(), json!(created.into_iter().collect::<Vec<_>>())),
            ("lineage_preexisting".into(), json!(saved.lineage_preexisting)),
            ("names".into(), json!(spec.names)),
            ("owner".into(), json!(action.owner)),
            ("ownership".into(), json!({saved.vhost.clone(): {"sha256": desired_hash}})),
            ("vhost".into(), json!(saved.vhost)),
            ("vhost_sha256".into(), json!(desired_hash)),
        ]))
    }

    fn run_checked(&self, argv: &[&str], message: &str, include_output: bool) -> Result<()> {
        let mut result = self.runner.bounded(argv, Bounded::CERTIFICATES)?;
        if result.returncode != 0
            && argv.starts_with(&["certbot", "renew"])
            && argv.contains(&"--dry-run")
            && ["authorization must be pending", "orderNotReady", "not acceptable for finalization"]
                .iter()
                .any(|race| format!("{}\n{}", result.stderr, result.stdout).contains(race))
        {
            std::thread::sleep(Duration::from_secs(3));
            result = self.runner.bounded(argv, Bounded::CERTIFICATES)?;
        }
        if result.returncode != 0 {
            let detail = if include_output {
                sanitize_diagnostic(&format!("{}\n{}", result.stderr, result.stdout), 800)
            } else {
                "see /var/log/letsencrypt/letsencrypt.log for the full ACME reason".into()
            };
            return topology(if detail.is_empty() { message.to_string() } else { format!("{message}: {detail}") });
        }
        Ok(())
    }
}

impl Adapter for CertificatePlan {
    fn name(&self) -> &str {
        "certificates"
    }

    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>> {
        if facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|stops| !stops.is_empty()) {
            return topology("host audit contains blocking findings");
        }
        let groups = certificate_groups(config)?;
        for (_, _, names) in &groups {
            validate_certificate_facts(names, facts)?;
        }
        groups
            .into_iter()
            .map(|(service, certificate, names)| {
                let skip = config.ingress.as_ref().is_some_and(|ingress| ingress.skip_renewal_dry_run);
                let mut mutations = vec![
                    format!("service={service}"),
                    format!("certificate={certificate}"),
                    format!("email={}", config.acme_email),
                ];
                if skip {
                    mutations.push("skip-renewal-dry-run=true".into());
                }
                mutations.extend(names.iter().map(|name| format!("name={name}")));
                mutations.extend(names.iter().map(|name| format!("webroot=/var/www/{name}")));
                Ok(Action::new(
                    &format!("certificate.{service}"),
                    "certificates",
                    &format!("proxy-control:certificate:{service}"),
                    mutations,
                    vec!["strict local A, handled AAAA, and HTTP-01 CAA facts pass".into()],
                    vec![
                        "owned port-80 HTTP-01 vhosts are active".into(),
                        "certificate validity, trust, exact SANs, and key pair pass".into(),
                        if skip {
                            "existing valid lineage is verified locally; ACME renewal simulation is explicitly deferred"
                                .into()
                        } else {
                            "Certbot renewal dry run succeeds for the exact lineage".into()
                        },
                    ],
                    vec!["remove only the exact owned HTTP-01 vhost and preserve ACME data".into()],
                    false,
                )?)
            })
            .collect()
    }

    fn prepare(&self, action: &Action) -> Result<CheckpointData> {
        let spec = certificate_action(action)?;
        let vhost_name = certificate_vhost_path(&spec);
        let vhost = self.contained_path(&vhost_name, true)?;
        if path_exists(&vhost) {
            return topology("certificate HTTP-01 vhost path is already occupied");
        }
        let lineage_state = self.lineage_state(&spec)?;
        if lineage_state == "incomplete" {
            return topology("pre-existing certificate lineage is incomplete");
        }
        Ok(Map::from_iter([
            ("certificate".into(), json!(spec.certificate)),
            ("created_webroots".into(), json!([])),
            ("lineage_preexisting".into(), json!(lineage_state == "complete")),
            ("names".into(), json!(spec.names)),
            ("owner".into(), json!(action.owner)),
            ("ownership".into(), json!({})),
            ("vhost".into(), json!(vhost_name)),
            ("vhost_sha256".into(), Value::Null),
        ]))
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData> {
        self.activate(action, checkpoint, false)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData> {
        self.apply(action, checkpoint)
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData> {
        self.activate(action, checkpoint, true)
    }

    fn verify(&self, action: &Action) -> Result<Evidence> {
        let spec = certificate_action(action)?;
        let success = (|| {
            let vhost_name = certificate_vhost_path(&spec);
            let desired = render_certificate_vhost(action, &spec);
            if !self.vhost_valid(action, &spec) {
                return topology("owned HTTP-01 vhost is invalid");
            }
            self.assert_vhost_effective(&vhost_name, &desired)?;
            if self.lineage_state(&spec)? != "complete" {
                return topology("certificate lineage is incomplete");
            }
            if !self.certificate_valid(&spec) {
                return topology("certificate lineage is invalid");
            }
            if !spec.skip_renewal_dry_run {
                self.run_renewal(&spec)?;
            }
            Ok(true)
        })()
        .unwrap_or(false);
        if !success {
            self.renewal_evidence.lock().unwrap_or_else(|error| error.into_inner()).remove(&spec.certificate);
        }
        let observation = if success {
            "owned HTTP-01 vhost and service certificate are valid"
        } else {
            "owned HTTP-01 vhost or service certificate is invalid"
        };
        Evidence::with_details(
            &action.id,
            success,
            vec![observation.into()],
            Map::from_iter([("certificate".into(), json!(spec.certificate)), ("names".into(), json!(spec.names))]),
        )
        .map_err(Into::into)
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        _purge_data: bool,
        _target: RollbackTarget,
    ) -> Result<Evidence> {
        let spec = certificate_action(action)?;
        let saved = certificate_checkpoint(&checkpoint, &spec)?;
        let vhost = self.contained_path(&saved.vhost, true)?;
        let desired = render_certificate_vhost(action, &spec);
        let mut removed = false;
        if path_exists(&vhost) {
            if vhost.is_symlink() || !vhost.is_file() || fs::read(&vhost)? != desired {
                return topology("owned certificate HTTP-01 vhost has drifted");
            }
            durable_remove(&vhost, false)?;
            removed = true;
        }
        if let Err(error) = (|| {
            self.run_checked(&["nginx", "-t"], "Nginx HTTP-01 rollback test failed", false)?;
            reload_nginx(self.runner.as_ref(), Bounded::CERTIFICATES, "Nginx HTTP-01 rollback reload failed")?;
            self.assert_vhost_absent(&saved.vhost)
        })() {
            if removed {
                let _ = atomic_write(&vhost, &desired, 0o644, Some(current_uid_gid()));
            }
            return Err(error);
        }
        if !saved.lineage_preexisting {
            let state = self.lineage_state(&spec)?;
            if state == "incomplete" || (state == "complete" && !self.certificate_valid(&spec)) {
                self.remove_action_lineage(&spec)?;
            }
        }
        Evidence::with_details(
            &action.id,
            true,
            vec!["owned HTTP-01 vhost removed; valid certificates and webroots preserved".into()],
            Map::from_iter([("certificate".into(), json!(spec.certificate))]),
        )
        .map_err(Into::into)
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence> {
        self.rollback(action, checkpoint, purge_data, target)
    }
}

fn certificate_groups(config: &InstallerConfig) -> Result<Vec<(String, String, Vec<String>)>> {
    let mut core_names = BTreeSet::from([config.domains.mtproxy.clone(), config.domains.panel.clone()]);
    core_names.extend(config.domains.subscription.clone());
    core_names.extend(config.domains.mcp.clone());
    let mut groups =
        vec![("proxy-control".to_string(), config.domains.mtproxy.clone(), core_names.into_iter().collect())];
    if config.profile.includes_naive() {
        let Some(domain) = &config.domains.naive else { return topology("Naive certificate domain is missing") };
        groups.push(("naive".into(), domain.clone(), vec![domain.clone()]));
    }
    if let Some(trusttunnel) = &config.trusttunnel {
        groups.push(("trusttunnel".into(), trusttunnel.hostname.clone(), vec![trusttunnel.hostname.clone()]));
    }
    if config.three_xui.mode == ThreeXuiMode::ManagedNew {
        if let Some(domain) = &config.three_xui.panel_domain {
            groups.push(("three-xui-panel".into(), domain.clone(), vec![domain.clone()]));
        }
        if let Some(domain) = &config.three_xui.hysteria_domain {
            groups.push(("three-xui-hysteria".into(), domain.clone(), vec![domain.clone()]));
        }
    }
    if let Some(domain) = &config.three_xui.subscription_domain {
        groups.push(("three-xui-subscription".into(), domain.clone(), vec![domain.clone()]));
    }
    groups.sort();
    Ok(groups)
}

fn validate_certificate_facts(names: &[String], facts: &AuditFacts) -> Result<()> {
    let Some(dns) = facts.topology.get("dns").and_then(Value::as_object) else {
        return topology("certificate domain preflight facts are missing");
    };
    let Some(certificates) = facts.topology.get("certificates").and_then(Value::as_object) else {
        return topology("certificate domain preflight facts are missing");
    };
    for name in names {
        let failed = || Error::other("TopologyError", format!("certificate domain preflight failed: {name}"));
        let observation = dns.get(name).and_then(Value::as_object).ok_or_else(failed)?;
        let certificate = certificates.get(name).and_then(Value::as_object).ok_or_else(failed)?;
        let valid_caa_source = observation
            .get("caa_source")
            .is_some_and(|source| source.is_null() || source.as_str().is_some_and(|source| !source.is_empty()));
        let present = certificate.get("present").and_then(Value::as_bool);
        let covers = certificate.get("covers_domain").and_then(Value::as_bool);
        if !address_facts(observation.get("a"), 4, true)
            || !address_facts(observation.get("aaaa"), 6, false)
            || !observation.get("caa").is_some_and(Value::is_array)
            || !valid_caa_source
            || observation.get("a_matches_local").and_then(Value::as_bool) != Some(true)
            || observation.get("aaaa_handled").and_then(Value::as_bool) != Some(true)
            || observation.get("caa_compatible").and_then(Value::as_bool) != Some(true)
            || present.is_none()
            || covers.is_none()
            || (present == Some(true) && covers != Some(true))
        {
            return Err(failed());
        }
    }
    Ok(())
}

fn address_facts(value: Option<&Value>, version: u8, require_one: bool) -> bool {
    let Some(values) = value.and_then(Value::as_array) else { return false };
    if require_one && values.is_empty() {
        return false;
    }
    values.iter().all(|value| {
        value
            .as_str()
            .and_then(|address| address.parse::<IpAddr>().ok())
            .is_some_and(|address| matches!((version, address), (4, IpAddr::V4(_)) | (6, IpAddr::V6(_))))
    })
}

fn certificate_action(action: &Action) -> Result<CertificateSpec> {
    if action.adapter != "certificates" || !action.id.starts_with("certificate.") {
        return topology("certificate action identity is invalid");
    }
    let mut singular = BTreeMap::new();
    let mut names = Vec::new();
    let mut webroots = Vec::new();
    for mutation in &action.mutations {
        let Some((key, value)) = mutation.split_once('=') else { return topology("certificate action is malformed") };
        match key {
            "name" => names.push(value.to_string()),
            "webroot" => webroots.push(value.to_string()),
            _ if singular.insert(key, value).is_some() => return topology("certificate action is malformed"),
            _ => {}
        }
    }
    if !singular.contains_key("certificate")
        || !singular.contains_key("email")
        || !singular.contains_key("service")
        || singular.keys().any(|key| !["certificate", "email", "service", "skip-renewal-dry-run"].contains(key))
    {
        return topology("certificate action is malformed");
    }
    let service = singular["service"];
    let sorted: BTreeSet<&String> = names.iter().collect();
    if action.id != format!("certificate.{service}")
        || action.owner != format!("proxy-control:certificate:{service}")
        || !valid_service(service)
        || names.is_empty()
        || sorted.len() != names.len()
        || !names.iter().is_sorted()
        || webroots.len() != names.len()
        || !webroots.iter().zip(&names).all(|(webroot, name)| webroot == &format!("/var/www/{name}"))
        || !names.contains(&singular["certificate"].to_string())
        || !valid_email(singular["email"])
        || names.iter().any(|name| !valid_domain(name))
    {
        return topology("certificate action is malformed");
    }
    let skip = singular.get("skip-renewal-dry-run").copied().unwrap_or("false");
    if !["true", "false"].contains(&skip) {
        return topology("certificate action is malformed");
    }
    Ok(CertificateSpec {
        certificate: singular["certificate"].into(),
        email: singular["email"].into(),
        names,
        service: service.into(),
        skip_renewal_dry_run: skip == "true",
        webroots,
    })
}

fn valid_service(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= 64
        && service.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && service.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else { return false };
    !local.is_empty()
        && local.len() <= 64
        && local.chars().all(|c| c.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(c))
        && !domain.is_empty()
        && domain.len() <= 253
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && domain.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && domain.chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric())
        && !domain.contains('@')
}

fn certificate_vhost_path(spec: &CertificateSpec) -> String {
    format!("/etc/nginx/conf.d/proxy-control-acme-{}.conf", spec.service)
}

fn render_certificate_vhost(action: &Action, spec: &CertificateSpec) -> Vec<u8> {
    let mut lines = vec![format!("# BEGIN PROXY-CONTROL ACME {}", action.id)];
    for (name, webroot) in spec.names.iter().zip(&spec.webroots) {
        lines.extend([
            "server {".into(),
            "    listen 80;".into(),
            "    listen [::]:80;".into(),
            format!("    server_name {name};"),
            "    location ^~ /.well-known/acme-challenge/ {".into(),
            format!("        root {webroot};"),
            "        try_files $uri =404;".into(),
            "    }".into(),
            "    location / { return 404; }".into(),
            "}".into(),
        ]);
    }
    lines.extend([format!("# END PROXY-CONTROL ACME {}", action.id), String::new()]);
    lines.join("\n").into_bytes()
}

fn certificate_checkpoint(checkpoint: &CheckpointData, spec: &CertificateSpec) -> Result<SavedCheckpoint> {
    let required: BTreeSet<&str> = [
        "certificate",
        "created_webroots",
        "lineage_preexisting",
        "names",
        "owner",
        "ownership",
        "vhost",
        "vhost_sha256",
    ]
    .into();
    let expected_vhost = certificate_vhost_path(spec);
    if checkpoint.keys().map(String::as_str).collect::<BTreeSet<_>>() != required
        || checkpoint["certificate"].as_str() != Some(spec.certificate.as_str())
        || checkpoint["names"].as_array().is_none_or(|names| {
            names.iter().map(|name| name.as_str().map(str::to_string)).collect::<Option<Vec<_>>>()
                != Some(spec.names.clone())
        })
        || checkpoint["owner"].as_str() != Some(format!("proxy-control:certificate:{}", spec.service).as_str())
        || checkpoint["vhost"].as_str() != Some(expected_vhost.as_str())
        || checkpoint["lineage_preexisting"].as_bool().is_none()
    {
        return topology("certificate checkpoint is invalid");
    }
    let Some(created) = checkpoint["created_webroots"].as_array() else {
        return topology("certificate checkpoint is invalid");
    };
    let mut created_paths = Vec::new();
    for path in created {
        let Some(path) = path.as_str().filter(|path| {
            path.starts_with('/')
                && !Path::new(path).components().any(|component| matches!(component, std::path::Component::ParentDir))
        }) else {
            return topology("certificate checkpoint is invalid");
        };
        created_paths.push(path.to_string());
    }
    let sorted: BTreeSet<String> = created_paths.iter().cloned().collect();
    if sorted.len() != created_paths.len() || !created_paths.iter().is_sorted() {
        return topology("certificate checkpoint is invalid");
    }
    let vhost_hash = match &checkpoint["vhost_sha256"] {
        Value::Null => None,
        Value::String(hash) if hex64(hash) => Some(hash.clone()),
        _ => return topology("certificate checkpoint is invalid"),
    };
    let expected_ownership =
        vhost_hash.as_ref().map_or_else(|| json!({}), |hash| json!({expected_vhost.clone(): {"sha256": hash}}));
    if checkpoint["ownership"] != expected_ownership {
        return topology("certificate checkpoint is invalid");
    }
    Ok(SavedCheckpoint {
        created_webroots: created_paths,
        lineage_preexisting: checkpoint["lineage_preexisting"].as_bool().expect("checked"),
        vhost: expected_vhost,
        vhost_sha256: vhost_hash,
    })
}

fn certificate_sans(text: &str) -> BTreeSet<String> {
    let lower = text.to_lowercase();
    if ["ip address:", "uri:", "email:", "othername:"].iter().any(|marker| lower.contains(marker)) {
        return BTreeSet::new();
    }
    let mut names = BTreeSet::new();
    let mut rest = text;
    while let Some(index) = rest.find("DNS:") {
        let value = &rest[index + 4..];
        let end = value.find([',', ' ', '\t', '\r', '\n']).unwrap_or(value.len());
        let normalized = value[..end].trim_end_matches('.').to_lowercase();
        if !valid_domain(&normalized) {
            return BTreeSet::new();
        }
        names.insert(normalized);
        rest = &value[end..];
    }
    names
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;
    use pc_host::runner::{CallKind, RecordingRunner, Reply};

    fn action() -> Action {
        Action::new(
            "certificate.proxy-control",
            "certificates",
            "proxy-control:certificate:proxy-control",
            vec![
                "service=proxy-control".into(),
                "certificate=relay.example.com".into(),
                "email=owner@example.com".into(),
                "name=panel.example.com".into(),
                "name=relay.example.com".into(),
                "webroot=/var/www/panel.example.com".into(),
                "webroot=/var/www/relay.example.com".into(),
            ],
            vec!["strict local A, handled AAAA, and HTTP-01 CAA facts pass".into()],
            vec!["owned port-80 HTTP-01 vhosts are active".into()],
            vec!["remove only the exact owned HTTP-01 vhost and preserve ACME data".into()],
            false,
        )
        .unwrap()
    }

    #[test]
    fn acme_vhost_matches_python_golden() {
        let dir = TempDir::new("acme-render");
        let runner = Arc::new(RecordingRunner::new());
        let adapter =
            CertificatePlan::new(&AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner });
        let action = action();
        let rendered = render_certificate_vhost(&action, &certificate_action(&action).unwrap());
        let expected = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/host-golden/renders/coexist-ingress/acme/proxy-control.conf"),
        )
        .unwrap();
        assert_eq!(rendered, expected);
        let _ = adapter;
    }

    #[test]
    fn recording_runner_drives_certificate_lifecycle_and_renewal_cache() {
        let dir = TempDir::new("certificate-lifecycle");
        let root = dir.path().to_path_buf();
        let responder_root = root.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let args = &call.argv;
            match args[0].as_str() {
                "nginx" if args.get(1).map(String::as_str) == Some("-T") => {
                    let mut output = String::new();
                    {
                        let service = "proxy-control";
                        let path = responder_root.join(format!("etc/nginx/conf.d/proxy-control-acme-{service}.conf"));
                        if let Ok(content) = fs::read_to_string(path) {
                            output.push_str(&format!("# configuration file /etc/nginx/conf.d/proxy-control-acme-{service}.conf:\n{content}\n"));
                        }
                    }
                    Some(Reply::ok(&output))
                }
                "certbot" if args.get(1).map(String::as_str) == Some("certonly") => {
                    let live = responder_root.join("etc/letsencrypt/live/relay.example.com");
                    fs::create_dir_all(&live).unwrap();
                    fs::create_dir_all(responder_root.join("etc/letsencrypt/archive/relay.example.com")).unwrap();
                    fs::create_dir_all(responder_root.join("etc/letsencrypt/renewal")).unwrap();
                    fs::write(responder_root.join("etc/letsencrypt/renewal/relay.example.com.conf"), "renewal\n")
                        .unwrap();
                    for name in ["cert.pem", "chain.pem", "fullchain.pem"] {
                        fs::write(live.join(name), "certificate\n").unwrap();
                    }
                    let key = live.join("privkey.pem");
                    fs::write(&key, "key\n").unwrap();
                    fs::set_permissions(key, fs::Permissions::from_mode(0o600)).unwrap();
                    Some(Reply::ok(""))
                }
                "openssl" if args.get(1).map(String::as_str) == Some("pkey") => Some(Reply::ok("PUBLIC KEY\n")),
                "openssl" if args.contains(&"-pubkey".into()) => Some(Reply::ok("PUBLIC KEY\n")),
                "openssl" if args.contains(&"subjectAltName".into()) => Some(Reply::ok(
                    "X509v3 Subject Alternative Name:\n    DNS:panel.example.com, DNS:relay.example.com\n",
                )),
                "openssl" => Some(Reply::ok("OK\n")),
                _ => Some(Reply::ok("")),
            }
        }));
        let adapter =
            CertificatePlan::new(&AdapterContext { root: root.clone(), tree: root.clone(), runner: runner.clone() });
        let action = action();
        let prepared = adapter.prepare(&action).unwrap();
        let applied = adapter.apply(&action, prepared).unwrap();
        assert_eq!(
            applied["ownership"][certificate_vhost_path(&certificate_action(&action).unwrap())]["sha256"],
            applied["vhost_sha256"]
        );
        runner.clear();
        assert!(adapter.verify(&action).unwrap().success);
        assert!(
            !runner.argvs().iter().any(|argv| argv.starts_with(&["certbot".into(), "renew".into()])),
            "apply-to-verify cache consumed"
        );
        assert!(adapter.rollback(&action, applied, false, RollbackTarget::RolledBack).unwrap().success);
        assert!(!root.join("etc/nginx/conf.d/proxy-control-acme-proxy-control.conf").exists());
        assert!(root.join("etc/letsencrypt/live/relay.example.com/fullchain.pem").exists());
        assert!(root.join("var/www/relay.example.com/.well-known/acme-challenge").is_dir());
        assert!(runner
            .calls()
            .iter()
            .all(|call| call.kind == CallKind::Bounded && call.timeout == Duration::from_secs(600)));
    }

    #[test]
    fn renewal_retries_only_the_pinned_acme_races() {
        let dir = TempDir::new("acme-retry");
        let runner = Arc::new(RecordingRunner::new());
        runner.reply_once(&["certbot", "renew"], Reply::exit(1, "", "orderNotReady"));
        let adapter = CertificatePlan::new(&AdapterContext {
            root: dir.path().into(),
            tree: dir.path().into(),
            runner: runner.clone(),
        });
        let spec = certificate_action(&action()).unwrap();
        adapter.run_renewal(&spec).unwrap();
        assert_eq!(
            runner.argvs().iter().filter(|argv| argv.starts_with(&["certbot".into(), "renew".into()])).count(),
            2
        );
    }
}
