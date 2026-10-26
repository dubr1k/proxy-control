//! NaiveProxy host adapter (installer/adapters/naive.py), including real HTTP/2 and accounting acceptance.
use std::fs;
use installer_core::model::InstallerConfig;
use installer_core::planner::{Action, AuditFacts, Evidence};
use pc_host::fs::{sha256_hex,token_hex};
use serde_json::{json,Map,Value};
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData,RollbackTarget};
use super::AdapterContext;
use super::proxy_common::*;

pub const DATA_DIR:&str="/var/lib/naive-manager";
pub const LOG_DIR:&str="/var/log/naive-proxy";
pub const CADDY_BINARY:&str="/usr/local/bin/caddy";
pub const CADDY_VERSION:&str="v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4=";
const IMAGE:&str="proxy-control-caddy-naive:v2.11.7";
const PIN:&str="/etc/proxy-control/caddy-naive.pin";
const UNIT:&str="/etc/systemd/system/caddy-naive.service";
const PREPARER:&str="/usr/local/libexec/prepare-naive-state";
const HOOK:&str="/etc/letsencrypt/renewal-hooks/deploy/proxy-control-naive-caddy";
const ENV:&str="/opt/mtproxy-shared443/.env.naive";
const CADDYFILE:&str="/var/lib/naive-manager/Caddyfile";
const TOKEN:&str="/var/lib/naive-manager/manager-token";
const SECRET:&str="/opt/mtproxy-shared443/secrets/naive-manager-token";
const BOOTSTRAP_USER:&str="__PROXY_CONTROL_BOOTSTRAP_USERNAME__";
const BOOTSTRAP_PASSWORD:&str="__PROXY_CONTROL_BOOTSTRAP_PASSWORD__";
const ROUTER_CREDENTIAL:&str="__PROXY_CONTROL_ROUTER_CREDENTIAL__";
const HELPERS:&[(&str,&str,u32)]=&[
    ("scripts/check-naive-caddy-build.sh","/usr/local/libexec/check-naive-caddy-build",0o755),
    ("scripts/caddy-naive-adapt","/usr/local/libexec/caddy-naive-adapt",0o755),
    ("prepare-naive-state",PREPARER,0o755),
    ("deploy/caddy-naive.service",UNIT,0o644),
];
const OWNED:&[(&str,bool,bool)]=&[
    ("/etc/proxy-control/naive-owned",true,false),(PIN,false,false),(UNIT,false,false),
    ("/usr/local/libexec/check-naive-caddy-build",false,false),("/usr/local/libexec/caddy-naive-adapt",false,false),
    (PREPARER,false,false),(HOOK,false,false),(ENV,false,false),("/etc/proxy-control/naive-acceptance-owner",false,true),
    ("/var/lib/naive-caddy/tls/fullchain.pem",false,false),("/var/lib/naive-caddy/tls/privkey.pem",false,false),
    (SECRET,true,false),(TOKEN,true,false),(CADDYFILE,true,true),
];
const KEYS:&[&str]=&["acceptance_name","adoption","caddy_preexisting","identities_created","log_dir_preexisting","marker_value","owner","ownership","planned_ownership","state_dir_preexisting","unit_preexisting"];
#[derive(Debug,Clone)]
pub struct NaiveSelection {pub domain:String,pub panel:String,pub adjacent:Vec<(String,String)>,pub egress:String,pub warp_port:u16,pub warp_provider:String,pub router_provider:String}
#[derive(Debug,Clone)]
pub struct RenderedNaive {pub caddyfile_template:String,pub env_text:String,pub unit_text:String,pub pin_text:String,pub file_modes:std::collections::BTreeMap<String,u32>}
pub struct NaiveAdapter {pub(super) host:Host, #[cfg(test)] pub(super) test_acceptance:Option<super::proxy_acceptance::TestAcceptance>}
impl NaiveAdapter {
    pub fn new(context:&AdapterContext)->Self{Self{host:Host{context:context.clone(),name:"naive",label:"Naive"},#[cfg(test)]test_acceptance:None}}
    pub fn selection(&self,action:&Action)->Result<NaiveSelection,Error>{
        let values=mutations(action,"naive",&["project","naive-domain","panel-domain","data-dir","log-dir","caddy-binary","caddy-build","unit","private-port","caddy-uid","accounting-gid","manager-uid","manager-gid","adjacent-sni","egress"],&["warp-port","warp-provider","router-provider"])?;
        let expected=[("project",PROJECT),("data-dir",DATA_DIR),("log-dir",LOG_DIR),("caddy-binary",CADDY_BINARY),("caddy-build",CADDY_VERSION),("unit",UNIT),("private-port","4443"),("caddy-uid","10003"),("accounting-gid","10004"),("manager-uid","10002"),("manager-gid","101")];
        if expected.iter().any(|(key,value)|values[*key]!=*value)||!domain(&values["naive-domain"])||!domain(&values["panel-domain"])||values["naive-domain"]==values["panel-domain"]||!matches!(values["egress"].as_str(),"direct"|"proxy"|"router"){return Err(self.host.error("Naive action is invalid"));}
        let (warp_port,warp_provider,router_provider)=providers(&values,45101,&self.host)?;
        let adjacent=decode_adjacent(&values["adjacent-sni"])?;
        Ok(NaiveSelection{domain:values["naive-domain"].to_lowercase(),panel:values["panel-domain"].to_lowercase(),adjacent,egress:values["egress"].clone(),warp_port,warp_provider,router_provider})
    }
    pub fn render(&self,action:&Action)->Result<RenderedNaive,Error>{self.render_selection(&self.selection(action)?)}
    fn render_selection(&self,selected:&NaiveSelection)->Result<RenderedNaive,Error>{
        let upstream=match selected.egress.as_str(){"proxy"=>format!("            upstream socks5://127.0.0.1:{}\n",selected.warp_port),"router"=>format!("            upstream socks5://{ROUTER_CREDENTIAL}@127.0.0.1:45101\n"),_=>String::new()};
        let caddyfile_template=format!("{{\n    admin 127.0.0.1:2019\n    auto_https disable_redirects\n}}\n# NaiveProxy cover site and forward proxy for {}.\nhttps://:443 {{\n    bind 127.0.0.1\n    tls /var/lib/naive-caddy/tls/fullchain.pem /var/lib/naive-caddy/tls/privkey.pem\n    log {{\n        output file {LOG_DIR}/access.json {{\n            mode 0640\n            roll_size 10MiB\n            roll_keep 10\n            roll_keep_for 168h\n            roll_uncompressed\n        }}\n        format json\n    }}\n    root * /var/www/{}\n    route {{\n        forward_proxy {{\n            basic_auth {BOOTSTRAP_USER} {BOOTSTRAP_PASSWORD}\n            hide_ip\n            hide_via\n            probe_resistance\n{upstream}        }}\n        file_server\n    }}\n}}\n",selected.domain,selected.domain);
        let env_text=format!("NAIVE_PUBLIC_HOST={}\nNAIVE_DATA_DIR={DATA_DIR}\nNAIVE_EGRESS_WARP={}\nNAIVE_EGRESS_ROUTER={}\nNAIVE_EGRESS_ROUTER_CREDENTIAL_FILE={}\n",selected.domain,selected.warp_provider,selected.router_provider,if selected.router_provider.is_empty(){""}else{"/data/xray-router-ingress"});
        let unit_text=fs::read_to_string(self.host.context.tree.join("deploy/caddy-naive.service")).map_err(|_|self.host.error("Naive unit source is unavailable"))?;
        if !unit_text.contains("User=naive-caddy")||unit_text.contains("User=root"){return Err(self.host.error("Naive unit identity is invalid"));}
        let mut file_modes=std::collections::BTreeMap::from([(CADDYFILE.into(),0o640),(TOKEN.into(),0o400),(SECRET.into(),0o600),(ENV.into(),0o600),(self.host.marker(),0o600),(PIN.into(),0o644),(HOOK.into(),0o755),(self.host.acceptance_owner(),0o600),(self.host.pending(),0o600)]);
        for (_,path,mode)in HELPERS{file_modes.insert((*path).into(),*mode);}
        Ok(RenderedNaive{caddyfile_template,env_text,unit_text,pin_text:format!("{CADDY_VERSION}\n"),file_modes})
    }
    fn live_identities(&self)->Result<(),Error>{for(kind,id,expected)in[("uid",10003,"naive-caddy"),("gid",10004,"naive-accounting")]{if let Some(name)=self.host.identity(kind,id){if name!=expected{return Err(self.host.error(format!("{} {id} collision: {name}",kind.to_uppercase())));}}}Ok(())}
    fn pinned_caddy(&self)->Result<(),Error>{
        let binary=self.host.host(CADDY_BINARY)?;
        let info=fs::symlink_metadata(&binary)?;
        if !info.is_file(){return Err(self.host.error("refusing an unpinned Caddy build"));}
        let binary=binary.to_string_lossy();
        let version=self.host.checked(&[&binary,"version"])?;
        let modules=self.host.checked(&[&binary,"list-modules"])?;
        if version.trim()!=CADDY_VERSION&&self.host.agent_value("naive","runtime_version").as_deref()!=Some(version.trim())||!modules.lines().any(|line|line.trim()=="http.handlers.forward_proxy"){return Err(self.host.error("refusing an unpinned Caddy build"));}
        Ok(())
    }
    fn install_caddy(&self,checkpoint:&CheckpointData)->Result<(),Error>{
        if checkpoint["caddy_preexisting"]==true{return self.pinned_caddy();}
        let dest=self.host.host(CADDY_BINARY)?;if let Some(parent)=dest.parent(){fs::create_dir_all(parent)?;}
        let tree=self.host.context.tree.to_string_lossy();let dockerfile=self.host.context.tree.join("docker/Dockerfile.caddy-naive");
        self.host.run(&["docker","build","-f",&dockerfile.to_string_lossy(),"-t",IMAGE,&tree])?;
        let container=self.host.checked(&["docker","create","--entrypoint","/caddy",IMAGE,"version"])?;
        let container=container.trim();if !(12..=64).contains(&container.len())||!container.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(self.host.error("pinned Caddy build produced no container"));}
        let result=self.host.run(&["docker","cp",&format!("{container}:/caddy"),&dest.to_string_lossy()]);
        let cleanup=self.host.run(&["docker","rm",container]);result?;cleanup?;
        self.host.chown(CADDY_BINARY,0,0,0o755)?;
        self.pinned_caddy()
    }
    fn ensure_identities(&self)->Result<Value,Error>{
        self.live_identities()?;let group=self.host.identity("gid",10004).is_none();let user=self.host.identity("uid",10003).is_none();
        if group{self.host.run(&["groupadd","--system","--gid","10004","naive-accounting"])?;}
        if user{self.host.run(&["useradd","--system","--uid","10003","--gid","10004","--home","/nonexistent","--shell","/usr/sbin/nologin","naive-caddy"])?;}
        self.live_identities()?;Ok(json!({"group":group,"user":user}))
    }
    fn private_listeners(&self)->Result<(),Error>{if !loopback(&self.host,2019)||!loopback(&self.host,4443){return Err(self.host.error("Caddy Admin API and private listener must stay loopback"));}Ok(())}
    fn checkpoint(&self,checkpoint:&CheckpointData,action:&Action,applied:bool)->Result<(),Error>{let mut paths:Vec<_>=OWNED.iter().map(|(p,_,_)|*p).collect();paths.push(CADDY_BINARY);self.host.validate_checkpoint(checkpoint,action,KEYS,applied,&paths)}
    fn planned(&self,action:&Action,name:&str,marker:&str)->Result<Value,Error>{
        let rendered=self.render(action)?;let mut planned=Map::new();
        planned.insert(self.host.marker(),json!({"preserve":true,"sha256":marker}));
        planned.insert(self.host.acceptance_owner(),declaration(false,format!("{name}\n").as_bytes()));
        planned.insert(ENV.into(),declaration(false,rendered.env_text.as_bytes()));
        planned.insert(PIN.into(),declaration(false,rendered.pin_text.as_bytes()));
        self.host.planned_helpers(HELPERS,&mut planned)?;
        planned.insert(HOOK.into(),declaration(false,deploy_hook_text(&self.selection(action)?.domain).as_bytes()));
        Ok(Value::Object(planned))
    }
    fn credentials(&self,selected:&NaiveSelection,rendered:&RenderedNaive)->Result<(),Error>{
        if !self.host.exists(SECRET)?{self.host.atomic(SECRET,format!("{}\n",token_hex::<32>()).as_bytes(),0o600)?;}
        self.host.private_file(&self.host.host(SECRET)?,0o600)?;
        if !self.host.exists(TOKEN)?{self.host.atomic(TOKEN,&fs::read(self.host.host(SECRET)?)?,0o400)?;}
        self.host.chown(TOKEN,10002,101,0o400)?;
        let ingress=format!("{DATA_DIR}/xray-router-ingress");
        if selected.router_provider.is_empty(){self.host.remove(&ingress)?;}else{let(user,password)=self.host.router_credential()?;self.host.atomic(&ingress,format!("{user}:{password}\n").as_bytes(),0o400)?;self.host.chown(&ingress,10002,101,0o400)?;}
        if !self.host.exists(CADDYFILE)?{
            let mut body=rendered.caddyfile_template.replace(BOOTSTRAP_USER,&format!("bootstrap-{}",token_hex::<4>())).replace(BOOTSTRAP_PASSWORD,&super::proxy_acceptance::random_urlsafe::<24>()?);
            if body.contains(ROUTER_CREDENTIAL){let(user,password)=self.host.router_credential()?;body=body.replace(ROUTER_CREDENTIAL,&format!("{}:{}",super::proxy_acceptance::quote(&user),super::proxy_acceptance::quote(&password)));}
            self.host.atomic(CADDYFILE,body.as_bytes(),0o640)?;
        }
        self.host.chown(CADDYFILE,10002,101,0o640)
    }
}
impl Adapter for NaiveAdapter{
    fn name(&self)->&str{"naive"}
    fn plan(&self,config:&InstallerConfig,facts:&AuditFacts)->Result<Vec<Action>,Error>{
        if !config.profile.includes_naive(){return Ok(Vec::new());}
        let name=config.domains.naive.as_deref().filter(|s|domain(s)).ok_or_else(||plan_error("Naive public domain is missing or invalid"))?;
        audited_identities(facts,&[("uid",10003,Some("naive-caddy")),("gid",10004,Some("naive-accounting")),("uid",10002,None)])?;
        let mut adjacent=Vec::new();
        if let Some(routes)=facts.topology.get("nginx").and_then(|nginx|nginx.get("sni_routes")){
            let routes=routes.as_object().ok_or_else(||self.host.error("audited adjacent SNI routes are invalid"))?;
            for(host,backend)in routes{if [config.domains.panel.as_str(),config.domains.mtproxy.as_str(),name].contains(&host.as_str()){continue;}let backend=backend.as_str().ok_or_else(||self.host.error("audited adjacent SNI routes are invalid"))?;if !domain(host)||!valid_backend(backend){return Err(self.host.error("audited adjacent SNI routes are invalid"));}adjacent.push((host.to_lowercase(),backend.to_string()));}
        }
        adjacent.sort();let egress=config.effective_egress();
        let mutations=vec![format!("project={PROJECT}"),format!("naive-domain={name}"),format!("panel-domain={}",config.domains.panel),format!("data-dir={DATA_DIR}"),format!("log-dir={LOG_DIR}"),format!("caddy-binary={CADDY_BINARY}"),format!("caddy-build={CADDY_VERSION}"),format!("unit={UNIT}"),"private-port=4443".into(),"caddy-uid=10003".into(),"accounting-gid=10004".into(),"manager-uid=10002".into(),"manager-gid=101".into(),format!("adjacent-sni={}",encode_adjacent(&adjacent)),format!("egress={}",seed(egress.naive)),format!("warp-port={}",egress.warp_port),format!("warp-provider={}",egress.provider_url().unwrap_or_default()),format!("router-provider={}",egress.router_url("naive").unwrap_or_default())];
        Ok(vec![Action{id:"naive.runtime".into(),adapter:"naive".into(),owner:"proxy-control:naive".into(),mutations,preconditions:strings(&["the Core runtime and the Naive certificate are verified","fixed Naive identities are free or already owned","the shared 443 route reaches the private Caddy listener"]),verification:strings(&["loopback Admin API and private Caddy listener are private","public cover HTTPS answers without credentials","one authenticated CONNECT carries a known payload and closes","closed-tunnel accounting observes at least the sent payload","manager, panel, adjacent SNI, and log boundary pass"]),inverse:strings(&["stop only the Caddy unit and the naive-manager service","preserve manager state and credentials unless purge is explicit","restore binary, unit, helper, hook, and identity ownership"]),credentials_required:true}])
    }
    fn prepare(&self,action:&Action)->Result<CheckpointData,Error>{
        self.selection(action)?;self.live_identities()?;
        let recovery=self.host.exists(&self.host.marker())?;
        if !recovery&&(self.host.exists(UNIT)?||self.host.service_present()){return Err(self.host.error("active Naive resources require a proven owned recovery generation"));}
        let name=self.host.existing_acceptance()?.unwrap_or(self.host.fresh_name()?);
        let marker=if recovery{Value::Null}else{Value::String(token_hex::<16>())};
        let digest=if let Some(marker)=marker.as_str(){sha256_hex(format!("{marker}\n").as_bytes())}else{self.host.marker_sha256()?};
        let preexisting=self.host.exists(CADDY_BINARY)?;if preexisting{self.pinned_caddy()?;}
        Ok(json!({"acceptance_name":name,"adoption":if recovery{"recovery"}else{"absent"},"caddy_preexisting":preexisting,"identities_created":{},"log_dir_preexisting":self.host.exists(LOG_DIR)?,"marker_value":marker,"owner":action.owner,"ownership":{},"planned_ownership":self.planned(action,&name,&digest)?,"state_dir_preexisting":self.host.exists(DATA_DIR)?,"unit_preexisting":self.host.exists(UNIT)?}).as_object().unwrap().clone())
    }
    fn apply(&self,action:&Action,mut checkpoint:CheckpointData)->Result<CheckpointData,Error>{
        let selected=self.selection(action)?;self.checkpoint(&checkpoint,action,false)?;
        self.install_caddy(&checkpoint)?;let identities=self.ensure_identities()?;
        self.host.install_helpers(HELPERS)?;
        self.host.run(&[PREPARER,"prepare","--state-dir",DATA_DIR,"--log-dir",LOG_DIR])?;
        let rendered=self.render_selection(&selected)?;
        if let Some(marker)=checkpoint["marker_value"].as_str(){self.host.atomic(&self.host.marker(),format!("{marker}\n").as_bytes(),0o600)?;}
        self.host.atomic(PIN,rendered.pin_text.as_bytes(),0o644)?;
        // Render the original selection: never discard the planned WARP port/providers.
        self.host.atomic(ENV,rendered.env_text.as_bytes(),0o600)?;
        self.host.write_acceptance(checkpoint["acceptance_name"].as_str().unwrap())?;
        self.credentials(&selected,&rendered)?;
        self.host.atomic(HOOK,deploy_hook_text(&selected.domain).as_bytes(),0o755)?;self.host.run(&[&self.host.host(HOOK)?.to_string_lossy()])?;
        let cover=format!("/var/www/{}/index.html",selected.domain);
        if !self.host.exists(&cover)?{self.host.atomic(&cover,b"<!doctype html><title>Welcome</title><h1>Welcome</h1>\n",0o644)?;}
        self.host.run(&["systemctl","daemon-reload"])?;self.host.run(&["systemctl","enable","--now","caddy-naive"])?;self.private_listeners()?;
        self.host.compose(&["run","--rm","--build","naive-manager","--bootstrap-only"])?;self.host.run(&["systemctl","reload","caddy-naive"])?;self.host.compose(&["up","-d","--build","--wait"])?;
        checkpoint.insert("identities_created".into(),identities);
        checkpoint.insert("ownership".into(),self.host.ownership(OWNED,CADDY_BINARY,checkpoint["caddy_preexisting"]==true)?);Ok(checkpoint)
    }
    fn reconcile_apply(&self,action:&Action,mut checkpoint:CheckpointData)->Result<CheckpointData,Error>{checkpoint.insert("ownership".into(),json!({}));self.apply(action,checkpoint)}
    fn verify(&self,action:&Action)->Result<Evidence,Error>{
        let selected=self.selection(action)?;let(name,recover)=self.host.begin_acceptance()?;
        let result=self.acceptance(&selected,&name,recover).and_then(|value|{super::proxy_acceptance::require_naive(&value)?;Ok(value)});
        let collision=result.as_ref().err().is_some_and(|error|error.python_class_name()=="_AcceptanceCollision")&&!recover;
        let cleanup=if collision{Ok(())}else{self.cleanup(&selected.panel,&name)};
        if cleanup.is_ok(){self.host.remove(&self.host.pending())?;}
        let mut value=result?;cleanup.map_err(|_|self.host.acceptance("temporary-user and session cleanup failed"))?;
        value.as_object_mut().unwrap().insert("temporary_state_removed".into(),true.into());
        Ok(evidence(action,&["Naive listener, cover, authenticated CONNECT, and accounting passed","temporary acceptance state was removed"],value))
    }
    fn repair(&self,action:&Action,checkpoint:CheckpointData)->Result<CheckpointData,Error>{self.selection(action)?;self.checkpoint(&checkpoint,action,true)?;self.host.assert_ownership(&checkpoint)?;self.live_identities()?;self.pinned_caddy()?;self.host.run(&[PREPARER,"verify","--state-dir",DATA_DIR,"--log-dir",LOG_DIR])?;self.host.run(&["systemctl","restart","caddy-naive"])?;self.private_listeners()?;self.host.compose(&["up","-d","--wait"])?;Ok(checkpoint)}
    fn rollback(&self,action:&Action,checkpoint:CheckpointData,purge_data:bool,target:RollbackTarget)->Result<Evidence,Error>{
        let selected=self.selection(action)?;self.checkpoint(&checkpoint,action,true)?;let purge=purge_data&&target==RollbackTarget::Uninstalled;
        let mut pending=false;if self.host.exists(&self.host.pending())?{let name=self.host.existing_acceptance()?.unwrap_or_else(||checkpoint["acceptance_name"].as_str().unwrap().to_string());if self.cleanup(&selected.panel,&name).is_err(){pending=!purge;if pending{self.host.write_acceptance(&name)?;}}self.host.remove(&self.host.pending())?;}
        if self.host.exists(UNIT)?{self.host.best_effort(&["systemctl","disable","--now","caddy-naive"])?;}
        if self.host.service_present(){self.host.compose(&["rm","--stop","--force","naive-manager"])?;}
        self.host.remove_generation(&checkpoint,CADDY_BINARY,!purge,pending)?;self.host.remove_binary(&checkpoint,CADDY_BINARY,"caddy_preexisting")?;self.host.best_effort(&["systemctl","daemon-reload"])?;
        if purge{for path in [SECRET,TOKEN,CADDYFILE]{self.host.remove(path)?;}clear_directory(&self.host.host(DATA_DIR)?)?;if checkpoint["identities_created"]["user"]==true{self.host.best_effort(&["userdel","naive-caddy"])?;}if checkpoint["identities_created"]["group"]==true{self.host.best_effort(&["groupdel","naive-accounting"])?;}}
        Ok(evidence(action,&["the Naive runtime was removed",if purge{"manager state and credentials were purged"}else{"manager state and credentials were preserved"}],json!({"persistent_data_preserved":!purge,"identities_removed":purge,"temporary_cleanup_pending":pending})))
    }
    fn reconcile_rollback(&self,action:&Action,checkpoint:CheckpointData,purge:bool,target:RollbackTarget)->Result<Evidence,Error>{self.rollback(action,checkpoint,purge,target)}
}
pub fn deploy_hook_text(domain:&str)->String{format!("#!/bin/sh\n# Managed by proxy-control: publish the Naive keypair for the\n# unprivileged Caddy identity after every issuance and renewal.\nset -eu\nlineage=\"/etc/letsencrypt/live/{domain}\"\ntarget=\"/var/lib/naive-caddy/tls\"\n[ \"${{RENEWED_LINEAGE:-$lineage}}\" = \"$lineage\" ] || exit 0\n[ -r \"$lineage/fullchain.pem\" ] || exit 1\n[ -r \"$lineage/privkey.pem\" ] || exit 1\ninstall -d -m 0750 -o root -g naive-accounting \"$target\"\ninstall -m 0640 -o root -g naive-accounting \"$lineage/fullchain.pem\" \"$target/fullchain.pem\"\ninstall -m 0640 -o root -g naive-accounting \"$lineage/privkey.pem\" \"$target/privkey.pem\"\n")}
fn valid_backend(value:&str)->bool{
    if value=="audited"{return true;}
    if let Some(path)=value.strip_prefix("unix:"){return path.starts_with('/')&&!path.contains([';','|','\0'])&&!path.chars().any(char::is_whitespace)&&!path.split('/').any(|p|p=="..");}
    value.rsplit_once(':').is_some_and(|(host,port)|{
        let hostname=if host.starts_with('[')&&host.ends_with(']'){let inner=&host[1..host.len()-1];!inner.is_empty()&&inner.bytes().all(|b|b.is_ascii_hexdigit()||b==b':')}else{!host.is_empty()&&host.as_bytes()[0].is_ascii_alphanumeric()&&host.as_bytes()[host.len()-1].is_ascii_alphanumeric()&&host.bytes().all(|b|b.is_ascii_alphanumeric()||b".-".contains(&b))};
        hostname&&port.len()<=5&&port.bytes().all(|b|b.is_ascii_digit())&&port.parse::<u16>().is_ok_and(|p|p>0)
    })
}
fn encode_adjacent(values:&[(String,String)])->String{if values.is_empty(){"none".into()}else{values.iter().map(|(host,backend)|format!("{host}|{backend}")).collect::<Vec<_>>().join(";")}}
fn decode_adjacent(value:&str)->Result<Vec<(String,String)>,Error>{if value=="none"{return Ok(Vec::new());}let mut routes=Vec::new();for part in value.split(';'){let(host,backend)=part.split_once('|').ok_or_else(||Error::other("NaiveError","adjacent SNI routes are invalid"))?;if !domain(host)||!valid_backend(backend)||routes.iter().any(|(name,_)|name==host){return Err(Error::other("NaiveError","adjacent SNI routes are invalid"));}routes.push((host.into(),backend.into()));}routes.sort();Ok(routes)}
