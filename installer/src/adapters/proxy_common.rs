//! Common host mechanics of the two protocol adapters. All commands use the frozen HostRunner.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use installer_core::model::EgressChoice;
use installer_core::planner::{Action, AuditFacts, Evidence, PlanError};
use pc_host::fs::{atomic_write, durable_remove, fsync_directory, root_path, sha256_file, sha256_hex, token_hex};
use pc_host::runner::{Capture, RunOptions, QUERY_TIMEOUT};
use serde_json::{json, Map, Value};
use super::AdapterContext;
use crate::error::Error;
use crate::journal::CheckpointData;

pub(super) const PROJECT: &str = "/opt/mtproxy-shared443";
#[derive(Clone)]
pub(super) struct Host { pub context: AdapterContext, pub name: &'static str, pub label: &'static str }
impl Host {
    pub fn error(&self, message: impl Into<String>) -> Error { Error::other(format!("{}Error", self.label), message) }
    pub fn acceptance(&self, message: impl Into<String>) -> Error { Error::other("AcceptanceError", message) }
    pub fn artifact(&self, message: impl Into<String>) -> Error { Error::other("ArtifactError", message) }
    pub fn host(&self, absolute: &str) -> Result<PathBuf, Error> {
        let path = root_path(&self.context.root, absolute)?;
        let mut cursor = self.context.root.clone();
        for component in Path::new(absolute).parent().unwrap_or_else(||Path::new("/")).components().filter_map(|part| match part { std::path::Component::Normal(part) => Some(part), _ => None }) {
            cursor.push(component);
            if fs::symlink_metadata(&cursor).is_ok_and(|info| !info.is_dir()) {
                return Err(self.error(format!("{} host path crosses an unsafe parent",self.label)));
            }
        }
        Ok(path)
    }
    pub fn exists(&self, absolute: &str) -> Result<bool, Error> { Ok(fs::symlink_metadata(self.host(absolute)?).is_ok()) }
    pub fn atomic(&self, absolute: &str, body: &[u8], mode: u32) -> Result<(), Error> {
        let path = self.host(absolute)?;
        if fs::symlink_metadata(&path).is_ok_and(|info| info.file_type().is_symlink()) { return Err(self.error("refusing a symlink at an owned file boundary")); }
        atomic_write(&path, body, mode, self.owner())?;
        Ok(())
    }
    pub fn owner(&self) -> Option<(u32,u32)> { (self.context.root == Path::new("/") && unsafe { libc::geteuid() } == 0).then_some((0,0)) }
    pub fn chown(&self, absolute: &str, uid: u32, gid: u32, mode: u32) -> Result<(), Error> {
        let path = self.host(absolute)?;
        let info = fs::symlink_metadata(&path)?;
        if !info.is_file() || info.nlink() != 1 { return Err(self.error("pre-existing credentials are unsafe")); }
        let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&path)?;
        use std::os::fd::AsRawFd;
        if self.owner().is_some() && unsafe { libc::fchown(file.as_raw_fd(),uid,gid) } != 0 { return Err(std::io::Error::last_os_error().into()); }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        let after = fs::symlink_metadata(path)?;
        if (info.dev(),info.ino()) != (after.dev(),after.ino()) { return Err(self.error("credential path identity changed during operation")); }
        Ok(())
    }
    pub fn run(&self, argv: &[&str]) -> Result<(), Error> {
        let result = self.context.runner.run(argv, &RunOptions::default()).map_err(|error| {
            if error.stops_the_engine() { Error::from(error) } else { self.error(command_failure(self.label,argv)) }
        })?;
        if result.returncode != 0 { return Err(self.error(format!("{}; {}", command_failure(self.label,argv), sanitize(&String::from_utf8_lossy(&result.stderr))))); }
        Ok(())
    }
    pub fn best_effort(&self, argv: &[&str]) -> Result<(), Error> {
        match self.run(argv) { Err(error) if error.is_fatal() => Err(error), _ => Ok(()) }
    }
    pub fn capture(&self, argv: &[&str], limit: usize) -> String { self.context.runner.capture(argv, limit, Capture::CORE) }
    pub fn checked(&self, argv: &[&str]) -> Result<String,Error> { self.context.runner.capture_checked(argv, QUERY_TIMEOUT).map_err(|_| self.error(command_failure(self.label,argv))) }
    pub fn service_present(&self) -> bool {
        ["proxy_panel_by_dubr1k", "mtproxy"].iter().any(|project| {
            let output = self.capture(&["docker","container","ls","--all","--quiet","--filter",&format!("label=com.docker.compose.project={project}"),"--filter",&format!("label=com.docker.compose.service={}-manager",self.name)],512);
            let value = output.trim(); !value.is_empty() && !value.starts_with("exit=") && !value.starts_with("diagnostic ")
        })
    }
    pub fn identity(&self, kind: &str, id: u32) -> Option<String> {
        identity_from_entry(&self.capture(&["getent",if kind=="uid" {"passwd"} else {"group"}, &id.to_string()],512),id)
    }
    pub fn compose_argv(&self, arguments: &[&str]) -> Result<Vec<String>,Error> {
        let mut envs = vec![format!("{PROJECT}/.env")];
        let mut files = vec![format!("{PROJECT}/compose.yaml")];
        for sibling in ["naive","mieru","xray-router","amneziawg","trusttunnel"] {
            if sibling == self.name { continue; }
            let path = format!("{PROJECT}/.env.{sibling}");
            if self.host(&path)?.is_file() { envs.push(path); files.push(format!("{PROJECT}/compose.{sibling}.yaml")); }
        }
        envs.push(format!("{PROJECT}/.env.{}",self.name));
        files.push(format!("{PROJECT}/compose.{}.yaml",self.name));
        let overrides=format!("{PROJECT}/version-overrides/compose.versions.yaml");
        if self.host(&overrides)?.is_file(){files.push(overrides);}
        let mut argv = strings(&["docker","compose","--project-directory",PROJECT]);
        for path in envs { argv.extend(["--env-file".into(),path]); }
        for path in files { argv.extend(["-f".into(),path]); }
        argv.extend(arguments.iter().map(|s|s.to_string()));
        Ok(argv)
    }
    pub fn compose(&self, arguments: &[&str]) -> Result<(),Error> {
        let argv=self.compose_argv(arguments)?;
        match self.run(&refs(&argv)) {
            Err(error) if self.name == "mieru" && arguments.first()==Some(&"up") && !error.is_fatal() => {
                let base = &argv[..argv.len()-arguments.len()];
                let mut details = Vec::new();
                for service in ["mieru-manager","panel"] {
                    let mut query=base.to_vec();query.extend(strings(&["ps","-a","-q",service]));
                    let id=self.capture(&refs(&query),128);let id=id.trim();
                    if !is_hex(id,64) {details.push(format!("{service}: id unavailable"));continue;}
                    let state=self.capture(&["docker","inspect","--format","{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}",id],240);
                    let fields:Vec<_>=state.split_whitespace().collect();
                    let valid=fields.len()==4&&fields[0].bytes().all(|b|b.is_ascii_lowercase())&&fields[1].strip_prefix("exit=").is_some_and(|v|v.parse::<i32>().is_ok())&&["oom=true","oom=false"].contains(&fields[2])&&fields[3].strip_prefix("health=").is_some_and(|v|v.bytes().all(|b|b.is_ascii_lowercase()));
                    let logs=self.capture(&["docker","logs","--tail","12",id],1000);
                    let classes=["UnicodeDecodeError","PermissionError","FileNotFoundError","ConnectionRefusedError","TimeoutError","ModuleNotFoundError","ImportError","RuntimeError","ValueError","TypeError"].into_iter().filter(|class|logs.split(|c:char|!c.is_ascii_alphanumeric()&&c!='_').any(|word|word==*class)).collect::<Vec<_>>().join(",");
                    details.push(format!("{service}: {}; error classes: {}",if valid{state.trim()}else{"state unavailable"},if classes.is_empty(){"unclassified"}else{&classes}));
                }
                Err(self.error(format!("Compose startup failed; {}",details.join("; "))))
            }
            result=>result,
        }
    }
    pub fn marker(&self) -> String { format!("/etc/proxy-control/{}-owned",self.name) }
    pub fn acceptance_owner(&self) -> String { format!("/etc/proxy-control/{}-acceptance-owner",self.name) }
    pub fn pending(&self) -> String { format!("/etc/proxy-control/{}-acceptance-pending",self.name) }
    pub fn valid_name(&self, value: &str) -> bool { value.strip_prefix(&format!("proxy-control-{}-",self.name)).is_some_and(|hex| is_hex(hex,16)) }
    pub fn fresh_name(&self) -> Result<String,Error> { Ok(format!("proxy-control-{}-{}",self.name,token_hex::<8>())) }
    pub fn marker_sha256(&self) -> Result<String,Error> {
        let path=self.host(&self.marker())?; self.private_file(&path,0o600)?; Ok(sha256_file(&path)?)
    }
    pub fn private_file(&self,path:&Path,mode:u32)->Result<(),Error> {
        let info=fs::symlink_metadata(path)?;
        if !info.is_file() || info.nlink()!=1 || info.mode()&0o7777 != mode || (self.owner().is_some() && (info.uid(),info.gid())!=(0,0)) { return Err(self.error(format!("{} generation ownership has drifted",self.label))); }
        Ok(())
    }
    pub fn existing_acceptance(&self)->Result<Option<String>,Error> {
        if !self.exists(&self.acceptance_owner())? {
            if self.exists(&self.pending())? { return Err(self.error("temporary-user ownership has drifted")); }
            return Ok(None);
        }
        let path=self.host(&self.acceptance_owner())?;
        self.private_file(&path,0o600)?;
        let name=fs::read_to_string(path)?.trim().to_string();
        if !self.valid_name(&name) { return Err(self.error("temporary-user ownership has drifted")); }
        if self.exists(&self.pending())? { self.assert_pending(&name)?; }
        Ok(Some(name))
    }
    pub fn assert_pending(&self,name:&str)->Result<(),Error> {
        let path=self.host(&self.pending())?;
        self.private_file(&path,0o600)?;
        if fs::read_to_string(path)?.trim()!=name { return Err(self.acceptance("temporary-user ownership has drifted")); }
        Ok(())
    }
    pub fn write_acceptance(&self,name:&str)->Result<(),Error> {
        if !self.valid_name(name) { return Err(self.error("temporary-user ownership has drifted")); }
        self.atomic(&self.acceptance_owner(),format!("{name}\n").as_bytes(),0o600)
    }
    pub fn begin_acceptance(&self)->Result<(String,bool),Error> {
        let recover=self.exists(&self.pending())?;
        if recover { let name=self.existing_acceptance()?.ok_or_else(||self.acceptance("temporary-user ownership has drifted"))?; self.assert_pending(&name)?; Ok((name,true)) }
        else { let name=self.fresh_name()?; self.write_acceptance(&name)?; self.atomic(&self.pending(),format!("{name}\n").as_bytes(),0o600)?; Ok((name,false)) }
    }
    pub fn remove(&self,path:&str)->Result<(),Error> { durable_remove(&self.host(path)?,true)?; Ok(()) }
    pub fn helper_bytes(&self,source:&str)->Result<Vec<u8>,Error> {
        match source {
            "prepare-naive-state" | "prepare-mieru-token" => Ok(format!("#!/bin/sh\nexec {PROJECT}/installer/bin/linux-amd64/proxy-control-installer {source} \"$@\"\n").into_bytes()),
            _ => fs::read(self.context.tree.join(source)).map_err(|_|self.error("installer source generation is incomplete")),
        }
    }
    pub fn install_helpers(&self,helpers:&[(&str,&str,u32)])->Result<(),Error> { for (source,path,mode) in helpers { self.atomic(path,&self.helper_bytes(source)?,*mode)?; } Ok(()) }
    pub fn planned_helpers(&self,helpers:&[(&str,&str,u32)],planned:&mut Map<String,Value>)->Result<(),Error> {
        for (source,path,_) in helpers { planned.insert((*path).into(),declaration(false,&self.helper_bytes(source)?)); }
        Ok(())
    }
    pub fn ownership(&self,paths:&[(&str,bool,bool)],binary:&str,preexisting:bool)->Result<Value,Error> {
        let mut map=Map::new();
        for (path,preserve,mutable) in paths { if self.exists(path)? { map.insert((*path).into(),json!({"preserve":preserve,"mutable":mutable,"sha256":path_sha(&self.host(path)?)?})); } }
        if self.exists(binary)? { map.insert(binary.into(),json!({"preserve":preexisting,"sha256":path_sha(&self.host(binary)?)?})); }
        Ok(Value::Object(map))
    }
    pub fn validate_checkpoint(&self,checkpoint:&CheckpointData,action:&Action,keys:&[&str],applied:bool,allowed:&[&str])->Result<(),Error> {
        let invalid=||self.error(format!("{} checkpoint is invalid",self.label));
        if checkpoint.len()!=keys.len() || keys.iter().any(|key|!checkpoint.contains_key(*key)) || checkpoint.get("owner").and_then(Value::as_str)!=Some(action.owner.as_str()) || !checkpoint.get("acceptance_name").and_then(Value::as_str).is_some_and(|s|self.valid_name(s)) { return Err(invalid()); }
        match checkpoint.get("adoption").and_then(Value::as_str) {
            Some("absent") if checkpoint.get("marker_value").and_then(Value::as_str).is_some_and(|s|is_hex(s,32))=>(),
            Some("recovery") if checkpoint.get("marker_value")==Some(&Value::Null)=>(),
            _=>return Err(invalid()),
        }
        if !checkpoint.get("identities_created").and_then(Value::as_object).is_some_and(|map|map.iter().all(|(key,value)|matches!(key.as_str(),"user"|"group")&&value.is_boolean())) {return Err(invalid());}
        for key in keys.iter().filter(|key| key.ends_with("preexisting")) {if !checkpoint[*key].is_boolean(){return Err(invalid());}}
        for key in ["ownership","planned_ownership"] {
            let entries=checkpoint.get(key).and_then(Value::as_object).ok_or_else(invalid)?;
            if key=="planned_ownership" && entries.is_empty() || key=="ownership" && !applied && !entries.is_empty() {return Err(invalid());}
            for (path,entry) in entries {
                let entry=entry.as_object().ok_or_else(invalid)?;
                if !allowed.contains(&path.as_str()) || !entry.get("preserve").is_some_and(Value::is_boolean) || !entry.get("sha256").and_then(Value::as_str).is_some_and(|s|is_hex(s,64)) || entry.get("mutable").is_some_and(|v|!v.is_boolean()) || entry.keys().any(|k| !["preserve","mutable","sha256"].contains(&k.as_str())) { return Err(self.error(format!("{} checkpoint ownership escapes the boundary",self.label))); }
            }
        }
        Ok(())
    }
    pub fn assert_ownership(&self,checkpoint:&CheckpointData)->Result<(),Error> {
        for (path,entry) in checkpoint["ownership"].as_object().expect("validated checkpoint") {
            if !self.exists(path)? || entry.get("mutable")!=Some(&Value::Bool(true)) && path_sha(&self.host(path)?)? != entry["sha256"].as_str().unwrap_or("") {return Err(self.error(format!("{} owned file has drifted: {path}",self.label)));}
        }
        Ok(())
    }
    pub fn remove_generation(&self,checkpoint:&CheckpointData,binary:&str,preserve:bool,preserve_acceptance:bool)->Result<(),Error> {
        let owned=checkpoint["ownership"].as_object().expect("validated checkpoint");
        let planned=owned.is_empty();
        let entries=if planned {checkpoint["planned_ownership"].as_object().expect("validated checkpoint")}else{owned};
        let mut dirs=BTreeSet::new();
        for (path,entry) in entries.iter().rev() {
            if path==binary || preserve&&entry["preserve"]==true || preserve_acceptance&&path==&self.acceptance_owner(){continue;}
            let actual=self.host(path)?;
            if !self.exists(path)? {continue;}
            if entry.get("mutable")!=Some(&Value::Bool(true))&&path_sha(&actual)?!=entry["sha256"].as_str().unwrap_or("") {if planned {continue;}return Err(self.error(format!("{} owned file has drifted: {path}",self.label)));}
            durable_remove(&actual,false)?;
            if let Some(parent)=actual.parent(){dirs.insert(parent.to_path_buf());}
        }
        for dir in dirs.iter().rev(){if fs::remove_dir(dir).is_ok(){if let Some(parent)=dir.parent(){fsync_directory(parent)?;}}}
        Ok(())
    }
    pub fn remove_binary(&self,checkpoint:&CheckpointData,binary:&str,preexisting:&str)->Result<(),Error>{
        if checkpoint[preexisting]==true||!self.exists(binary)?{return Ok(());}
        if let Some(expected)=checkpoint["ownership"].get(binary).and_then(|v|v.get("sha256")).and_then(Value::as_str){if path_sha(&self.host(binary)?)?!=expected{return Err(self.error(format!("{} owned binary has drifted",self.label)));}}
        self.remove(binary)
    }
    pub fn router_credential(&self)->Result<(String,String),Error>{
        let path=self.host(&format!("{PROJECT}/secrets/xray-router-ingress-{}",self.name))?;
        let info=fs::symlink_metadata(&path).map_err(|_|self.error("the Xray-router ingress credential is missing; install the router first"))?;
        if !info.is_file()||info.nlink()!=1||info.mode()&0o027!=0||self.owner().is_some()&&info.uid()!=0{return Err(self.error("the Xray-router ingress credential is unsafe"));}
        let content=fs::read_to_string(path)?;
        let (user,password)=content.trim().split_once(':').ok_or_else(||self.error("the Xray-router ingress credential is malformed"))?;
        if !safe_chars(user,1,64,"._-")||!safe_chars(password,16,128,"._~-"){return Err(self.error("the Xray-router ingress credential is malformed"));}
        Ok((user.into(),password.into()))
    }
    pub fn agent_value(&self,component:&str,key:&str)->Option<String>{
        let path=self.host("/var/lib/proxy-control/version-agent/state.json").ok()?;
        let value:Value=serde_json::from_slice(&fs::read(path).ok()?).ok()?;
        let component=value.get("components")?.get(component)?;
        if component.get("status").and_then(Value::as_str)==Some("rollback_failed"){return None;}
        component.get(key)?.as_str().map(str::to_string)
    }
}
use std::os::unix::fs::OpenOptionsExt;
pub(super) fn strings(values:&[&str])->Vec<String>{values.iter().map(|s|s.to_string()).collect()}
pub(super) fn refs(values:&[String])->Vec<&str>{values.iter().map(String::as_str).collect()}
pub(super) fn is_hex(value:&str,length:usize)->bool{value.len()==length&&value.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
pub(super) fn safe_chars(value:&str,min:usize,max:usize,extra:&str)->bool{(min..=max).contains(&value.len())&&value.bytes().all(|c|c.is_ascii_alphanumeric()||extra.as_bytes().contains(&c))}
pub(super) fn domain(value:&str)->bool{
    if !(4..=253).contains(&value.len()){return false;}
    let parts:Vec<_>=value.split('.').collect();
    parts.len()>=2&&parts.iter().all(|part|!part.is_empty()&&part.len()<=63&&part.as_bytes()[0].is_ascii_alphanumeric()&&part.as_bytes()[part.len()-1].is_ascii_alphanumeric()&&part.bytes().all(|c|c.is_ascii_lowercase()||c.is_ascii_digit()||c==b'-'))&&parts.last().is_some_and(|p|p.as_bytes()[0].is_ascii_lowercase())
}
pub(super) fn seed(choice:EgressChoice)->&'static str{match choice{EgressChoice::Direct=>"direct",EgressChoice::Warp=>"proxy",EgressChoice::Router=>"router"}}
pub(super) fn declaration(preserve:bool,bytes:&[u8])->Value{json!({"preserve":preserve,"sha256":sha256_hex(bytes)})}
pub(super) fn path_sha(path:&Path)->Result<String,Error>{Ok(pc_host::fs::path_identity(path)?.sha256)}
pub(super) fn plan_error(message:impl Into<String>)->Error{Error::Plan(PlanError::new(message))}
pub(super) fn identity_from_entry(value:&str,id:u32)->Option<String>{value.lines().find_map(|line|{let fields:Vec<_>=line.split(':').collect();(fields.len()>=3&&fields[2]==id.to_string()&&safe_chars(fields[0],1,64,"._-")).then(||fields[0].to_string())})}
pub(super) fn audited_identities(facts:&AuditFacts,identities:&[(&str,u32,Option<&str>)])->Result<(),Error>{
    let Some(value)=facts.ownership.get("identities")else{return Ok(());};
    let values=value.as_object().ok_or_else(||plan_error("audited identity facts are invalid"))?;
    for (kind,id,expected) in identities {if let Some(name)=values.get(*kind).and_then(Value::as_object).and_then(|group|group.get(&id.to_string())){if name.is_null()||name==""{continue;}let name=name.as_str().ok_or_else(||plan_error("audited identity facts are invalid"))?;if expected.is_some_and(|e|e!=name){return Err(plan_error(format!("{} {id} collision: {name}",kind.to_uppercase())));}}}
    Ok(())
}
pub(super) fn mutations(action:&Action,name:&str,required:&[&str],optional:&[&str])->Result<BTreeMap<String,String>,Error>{
    let invalid=||Error::other(if name=="naive"{"NaiveError"}else{"MieruError"},format!("{} action is invalid",if name=="naive"{"Naive"}else{"Mieru"}));
    if action.adapter!=name||action.id!=format!("{name}.runtime")||action.owner!=format!("proxy-control:{name}"){return Err(invalid());}
    let mut values=BTreeMap::new();
    for mutation in &action.mutations{let (key,value)=mutation.split_once('=').ok_or_else(invalid)?;if !required.contains(&key)&&!optional.contains(&key)||values.insert(key.to_string(),value.to_string()).is_some(){return Err(invalid());}}
    if required.iter().any(|key|!values.contains_key(*key)){return Err(invalid());}
    Ok(values)
}
pub(super) fn providers(values:&BTreeMap<String,String>,port:u16,host:&Host)->Result<(u16,String,String),Error>{
    let warp=values.get("warp-port").map(String::as_str).unwrap_or("45000").parse::<u16>().ok().filter(|p|*p>=1024).ok_or_else(||host.error("invalid WARP port"))?;
    let expected=format!("socks5://127.0.0.1:{warp}");
    let provider=values.get("warp-provider").cloned().unwrap_or_else(||if values["egress"]=="proxy"{expected.clone()}else{String::new()});
    if !provider.is_empty()&&provider!=expected||values["egress"]=="proxy"&&provider.is_empty(){return Err(host.error("invalid WARP provider"));}
    let expected=format!("socks5://127.0.0.1:{port}");
    let router=values.get("router-provider").cloned().unwrap_or_else(||if values["egress"]=="router"{expected.clone()}else{String::new()});
    if !router.is_empty()&&router!=expected||values["egress"]=="router"&&router.is_empty(){return Err(host.error("invalid router provider"));}
    Ok((warp,provider,router))
}
pub(super) fn evidence(action:&Action,observations:&[&str],details:Value)->Evidence{Evidence{action_id:action.id.clone(),success:true,observations:strings(observations),details:details.as_object().cloned().unwrap_or_default()}}
pub(super) fn command_failure(label:&str,argv:&[&str])->String{
    let program=argv.first().and_then(|s|Path::new(s).file_name()).and_then(|s|s.to_str()).unwrap_or("command");
    let mut text=format!("{label} command failed: {program}");
    for part in argv.iter().skip(1).take(2){if part.starts_with('-')||part.contains('/'){break;}text.push(' ');text.push_str(part);}
    text
}
pub(super) fn sanitize(value:&str)->String{
    let lower=value.to_ascii_lowercase();let mut out=String::new();let mut pos=0;
    while pos<value.len(){let rest=&lower[pos..];let found=["password","token","secret"].iter().filter_map(|word|rest.find(word).map(|i|(i,*word))).min_by_key(|(i,_)|*i);
        let Some((index,word))=found else{out.push_str(&value[pos..]);break;};let end=pos+index+word.len();out.push_str(&value[pos..end]);let mut cursor=end;
        while cursor<value.len()&&matches!(value.as_bytes()[cursor],b'='|b':'|b' '|b'\t'|b'\r'|b'\n'){cursor+=1;}
        out.push_str(&value[end..cursor]);if cursor>end{out.push_str("[REDACTED]");while cursor<value.len()&&!value.as_bytes()[cursor].is_ascii_whitespace(){cursor+=1;}}pos=cursor;
    }
    pc_host::pytext::tail_chars(&out,1200).replace('\n'," ").trim().to_string()
}
pub(super) fn clear_directory(path:&Path)->Result<(),Error>{
    if fs::symlink_metadata(path).is_ok_and(|m|m.is_dir()) {for entry in fs::read_dir(path)?{let path=entry?.path();if fs::symlink_metadata(&path)?.is_dir(){clear_directory(&path)?;fs::remove_dir(path)?;}else{durable_remove(&path,false)?;}}}
    Ok(())
}
pub(super) fn loopback(host:&Host,port:u16)->bool{let output=host.capture(&["ss","-H","-lnt",&format!("sport = :{port}")],4096);let addresses:BTreeSet<_>=output.lines().filter_map(|line|line.split_whitespace().nth(3)).collect();addresses==BTreeSet::from([format!("127.0.0.1:{port}").as_str()])}
pub(super) fn sleep_poll(deadline:std::time::Instant)->bool{if std::time::Instant::now()>=deadline{false}else{std::thread::sleep(Duration::from_millis(500));true}}
