//! Whitelisted read-only facts and byte identity of an existing 3x-ui installation.
use std::collections::{BTreeMap,BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use serde_json::{json,Value};
use crate::error::Error;
use super::ThreeXuiAdapter;
use super::super::router_host as h;
fn fail(message:&str)->Error{Error::other("ThreeXuiError",message)}
fn safe(value:&Value)->Option<&str>{value.as_str().filter(|text|!text.is_empty()&&text.len()<=128&&text.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.:@/-".contains(&b)))}
fn tags(value:&Value)->Vec<String>{let mut tags=value.as_array().into_iter().flatten().filter_map(|item|safe(&item["tag"]).map(str::to_owned)).collect::<Vec<_>>();tags.sort();tags}
fn hash(path:&Path)->Result<String,Error>{let mut file=fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path)?;Ok(pc_host::fs::sha256_reader(&mut file)?)}
fn walk(root:&Path,current:&Path,entries:&mut BTreeMap<String,std::path::PathBuf>)->Result<(),Error>{for entry in fs::read_dir(current)?{let entry=entry?;let path=entry.path();let relative=path.strip_prefix(root).map_err(|_|fail("3x-ui tree escaped its root"))?.to_str().ok_or_else(||fail("3x-ui tree path is not UTF-8"))?.to_owned();entries.insert(relative,path.clone());if entries.len()>4096{return Err(fail("3x-ui tree exceeds the audit bound"));}if entry.file_type()?.is_dir(){walk(root,&path,entries)?;}}Ok(())}
impl ThreeXuiAdapter{
 /// No credential-bearing object or key is returned; only whitelisted facts and hashes.
 pub fn audit_existing(&self)->Result<Value,Error>{
  let config=h::host(&self.context,"/usr/local/x-ui/bin/config.json")?;
  let installed=match fs::symlink_metadata(&config){Ok(metadata)=>{if !metadata.is_file(){return Err(fail("3x-ui configuration must be a regular file"));}if metadata.len()>4*1024*1024{return Err(fail("3x-ui configuration exceeds the audit bound"));}true},Err(error)if error.kind()==std::io::ErrorKind::NotFound=>false,Err(error)=>return Err(error.into())};
  let mut digests=BTreeMap::new();
  for(label,path)in [("config","/usr/local/x-ui/bin/config.json"),("database","/etc/x-ui/x-ui.db"),("unit","/etc/systemd/system/x-ui.service")]{let path=h::host(&self.context,path)?;if fs::symlink_metadata(&path).is_ok_and(|m|m.is_file()){digests.insert(label,hash(&path)?);}}
  let tree=h::host(&self.context,"/usr/local/x-ui")?;
  if fs::symlink_metadata(&tree).is_ok_and(|m|m.is_dir()){
   let mut entries=BTreeMap::new();walk(&tree,&tree,&mut entries)?;let mut identity=String::new();
   for(relative,path)in entries{let metadata=fs::symlink_metadata(&path)?;if metadata.is_symlink(){let target=fs::read_link(&path)?;identity.push_str(&format!("L {relative} {}\n",target.to_str().ok_or_else(||fail("3x-ui symlink is not UTF-8"))?));}else if metadata.is_dir(){identity.push_str(&format!("D {relative}\n"));}else if metadata.is_file(){identity.push_str(&format!("F {relative} {}\n",hash(&path)?));}}
   digests.insert("binary_tree",pc_host::fs::sha256_hex(identity.as_bytes()));
  }
  let mut result=json!({"installed":installed,"inbounds":[],"outbound_tags":[],"balancer_tags":[],"routing_selectors":[],"client_total":0,"digests":digests});
  if !installed{return Ok(result)}
  let mut bytes=Vec::new();fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(config)?.take(4*1024*1024+1).read_to_end(&mut bytes)?;
  if bytes.len()>4*1024*1024{return Err(fail("3x-ui configuration exceeds the audit bound"));}
  let document:Value=serde_json::from_slice(&bytes).map_err(|_|fail("3x-ui configuration is not readable JSON"))?;if !document.is_object(){return Err(fail("3x-ui configuration is not an object"));}
  let inbounds=document["inbounds"].as_array();if inbounds.is_some_and(|items|items.len()>256){return Err(fail("3x-ui declares more inbounds than the audit bound"));}
  let mut facts=Vec::new();let mut client_total=0;
  for item in inbounds.into_iter().flatten(){let Some(port)=item["port"].as_u64().filter(|port|(1..=65535).contains(port))else{continue};let Some(protocol)=safe(&item["protocol"])else{continue};
   let raw_network=item.pointer("/streamSettings/network").and_then(Value::as_str).unwrap_or("tcp");let network=if ["tcp","ws","grpc","http","xhttp","httpupgrade","kcp","quic"].contains(&raw_network){raw_network}else{"tcp"};
   let raw_security=item.pointer("/streamSettings/security").and_then(Value::as_str).unwrap_or("none");let security=if ["none","tls","reality","xtls"].contains(&raw_security){raw_security}else{"none"};
   let settings=match &item["settings"]{Value::String(text)=>serde_json::from_str(text).unwrap_or(Value::Null),value=>value.clone()};let client_count=settings["clients"].as_array().map_or(0,Vec::len);client_total+=client_count;
   let mut names=item.pointer("/streamSettings/realitySettings/serverNames").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).filter(|name|super::runtime::domain(name)).map(str::to_owned).collect::<Vec<_>>();names.sort();
   let target=item.pointer("/streamSettings/realitySettings/target").filter(|value|!value.is_null()&&value.as_str()!=Some("")).or_else(||item.pointer("/streamSettings/realitySettings/dest")).and_then(safe);
   let mut certificates=Vec::new();for certificate in item.pointer("/streamSettings/tlsSettings/certificates").and_then(Value::as_array).into_iter().flatten(){for key in ["certificateFile","keyFile"]{if let Some(path)=safe(&certificate[key]).filter(|path|path.starts_with('/')){certificates.push(path.to_owned());}}}certificates.sort();
   let mut overrides=item.pointer("/sniffing/destOverride").and_then(Value::as_array).into_iter().flatten().filter_map(safe).map(str::to_owned).collect::<Vec<_>>();overrides.sort();
   facts.push(json!({"tag":safe(&item["tag"]).map(str::to_owned).unwrap_or_else(||format!("inbound-{port}")),"protocol":protocol,"listen":safe(&item["listen"]).unwrap_or("0.0.0.0"),"port":port,"network":network,"security":security,"client_count":client_count,"reality_server_names":names,"reality_target":target,"tls_certificate_paths":certificates,"sniffing_enabled":item.pointer("/sniffing/enabled")==Some(&json!(true)),"sniffing_dest_override":overrides}));
  }
  facts.sort_by(|a,b|a["port"].as_u64().cmp(&b["port"].as_u64()).then_with(||a["tag"].as_str().cmp(&b["tag"].as_str())));
  let mut selectors=BTreeSet::new();for rule in document.pointer("/routing/rules").and_then(Value::as_array).into_iter().flatten(){for key in ["inboundTag","outboundTag","balancerTag","network","protocol"]{let values=rule[key].as_array().map(|values|values.iter().collect::<Vec<_>>()).unwrap_or_else(||vec![&rule[key]]);for value in values{if let Some(value)=safe(value){selectors.insert(format!("{key}={value}"));}}}}
  result["inbounds"]=json!(facts);result["outbound_tags"]=json!(tags(&document["outbounds"]));result["balancer_tags"]=json!(tags(&document["routing"]["balancers"]));result["routing_selectors"]=json!(selectors);result["client_total"]=json!(client_total);
  Ok(result)
 }
}
