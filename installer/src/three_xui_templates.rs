//! The reviewed managed 3x-ui templates; secret material stays out of plans and evidence.
use crate::error::Error;
use serde_json::{json, Value};
use std::collections::BTreeMap;
fn compact(value: &Value) -> String {
    pc_common::json::dumps(
        value,
        &pc_common::json::Options {
            indent: None,
            separators: Some((",", ":")),
            sort_keys: true,
            ensure_ascii: true,
            numbers: pc_common::json::NumberMode::Python(pc_common::json::FloatMode::Python),
        },
    )
}
fn client_id() -> String {
    let hex = pc_host::fs::uuid4_hex();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}
pub fn managed_inbounds(
    selected: &BTreeMap<String, String>,
    private: &str,
    public: &str,
    subscription: Option<&str>,
) -> Result<Vec<Value>, Error> {
    let sniffing = json!({"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true});
    let mut result = Vec::new();
    for (index, (tag, network, port, key)) in [
        ("managed-vless-reality-tcp", "tcp", 8449, "vless-tcp-domain"),
        ("managed-vless-reality-xhttp", "xhttp", 8450, "vless-xhttp-domain"),
        ("managed-hysteria2-tls", "hysteria", 443, "hysteria-domain"),
    ]
    .into_iter()
    .enumerate()
    {
        let domain = selected
            .get(key)
            .ok_or_else(|| Error::other("ThreeXuiApiError", "managed 3x-ui requires every selected domain"))?;
        let hysteria = network == "hysteria";
        let mut stream = if hysteria {
            json!({"externalProxy":[{"dest":domain,"port":443,"forceTls":"same"}],"network":"hysteria","security":"tls","hysteriaSettings":{"udpIdleTimeout":60,"version":2},"tlsSettings":{"alpn":["h3"],"serverName":domain,"certificates":[{"certificateFile":format!("/etc/letsencrypt/live/{domain}/fullchain.pem"),"keyFile":format!("/etc/letsencrypt/live/{domain}/privkey.pem")}]}})
        } else {
            json!({"network":network,"security":"reality","externalProxy":[{"dest":domain,"port":443,"forceTls":"same"}],"realitySettings":{"show":false,"dest":"127.0.0.1:8443","xver":0,"serverNames":[domain],"privateKey":private,"publicKey":public,"shortIds":[pc_host::fs::token_hex::<8>()]}})
        };
        if network == "tcp" {
            stream["tcpSettings"] = json!({"header":{"type":"none"}});
        } else if network == "xhttp" {
            stream["xhttpSettings"] = json!({"host":"","path":"/assets/","mode":"auto"});
        }
        let mut clients = Vec::new();
        for prefix in ["initial", "acceptance"] {
            let mut client = if hysteria {
                json!({"email":format!("{prefix}-{index}"),"auth":pc_host::fs::token_hex::<24>(),"enable":true})
            } else {
                json!({"id":client_id(),"email":format!("{prefix}-{index}"),"flow":if network=="tcp"{"xtls-rprx-vision"}else{""},"enable":true})
            };
            if prefix == "initial" {
                if let Some(subscription) = subscription {
                    client["subId"] = json!(subscription);
                }
            }
            clients.push(client);
        }
        let settings = if hysteria {
            json!({"version":2,"clients":clients})
        } else {
            json!({"decryption":"none","fallbacks":[],"clients":clients})
        };
        result.push(json!({"enable":true,"remark":tag,"listen":if hysteria{"0.0.0.0"}else{"127.0.0.1"},"port":port,"protocol":if hysteria{"hysteria"}else{"vless"},"settings":compact(&settings),"streamSettings":compact(&stream),"sniffing":compact(&sniffing)}));
    }
    Ok(result)
}
pub fn parse_reality_keypair(output: &str) -> Result<(String, String), Error> {
    let mut private = None;
    let mut public = None;
    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if value.len() != 43 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
            continue;
        }
        match label.trim() {
            "PrivateKey" | "Private key" | "Private Key" | "Privatekey" => private = Some(value.to_owned()),
            "Password (PublicKey)" | "PublicKey" | "Public key" | "Public Key" | "Publickey" => {
                public = Some(value.to_owned())
            }
            _ => {}
        }
    }
    match (private, public) {
        (Some(private), Some(public)) => Ok((private, public)),
        _ => Err(Error::other("ThreeXuiError", "Xray returned no usable Reality keypair")),
    }
}
