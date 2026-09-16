"""The Xray config one generation runs, rendered from the services' intents (spec §6).

Everything here is a pure function of (intents, ingress credentials, provider endpoint):
same input, same bytes, same digest. The shape is what the spike proved on the stand
(docs/spikes/XRAY_EGRESS_ROUTER.md):

- one `socks` inbound per service on the host loopback, `auth: password` with exactly one
  account, `udp: false`, sniffing with `routeOnly` so an IP-literal CONNECT still meets the
  domain rules while the dial keeps the client's address;
- outbounds `block` first (whatever nothing matches is refused), `direct` (`freedom` with
  `UseIP`: the address the decision was made on is the address dialled), `warp` (`socks`
  to the node's WARP proxy-mode endpoint) only when an intent uses it;
- `routing.domainStrategy: IPOnDemand` and, per inbound tag, the immutable bypass
  (`geoip:private` and `localhost` → `block`) before the intent's first-match rules and a
  catch-all to the service's default. No `api`, no `stats`, no access log.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass

from .intent import PORTS, SERVICES, provider_endpoint, uses_provider

RENDER_VERSION = "1"
OUTBOUND_FOR = {"direct": "direct", "block": "block", "egress": "warp"}


@dataclass(frozen=True)
class Ingress:
    tag: str
    port: int
    user: str
    password: str


def _domain_selector(value: str) -> str:
    """`example.com` and `*.example.com` both mean the suffix (Xray `domain:`), as mita does."""
    return "domain:" + (value[2:] if value.startswith("*.") else value)


def _rule(tag: str, rule: dict) -> dict:
    entry: dict = {"inboundTag": [tag]}
    domains = [_domain_selector(item) for item in rule["domains"]] + [f"geosite:{code}" for code in rule["geosites"]]
    addresses = list(rule["cidrs"]) + [f"geoip:{code}" for code in rule["geoips"]]
    if domains:
        entry["domain"] = domains
    if addresses:
        entry["ip"] = addresses
    if rule["ports"]:
        entry["port"] = ",".join(str(port) for port in rule["ports"])
    entry["outboundTag"] = OUTBOUND_FOR[rule["action"]]
    return entry


def render_config(intents: dict[str, dict], ingresses: list[Ingress], *, warp_url: str | None,
                  ports: dict[str, int] | None = None) -> dict:
    """The full Xray config for these intents. `intents` holds a validated document per
    service (a missing service runs pass-through); `EgressInvalid` when an intent needs the
    `warp` provider and this node has none."""
    ports = ports or PORTS
    by_tag = {ingress.tag: ingress for ingress in ingresses}
    inbounds = []
    for tag in SERVICES:
        ingress = by_tag[tag]
        inbounds.append({
            "tag": tag, "listen": "127.0.0.1", "port": ports[tag], "protocol": "socks",
            "settings": {"auth": "password", "accounts": [{"user": ingress.user, "pass": ingress.password}], "udp": False},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        })
    outbounds = [{"tag": "block", "protocol": "blackhole"},
                 {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}]
    needs_warp = [tag for tag in SERVICES if tag in intents and uses_provider(intents[tag])]
    if needs_warp:
        host, port = provider_endpoint(warp_url)
        outbounds.append({"tag": "warp", "protocol": "socks", "settings": {"servers": [{"address": host, "port": port}]}})
    rules = []
    for tag in SERVICES:
        intent = intents.get(tag) or {"default": {"action": "direct", "egress": None}, "rules": []}
        rules.append({"inboundTag": [tag], "ip": ["geoip:private"], "outboundTag": "block"})
        rules.append({"inboundTag": [tag], "domain": ["domain:localhost", "full:localhost"], "outboundTag": "block"})
        rules.extend(_rule(tag, rule) for rule in intent["rules"])
        rules.append({"inboundTag": [tag], "outboundTag": OUTBOUND_FOR[intent["default"]["action"]]})
    return {
        "log": {"access": "none", "loglevel": "warning"},
        "dns": {"servers": ["localhost"]},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPOnDemand", "rules": rules},
    }


def config_bytes(config: dict) -> bytes:
    return json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def generation_digest(config: dict) -> str:
    """SHA-256 of the exact bytes the generation file carries (credentials included: the
    digest names what Xray runs)."""
    return hashlib.sha256(config_bytes(config)).hexdigest()


def redact(config: dict) -> dict:
    """The config with every ingress account masked — what may reach a log or an error."""
    masked = copy.deepcopy(config)
    for inbound in masked.get("inbounds", []):
        for account in inbound.get("settings", {}).get("accounts", []):
            account["user"], account["pass"] = "***", "***"
    return masked

