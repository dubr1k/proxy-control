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

Schema 2 (v0.7, docs/spikes/CHAINS_PER_CLIENT.md) adds, on the same shape:

- one more account per *lane* on the service's inbound and the lane's rules carrying
  `user: [account]`, the service's own lane last — Xray routes by the authenticated account;
- a `vless` + `reality` outbound per chain hop (`chain:<service>:<id>:<n>`), every hop after
  the first dialled through the previous one (`proxySettings.tag`); a rule whose egress is a
  chain lands on the chain's last hop;
- the node's relay inbound (`vless` + `reality` on the public relay port, cover = the panel's
  own TLS listener) with one client per `relay:<source>:<exit>` account and rules that send
  `…:warp` accounts to this node's WARP and everything else direct.

A schema-1 intent without lanes or a relay renders byte-for-byte as in v0.5.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field

from .intent import PORTS, SCHEMA_V2, SERVICES, EgressInvalid, provider_endpoint, uses_provider

RENDER_VERSION = "2"
OUTBOUND_FOR = {"direct": "direct", "block": "block", "egress": "warp"}
RELAY_TAG = "relay"
RELAY_COVER = "127.0.0.1:8443"


@dataclass(frozen=True)
class Ingress:
    tag: str
    port: int
    user: str
    password: str


@dataclass(frozen=True)
class LaneAccount:
    """A `grant:<id>` lane's SOCKS account on its service's ingress (the service's own lane
    is the `Ingress` account)."""
    lane: str
    user: str
    password: str


@dataclass(frozen=True)
class Relay:
    """This node's relay inbound: where other nodes' chains arrive."""
    port: int
    server_name: str
    private_key: str
    short_ids: list[str]
    accounts: list[tuple[str, str]] = field(default_factory=list)  # (email, uuid)


def _domain_selector(value: str) -> str:
    """`example.com` and `*.example.com` both mean the suffix (Xray `domain:`), as mita does."""
    return "domain:" + (value[2:] if value.startswith("*.") else value)


def _outbound_tag(tag: str, action: str, egress: str | None, chain_tags: dict[str, str]) -> str:
    if action == "egress" and egress and egress.startswith("chain:"):
        return chain_tags[egress[6:]]
    return OUTBOUND_FOR[action]


def _rule(tag: str, rule: dict, *, user: str | None = None, chain_tags: dict[str, str] | None = None) -> dict:
    entry: dict = {"inboundTag": [tag]}
    if user is not None:
        entry["user"] = [user]
    domains = [_domain_selector(item) for item in rule["domains"]] + [f"geosite:{code}" for code in rule["geosites"]]
    addresses = list(rule["cidrs"]) + [f"geoip:{code}" for code in rule["geoips"]]
    if domains:
        entry["domain"] = domains
    if addresses:
        entry["ip"] = addresses
    if rule["ports"]:
        entry["port"] = ",".join(str(port) for port in rule["ports"])
    entry["outboundTag"] = _outbound_tag(tag, rule["action"], rule.get("egress"), chain_tags or {})
    return entry


def _bypass(tag: str) -> list[dict]:
    return [{"inboundTag": [tag], "ip": ["geoip:private"], "outboundTag": "block"},
            {"inboundTag": [tag], "domain": ["domain:localhost", "full:localhost"], "outboundTag": "block"}]


def _hop_outbound(tag: str, hop: dict, previous: str | None) -> dict:
    outbound = {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": hop["address"], "port": hop["port"],
                                "users": [{"id": hop["uuid"], "encryption": "none", "flow": ""}]}]},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "serverName": hop["server_name"], "fingerprint": "chrome", "publicKey": hop["public_key"],
            "shortId": hop["short_id"]}},
    }
    if previous is not None:
        outbound["proxySettings"] = {"tag": previous}
    return outbound


def _chain_outbounds(tag: str, intent: dict) -> tuple[list[dict], dict[str, str]]:
    """One outbound per hop of every chain the service's intent names; the tag a rule lands
    on is the chain's last hop."""
    outbounds: list[dict] = []
    chain_tags: dict[str, str] = {}
    for chain_id, chain in intent.get("chains", {}).items():
        previous = None
        for index, hop in enumerate(chain["hops"], 1):
            hop_tag = f"chain:{tag}:{chain_id}:{index}"
            outbounds.append(_hop_outbound(hop_tag, hop, previous))
            previous = hop_tag
        chain_tags[chain_id] = previous
    return outbounds, chain_tags


def _lane_rules(tag: str, ingress: Ingress, intent: dict, accounts: dict[str, LaneAccount], chain_tags: dict[str, str]) -> list[dict]:
    """Schema 2: every lane's rules and catch-all carry its account; the service lane last."""
    rules: list[dict] = []
    lanes = intent["lanes"]
    ordered = [lane for lane in lanes if lane.startswith("grant:")] + [lane for lane in lanes if lane.startswith("svc:")]
    for lane in ordered:
        if lane.startswith("svc:"):
            user = ingress.user
        elif lane in accounts:
            user = accounts[lane].user
        else:
            raise EgressInvalid(f"lane {lane} has no account on ingress {tag}")
        body = lanes[lane]
        rules.extend(_rule(tag, rule, user=user, chain_tags=chain_tags) for rule in body["rules"])
        rules.append({"inboundTag": [tag], "user": [user],
                      "outboundTag": _outbound_tag(tag, body["default"]["action"], body["default"]["egress"], chain_tags)})
    return rules


def _relay_inbound(relay: Relay) -> dict:
    return {
        "tag": RELAY_TAG, "listen": "0.0.0.0", "port": relay.port, "protocol": "vless",
        "settings": {"clients": [{"id": uuid, "email": email, "flow": ""} for email, uuid in relay.accounts], "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "dest": RELAY_COVER, "serverNames": [relay.server_name], "privateKey": relay.private_key,
            "shortIds": list(relay.short_ids)}},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
    }


def render_config(intents: dict[str, dict], ingresses: list[Ingress], *, warp_url: str | None,
                  ports: dict[str, int] | None = None, lanes: dict[str, list[LaneAccount]] | None = None,
                  relay: Relay | None = None) -> dict:
    """The full Xray config for these intents. `intents` holds a validated document per
    service (a missing service runs pass-through); `lanes` the grant lanes' accounts per
    service; `relay` this node's relay inbound when enabled. `EgressInvalid` when something
    needs the `warp` provider and this node has none, or a lane has no account."""
    ports = ports or PORTS
    lanes = lanes or {}
    by_tag = {ingress.tag: ingress for ingress in ingresses}
    inbounds = []
    for tag in SERVICES:
        ingress = by_tag[tag]
        accounts = [{"user": ingress.user, "pass": ingress.password}]
        accounts += [{"user": account.user, "pass": account.password} for account in lanes.get(tag, [])]
        inbounds.append({
            "tag": tag, "listen": "127.0.0.1", "port": ports[tag], "protocol": "socks",
            "settings": {"auth": "password", "accounts": accounts, "udp": False},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        })
    if relay is not None:
        inbounds.append(_relay_inbound(relay))
    outbounds = [{"tag": "block", "protocol": "blackhole"},
                 {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}]
    relay_warp = [email for email, _uuid in (relay.accounts if relay else []) if email.endswith(":warp")]
    needs_warp = [tag for tag in SERVICES if tag in intents and uses_provider(intents[tag])] or relay_warp
    if needs_warp:
        host, port = provider_endpoint(warp_url)
        outbounds.append({"tag": "warp", "protocol": "socks", "settings": {"servers": [{"address": host, "port": port}]}})
    rules = []
    for tag in SERVICES:
        intent = intents.get(tag) or {"default": {"action": "direct", "egress": None}, "rules": []}
        chain_outbounds, chain_tags = _chain_outbounds(tag, intent)
        outbounds.extend(chain_outbounds)
        rules.extend(_bypass(tag))
        if intent.get("schema") == SCHEMA_V2:
            rules.extend(_lane_rules(tag, by_tag[tag], intent, {a.lane: a for a in lanes.get(tag, [])}, chain_tags))
        else:
            rules.extend(_rule(tag, rule) for rule in intent["rules"])
            rules.append({"inboundTag": [tag], "outboundTag": OUTBOUND_FOR[intent["default"]["action"]]})
    if relay is not None:
        rules.extend(_bypass(RELAY_TAG))
        if relay_warp:
            rules.append({"inboundTag": [RELAY_TAG], "user": relay_warp, "outboundTag": "warp"})
        rules.append({"inboundTag": [RELAY_TAG], "outboundTag": "direct"})
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
    """The config with every secret masked — ingress accounts, relay clients and the Reality
    private key, chain hop credentials — what may reach a log or an error."""
    masked = copy.deepcopy(config)
    for inbound in masked.get("inbounds", []):
        settings = inbound.get("settings", {})
        for account in settings.get("accounts", []):
            account["user"], account["pass"] = "***", "***"
        for client in settings.get("clients", []):
            client["id"] = "***"
        reality = inbound.get("streamSettings", {}).get("realitySettings", {})
        if "privateKey" in reality:
            reality["privateKey"] = "***"
    for outbound in masked.get("outbounds", []):
        for server in outbound.get("settings", {}).get("vnext", []):
            for user in server.get("users", []):
                user["id"] = "***"
    return masked

