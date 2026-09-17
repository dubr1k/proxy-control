"""The compiled egress document as the panel and both managers see it (v0.4 routing).

`document_digest` is the one canonical form the panel, the naive-manager and the
mieru-manager all hash — `json.dumps(sort_keys=True, compact, ascii)` — so a policy
revision on the central, the `applied_digest` a node reports and the manager's journal
entry compare by the same bytes on every host.
"""
from __future__ import annotations

import hashlib
import json
import re

# What the managers' egress APIs answer with (naive_manager/server.py, mieru_manager/
# server.py). Bounded on purpose: any other code is a plain conflict or an outage, so a
# manager response never dictates panel copy.
EGRESS_REASON_CODES = frozenset({
    "egress_conflict",
    "egress_invalid",
    "egress_unreachable",
    "egress_readback_mismatch",
    "manual_intervention_required",
    "egress_no_previous",
    # The Xray-router manager (v0.5): what `xray run -test` named, and a runtime whose
    # binary or geodata is not the release's.
    "geosite_unknown",
    "geoip_unknown",
    "artifact_mismatch",
    # Lanes and the relay (v0.7): the router's and the service managers' own codes.
    "lane_unknown",
    "lanes_invalid",
    "lane_slots_exhausted",
    "relay_disabled",
})

# The native document that hands a service's whole traffic to the node's Xray-router
# (v0.5): the managers render the private ingress endpoint and credential themselves.
ATTACH_DOCUMENTS = {
    "naive": {"schema": 1, "upstream": {"provider": "router"}, "acl": []},
    "mieru": {"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
              "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]},
}
ROUTER_DIRECT_INTENT = {"schema": 1, "default": {"action": "direct", "egress": None}, "rules": []}


def attach_document(protocol: str) -> dict:
    return json.loads(json.dumps(ATTACH_DOCUMENTS[protocol]))


def attached_to_router(protocol: str, document: dict | None) -> bool:
    """Whether a native manager's applied document hands the service to the router."""
    if not isinstance(document, dict):
        return False
    if protocol == "naive":
        return document.get("upstream") == {"provider": "router"}
    if protocol == "mieru":
        rules = document.get("rules") or []
        return (any(proxy.get("name") == "router" for proxy in document.get("proxies") or [] if isinstance(proxy, dict))
                and bool(rules) and rules[-1] == ATTACH_DOCUMENTS["mieru"]["rules"][0])
    return False


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document_digest(document: dict) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


_UUID_LINE = re.compile(r'("uuid":\s*")[^"]*(")')


def redact_document(document):
    """A router intent for the operator's eyes (v0.7): the relay accounts a chain carries
    (`chains.*.hops[].uuid`) masked — the API, the history and the diff never show them."""
    if not isinstance(document, dict):
        return document
    chains = document.get("chains")
    if not isinstance(chains, dict):
        return document
    copy = json.loads(json.dumps(document))
    for chain in copy["chains"].values():
        for hop in chain.get("hops", []) if isinstance(chain, dict) else []:
            if isinstance(hop, dict) and "uuid" in hop:
                hop["uuid"] = "***"
    return copy


def redact_diff(lines):
    return [_UUID_LINE.sub(r"\1***\2", line) for line in lines]


def without_lane(document: dict, lane: str) -> dict:
    """A schema-2 intent minus one lane and the chains only it used — what a node should run
    once a lane is withdrawn, until the service's policy is applied again."""
    if not isinstance(document, dict) or document.get("schema") != 2 or lane not in document.get("lanes", {}):
        return document
    lanes = {name: body for name, body in document["lanes"].items() if name != lane}
    used = {rule.get("egress") for body in lanes.values() for rule in body.get("rules", [])}
    used |= {body.get("default", {}).get("egress") for body in lanes.values()}
    chains = {chain_id: chain for chain_id, chain in document.get("chains", {}).items() if f"chain:{chain_id}" in used}
    return {**document, "lanes": lanes, "chains": chains}
