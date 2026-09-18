"""Policy → the router's intent (`XrayRoutingIntent`, xray_router_manager/intent.py), v0.5.

The router enforces every cell of the matrix the spike proved (docs/spikes/
XRAY_EGRESS_ROUTER.md): domains and geosite codes, CIDRs and geoip codes, ports, `block`
beside a `warp` default, `direct` exceptions beside `warp`. What it still refuses is what
no backend may do — opening a private destination — and what the node lacks: the `warp`
provider. The compiled document is the intent for the service's ingress tag; the native
manager's *attach* document (the service handed to the router) travels beside it.
"""
from __future__ import annotations

import difflib
import json
from dataclasses import dataclass

from ...protocols.base import RouterTarget
from ..document import attach_document, document_digest
from ..models import (
    COMPILER_VERSION,
    LANE_SERVICE,
    Compiled,
    Reason,
    RoutingPolicy,
    RoutingRule,
    exit_hops,
    is_node_exit,
)

MAX_DOCUMENT_BYTES = 16384
# Lanes multiply the volume (v0.7): the router's own ceiling for a schema-2 intent.
MAX_DOCUMENT_BYTES_V2 = 65536


@dataclass(frozen=True)
class ChainHop:
    """A node's relay as this panel knows it (v0.7): where to dial, the Reality public
    part, and the relay accounts the central issued to *this* node — one for a direct
    exit, one (optional) for the hop's WARP."""
    guid: str
    address: str
    port: int
    server_name: str
    public_key: str
    short_id: str
    uuid_direct: str
    uuid_warp: str | None = None


def _needed(rule: RoutingRule) -> set[str]:
    kind = "block" if rule.action == "block" else "selective"
    needed = set()
    if rule.match.domains:
        needed.add(f"{kind}_domain")
    if rule.match.geosites:
        needed.add(f"{kind}_geosite")
    if rule.match.cidrs:
        needed.add(f"{kind}_cidr")
    if rule.match.geoips:
        needed.add(f"{kind}_geoip")
    if rule.match.ports:
        needed.add(f"{kind}_port")
    if rule.match.protocols:
        needed.add(f"{kind}_protocol")
    return needed


def _lane_body(default_action: str, default_egress: str | None, rules: list[RoutingRule], egress_map) -> dict:
    """One lane's part of the intent: the rules in order, enabled only, the same selector
    vocabulary the policy uses (`*.x` and `x` both mean the suffix there); `egress_map`
    turns a policy egress into the router's (`warp` stays, a node exit becomes `chain:<id>`)."""
    compiled = []
    for rule in rules:
        domains = []
        for domain in rule.match.domains:
            suffix = domain[2:] if domain.startswith("*.") else domain
            if suffix not in domains:
                domains.append(suffix)
        entry = {"domains": domains, "geosites": list(rule.match.geosites), "cidrs": list(rule.match.cidrs),
                 "geoips": list(rule.match.geoips), "ports": list(rule.match.ports),
                 "action": rule.action, "egress": None if rule.egress is None else egress_map(rule.egress)}
        if rule.match.protocols:
            # Only when named: a v0.7 router refuses an unknown rule field, and a rule without
            # the selector compiles to the same intent it always did.
            entry["protocols"] = list(rule.match.protocols)
        compiled.append(entry)
    return {"default": {"action": default_action, "egress": None if default_egress is None else egress_map(default_egress)},
            "rules": compiled}


def intent_of(default_action: str, rules: list[RoutingRule]) -> dict:
    """The schema-1 intent (v0.5): one service, `warp` the only egress."""
    body = _lane_body(default_action, "warp" if default_action == "egress" else None, rules, lambda value: value)
    return {"schema": 1, **body}


def intent_v2(protocol: str, lanes: list[tuple[str, str, str | None, list[RoutingRule]]], chains: dict[str, dict]) -> dict:
    """The schema-2 intent (v0.7): every lane of the service — `(lane id, default action,
    default egress, rules)`, the service's own first — and the chains they name."""
    ids: dict[str, str] = {}

    def egress_map(value: str) -> str:
        if not is_node_exit(value):
            return value
        if value not in ids:
            ids[value] = f"c{len(ids) + 1}"
        return f"chain:{ids[value]}"

    rendered = {}
    for lane, default_action, default_egress, rules in lanes:
        key = f"svc:{protocol}" if lane == LANE_SERVICE else lane
        rendered[key] = _lane_body(default_action, default_egress, rules, egress_map)
    return {"schema": 2, "lanes": rendered, "chains": {ids[value]: chains[value] for value in ids}}


def resolve_chain(value: str, resolver, *, own_guids: set[str]) -> tuple[dict | None, Reason | None]:
    """The router's chain for a node exit: every hop's relay as this node may reach it, the
    middle hops with their *direct* account (they are dialled through), the last with the
    account its exit needs."""
    guids, via = exit_hops(value)
    if any(guid in own_guids for guid in guids):
        return None, Reason(code="chain_loop", message="a chain cannot pass through this node")
    hops = []
    for index, guid in enumerate(guids):
        found = resolver.resolve(guid)
        if isinstance(found, Reason):
            return None, found
        last = index == len(guids) - 1
        uuid = found.uuid_warp if last and via == "warp" else found.uuid_direct
        if uuid is None:
            return None, Reason(code="relay_no_warp", message=f"node {guid} has no relay account for its warp")
        hops.append({"guid": guid, "address": found.address, "port": found.port, "server_name": found.server_name,
                     "public_key": found.public_key, "short_id": found.short_id, "uuid": uuid})
    return {"hops": hops, "exit": via}, None


def _diff(before: dict | None, after: dict) -> list[str]:
    old = json.dumps(before, indent=1, sort_keys=True).splitlines()
    new = json.dumps(after, indent=1, sort_keys=True).splitlines()
    return [line for line in difflib.unified_diff(old, new, "applied", "planned", lineterm="", n=0)
            if not line.startswith(("---", "+++", "@@"))]


def _check_lane(policy: RoutingPolicy, router: RouterTarget, *, private, reasons: list[Reason], warnings: list[str],
                chains: dict[str, dict], resolver, own_guids: set[str]) -> tuple[str, str | None, list[RoutingRule]]:
    """One lane against the router: capabilities, private destinations, this node's warp
    (with the lane's own fallback), and every node exit resolved into `chains`. Returns
    the lane's effective default and rules."""
    rules = [rule for rule in policy.rules if rule.enabled]
    default_action, default_egress = policy.default_action, policy.default_egress
    whole = "whole_warp" if default_action == "egress" else "whole_direct"
    if whole not in router.capabilities:
        reasons.append(Reason(code="backend_capability_missing", message=f"xray_router lacks {whole}"))
    for rule in rules:
        missing = sorted(_needed(rule) - router.capabilities)
        if missing:
            reasons.append(Reason(code="backend_capability_missing", rule_id=rule.id,
                                  message=f"xray_router lacks {', '.join(missing)}"))
            continue
        if rule.action != "block" and private(rule):
            reasons.append(Reason(code="private_destination", rule_id=rule.id,
                                  message="loopback, link-local and private networks may only be blocked"))
    for rule_id, value in [(None, default_egress), *((rule.id, rule.egress) for rule in rules)]:
        if value is None or not is_node_exit(value) or value in chains:
            continue
        chain, reason = resolve_chain(value, resolver, own_guids=own_guids)
        if reason is not None:
            reasons.append(reason.model_copy(update={"rule_id": rule_id}))
        else:
            chains[value] = chain
    uses_warp = default_egress == "warp" or any(rule.egress == "warp" for rule in rules)
    if uses_warp:
        provider = router.providers.get("warp")
        if provider is None:
            reasons.append(Reason(code="provider_unavailable", message="the node's router has no warp egress configured"))
        elif provider.get("reachable") is False:
            if policy.fallback == "approved_direct":
                warnings.append("provider_unreachable")
                if default_egress == "warp":
                    default_action, default_egress = "direct", None
                rules = [rule.model_copy(update={"action": "direct", "egress": None}) if rule.egress == "warp" else rule
                         for rule in rules]
            else:
                reasons.append(Reason(code="provider_unreachable",
                                      message="warp does not answer on the node; the policy stays fail-closed"))
    return default_action, default_egress, rules


def compile_intent(policy: RoutingPolicy, router: RouterTarget, *, private, warnings: list[str],
                   lanes: list[RoutingPolicy] | None = None, resolver=None, own_guids: set[str] | None = None) -> Compiled:
    """`private(rule)` is the compiler's own private-destination test, shared with the native
    backends; `warnings` are the target's, carried through. `lanes` (v0.7) are the other
    policies of the same service — the service's own and the grant lanes — folded into the
    one intent the router runs; `resolver` answers node exits with `ChainHop`s."""
    unsupported = Compiled(status="unsupported", backend="xray_router", compiler_version=COMPILER_VERSION,
                           runtime_version=router.xray_version, restart_required=True)
    reasons: list[Reason] = []
    every = [policy, *(other for other in (lanes or []) if other.id != policy.id)]
    service = [item for item in every if item.lane == LANE_SERVICE]
    grants = [item for item in every if item.lane != LANE_SERVICE]
    ordered = [*service, *grants]
    chains: dict[str, dict] = {}
    checked = []
    for item in ordered:
        default_action, default_egress, rules = _check_lane(
            item, router, private=private, reasons=reasons, warnings=warnings, chains=chains,
            resolver=resolver, own_guids=own_guids or {"local"})
        checked.append((item.lane, default_action, default_egress, rules))
    if reasons:
        unsupported.reasons, unsupported.warnings = reasons, warnings
        return unsupported
    schema_2 = bool(grants) or bool(chains)
    if schema_2:
        document = intent_v2(policy.protocol, checked, chains)
        limit = MAX_DOCUMENT_BYTES_V2
    else:
        _lane, default_action, _egress, rules = checked[0]
        document = intent_of(default_action, rules)
        limit = MAX_DOCUMENT_BYTES
    if len(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()) > limit:
        unsupported.reasons = [Reason(code="document_too_large", message=f"the compiled document exceeds {limit // 1024} KiB")]
        unsupported.warnings = warnings
        return unsupported
    if not schema_2 and checked[0][1] == "direct" and not checked[0][3]:
        warnings.append("policy_empty")
    applied = router.applied
    digest = document_digest(document)
    if applied is not None and applied.get("document") is None:
        diff = [] if applied.get("digest") == digest else _diff(None, document)
    else:
        diff = _diff(None if applied is None else applied["document"], document)
    return Compiled(
        status="supported", document=document, digest=digest, diff=diff, warnings=warnings, restart_required=True,
        rollback=None if applied is None else {"to_revision": applied["revision"], "to_digest": applied["digest"]},
        compiler_version=COMPILER_VERSION, backend="xray_router", runtime_version=router.xray_version,
        attach=attach_document(policy.protocol),
    )
