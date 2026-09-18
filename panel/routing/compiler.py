"""Policy → compiled document, per backend, with every limitation said out loud.

The compiler never substitutes a backend and never quietly narrows a rule: whatever
the backend cannot enforce comes back as `unsupported` with the rule it concerns, so
the preview is the truth the operator applies. What a backend *can* do is what its
manager declares in `capabilities` (proved by the spike, `docs/spikes/
VNEXT_ROUTING_ENGINE.md`), plus the constraints that no capability flag can express:

- `naive_native` — one `upstream` per service, and forwardproxy skips its ACL when an
  upstream is set, so a block rule beside a WARP default cannot hold; block by port is
  not a deny in either engine.
- `mieru_native` — mita matches `domainNames` as a suffix, so `example.com` and
  `*.example.com` compile to the same selector; a wildcard-free block still covers the
  subdomains there.

Private destinations (loopback, link-local, RFC 1918) may be blocked but never opened
by a `direct`/`egress` rule (spec §10): Caddy denies them by default, mita must not hand
a client the node's loopback.
"""
from __future__ import annotations

import difflib
import ipaddress
import json

from ..protocols.base import EgressTarget, RouterTarget
from .adapters.xray_router import ChainHop, compile_intent
from .document import ROUTER_DIRECT_INTENT, canonical, document_digest
from .models import (
    BACKEND_FOR,
    COMPILER_VERSION,
    LANE_SERVICE,
    Compiled,
    Reason,
    RoutingPolicy,
    RoutingRule,
    exit_hops,
    is_node_exit,
)

__all__ = ["ChainHop", "compile", "direct_document", "explain"]

MAX_DOCUMENT_BYTES = 16384
# forwardproxy takes at most this many subjects per `deny` line (naive_manager/egress.py).
ACL_SUBJECTS_PER_LINE = 64
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
))
PRIVATE_DOMAINS = ("localhost", "*.localhost")
_ACTION_MITA = {"direct": "DIRECT", "block": "REJECT", "egress": "PROXY"}


def _private(rule: RoutingRule) -> bool:
    if any(domain in PRIVATE_DOMAINS for domain in rule.match.domains):
        return True
    for cidr in rule.match.cidrs:
        network = ipaddress.ip_network(cidr)
        if any(network.version == private.version and network.overlaps(private) for private in PRIVATE_NETWORKS):
            return True
    return False


def _needed(rule: RoutingRule) -> set[str]:
    kind = "block" if rule.action == "block" else "selective"
    needed = set()
    if rule.match.domains:
        needed.add(f"{kind}_domain")
    if rule.match.cidrs:
        needed.add(f"{kind}_cidr")
    return needed


def _diff(before: dict | None, after: dict) -> list[str]:
    old = json.dumps(before, indent=1, sort_keys=True).splitlines()
    new = json.dumps(after, indent=1, sort_keys=True).splitlines()
    return [line for line in difflib.unified_diff(old, new, "applied", "planned", lineterm="", n=0)
            if not line.startswith(("---", "+++", "@@"))]


def _naive_document(default_action: str, rules: list[RoutingRule]) -> dict:
    subjects = [item for rule in rules for item in (*rule.match.domains, *rule.match.cidrs)]
    acl = [{"deny": subjects[i:i + ACL_SUBJECTS_PER_LINE]} for i in range(0, len(subjects), ACL_SUBJECTS_PER_LINE)]
    return {"schema": 1, "upstream": {"provider": "warp"} if default_action == "egress" else None, "acl": acl}


def direct_document(backend: str) -> dict:
    """What «reset» applies: the whole service direct, no rules — the state a policy may be
    deleted in (spec §8.1). On the router (v0.5) that is the pass-through intent."""
    if backend == "xray_router":
        return json.loads(json.dumps(ROUTER_DIRECT_INTENT))
    return (_naive_document if backend == "naive_native" else _mieru_document)("direct", [])


def _mieru_document(default_action: str, rules: list[RoutingRule]) -> dict:
    compiled = []
    for rule in rules:
        domains = []
        for domain in rule.match.domains:
            suffix = domain[2:] if domain.startswith("*.") else domain
            if suffix not in domains:
                domains.append(suffix)
        compiled.append({"domains": domains, "cidrs": list(rule.match.cidrs), "action": _ACTION_MITA[rule.action],
                         "proxy": "warp" if rule.action == "egress" else None})
    if default_action == "egress":
        compiled.append({"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"})
    uses_warp = any(rule["action"] == "PROXY" for rule in compiled)
    return {"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}] if uses_warp else [], "rules": compiled}


def compile(policy: RoutingPolicy, target: EgressTarget | None, *, node_egress_v1: bool = True,  # noqa: A001
            router: RouterTarget | None = None, lanes: list[RoutingPolicy] | None = None, chains=None,
            own_guids: set[str] | None = None) -> Compiled:
    """What the node would run for this policy, or exactly why it cannot. `target` is the
    service's native manager; `router` its section on the node's Xray-router (v0.5), None
    when the panel knows of no router. `lanes` (v0.7) are the service's other policies —
    its own and the grant lanes — the router runs as one intent; `chains` resolves a node
    exit's guid into a `ChainHop` or a `Reason`; `own_guids` name this node (a loop)."""
    backend = BACKEND_FOR.get(policy.protocol)
    unsupported = Compiled(status="unsupported", backend=policy.backend, compiler_version=COMPILER_VERSION,
                           runtime_version=None if target is None else target.runtime_version)
    if backend is None:
        unsupported.reasons.append(Reason(code="protocol_out_of_scope", message=f"{policy.protocol} has no egress"))
        return unsupported
    if not node_egress_v1:
        unsupported.reasons.append(Reason(code="node_lacks_egress_v1", message="the node must be updated to v0.4"))
        return unsupported
    if target is None:
        unsupported.reasons.append(Reason(code="protocol_disabled_on_node",
                                          message=f"{policy.protocol} reports no egress target on this node"))
        return unsupported
    is_lane = policy.lane != LANE_SERVICE or any(other.lane != LANE_SERVICE for other in (lanes or []))
    if is_lane and (router is None or not router.available):
        unsupported.reasons.append(Reason(code="lane_requires_router",
                                          message="a client lane runs only on the node's Xray-router"))
        return unsupported
    if policy.backend == "xray_router":
        if router is None or not router.available:
            code = "router_unavailable" if router is None or router.reason in (None, "router_unavailable") else router.reason
            unsupported.reasons.append(Reason(code=code, message="the node has no Xray-router to run this policy"))
            return unsupported
        if not target.router_attached:
            code = "lane_not_attached" if is_lane else "not_attached"
            unsupported.reasons.append(Reason(code=code,
                                              message=f"{policy.protocol} is not attached to the node's Xray-router"))
            return unsupported
        return compile_intent(policy, router, private=_private, warnings=list(target.warnings), lanes=lanes,
                              resolver=chains, own_guids=own_guids)
    if is_lane:
        unsupported.reasons.append(Reason(code="lane_requires_router",
                                          message="a client lane runs only on the node's Xray-router"))
        return unsupported
    if policy.backend != target.backend:
        unsupported.reasons.append(Reason(code="backend_capability_missing",
                                          message=f"the node runs {target.backend}, the policy targets {policy.backend}"))
        return unsupported
    if target.router_attached:
        unsupported.reasons.append(Reason(code="backend_capability_missing",
                                          message=f"{policy.protocol} is attached to the node's Xray-router: "
                                                  "the policy must target xray_router"))
        return unsupported

    reasons: list[Reason] = []
    warnings: list[str] = list(target.warnings)
    rules = [rule for rule in policy.rules if rule.enabled]
    default_action = policy.default_action
    whole = "whole_warp" if default_action == "egress" else "whole_direct"
    if whole not in target.capabilities:
        reasons.append(Reason(code="backend_capability_missing", message=f"{target.backend} lacks {whole}"))
    if is_node_exit(policy.default_egress):
        reasons.append(Reason(code="rule_kind_unsupported",
                              message="an exit through another node is enforced only by xray_router"))
    for rule in rules:
        if is_node_exit(rule.egress):
            reasons.append(Reason(code="rule_kind_unsupported", rule_id=rule.id,
                                  message="an exit through another node is enforced only by xray_router"))
            continue
        if rule.match.ports or rule.match.geosites or rule.match.geoips or rule.match.protocols:
            reasons.append(Reason(code="rule_kind_unsupported", rule_id=rule.id,
                                  message="matching by port, geosite, geoip or protocol is enforced only by xray_router"))
            continue
        missing = sorted(_needed(rule) - target.capabilities)
        if missing:
            reasons.append(Reason(code="backend_capability_missing", rule_id=rule.id,
                                  message=f"{target.backend} lacks {', '.join(missing)}"))
            continue
        if rule.action != "block" and _private(rule):
            reasons.append(Reason(code="private_destination", rule_id=rule.id,
                                  message="loopback, link-local and private networks may only be blocked"))
            continue
        if target.backend == "naive_native" and rule.action == "block" and default_action == "egress":
            reasons.append(Reason(code="rule_kind_unsupported", rule_id=rule.id,
                                  message="forwardproxy does not enforce a block beside an upstream: "
                                          "naive_native cannot block while the whole service goes through warp"))

    uses_warp = default_action == "egress" or any(rule.action == "egress" for rule in rules)
    if uses_warp:
        provider = target.providers.get("warp")
        if provider is None:
            reasons.append(Reason(code="provider_unavailable", message="the node has no warp egress configured"))
        elif provider.get("reachable") is False:
            if policy.fallback == "approved_direct":
                warnings.append("provider_unreachable")
                default_action = "direct"
                rules = [rule.model_copy(update={"action": "direct", "egress": None}) if rule.action == "egress" else rule
                         for rule in rules]
            else:
                reasons.append(Reason(code="provider_unreachable",
                                      message="warp does not answer on the node; the policy stays fail-closed"))
    if reasons:
        unsupported.reasons, unsupported.warnings = reasons, warnings
        return unsupported

    document = (_naive_document if target.backend == "naive_native" else _mieru_document)(default_action, rules)
    if len(canonical(document)) > MAX_DOCUMENT_BYTES:
        unsupported.reasons = [Reason(code="document_too_large", message="the compiled document exceeds 16 KiB")]
        unsupported.warnings = warnings
        return unsupported
    if default_action == "direct" and not rules:
        warnings.append("policy_empty")
    applied = target.applied
    digest = document_digest(document)
    if applied is not None and applied.get("document") is None:
        # A linked panel reports only the digest of what it runs: same digest, no change to
        # show; otherwise the whole planned document is the diff.
        diff = [] if applied.get("digest") == digest else _diff(None, document)
    else:
        diff = _diff(None if applied is None else applied["document"], document)
    return Compiled(
        status="supported", reasons=[], warnings=warnings, document=document, digest=digest, diff=diff,
        restart_required=target.restart_required,
        rollback=None if applied is None else {"to_revision": applied["revision"], "to_digest": applied["digest"]},
        compiler_version=COMPILER_VERSION, backend=target.backend, runtime_version=target.runtime_version,
    )


def _port_matches(ports: list[int | str], port: int) -> bool:
    for item in ports:
        if isinstance(item, int):
            if item == port:
                return True
        else:
            low, high = item.split("-")
            if int(low) <= port <= int(high):
                return True
    return False


def _destination_matches(rule: RoutingRule, host: str, port: int) -> bool | None:
    """True/False when the rule's selectors decide on their own; None when only geodata
    (`geosite`/`geoip`) could say — the panel has no geodata, the router has."""
    match = rule.match
    if match.ports and not _port_matches(match.ports, port):
        return False
    address = None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    named = False
    if match.domains:
        lowered = host.lower().rstrip(".")
        for domain in match.domains:
            suffix = domain[2:] if domain.startswith("*.") else domain
            if lowered == suffix or lowered.endswith("." + suffix):
                named = True
    if match.cidrs and address is not None:
        for cidr in match.cidrs:
            network = ipaddress.ip_network(cidr)
            if network.version == address.version and address in network:
                named = True
    if named:
        return True
    if match.geosites or match.geoips or match.protocols:
        return None  # only the router sees the geodata and the sniffed protocol
    if not match.domains and not match.cidrs:
        return True  # a rule on ports alone, and the port matched
    return False


def explain(policy: RoutingPolicy, host: str, port: int) -> dict:
    """The path a destination takes through one lane's rules: the first rule that decides
    it, the lane's default otherwise, and the rules before it that only geodata could
    match (`uncertain`) — what the screen shows for «куда пойдёт этот домен»."""
    uncertain: list[str] = []
    winner: RoutingRule | None = None
    for rule in policy.rules:
        if not rule.enabled:
            continue
        verdict = _destination_matches(rule, host, port)
        if verdict is None:
            uncertain.append(rule.id or "")
        elif verdict:
            winner = rule
            break
    action = winner.action if winner else policy.default_action
    value = winner.egress if winner else policy.default_egress
    hops, via = exit_hops(value)
    return {"lane": policy.lane, "rule_id": winner.id if winner else None, "action": action, "exit": value,
            "hops": hops, "via": via, "uncertain": uncertain}
