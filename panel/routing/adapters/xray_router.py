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

from ...protocols.base import RouterTarget
from ..document import attach_document, document_digest
from ..models import COMPILER_VERSION, Compiled, Reason, RoutingPolicy, RoutingRule

MAX_DOCUMENT_BYTES = 16384


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
    return needed


def intent_of(default_action: str, rules: list[RoutingRule]) -> dict:
    """The intent the router manager validates: the rules in order, enabled only, the
    same selector vocabulary the policy uses (`*.x` and `x` both mean the suffix there)."""
    compiled = []
    for rule in rules:
        domains = []
        for domain in rule.match.domains:
            suffix = domain[2:] if domain.startswith("*.") else domain
            if suffix not in domains:
                domains.append(suffix)
        compiled.append({"domains": domains, "geosites": list(rule.match.geosites), "cidrs": list(rule.match.cidrs),
                         "geoips": list(rule.match.geoips), "ports": list(rule.match.ports),
                         "action": rule.action, "egress": rule.egress})
    return {"schema": 1, "default": {"action": default_action, "egress": "warp" if default_action == "egress" else None},
            "rules": compiled}


def _diff(before: dict | None, after: dict) -> list[str]:
    old = json.dumps(before, indent=1, sort_keys=True).splitlines()
    new = json.dumps(after, indent=1, sort_keys=True).splitlines()
    return [line for line in difflib.unified_diff(old, new, "applied", "planned", lineterm="", n=0)
            if not line.startswith(("---", "+++", "@@"))]


def compile_intent(policy: RoutingPolicy, router: RouterTarget, *, private, warnings: list[str]) -> Compiled:
    """`private(rule)` is the compiler's own private-destination test, shared with the native
    backends; `warnings` are the target's, carried through."""
    unsupported = Compiled(status="unsupported", backend="xray_router", compiler_version=COMPILER_VERSION,
                           runtime_version=router.xray_version, restart_required=True)
    reasons: list[Reason] = []
    rules = [rule for rule in policy.rules if rule.enabled]
    default_action = policy.default_action
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
    uses_warp = default_action == "egress" or any(rule.action == "egress" for rule in rules)
    if uses_warp:
        provider = router.providers.get("warp")
        if provider is None:
            reasons.append(Reason(code="provider_unavailable", message="the node's router has no warp egress configured"))
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
    document = intent_of(default_action, rules)
    if len(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()) > MAX_DOCUMENT_BYTES:
        unsupported.reasons = [Reason(code="document_too_large", message="the compiled document exceeds 16 KiB")]
        unsupported.warnings = warnings
        return unsupported
    if default_action == "direct" and not rules:
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
