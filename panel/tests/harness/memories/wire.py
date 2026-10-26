"""Wire fixture vocabulary shared by the manager doubles."""
from __future__ import annotations

import hashlib
import json

EGRESS_REASON_CODES = frozenset({
    "egress_conflict", "egress_invalid", "egress_unreachable", "egress_readback_mismatch",
    "manual_intervention_required", "egress_no_previous", "geosite_unknown", "geoip_unknown",
    "artifact_mismatch", "lane_unknown", "lanes_invalid", "lane_slots_exhausted", "relay_disabled",
})
ROUTER_DIRECT_INTENT = {"schema": 1, "default": {"action": "direct", "egress": None}, "rules": []}


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document_digest(document: dict) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()
