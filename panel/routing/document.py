"""The compiled egress document as the panel and both managers see it (v0.4 routing).

`document_digest` is the one canonical form the panel, the naive-manager and the
mieru-manager all hash — `json.dumps(sort_keys=True, compact, ascii)` — so a policy
revision on the central, the `applied_digest` a node reports and the manager's journal
entry compare by the same bytes on every host.
"""
from __future__ import annotations

import hashlib
import json

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
})


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document_digest(document: dict) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()
