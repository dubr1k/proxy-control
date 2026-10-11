"""One safe, node-first display name across subscription formats.

Only presentation changes: usernames, endpoints and credentials remain untouched.
The whole manifest participates (including disabled grants), so toggling a sibling
cannot rename the selected profile. Stable suffixes resolve duplicate node labels
and multiple accesses to the same protocol on one node, independent of row order.
"""
from __future__ import annotations

import hashlib
import unicodedata
from collections import Counter

from .models import Manifest

PROTOCOL_TITLES = {"mtproxy": "MTProxy", "naive": "Naive", "mieru": "Mieru"}


def display_text(value: str) -> str:
    # Drop invisible/bidi controls, fold whitespace, and keep names compatible
    # with the deliberately restricted single-quoted Clash YAML writer.
    value = unicodedata.normalize("NFC", value)
    value = "".join(char if char.isprintable() else " " for char in value)
    return " ".join(value.split()).replace("'", "’")[:64].strip()


def grant_names(manifest: Manifest) -> dict[str, str]:
    bases = {}
    for grant in manifest.grants:
        node = display_text(grant.node_name) or display_text(grant.node_id) or "Local"
        bases[grant.grant_id] = f"{node} · {PROTOCOL_TITLES.get(grant.protocol, grant.protocol)}"
    counts = Counter(bases.values())
    # Reserve all literal names first, including names that look like a suffix.
    used = set(bases.values())
    result = {}
    for grant_id, base in sorted(bases.items()):
        if counts[base] == 1:
            result[grant_id] = base
            continue
        digest = hashlib.sha256(grant_id.encode()).hexdigest()
        width = 8
        candidate = f"{base} [{digest[:width]}]"
        while candidate in used:
            width += 1
            if width > len(digest):
                raise ValueError("subscription display name collision")
            candidate = f"{base} [{digest[:width]}]"
        used.add(candidate)
        result[grant_id] = candidate
    return result
