"""`manifest`: the canonical JSON — the panel's own contract, for the panel, CLI and tools.

Everything the other formats derive from is here in one place: each grant as the
manifest describes it, the artifacts rendered for it, the reason it has none, and the
compatibility matrix that says which client can auto-refresh which protocol. The token
and the secret reference are not part of it; `secret_version` is the only trace of the
credential, and it is a number.
"""
from __future__ import annotations

import dataclasses
import json

from ..compatibility import MATRIX
from ..models import Manifest
from .base import MEDIA_TYPE_MANIFEST, check, credential_reason, finish


class ManifestRenderer:
    name = "manifest"
    media_type = MEDIA_TYPE_MANIFEST
    version = 1

    def render(self, manifest: Manifest, artifacts: dict) -> bytes:
        check(manifest)
        grants = []
        for grant in manifest.grants:
            reason = credential_reason(grant, artifacts) if grant.enabled else None
            grants.append({
                **dataclasses.asdict(grant),
                "artifacts": [
                    dataclasses.asdict(artifact) for artifact in artifacts.get(grant.grant_id, [])
                ] if grant.enabled else [],
                "unsupported": reason,
            })
        payload = {
            "version": manifest.version,
            "client_id": manifest.client_id,
            "client_name": manifest.client_name,
            "generation": manifest.generation,
            "grants": grants,
            "compatibility": MATRIX,
        }
        return finish(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n")
