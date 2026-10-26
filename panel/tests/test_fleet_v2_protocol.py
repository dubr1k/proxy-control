import json

import pytest
from pydantic import ValidationError

from panel.fleet_v2.protocol import GenerationDocument, PushRequest, Resource, canonical_digest


def _doc(**overrides):
    base = dict(node_guid="n" * 36, master_guid="m" * 36, generation=3, previous_generation=2,
                created_at=1, created_by="owner", resources=[Resource(
                    ref="grant:a", protocol="naive", runtime_username="alice", desired_state="enabled",
                    credential_ref="grant:a:1", credential_origin="caller", options={"quota_bytes": 5})])
    base.update(overrides)
    return GenerationDocument(**base)





















