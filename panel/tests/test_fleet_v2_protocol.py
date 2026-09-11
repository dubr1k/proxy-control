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


def test_digest_is_order_independent_and_secret_free():
    one = _doc()
    two = _doc(resources=list(reversed(one.resources + [Resource(
        ref="grant:b", protocol="mieru", runtime_username="bob", desired_state="disabled",
        credential_ref="grant:b:2", credential_origin="caller", options={"quotas": []})])))
    assert canonical_digest(one) != canonical_digest(two)
    assert canonical_digest(two) == canonical_digest(_doc(resources=two.resources[::-1]))
    assert "secret" not in json.dumps(one.model_dump())


def test_unknown_protocol_state_or_extra_field_is_refused():
    with pytest.raises(ValidationError):
        Resource(ref="x", protocol="xray", runtime_username="a", desired_state="enabled",
                 credential_ref="x:1", credential_origin="caller")
    with pytest.raises(ValidationError):
        Resource(ref="x", protocol="naive", runtime_username="a", desired_state="paused",
                 credential_ref="x:1", credential_origin="caller")
    with pytest.raises(ValidationError):
        PushRequest(expected_guid="g", generation=_doc(), secrets={}, shell="rm -rf /")


def test_push_secrets_must_reference_document_refs():
    with pytest.raises(ValidationError):
        PushRequest(expected_guid="n" * 36, generation=_doc(), secrets={"grant:zzz:1": "pw"})
    ok = PushRequest(expected_guid="n" * 36, generation=_doc(), secrets={"grant:a:1": "pw"})
    assert ok.secrets["grant:a:1"] == "pw"
