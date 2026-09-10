"""One contract, three data planes — and the places where they honestly differ.

The same lifecycle runs against every adapter. Where the protocols really differ, the
test asserts the difference (`credential_origin`, `capture_supported`) instead of
letting a uniform interface paper over it.
"""

from __future__ import annotations

import pytest

from panel.clients.models import (
    AccessGrant,
    GrantIntent,
    MieruOptions,
    MtproxyOptions,
    NaiveOptions,
)
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import (
    CredentialPlan,
    GrantRef,
    ManualInterventionRequired,
    MieruAdapter,
    NaiveAdapter,
    TelemtAdapter,
)
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def backends():
    return {
        "mtproxy": MemoryTelemt(public_host="proxy.example.com", public_port=443),
        "naive": MemoryNaive(),
        "mieru": MemoryMieru(),
    }


@pytest.fixture(params=["mtproxy", "naive", "mieru"])
def adapter(request, backends):
    return {
        "mtproxy": lambda: TelemtAdapter(backends["mtproxy"], public_host="proxy.example.com"),
        "naive": lambda: NaiveAdapter(backends["naive"], public_host="naive.example.com"),
        "mieru": lambda: MieruAdapter(backends["mieru"], public_host="mieru.example.com"),
    }[request.param]()


def _intent(protocol, username="alice"):
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(quota_bytes=None),
        "mieru": MieruOptions(quotas=[], share_template=None),
    }[protocol]
    return GrantIntent(protocol=protocol, runtime_username=username, options=options)


def _credential(adapter, password=b"caller-supplied-password-01"):
    if adapter.credential_origin == "manager":
        return CredentialPlan("manager", None)
    return CredentialPlan("caller", password)


def _grant_row(protocol, applied, username="alice"):
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(),
        "mieru": MieruOptions(quotas=[], share_template=applied.artifact_template.get("share_template")),
    }[protocol]
    return AccessGrant(
        id="g1", client_id="c1", protocol=protocol, node_id="local", endpoint_id="default",
        runtime_username=username, desired_state="enabled", options=options,
        origin="provisioned", created_at=1, updated_at=1,
    )


async def test_full_lifecycle_matches_the_capability_matrix(adapter):
    assert (await adapter.preflight(_intent(adapter.protocol))).ok
    applied = await adapter.create("op-1", _intent(adapter.protocol), _credential(adapter))
    assert applied.enabled and applied.credential and applied.recovered is False

    disabled = await adapter.disable(GrantRef(adapter.protocol, "alice", applied.revision))
    assert disabled.enabled is False
    enabled = await adapter.enable(GrantRef(adapter.protocol, "alice", disabled.revision))
    assert enabled.enabled is True

    rotated = await adapter.rotate(
        "op-2",
        GrantRef(adapter.protocol, "alice", enabled.revision),
        _credential(adapter, b"rotated-password-0123456"),
    )
    assert rotated.credential and rotated.credential != applied.credential

    captured = await adapter.capture(GrantRef(adapter.protocol, "alice", rotated.revision))
    if adapter.capture_supported:
        assert captured == rotated.credential
    else:
        # Saying "no" is the honest answer: mita keeps a hash, not the password.
        assert captured is None

    artifacts = adapter.render_artifacts(
        _grant_row(adapter.protocol, rotated), rotated.credential, public_host="x.example.com"
    )
    assert artifacts
    assert all(rotated.credential.decode() in item.value for item in artifacts)
    # Where the panel learned the shape from the runtime, that host is authoritative:
    # mita serves `mieru.example.com` and the caller cannot rename it from here.
    expected_host = "mieru.example.com" if adapter.protocol == "mieru" else "x.example.com"
    assert all(expected_host in item.value for item in artifacts)

    await adapter.delete(GrantRef(adapter.protocol, "alice", rotated.revision))
    assert all(item.runtime_username != "alice" for item in (await adapter.discover()).items)


async def test_preflight_refuses_a_username_the_runtime_already_uses(adapter):
    await adapter.create("op-1", _intent(adapter.protocol), _credential(adapter))
    refused = await adapter.preflight(_intent(adapter.protocol))
    assert refused.ok is False and "already" in refused.reason


async def test_lost_response_after_manager_commit_never_creates_a_second_user(adapter, backends):
    backends[adapter.protocol].faults["create"] = "lose_response"
    applied = await adapter.create("op-1", _intent(adapter.protocol), _credential(adapter))
    assert applied.recovered is True and applied.credential
    inventory = await adapter.discover()
    assert [item.runtime_username for item in inventory.items].count("alice") == 1


async def test_a_credential_plan_must_match_the_protocol(adapter):
    wrong = (
        CredentialPlan("caller", b"caller-supplied-password-01")
        if adapter.credential_origin == "manager"
        else CredentialPlan("manager", None)
    )
    with pytest.raises(Exception):
        await adapter.create("op-1", _intent(adapter.protocol), wrong)


async def test_manager_generated_mieru_credential_lost_requires_manual_intervention(backends):
    """Mieru refuses to replay a password it never stored, so a human must decide."""
    mieru = backends["mieru"]
    adapter = MieruAdapter(mieru, public_host="mieru.example.com")
    await mieru.create({
        "username": "alice", "quotas": [], "expected_revision": mieru.revision, "operation_id": "op-1",
    })
    mieru.faults["create"] = "lose_response"
    with pytest.raises(ManualInterventionRequired):
        await adapter.create(
            "op-1", _intent("mieru"), CredentialPlan("caller", b"caller-supplied-password-01")
        )


# --- Step 4/4a: making an imported grant renderable ------------------------------


@pytest.fixture
def adopted(tmp_path, backends):
    from panel.clients.service import ClientService
    from panel.database import Database
    from panel.keyring import Keyring
    from panel.migrations import apply_migrations
    from panel.secrets_store import SecretStore

    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    service = ClientService(database, SecretStore(Keyring.generate()))
    service.adapters = {
        "mtproxy": TelemtAdapter(backends["mtproxy"]),
        "naive": NaiveAdapter(backends["naive"], public_host="naive.example.com"),
        "mieru": MieruAdapter(backends["mieru"]),
    }
    return service


CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}


async def _imported(service, backends, protocol, username="alice"):
    """Seed a runtime account the panel did not create, then adopt it as a grant."""
    import time
    import uuid

    if protocol == "mtproxy":
        await backends["mtproxy"].create_user(username)
        options = MtproxyOptions()
    elif protocol == "naive":
        await backends["naive"].create(username)
        options = NaiveOptions()
    else:
        mieru = backends["mieru"]
        await mieru.create({"username": username, "quotas": [], "expected_revision": mieru.revision})
        options = MieruOptions(quotas=[])
    client = service.create_client("Sergey", **CTX)
    now = int(time.time())
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id=client.id, protocol=protocol, node_id="local",
        endpoint_id="default", runtime_username=username, desired_state="enabled",
        observed_state="enabled", options=options, origin="imported", created_at=now, updated_at=now,
    )
    with service.database.transaction() as db:
        service.store.insert_grant(db, grant)
    return grant


async def test_capture_fills_the_secret_reference_without_touching_the_manager(adopted, backends):
    for protocol in ("mtproxy", "naive"):
        grant = await _imported(adopted, backends, protocol, username=f"{protocol}-user")
        before = await adopted.adapters[protocol].capture(
            GrantRef(protocol, grant.runtime_username)
        )
        result = await adopted.capture_credential(grant.id, **CTX)
        assert result.secret_ref is not None
        with adopted.database.connect() as db:
            stored = adopted.store.grant(db, grant.id)
        assert stored.secret_ref == result.secret_ref
        # Capture is a read: the runtime credential is unchanged.
        after = await adopted.adapters[protocol].capture(GrantRef(protocol, grant.runtime_username))
        assert after == before


async def test_mieru_cannot_be_captured_and_says_so(adopted, backends):
    from panel.clients.store import ClientConflict

    grant = await _imported(adopted, backends, "mieru")
    with pytest.raises(ClientConflict, match="rotation"):
        await adopted.capture_credential(grant.id, **CTX)
    with pytest.raises(ClientConflict, match="rotation"):
        await adopted.adopt_credential(grant.id, allow_rotation=False, **CTX)
    with adopted.database.connect() as db:
        assert adopted.store.grant(db, grant.id).secret_ref is None


async def test_adopting_mieru_with_rotation_replaces_the_credential_exactly_once(adopted, backends):
    from panel.clients.store import ClientConflict

    grant = await _imported(adopted, backends, "mieru")
    revision_before = backends["mieru"].revision
    result = await adopted.adopt_credential(grant.id, allow_rotation=True, **CTX)
    assert result.secret_ref is not None
    assert backends["mieru"].revision != revision_before
    with adopted.database.connect() as db:
        plaintext = adopted.secrets.reveal(
            db, result.secret_ref, purpose="grant.credential",
            grant_id=grant.id, permitted_node_id="local",
        )
    assert plaintext
    # A second adoption is refused: the grant already has a credential.
    with pytest.raises(ClientConflict, match="already"):
        await adopted.adopt_credential(grant.id, allow_rotation=True, **CTX)


@pytest.mark.parametrize(
    ("protocol", "allow_rotation", "action", "rotated"),
    [
        # Adopting a protocol the panel can read back is a capture, not a rotation:
        # the subscriber's current link keeps working.
        ("naive", False, "grant.credential.capture", False),
        ("mieru", True, "grant.credential.adopt", True),
    ],
)
async def test_adoption_records_what_happened_and_never_the_credential(
    adopted, backends, protocol, allow_rotation, action, rotated
):
    grant = await _imported(adopted, backends, protocol)
    result = await adopted.adopt_credential(grant.id, allow_rotation=allow_rotation, **CTX)
    with adopted.database.connect() as db:
        plaintext = adopted.secrets.reveal(
            db, result.secret_ref, purpose="grant.credential",
            grant_id=grant.id, permitted_node_id="local",
        )
        rows = [dict(row) for row in db.execute("SELECT * FROM audit_log WHERE target=?", (grant.id,))]
    assert [row["action"] for row in rows] == [action]
    assert f'"rotated": {str(rotated).lower()}' in rows[0]["detail_json"]
    assert plaintext.decode() not in str(rows)
