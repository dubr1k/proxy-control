"""Creating several accesses at once: every failure ends in a state an operator can act on.

Three managers, no shared transaction. The saga's promise is not that nothing fails —
it is that after any single failure the operation lands in exactly one of three declared
outcomes, that resuming it never creates a second account, and that anything the panel
did not create is never deleted while cleaning up.
"""

from __future__ import annotations

import pytest

from panel.clients.models import GrantIntent, MieruOptions, MtproxyOptions, NaiveOptions
from panel.clients.provisioning import ProvisioningService
from panel.clients.service import ClientService
from panel.database import Database
from panel.keyring import Keyring
from panel.mieru import MemoryMieru
from panel.migrations import apply_migrations
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.secrets_store import SecretStore
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio

CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}
FAULTS = [
    "before_first_apply",
    "after_apply:naive",
    "after_apply:mieru",
    "during_compensation",
    "after_manager_commit_before_response:naive",
]


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


@pytest.fixture
def provisioning(tmp_path, backends):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    secrets = SecretStore(Keyring.generate())
    adapters = {
        "mtproxy": TelemtAdapter(backends["mtproxy"]),
        "naive": NaiveAdapter(backends["naive"], public_host="naive.example.com"),
        "mieru": MieruAdapter(backends["mieru"]),
    }
    clients = ClientService(database, secrets)
    clients.adapters = adapters
    service = ProvisioningService(database, secrets, adapters, clients)
    service.client_id = clients.create_client("Sergey", **CTX).id
    return service


def _intent(protocol, username="alice"):
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(quota_bytes=None),
        "mieru": MieruOptions(quotas=[]),
    }[protocol]
    return GrantIntent(protocol=protocol, runtime_username=username, options=options)


def _grants(service):
    return service.clients.client_with_grants(service.client_id)[1]


async def test_a_clean_run_activates_every_grant_with_a_stored_credential(provisioning, backends):
    intents = [_intent("mtproxy"), _intent("naive"), _intent("mieru")]
    operation_id = await provisioning.start(provisioning.client_id, intents, **CTX)
    result = await provisioning.run(operation_id)
    assert result.status == "succeeded"
    grants = _grants(provisioning)
    assert len(grants) == 3
    assert all(grant.secret_ref is not None for grant in grants)
    assert all(grant.observed_state == "enabled" for grant in grants)
    assert list(backends["naive"].users) == ["alice"]


@pytest.mark.parametrize("fault", FAULTS)
async def test_every_fault_ends_in_a_declared_outcome_and_resumes(fault, provisioning, backends):
    # A pre-existing account the panel did not create must survive any compensation.
    backends["naive"].seed("keep", "pre-existing-password-0001")
    intents = [_intent("mtproxy"), _intent("naive"), _intent("mieru")]
    if fault.startswith("after_apply:"):
        provisioning.faults["after_apply"] = fault.split(":")[1]
    elif fault == "before_first_apply":
        provisioning.faults["before_first_apply"] = True
    elif fault == "during_compensation":
        provisioning.faults["after_apply"] = "mieru"
        provisioning.faults["during_compensation"] = True
    elif fault.startswith("after_manager_commit_before_response:"):
        backends["naive"].faults["create"] = "lose_response"

    operation_id = await provisioning.start(provisioning.client_id, intents, **CTX)
    try:
        await provisioning.run(operation_id)
    except RuntimeError:
        pass  # crashed mid-flight; a fresh process picks the journal up below
    provisioning.faults.clear()
    backends["naive"].faults.clear()

    resumed = await ProvisioningService(
        provisioning.database, provisioning.secrets, provisioning.adapters, provisioning.clients
    ).run(operation_id)
    assert resumed.status in {"succeeded", "compensated", "manual_intervention_required"}
    # Whatever happened, the account nobody asked us to touch is still there.
    assert "keep" in backends["naive"].users

    if resumed.status == "succeeded":
        assert [row["username"] for row in await backends["naive"].list_users()].count("alice") == 1
        assert all(grant.secret_ref is not None for grant in _grants(provisioning))
    if resumed.status == "compensated":
        assert "alice" not in backends["naive"].users
        assert "alice" not in backends["mieru"].users
        with provisioning.database.connect() as db:
            rows = provisioning.clients.store.grants(db, client_id=provisioning.client_id, include_deleted=True)
        assert all(grant.desired_state == "deleted" for grant in rows)


async def test_compensation_never_deletes_what_the_operation_did_not_create(provisioning, backends):
    backends["naive"].seed("keep", "pre-existing-password-0001")
    provisioning.faults["after_apply"] = "naive"
    operation_id = await provisioning.start(
        provisioning.client_id, [_intent("naive"), _intent("mieru")], **CTX
    )
    result = await provisioning.run(operation_id)
    assert result.status == "compensated"
    assert list(backends["naive"].users) == ["keep"]


async def test_resuming_a_finished_operation_changes_nothing(provisioning, backends):
    operation_id = await provisioning.start(provisioning.client_id, [_intent("naive")], **CTX)
    first = await provisioning.run(operation_id)
    assert first.status == "succeeded"
    password = backends["naive"].users["alice"]["password"]
    again = await provisioning.run(operation_id)
    assert again.status == "succeeded"
    assert backends["naive"].users["alice"]["password"] == password
    assert len(_grants(provisioning)) == 1


async def test_a_refused_preflight_reserves_nothing(provisioning, backends):
    from panel.clients.store import ClientConflict

    await backends["naive"].create("alice")
    with pytest.raises(ClientConflict, match="already"):
        await provisioning.start(provisioning.client_id, [_intent("naive"), _intent("mieru")], **CTX)
    assert _grants(provisioning) == []
    with provisioning.database.connect() as db:
        assert db.execute("SELECT count(*) FROM provisioning_operations").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM secret_versions").fetchone()[0] == 0


async def test_the_operation_status_is_readable_while_it_runs(provisioning):
    operation_id = await provisioning.start(provisioning.client_id, [_intent("naive")], **CTX)
    pending = provisioning.status(operation_id)
    assert pending["status"] == "pending"
    assert [step["protocol"] for step in pending["steps"]] == ["naive"]
    await provisioning.run(operation_id)
    assert provisioning.status(operation_id)["status"] == "succeeded"


async def test_the_bundle_carries_every_artifact_of_the_operation(provisioning):
    operation_id = await provisioning.start(
        provisioning.client_id, [_intent("mtproxy"), _intent("naive")], **CTX
    )
    assert (await provisioning.run(operation_id)).status == "succeeded"
    bundle = provisioning.bundle(operation_id, public_hosts={"mtproxy": "p.example.com", "naive": "n.example.com"})
    assert {item["protocol"] for item in bundle["grants"]} == {"mtproxy", "naive"}
    for item in bundle["grants"]:
        assert item["artifacts"] and all(artifact["value"] for artifact in item["artifacts"])
