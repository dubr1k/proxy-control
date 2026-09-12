"""Creating several accesses as one operation, with a journal that survives a crash.

Three managers cannot share a transaction, so "all or nothing" is not available. What
is available is a written-down journal: every step records what it reached before the
next one runs, so a restart resumes instead of repeating, and a failure compensates
only what this operation actually created.

Every run ends in exactly one of three outcomes — `succeeded`, `compensated`, or
`manual_intervention_required`. The last one is not a failure to handle later: it means
the runtime changed in a way the panel cannot undo safely, and it names the operation so
a person can finish the job.

A grant on a linked panel (spec §6) has no manager here to call: its step is `remote`,
the operation waits as `pending_remote`, and the fleet pusher finishes the step from
what the node reports (`remote_applied`).
"""
from __future__ import annotations

import json
import secrets as secret_tokens
import time
import uuid
from dataclasses import dataclass, field

from ..audit import record
from ..fleet_v2.managed import ManagedStore
from ..fleet_v2.protocol import ObservedGeneration
from ..protocols.base import (
    AdapterError,
    CredentialPlan,
    GrantRef,
    ManualInterventionRequired,
)
from ..secrets_store import SecretRef
from .models import AccessGrant, GrantIntent
from .service import CREDENTIAL_PURPOSE, ClientService
from .store import ClientConflict

TERMINAL = ("succeeded", "compensated", "manual_intervention_required")
# A step never skips backwards: each transition is its own durable checkpoint.
CREATED = ("applied", "escrowed", "active")
# Steps `run()` has nothing to do for: finished, or waiting for a linked panel.
SETTLED = ("active", "remote")


def new_credential(protocol: str) -> bytes:
    """Telemt wants 32 hex characters; a runtime handed anything else falls back to a
    secret of its own choosing and the panel has to escrow that instead. One rule for
    every credential the central chooses — at provisioning and at every rotation."""
    return (secret_tokens.token_hex(16) if protocol == "mtproxy" else secret_tokens.token_urlsafe(24)).encode()


def is_remote_node(db, node_id: str) -> bool:
    """A grant on a linked panel is applied by that panel's reconcile, not by a manager here."""
    row = db.execute("SELECT transport FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()
    return row is not None and row["transport"] == "panel"


@dataclass(frozen=True)
class StepResult:
    grant_id: str
    protocol: str
    status: str
    error: str | None = None


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    status: str
    steps: list[StepResult] = field(default_factory=list)


class ProvisioningService:
    def __init__(self, database, secret_store, adapters: dict, clients: ClientService, clock=time,
                 managed: ManagedStore | None = None):
        self.database = database
        self.secrets = secret_store
        self.adapters = adapters
        self.clients = clients
        self.clock = clock
        # Runtime users the central panel owns (ADR 003) are never provisioned over.
        self.managed = managed or ManagedStore(database)
        # Test hook only: production leaves this empty and never reads a fault from it.
        self.faults: dict = {}

    # --- journal -----------------------------------------------------------------

    def _operation(self, db, operation_id: str) -> dict:
        row = db.execute(
            "SELECT * FROM provisioning_operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise KeyError(operation_id)
        return {**dict(row), "steps": json.loads(row["steps_json"])}

    def _write(self, db, operation_id: str, *, status: str, steps: list[dict]) -> None:
        db.execute(
            "UPDATE provisioning_operations SET status=?,steps_json=?,updated_at=? WHERE operation_id=?",
            (status, json.dumps(steps, sort_keys=True), int(self.clock.time()), operation_id),
        )

    def _mark_step(self, operation_id: str, grant_id: str, status: str, error: str | None = None) -> None:
        """One durable checkpoint per transition, in its own transaction."""
        with self.database.transaction() as db:
            operation = self._operation(db, operation_id)
            for step in operation["steps"]:
                if step["grant_id"] == grant_id:
                    step["status"] = status
                    step["error"] = error
            self._write(db, operation_id, status=operation["status"], steps=operation["steps"])

    def _mark_operation(self, operation_id: str, status: str) -> None:
        with self.database.transaction() as db:
            operation = self._operation(db, operation_id)
            self._write(db, operation_id, status=status, steps=operation["steps"])

    def status(self, operation_id: str) -> dict:
        with self.database.connect() as db:
            operation = self._operation(db, operation_id)
        return {
            "operation_id": operation_id,
            "client_id": operation["client_id"],
            "status": operation["status"],
            "steps": operation["steps"],
        }

    # --- start -------------------------------------------------------------------

    def _adapter(self, protocol: str):
        adapter = self.adapters.get(protocol)
        if adapter is None:
            raise ClientConflict(f"no adapter is configured for {protocol}")
        return adapter

    async def start(
        self, client_id: str, intents: list[GrantIntent], *, actor: dict, ip: str, request_id: str | None = None
    ) -> str:
        """Reserve every row of the operation, or none of them.

        Preflight asks each runtime whether the username is free before anything is
        written, which is why this is async: refusing here costs nothing, while
        refusing halfway through would leave accounts to compensate. A grant on a
        linked panel skips it — the node answers through its generation instead — and
        is reserved together with its credential and the generation that carries it.
        """
        if not intents:
            raise ClientConflict("an operation needs at least one grant")
        with self.database.connect() as db:
            remote = {intent.node_id for intent in intents if is_remote_node(db, intent.node_id)}
            for intent in intents:
                if intent.node_id != "local" and intent.node_id not in remote:
                    # Neither this runtime nor a linked panel: nothing here could apply it.
                    raise ClientConflict(f"node {intent.node_id} is not a linked panel")
                if intent.node_id == "local" and self.managed.is_managed(db, intent.protocol, intent.runtime_username):
                    raise ClientConflict(f"{intent.protocol}: runtime_username is managed by central")
        for intent in intents:
            if intent.node_id in remote:
                continue  # no manager to ask here: the node's own reconcile reports a taken name
            check = await self._adapter(intent.protocol).preflight(intent)
            if not check.ok:
                raise ClientConflict(f"{intent.protocol}: {check.reason}")
        operation_id = str(uuid.uuid4())
        now = int(self.clock.time())
        steps: list[dict] = []
        with self.database.transaction() as db:
            self.clients.store.client(db, client_id)
            for intent in intents:
                is_remote = intent.node_id in remote
                adapter = None if is_remote else self._adapter(intent.protocol)
                taken = self.clients.store.find_grant(
                    db, intent.protocol, intent.node_id, intent.endpoint_id, intent.runtime_username
                )
                if taken is not None:
                    raise ClientConflict("runtime_username is already granted on this endpoint")
                grant_id = str(uuid.uuid4())
                self.clients.store.insert_grant(
                    db,
                    AccessGrant(
                        id=grant_id,
                        client_id=client_id,
                        protocol=intent.protocol,
                        node_id=intent.node_id,
                        endpoint_id=intent.endpoint_id,
                        runtime_username=intent.runtime_username,
                        # A remote grant points at its credential from the start: the
                        # generation names that version, and a rotation must retire it.
                        secret_ref=SecretRef(f"grant:{grant_id}", 1) if is_remote else None,
                        desired_state="enabled",
                        observed_state="pending",
                        valid_from=intent.valid_from,
                        valid_until=intent.valid_until,
                        options=intent.options,
                        origin="provisioned",
                        created_at=now,
                        updated_at=now,
                    ),
                )
                if is_remote or adapter.credential_origin == "caller":
                    # The panel escrows the credential before the manager ever sees it,
                    # so a lost reply can never cost the subscriber their access. A remote
                    # grant always travels with one; a runtime that insists on choosing
                    # its own hands it back through the push response.
                    self.secrets.store(
                        db,
                        secret_id=f"grant:{grant_id}",
                        version=1,
                        purpose=CREDENTIAL_PURPOSE,
                        grant_id=grant_id,
                        permitted_node_id=intent.node_id,
                        plaintext=new_credential(intent.protocol),
                        state="pending",
                    )
                steps.append({"grant_id": grant_id, "protocol": intent.protocol,
                              "status": "remote" if is_remote else "pending", "error": None})
            db.execute(
                """INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?)""",
                (operation_id, client_id, "pending_remote" if remote else "pending",
                 json.dumps(steps, sort_keys=True), now, now),
            )
            record(
                db,
                actor=actor,
                action="grant.provision.start",
                target=operation_id,
                ip=ip,
                request_id=request_id,
                detail={"client_id": client_id, "protocols": [intent.protocol for intent in intents]},
            )
            if remote:
                # The generation that carries the remote grants is published in this same
                # transaction: a rolled-back operation leaves nothing for the pusher.
                self.clients.notify(db, client_id)
            if self.faults.pop("before_remote_commit", None):
                raise RuntimeError("injected before the remote commit")
        return operation_id

    # --- run ---------------------------------------------------------------------

    def _grant(self, grant_id: str) -> AccessGrant:
        with self.database.connect() as db:
            return self.clients.store.grant(db, grant_id)

    def _credential(self, grant: AccessGrant) -> CredentialPlan:
        adapter = self._adapter(grant.protocol)
        if adapter.credential_origin == "manager":
            return CredentialPlan("manager", None)
        with self.database.connect() as db:
            plaintext = self.secrets.reveal(
                db,
                SecretRef(f"grant:{grant.id}", 1),
                purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id,
                permitted_node_id=grant.node_id,
            )
        return CredentialPlan("caller", plaintext)

    def _intent(self, grant: AccessGrant) -> GrantIntent:
        return GrantIntent(
            protocol=grant.protocol,
            node_id=grant.node_id,
            endpoint_id=grant.endpoint_id,
            runtime_username=grant.runtime_username,
            options=grant.options,
            valid_from=grant.valid_from,
            valid_until=grant.valid_until,
        )

    def _escrow_manager_credential(self, grant: AccessGrant, plaintext: bytes) -> None:
        with self.database.transaction() as db:
            existing = db.execute(
                "SELECT 1 FROM secret_versions WHERE secret_id=? AND version=1", (f"grant:{grant.id}",)
            ).fetchone()
            if existing is None:
                self.secrets.store(
                    db,
                    secret_id=f"grant:{grant.id}",
                    version=1,
                    purpose=CREDENTIAL_PURPOSE,
                    grant_id=grant.id,
                    permitted_node_id=grant.node_id,
                    plaintext=plaintext,
                    state="pending",
                )

    def _remember_template(self, grant: AccessGrant, artifact_template: dict) -> None:
        """Keep the shape the runtime reported, so a link can be rebuilt without it.

        Only what the protocol's options model has a field for is kept: Mieru's share
        template, Telemt's host and port. Everything else the adapter reported is
        transient.
        """
        learned = {
            key: value
            for key, value in artifact_template.items()
            if key in type(grant.options).model_fields and value not in (None, "")
        }
        if not learned:
            return
        options = grant.options.model_copy(update=learned)
        with self.database.transaction() as db:
            self.clients.store.update_grant(
                db, grant.id, protocol_options_json=options.model_dump_json(),
                updated_at=int(self.clock.time()),
            )

    def _activate(self, grant: AccessGrant) -> None:
        reference = SecretRef(f"grant:{grant.id}", 1)
        with self.database.transaction() as db:
            self.secrets.transition(db, reference, "active")
            self.clients.store.update_grant(
                db,
                grant.id,
                secret_id=reference.secret_id,
                secret_version=reference.version,
                observed_state="enabled",
                updated_at=int(self.clock.time()),
            )
            self.clients.notify(db, grant.client_id)

    async def run(self, operation_id: str) -> OperationResult:
        with self.database.connect() as db:
            operation = self._operation(db, operation_id)
        if operation["status"] in TERMINAL:
            return self._result(operation_id)
        if any(step["status"] not in SETTLED for step in operation["steps"]):
            self._mark_operation(operation_id, "applying")
        for step in operation["steps"]:
            if step["status"] in SETTLED:
                continue  # a `remote` step is the node's to finish; see remote_applied()
            try:
                await self._advance(operation_id, step)
            except ManualInterventionRequired as exc:
                self._mark_step(operation_id, step["grant_id"], "manual", str(exc))
                self._mark_operation(operation_id, "manual_intervention_required")
                return self._result(operation_id)
            except AdapterError as exc:
                self._mark_step(operation_id, step["grant_id"], step["status"], str(exc))
                return await self._compensate(operation_id, reason=str(exc))
            except RuntimeError:
                # An injected or unexpected crash leaves the journal where it is; the
                # next run resumes from the last durable checkpoint.
                raise
        # The journal decides, not this loop's snapshot: a node may have reported a
        # remote step applied while the local ones were running.
        with self.database.connect() as db:
            steps = self._operation(db, operation_id)["steps"]
        waiting = any(step["status"] == "remote" for step in steps)
        self._mark_operation(operation_id, "pending_remote" if waiting else "succeeded")
        return self._result(operation_id)

    async def _advance(self, operation_id: str, step: dict) -> None:
        grant = self._grant(step["grant_id"])
        adapter = self._adapter(grant.protocol)
        if step["status"] == "pending":
            if self.faults.pop("before_first_apply", None):
                raise RuntimeError("injected before the first apply")
            applied = await adapter.create(
                f"{operation_id}:{grant.id}", self._intent(grant), self._credential(grant)
            )
            if adapter.credential_origin == "manager" and applied.credential:
                self._escrow_manager_credential(grant, applied.credential)
            self._remember_template(grant, applied.artifact_template)
            self._mark_step(operation_id, grant.id, "applied")
            step["status"] = "applied"
            if self.faults.get("after_apply") == grant.protocol:
                raise AdapterError(f"injected after applying {grant.protocol}")
        if step["status"] == "applied":
            self._mark_step(operation_id, grant.id, "escrowed")
            step["status"] = "escrowed"
        if step["status"] == "escrowed":
            self._activate(grant)
            self._mark_step(operation_id, grant.id, "active")
            step["status"] = "active"

    async def _compensate(self, operation_id: str, *, reason: str) -> OperationResult:
        """Undo only what this operation created; anything pre-existing is never touched."""
        self._mark_operation(operation_id, "compensating")
        with self.database.connect() as db:
            operation = self._operation(db, operation_id)
        outcome = "compensated"
        for step in operation["steps"]:
            if step["status"] not in CREATED:
                # Nothing reached the manager for this step, so there is nothing to undo.
                self._mark_step(operation_id, step["grant_id"], "compensated")
                continue
            grant = self._grant(step["grant_id"])
            with self.database.connect() as db:
                remote = is_remote_node(db, grant.node_id)
            if remote:
                # `active` here means the node confirmed it (remote_applied), not that a
                # manager of this panel created it: the local runtime may hold an unrelated
                # user of the same name. The `deleted` written below withdraws it from the
                # node through the next generation.
                self._mark_step(operation_id, grant.id, "compensated")
                continue
            try:
                if self.faults.pop("during_compensation", None):
                    raise AdapterError("injected during compensation")
                await self._adapter(grant.protocol).delete(
                    GrantRef(grant.protocol, grant.runtime_username)
                )
            except AdapterError as exc:
                # The account may still exist; deleting blindly on a retry could remove
                # something else, so this is handed to a person with the operation id.
                self._mark_step(operation_id, grant.id, "manual", str(exc))
                outcome = "manual_intervention_required"
                continue
            self._mark_step(operation_id, grant.id, "compensated")
            with self.database.transaction() as db:
                self.clients.store.update_grant(
                    db, grant.id, desired_state="deleted", observed_state="missing",
                    updated_at=int(self.clock.time()),
                )
        with self.database.transaction() as db:
            operation = self._operation(db, operation_id)
            compensated = [step["grant_id"] for step in operation["steps"] if step["status"] == "compensated"]
            for grant_id in compensated:
                self.clients.store.update_grant(
                    db, grant_id, desired_state="deleted", updated_at=int(self.clock.time()),
                )
            if compensated:
                # A grant already published to a linked panel is withdrawn by the next
                # generation; a local one leaves the subscription, which must move too.
                self.clients.notify(db, operation["client_id"])
        with self.database.transaction() as db:
            record(
                db,
                actor={"id": None, "username": "system"},
                action=f"grant.provision.{outcome}",
                target=operation_id,
                ip="local",
                detail={"reason": reason},
            )
        self._mark_operation(operation_id, outcome)
        return self._result(operation_id)

    def _result(self, operation_id: str) -> OperationResult:
        state = self.status(operation_id)
        return OperationResult(
            operation_id=operation_id,
            status=state["status"],
            steps=[
                StepResult(step["grant_id"], step["protocol"], step["status"], step["error"])
                for step in state["steps"]
            ],
        )

    # --- remote (called by the fleet pusher, inside its transaction) ----------------

    def confirm_credential(self, db, grant_id: str) -> None:
        """The node reported the grant applied with the credential version the grant
        names: `pending` becomes `active`, and once that version is active the ones a
        rotation left `retiring` are revoked — the node runs the new credential, so the
        old one is history. Any other state stands: a retiring version is never
        resurrected, and a revoked one stays revoked."""
        grant = self.clients.store.grant(db, grant_id)
        if grant.secret_ref is None:
            return
        row = db.execute(
            "SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
            (grant.secret_ref.secret_id, grant.secret_ref.version),
        ).fetchone()
        state = None if row is None else row["state"]
        if state == "pending":
            self.secrets.transition(db, grant.secret_ref, "active")
            state = "active"
        if state != "active":
            return
        retiring = db.execute(
            "SELECT version FROM secret_versions WHERE secret_id=? AND state='retiring'",
            (grant.secret_ref.secret_id,),
        ).fetchall()
        for old in retiring:
            self.secrets.transition(db, SecretRef(grant.secret_ref.secret_id, old["version"]), "revoked")

    def escrow_returned_credential(self, db, grant_id: str, credential_ref: str, plaintext: str) -> None:
        """A credential the node's runtime chose itself, escrowed under exactly the
        `secret_id:version` the generation named (binding ruling). A bumped version would
        be a new `credential_ref`, and the node would rotate the account on the next
        generation for nothing. The row is replaced in place — `SecretStore.store` is a
        plain INSERT — because the runtime's value is the truth whatever the version's
        state was; it is `active` from here on."""
        secret_id, _, version = credential_ref.rpartition(":")
        if secret_id != f"grant:{grant_id}" or not version.isdigit():
            raise ValueError("credential_ref does not belong to this grant")
        grant = self.clients.store.grant(db, grant_id)
        db.execute("DELETE FROM secret_versions WHERE secret_id=? AND version=?", (secret_id, int(version)))
        reference = self.secrets.store(
            db,
            secret_id=secret_id,
            version=int(version),
            purpose=CREDENTIAL_PURPOSE,
            grant_id=grant.id,
            permitted_node_id=grant.node_id,
            plaintext=plaintext.encode(),
            state="active",
        )
        if grant.secret_ref is None:
            self.clients.store.update_grant(
                db, grant.id, secret_id=reference.secret_id, secret_version=reference.version,
                updated_at=int(self.clock.time()),
            )

    @staticmethod
    def _waiting(db) -> list[str]:
        rows = db.execute(
            "SELECT operation_id FROM provisioning_operations WHERE status IN ('pending_remote','applying')"
        ).fetchall()
        return [row["operation_id"] for row in rows]

    @staticmethod
    def _settled(operation: dict) -> str:
        """The status of an operation once a node answered for one of its steps: unchanged
        while a step still waits (`remote`) or `run()` is still applying the local steps
        (it settles the status itself); otherwise `succeeded` if the node applied any
        grant, `compensated` if every step was withdrawn before it did."""
        steps = operation["steps"]
        if operation["status"] != "pending_remote" or any(step["status"] == "remote" for step in steps):
            return operation["status"]
        return "succeeded" if any(step["status"] == "active" for step in steps) else "compensated"

    def remote_applied(self, db, observed: ObservedGeneration) -> None:
        """What one node reported, applied to the operations waiting for it: a grant the
        node holds (`enabled`, or `disabled` because the central asked for that meanwhile)
        finishes its `remote` step with its credential active; a `failed` one keeps the
        step and shows the node's error; the operation settles once no step waits. An
        operation still `applying` locally only has its step marked — `run()` settles its
        status when the local steps are done."""
        reported = {item.ref.removeprefix("grant:"): item for item in observed.resources}
        for operation_id in self._waiting(db):
            operation = self._operation(db, operation_id)
            changed = False
            for step in operation["steps"]:
                item = reported.get(step["grant_id"])
                if step["status"] != "remote" or item is None:
                    continue
                if item.state in ("enabled", "disabled"):
                    self.confirm_credential(db, step["grant_id"])
                    self.clients.store.update_grant(
                        db, step["grant_id"], observed_state=item.state, updated_at=int(self.clock.time()),
                    )
                    step["status"], step["error"], changed = "active", None, True
                elif item.state == "failed" and step["error"] != item.error:
                    step["error"], changed = item.error, True
            if changed:
                self._write(db, operation_id, status=self._settled(operation), steps=operation["steps"])

    def withdraw_remote(self, db, grant_id: str, *, reason: str) -> None:
        """The grant was deleted before its node applied it: the `remote` step waiting for
        that report will never see one, so it ends `compensated` (the next generation
        withdraws the resource, nothing was created that stays) and the operation settles
        now instead of waiting forever. In the caller's transaction, with the deletion."""
        for operation_id in self._waiting(db):
            operation = self._operation(db, operation_id)
            changed = False
            for step in operation["steps"]:
                if step["grant_id"] == grant_id and step["status"] == "remote":
                    step["status"], step["error"], changed = "compensated", reason, True
            if changed:
                self._write(db, operation_id, status=self._settled(operation), steps=operation["steps"])

    # --- bundle ------------------------------------------------------------------

    def bundle(self, operation_id: str, *, public_hosts: dict[str, str]) -> dict:
        """Every artifact of one operation, rendered from escrow — no manager call."""
        state = self.status(operation_id)
        if state["status"] != "succeeded":
            raise ClientConflict("only a succeeded operation has a bundle")
        grants = []
        with self.database.connect() as db:
            for step in state["steps"]:
                grant = self.clients.store.grant(db, step["grant_id"])
                if grant.secret_ref is None:
                    continue
                plaintext = self.secrets.reveal(
                    db,
                    grant.secret_ref,
                    purpose=CREDENTIAL_PURPOSE,
                    grant_id=grant.id,
                    permitted_node_id=grant.node_id,
                )
                adapter = self._adapter(grant.protocol)
                artifacts = adapter.render_artifacts(
                    grant, plaintext, public_host=public_hosts.get(grant.protocol, "")
                )
                grants.append(
                    {
                        "protocol": grant.protocol,
                        "runtime_username": grant.runtime_username,
                        "artifacts": [
                            {
                                "kind": item.kind,
                                "label": item.label,
                                "media_type": item.media_type,
                                "value": item.value,
                                "auto_refresh": item.auto_refresh,
                            }
                            for item in artifacts
                        ],
                    }
                )
        return {"operation_id": operation_id, "grants": grants}
