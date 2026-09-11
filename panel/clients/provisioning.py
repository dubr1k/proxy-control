"""Creating several accesses as one operation, with a journal that survives a crash.

Three managers cannot share a transaction, so "all or nothing" is not available. What
is available is a written-down journal: every step records what it reached before the
next one runs, so a restart resumes instead of repeating, and a failure compensates
only what this operation actually created.

Every run ends in exactly one of three outcomes — `succeeded`, `compensated`, or
`manual_intervention_required`. The last one is not a failure to handle later: it means
the runtime changed in a way the panel cannot undo safely, and it names the operation so
a person can finish the job.
"""
from __future__ import annotations

import json
import secrets as secret_tokens
import time
import uuid
from dataclasses import dataclass, field

from ..audit import record
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
    def __init__(self, database, secret_store, adapters: dict, clients: ClientService, clock=time):
        self.database = database
        self.secrets = secret_store
        self.adapters = adapters
        self.clients = clients
        self.clock = clock
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
        refusing halfway through would leave accounts to compensate.
        """
        if not intents:
            raise ClientConflict("an operation needs at least one grant")
        for intent in intents:
            check = await self._adapter(intent.protocol).preflight(intent)
            if not check.ok:
                raise ClientConflict(f"{intent.protocol}: {check.reason}")
        operation_id = str(uuid.uuid4())
        now = int(self.clock.time())
        steps: list[dict] = []
        with self.database.transaction() as db:
            self.clients.store.client(db, client_id)
            for intent in intents:
                adapter = self._adapter(intent.protocol)
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
                if adapter.credential_origin == "caller":
                    # The panel escrows the credential before the manager ever sees it,
                    # so a lost reply can never cost the subscriber their access.
                    self.secrets.store(
                        db,
                        secret_id=f"grant:{grant_id}",
                        version=1,
                        purpose=CREDENTIAL_PURPOSE,
                        grant_id=grant_id,
                        permitted_node_id=intent.node_id,
                        plaintext=secret_tokens.token_urlsafe(24).encode(),
                        state="pending",
                    )
                steps.append(
                    {"grant_id": grant_id, "protocol": intent.protocol, "status": "pending", "error": None}
                )
            db.execute(
                """INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?)""",
                (operation_id, client_id, "pending", json.dumps(steps, sort_keys=True), now, now),
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
        self._mark_operation(operation_id, "applying")
        for step in operation["steps"]:
            if step["status"] == "active":
                continue
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
        self._mark_operation(operation_id, "succeeded")
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
            for step in self._operation(db, operation_id)["steps"]:
                if step["status"] == "compensated":
                    self.clients.store.update_grant(
                        db, step["grant_id"], desired_state="deleted",
                        updated_at=int(self.clock.time()),
                    )
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
