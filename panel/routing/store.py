"""Routing policies at rest (migration 14): reads and writes a caller composes into one
transaction, like the other stores — the audit row commits with the change."""
from __future__ import annotations

import json
import time
import uuid

from ..database import Database
from .models import backends_for, BACKEND_FOR, COMPILER_VERSION, PolicyInput, RoutingPolicy, RoutingRule, RuleMatch

HISTORY_LIMIT = 50


class PolicyConflict(Exception):
    """`expected_revision` is not the stored one: somebody saved in between."""

    def __init__(self, current_revision: int):
        super().__init__(f"policy revision is {current_revision}")
        self.current_revision = current_revision


class PolicyNotFound(KeyError):
    pass


class RoutingStore:
    def __init__(self, database: Database):
        self.database = database

    # -- reads -----------------------------------------------------------------

    @staticmethod
    def _rules(db, policy_id: str) -> list[RoutingRule]:
        rows = db.execute("SELECT * FROM routing_rules WHERE policy_id=? ORDER BY position", (policy_id,)).fetchall()
        return [RoutingRule(id=row["id"], position=row["position"], enabled=bool(row["enabled"]),
                            match=RuleMatch.model_validate(json.loads(row["match_json"])), action=row["action"],
                            egress=row["egress"], note=row["note"]) for row in rows]

    @classmethod
    def _policy(cls, db, row) -> RoutingPolicy:
        return RoutingPolicy(
            id=row["id"], node_id=row["node_id"], protocol=row["protocol"], backend=row["backend"],
            default_action=row["default_action"], default_egress=row["default_egress"], fallback=row["fallback"],
            revision=row["revision"], state=row["state"], applied_revision=row["applied_revision"],
            applied_digest=row["applied_digest"], applied_at=row["applied_at"], last_error=row["last_error"],
            created_at=row["created_at"], updated_at=row["updated_at"], rules=cls._rules(db, row["id"]),
        )

    @classmethod
    def get(cls, db, node_id: str, protocol: str) -> RoutingPolicy | None:
        row = db.execute("SELECT * FROM routing_policies WHERE node_id=? AND protocol=?", (node_id, protocol)).fetchone()
        return None if row is None else cls._policy(db, row)

    @classmethod
    def get_by_id(cls, db, policy_id: str) -> RoutingPolicy:
        row = db.execute("SELECT * FROM routing_policies WHERE id=?", (policy_id,)).fetchone()
        if row is None:
            raise PolicyNotFound(policy_id)
        return cls._policy(db, row)

    @classmethod
    def list(cls, db, node_id: str | None = None) -> list[RoutingPolicy]:
        query, params = "SELECT * FROM routing_policies", ()
        if node_id is not None:
            query, params = f"{query} WHERE node_id=?", (node_id,)
        return [cls._policy(db, row) for row in db.execute(f"{query} ORDER BY node_id, protocol", params).fetchall()]

    # -- writes ----------------------------------------------------------------

    @classmethod
    def upsert(cls, db, node_id: str, protocol: str, policy: PolicyInput, *, expected_revision: int | None,
               now: int | None = None) -> RoutingPolicy:
        """Save the whole policy — head and every rule — as one revision. Rule ids the
        caller sends back are kept; anything else is a new rule. A rule id from another
        policy is not adopted: it becomes a new rule here."""
        now = int(time.time()) if now is None else now
        if policy.backend is not None and policy.backend not in backends_for(protocol):
            raise ValueError(f"{protocol} cannot run on {policy.backend}")
        current = db.execute("SELECT id, revision, backend FROM routing_policies WHERE node_id=? AND protocol=?",
                             (node_id, protocol)).fetchone()
        if current is None:
            if expected_revision not in (None, 0):
                raise PolicyConflict(0)
            backend = policy.backend or BACKEND_FOR[protocol]
            policy_id, revision = str(uuid.uuid4()), 1
            db.execute(
                "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,default_egress,fallback,revision,"
                "state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'draft',?,?)",
                (policy_id, node_id, protocol, backend, policy.default_action, policy.default_egress, policy.fallback,
                 revision, now, now))
            known: set[str] = set()
        else:
            policy_id = current["id"]
            if expected_revision is not None and expected_revision != current["revision"]:
                raise PolicyConflict(current["revision"])
            revision = current["revision"] + 1
            backend = policy.backend or current["backend"]
            db.execute(
                "UPDATE routing_policies SET backend=?, default_action=?, default_egress=?, fallback=?, revision=?,"
                " updated_at=? WHERE id=?",
                (backend, policy.default_action, policy.default_egress, policy.fallback, revision, now, policy_id))
            known = {row["id"] for row in db.execute("SELECT id FROM routing_rules WHERE policy_id=?", (policy_id,))}
            db.execute("DELETE FROM routing_rules WHERE policy_id=?", (policy_id,))
        used: set[str] = set()
        for position, rule in enumerate(policy.rules):
            rule_id = rule.id if rule.id in known and rule.id not in used else str(uuid.uuid4())
            used.add(rule_id)
            db.execute(
                "INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,egress,note,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (rule_id, policy_id, position, int(rule.enabled), json.dumps(rule.match.model_dump(), sort_keys=True),
                 rule.action, rule.egress, rule.note, now, now))
        return cls.get_by_id(db, policy_id)

    @classmethod
    def retarget(cls, db, policy_id: str, backend: str, *, now: int | None = None) -> RoutingPolicy:
        """The policy on another backend (attach/detach, v0.5): a new revision in `draft`,
        the rules kept — what was applied on the old backend is no longer what runs."""
        now = int(time.time()) if now is None else now
        policy = cls.get_by_id(db, policy_id)
        if backend not in backends_for(policy.protocol):
            raise ValueError(f"{policy.protocol} cannot run on {backend}")
        db.execute("UPDATE routing_policies SET backend=?, revision=revision+1, state='draft', last_error=NULL, updated_at=?"
                   " WHERE id=?", (backend, now, policy_id))
        return cls.get_by_id(db, policy_id)

    @staticmethod
    def delete(db, policy_id: str) -> None:
        if db.execute("DELETE FROM routing_policies WHERE id=?", (policy_id,)).rowcount == 0:
            raise PolicyNotFound(policy_id)

    @staticmethod
    def mark(db, policy_id: str, *, state: str, applied_revision: int | None = None,
             applied_digest: str | None = None, last_error: str | None = None, now: int | None = None) -> None:
        """Where the policy stands on the node. `applied` records what is running there;
        `failed` keeps the last applied revision and says why the new one is not."""
        now = int(time.time()) if now is None else now
        if state == "applied":
            db.execute(
                "UPDATE routing_policies SET state=?, applied_revision=?, applied_digest=?, applied_at=?, last_error=NULL,"
                " updated_at=? WHERE id=?", (state, applied_revision, applied_digest, now, now, policy_id))
        elif state in ("rolled_back", "draft"):
            # `draft` with applied fields (v0.5): the node runs the backend's pass-through after
            # an attach/detach while the policy's rules wait to be applied.
            db.execute(
                "UPDATE routing_policies SET state=?, applied_revision=?, applied_digest=?, applied_at=?, last_error=?,"
                " updated_at=? WHERE id=?", (state, applied_revision, applied_digest, now, last_error, now, policy_id))
        else:
            db.execute("UPDATE routing_policies SET state=?, last_error=?, updated_at=? WHERE id=?",
                       (state, last_error, now, policy_id))

    @staticmethod
    def record_apply(db, policy_id: str, *, revision: int, digest: str | None, backend: str, outcome: str,
                     detail: str | None = None, actor: str = "system", runtime_version: str | None = None,
                     compiler_version: str = COMPILER_VERSION, document: dict | None = None,
                     now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        db.execute(
            "INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,runtime_version,outcome,detail,"
            "document_json,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (policy_id, revision, digest, backend, compiler_version, runtime_version, outcome, detail,
             None if document is None else json.dumps(document, sort_keys=True), actor, now))

    @staticmethod
    def _apply_row(row) -> dict:
        value = dict(row)
        raw = value.pop("document_json", None)
        value["document"] = None if raw is None else json.loads(raw)
        return value

    @classmethod
    def history(cls, db, policy_id: str, limit: int = HISTORY_LIMIT) -> list[dict]:
        rows = db.execute("SELECT * FROM routing_applies WHERE policy_id=? ORDER BY id DESC LIMIT ?",
                          (policy_id, limit)).fetchall()
        return [cls._apply_row(row) for row in rows]

    @classmethod
    def last_applied(cls, db, policy_id: str) -> dict | None:
        """The most recent successful apply before the current one — what a rollback returns to."""
        rows = db.execute("SELECT * FROM routing_applies WHERE policy_id=? AND outcome='applied' ORDER BY id DESC LIMIT 2",
                          (policy_id,)).fetchall()
        return None if len(rows) < 2 else cls._apply_row(rows[1])

    # -- the egress section a linked panel's generations carry (spec §8.3) ---------------

    @staticmethod
    def set_desired(db, policy_id: str, desired: dict | None, *, now: int | None = None) -> None:
        """`desired` is the EgressDocument (as a dict) the node should run for this policy;
        None withdraws it — later generations then leave the node's egress as it is."""
        now = int(time.time()) if now is None else now
        db.execute("UPDATE routing_policies SET desired_json=?, updated_at=? WHERE id=?",
                   (None if desired is None else json.dumps(desired, sort_keys=True), now, policy_id))

    @staticmethod
    def desired_for_node(db, node_id: str) -> dict[str, dict]:
        rows = db.execute("SELECT protocol, desired_json FROM routing_policies WHERE node_id=? AND desired_json IS NOT NULL"
                          " ORDER BY protocol", (node_id,)).fetchall()
        return {row["protocol"]: json.loads(row["desired_json"]) for row in rows}
