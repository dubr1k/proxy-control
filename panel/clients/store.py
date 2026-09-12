"""Client and grant rows. Every method takes the caller's `db`, so a write and its
audit row commit together — the store never opens a transaction of its own."""
from __future__ import annotations

import json

from ..database import Database
from ..secrets_store import SecretRef
from .models import PROTOCOL_OPTIONS, AccessGrant, Client


class ClientConflict(RuntimeError):
    pass


def _client(row) -> Client:
    return Client(
        id=row["id"],
        display_name=row["display_name"],
        state=row["state"],
        metadata=json.loads(row["metadata_json"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _grant(row) -> AccessGrant:
    options = PROTOCOL_OPTIONS[row["protocol"]].model_validate_json(row["protocol_options_json"])
    reference = (
        SecretRef(row["secret_id"], row["secret_version"])
        if row["secret_id"] is not None and row["secret_version"] is not None
        else None
    )
    return AccessGrant(
        id=row["id"],
        client_id=row["client_id"],
        protocol=row["protocol"],
        node_id=row["node_id"],
        endpoint_id=row["endpoint_id"],
        runtime_username=row["runtime_username"],
        secret_ref=reference,
        desired_state=row["desired_state"],
        observed_state=row["observed_state"],
        valid_from=row["valid_from"],
        valid_until=row["valid_until"],
        options=options,
        origin=row["origin"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# Only these columns may be written through update_grant; anything else is a bug in the caller.
UPDATABLE = (
    "client_id", "secret_id", "secret_version", "desired_state", "observed_state",
    "valid_from", "valid_until", "protocol_options_json", "updated_at",
)


class ClientStore:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def insert_client(db, client: Client) -> None:
        db.execute(
            """INSERT INTO clients(id,display_name,state,metadata_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?)""",
            (
                client.id,
                client.display_name,
                client.state,
                json.dumps(client.metadata, sort_keys=True, separators=(",", ":")),
                client.created_at,
                client.updated_at,
            ),
        )

    @staticmethod
    def client(db, client_id: str) -> Client:
        row = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if row is None:
            raise KeyError(client_id)
        return _client(row)

    @staticmethod
    def clients(db, *, state: str | None = None) -> list[Client]:
        sql = "SELECT * FROM clients"
        parameters: tuple = ()
        if state is not None:
            sql, parameters = sql + " WHERE state=?", (state,)
        return [_client(row) for row in db.execute(sql + " ORDER BY created_at, id", parameters)]

    @staticmethod
    def set_client_state(db, client_id: str, state: str, *, updated_at: int) -> None:
        changed = db.execute(
            "UPDATE clients SET state=?,updated_at=? WHERE id=?", (state, updated_at, client_id)
        ).rowcount
        if changed != 1:
            raise KeyError(client_id)

    def insert_grant(self, db, grant: AccessGrant) -> None:
        # The UNIQUE index would raise too, but a failed statement aborts the caller's
        # transaction; checking first lets the caller handle the conflict and carry on.
        taken = self.find_grant(db, grant.protocol, grant.node_id, grant.endpoint_id, grant.runtime_username)
        if taken is not None:
            raise ClientConflict("runtime_username is already granted on this endpoint")
        db.execute(
            """INSERT INTO access_grants(id,client_id,protocol,node_id,endpoint_id,runtime_username,
               secret_id,secret_version,desired_state,observed_state,valid_from,valid_until,
               protocol_options_json,origin,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                grant.id,
                grant.client_id,
                grant.protocol,
                grant.node_id,
                grant.endpoint_id,
                grant.runtime_username,
                grant.secret_ref.secret_id if grant.secret_ref else None,
                grant.secret_ref.version if grant.secret_ref else None,
                grant.desired_state,
                grant.observed_state,
                grant.valid_from,
                grant.valid_until,
                grant.options.model_dump_json(),
                grant.origin,
                grant.created_at,
                grant.updated_at,
            ),
        )

    @staticmethod
    def grant(db, grant_id: str) -> AccessGrant:
        row = db.execute("SELECT * FROM access_grants WHERE id=?", (grant_id,)).fetchone()
        if row is None:
            raise KeyError(grant_id)
        return _grant(row)

    @staticmethod
    def grants(
        db,
        *,
        client_id: str | None = None,
        protocol: str | None = None,
        node_id: str | None = None,
        include_deleted: bool = False,
    ) -> list[AccessGrant]:
        conditions, parameters = [], []
        for column, value in (("client_id", client_id), ("protocol", protocol), ("node_id", node_id)):
            if value is not None:
                conditions.append(f"{column}=?")
                parameters.append(value)
        if not include_deleted:
            conditions.append("desired_state<>'deleted'")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = db.execute(f"SELECT * FROM access_grants{where} ORDER BY created_at, id", tuple(parameters))
        return [_grant(row) for row in rows]

    @staticmethod
    def find_grant(db, protocol: str, node_id: str, endpoint_id: str, runtime_username: str) -> AccessGrant | None:
        row = db.execute(
            """SELECT * FROM access_grants
               WHERE protocol=? AND node_id=? AND endpoint_id=? AND runtime_username=?""",
            (protocol, node_id, endpoint_id, runtime_username),
        ).fetchone()
        return None if row is None else _grant(row)

    @staticmethod
    def update_grant(db, grant_id: str, **fields) -> None:
        unknown = set(fields) - set(UPDATABLE)
        if unknown:
            raise ClientConflict(f"grant fields are not updatable: {sorted(unknown)}")
        if not fields:
            return
        assignments = ",".join(f"{column}=?" for column in fields)
        changed = db.execute(
            f"UPDATE access_grants SET {assignments} WHERE id=?", (*fields.values(), grant_id)
        ).rowcount
        if changed != 1:
            raise KeyError(grant_id)

    @staticmethod
    def delete_grant(db, grant_id: str) -> None:
        """Only once the runtime account is confirmed gone; the UNIQUE index frees the name."""
        if db.execute("DELETE FROM access_grants WHERE id=?", (grant_id,)).rowcount != 1:
            raise KeyError(grant_id)
