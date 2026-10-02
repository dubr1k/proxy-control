"""Client and grant rows. Every method takes the caller's `db`, so a write and its
audit row commit together — the store never opens a transaction of its own."""
from __future__ import annotations

import base64
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
        routing_lane=row["routing_lane"] if "routing_lane" in row.keys() else None,
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

    def clients_with_grants(self, db) -> list[tuple[Client, list[AccessGrant]]]:
        """Legacy full listing: two queries regardless of the number of clients."""
        clients = self.clients(db)
        grouped: dict[str, list[AccessGrant]] = {client.id: [] for client in clients}
        for grant in self.grants(db):
            # A concurrent import may create a client between the two reads.
            if grant.client_id in grouped:
                grouped[grant.client_id].append(grant)
        return [(client, grouped[client.id]) for client in clients]

    @staticmethod
    def client_page(db, *, limit: int, cursor: str | None = None, query: str = "",
                    state: str = "all", protocol: str = "", node: str = "", issue: str = "") -> dict:
        """Filter before paging; hydrate grants only for the returned client IDs.

        SQLite's built-in LOWER is ASCII-only. Python's Unicode lower preserves the
        existing browser search, including Cyrillic and literal '%'/'_' characters.
        """
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        db.create_function("client_lower", 1, lambda value: str(value or "").lower(), deterministic=True)
        conditions, parameters = [], []
        if state != "all":
            conditions.append("c.state=?")
            parameters.append(state)
        live = "g.client_id=c.id AND g.desired_state<>'deleted'"
        for word in query.lower().split():
            conditions.append(f"""(instr(client_lower(c.display_name || char(10) || c.id), ?) > 0
                OR EXISTS (SELECT 1 FROM access_grants g LEFT JOIN fleet_nodes n ON n.node_id=g.node_id
                WHERE {live} AND instr(client_lower(g.runtime_username || char(10) ||
                    CASE g.protocol WHEN 'naive' THEN 'NaiveProxy' WHEN 'mtproxy' THEN 'MTProxy' ELSE 'Mieru' END
                    || char(10) || CASE WHEN g.node_id='local' THEN 'Этот сервер'
                        ELSE COALESCE(NULLIF(n.display_name,''), g.node_id) END), ?) > 0))""")
            parameters.extend((word, word))
        placement = [live]
        for column, value in (("protocol", protocol), ("node_id", node)):
            if value:
                placement.append(f"g.{column}=?")
                parameters.append(value)
        orphan = "(g.secret_id IS NULL OR g.secret_version IS NULL)"
        issues = {
            "problem": f"(g.observed_state IN ('failed','pending','drifted','missing') OR {orphan})",
            "pending": "g.observed_state='pending'", "failed": "g.observed_state='failed'",
            "orphan": orphan, "disabled": "g.desired_state='disabled'", "lane": "g.routing_lane='own'",
        }
        if issue in issues:
            placement.append(issues[issue])
        elif issue not in ("", "empty"):
            raise ValueError("unknown issue filter")
        if protocol or node or issue:
            exists = "NOT EXISTS" if issue == "empty" else "EXISTS"
            conditions.append(f"{exists} (SELECT 1 FROM access_grants g WHERE {' AND '.join(placement)})")
        where = " AND ".join(conditions) or "1"
        matched = db.execute(f"SELECT COUNT(*) FROM clients c WHERE {where}", parameters).fetchone()[0]
        rank = "CASE c.state WHEN 'active' THEN 0 WHEN 'suspended' THEN 1 ELSE 2 END"
        if cursor:
            try:
                position = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
                if (not isinstance(position, list) or len(position) != 3
                        or type(position[0]) is not int or position[0] not in (0, 1, 2)
                        or type(position[1]) is not int or not 0 <= position[1] < 2**63
                        or not isinstance(position[2], str)):
                    raise ValueError
            except (ValueError, TypeError, UnicodeError) as exc:
                raise ValueError("invalid client cursor") from exc
            where += f" AND ({rank},c.created_at,c.id) > (?,?,?)"
            parameters.extend(position)
        rows = list(db.execute(
            f"SELECT c.* FROM clients c WHERE {where} ORDER BY {rank},c.created_at,c.id LIMIT ?",
            (*parameters, limit + 1),
        ))
        clients = [_client(row) for row in rows[:limit]]
        next_cursor = None
        if len(rows) > limit:
            last = clients[-1]
            position = [{"active": 0, "suspended": 1, "archived": 2}[last.state], last.created_at, last.id]
            next_cursor = base64.urlsafe_b64encode(json.dumps(position).encode()).decode().rstrip("=")
        grouped: dict[str, list[AccessGrant]] = {client.id: [] for client in clients}
        if clients:
            placeholders = ",".join("?" for _ in clients)
            for row in db.execute(
                f"SELECT * FROM access_grants WHERE desired_state<>'deleted' AND client_id IN ({placeholders}) ORDER BY created_at,id",
                list(grouped),
            ):
                grouped[row["client_id"]].append(_grant(row))
        counts = {key: 0 for key in ("active", "suspended", "archived")}
        counts.update(dict(db.execute("SELECT state,COUNT(*) FROM clients GROUP BY state")))
        node_ids = [row[0] for row in db.execute(
            "SELECT DISTINCT node_id FROM access_grants WHERE desired_state<>'deleted' ORDER BY node_id"
        )]
        return {
            "items": [(client, grouped[client.id]) for client in clients], "next_cursor": next_cursor,
            "matched": matched, "total": sum(counts.values()), "counts": counts, "node_ids": node_ids,
        }

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
