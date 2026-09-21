"""Subscription rows. The token itself is written only as a hash; its escrowed copy lives
in `secret_versions` and the row keeps a reference."""
from __future__ import annotations

from ..secrets_store import SecretRef
from .models import Subscription

COLUMNS = (
    "id, client_id, generation, state, update_interval_hours, last_fetched_at, "
    "created_at, updated_at, revoked_at, secret_id, secret_version"
)


def to_subscription(row) -> Subscription:
    return Subscription(
        id=row["id"],
        client_id=row["client_id"],
        generation=row["generation"],
        state=row["state"],
        update_interval_hours=row["update_interval_hours"],
        last_fetched_at=row["last_fetched_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        revoked_at=row["revoked_at"],
        secret_ref=SecretRef(row["secret_id"], row["secret_version"]) if row["secret_id"] else None,
    )


class SubscriptionStore:
    @staticmethod
    def insert(db, subscription: Subscription, token_hash: str) -> None:
        ref = subscription.secret_ref
        db.execute(
            """INSERT INTO client_subscriptions(id,client_id,public_token_hash,generation,state,
               update_interval_hours,last_fetched_at,created_at,updated_at,revoked_at,secret_id,secret_version)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                subscription.id, subscription.client_id, token_hash, subscription.generation,
                subscription.state, subscription.update_interval_hours, subscription.last_fetched_at,
                subscription.created_at, subscription.updated_at, subscription.revoked_at,
                ref.secret_id if ref else None, ref.version if ref else None,
            ),
        )

    @staticmethod
    def active(db, client_id: str) -> Subscription | None:
        row = db.execute(
            f"SELECT {COLUMNS} FROM client_subscriptions WHERE client_id=? AND state='active'",
            (client_id,),
        ).fetchone()
        return None if row is None else to_subscription(row)

    @staticmethod
    def by_hash(db, token_hash: str) -> Subscription | None:
        row = db.execute(
            f"SELECT {COLUMNS} FROM client_subscriptions WHERE public_token_hash=? AND state='active'",
            (token_hash,),
        ).fetchone()
        return None if row is None else to_subscription(row)

    @staticmethod
    def revoke(db, client_id: str, *, now: int) -> int:
        return db.execute(
            "UPDATE client_subscriptions SET state='revoked',revoked_at=?,updated_at=?"
            " WHERE client_id=? AND state='active'",
            (now, now, client_id),
        ).rowcount

    @staticmethod
    def bump(db, client_id: str, *, now: int) -> int:
        return db.execute(
            "UPDATE client_subscriptions SET generation=generation+1,updated_at=?"
            " WHERE client_id=? AND state='active'",
            (now, client_id),
        ).rowcount

    @staticmethod
    def record_fetch(db, subscription_id: str, now: int) -> None:
        db.execute(
            "UPDATE client_subscriptions SET last_fetched_at=? WHERE id=?", (now, subscription_id)
        )
