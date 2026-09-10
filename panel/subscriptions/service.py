"""Subscriptions: a bearer URL the panel can invalidate, and an ETag that means something.

Three rules shape this module.

The URL is a bearer credential, so only its hash is stored and the plaintext is returned
exactly once, at creation. Rotating issues a new one and revokes the old in the same
transaction — there is never a window with two live URLs for one client.

`generation` moves inside the transaction of the change that caused it. A rolled-back
mutation must not leave a bumped counter behind telling every client to re-fetch a
manifest that never changed.

The ETag is computed from the *effective* grants — what a client would receive right
now — and deliberately excludes `generation` and `last_fetched_at`. Reading a
subscription is not a change to it, and an ETag that moved on every fetch would make
conditional requests useless.
"""
from __future__ import annotations

import hashlib
import json
import secrets as secret_tokens
import time
import uuid

from ..audit import record
from ..clients.models import effective_enabled
from ..clients.store import ClientConflict
from .models import Manifest, ManifestGrant, Subscription
from .store import SubscriptionStore

TOKEN_BYTES = 32


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SubscriptionService:
    def __init__(self, database, clients, secret_store, clock=time, public_base: str = ""):
        self.database = database
        self.clients = clients
        self.secrets = secret_store
        self.clock = clock
        self.public_base = public_base
        self.store = SubscriptionStore()

    # --- lifecycle ----------------------------------------------------------------

    def _renderable(self, db, client_id: str) -> None:
        """Refuse a subscription the panel could not actually render."""
        orphans = [
            grant.runtime_username
            for grant in self.clients.store.grants(db, client_id=client_id)
            if grant.secret_ref is None
        ]
        if orphans:
            raise ClientConflict(
                "these accesses have no stored credential and would be missing from the "
                f"subscription: {', '.join(sorted(orphans))}"
            )

    def _issue(self, db, client_id: str, *, generation: int) -> tuple[Subscription, str]:
        now = int(self.clock.time())
        token = secret_tokens.token_urlsafe(TOKEN_BYTES)
        subscription = Subscription(
            id=str(uuid.uuid4()),
            client_id=client_id,
            generation=generation,
            state="active",
            update_interval_hours=12,
            last_fetched_at=None,
            created_at=now,
            updated_at=now,
        )
        self.store.insert(db, subscription, _hash(token))
        return subscription, token

    def create(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        with self.database.transaction() as db:
            client = self.clients.store.client(db, client_id)
            if client.state != "active":
                raise ClientConflict("only an active client can hold a subscription")
            if self.store.active(db, client_id) is not None:
                raise ClientConflict("the client already has an active subscription")
            self._renderable(db, client_id)
            subscription, token = self._issue(db, client_id, generation=1)
            record(
                db, actor=actor, action="subscription.create", target=subscription.id,
                ip=ip, request_id=request_id, generation=subscription.generation,
                detail={"client_id": client_id},
            )
        return subscription, token

    def rotate(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        """A new URL and the old one's revocation land together: never two live at once."""
        with self.database.transaction() as db:
            current = self.store.active(db, client_id)
            if current is None:
                raise ClientConflict("the client has no active subscription to rotate")
            self._renderable(db, client_id)
            now = int(self.clock.time())
            self.store.revoke(db, client_id, now=now)
            subscription, token = self._issue(db, client_id, generation=current.generation + 1)
            record(
                db, actor=actor, action="subscription.rotate", target=subscription.id,
                ip=ip, request_id=request_id, generation=subscription.generation,
                detail={"client_id": client_id, "revoked": current.id},
            )
        return subscription, token

    def revoke(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None) -> None:
        with self.database.transaction() as db:
            current = self.store.active(db, client_id)
            if current is None:
                return
            self.store.revoke(db, client_id, now=int(self.clock.time()))
            record(
                db, actor=actor, action="subscription.revoke", target=current.id,
                ip=ip, request_id=request_id, detail={"client_id": client_id},
            )

    def get(self, client_id: str) -> Subscription | None:
        with self.database.connect() as db:
            return self.store.active(db, client_id)

    def bump_generation(self, db, client_id: str) -> None:
        """Runs inside the caller's transaction: a rolled-back change bumps nothing."""
        self.store.bump(db, client_id, now=int(self.clock.time()))

    def resolve(self, token: str) -> Subscription | None:
        """Look a bearer token up by hash; an unknown or revoked one is simply absent."""
        if not isinstance(token, str) or not token:
            return None
        with self.database.connect() as db:
            return self.store.by_hash(db, _hash(token))

    def record_fetch(self, subscription_id: str, now: int) -> None:
        with self.database.transaction() as db:
            self.store.record_fetch(db, subscription_id, int(now))

    # --- manifest -----------------------------------------------------------------

    def effective_manifest(self, subscription: Subscription, now: int) -> Manifest:
        with self.database.connect() as db:
            client = self.clients.store.client(db, subscription.client_id)
            grants = self.clients.store.grants(db, client_id=subscription.client_id)
            current = self.store.active(db, subscription.client_id) or subscription
        return Manifest(
            client_id=client.id,
            client_name=client.display_name,
            generation=current.generation,
            grants=[
                ManifestGrant(
                    grant_id=grant.id,
                    protocol=grant.protocol,
                    node_id=grant.node_id,
                    endpoint_id=grant.endpoint_id,
                    runtime_username=grant.runtime_username,
                    secret_version=grant.secret_ref.version if grant.secret_ref else 0,
                    options=grant.options.model_dump(),
                    enabled=effective_enabled(grant, client, int(now)),
                    valid_from=grant.valid_from,
                    valid_until=grant.valid_until,
                )
                for grant in grants
            ],
        )

    @staticmethod
    def etag(manifest: Manifest, renderer_version: int) -> str:
        """What the client would receive, not when it last asked.

        `generation` and `last_fetched_at` are excluded on purpose: they move for
        reasons a client cannot see in the body, and an ETag that changes without the
        body changing defeats conditional requests.
        """
        payload = {
            "grants": sorted(
                (
                    {
                        "grant_id": item.grant_id,
                        "protocol": item.protocol,
                        "node_id": item.node_id,
                        "endpoint_id": item.endpoint_id,
                        "runtime_username": item.runtime_username,
                        "secret_version": item.secret_version,
                        "options": item.options,
                        "valid_from": item.valid_from,
                        "valid_until": item.valid_until,
                    }
                    for item in manifest.grants
                    if item.enabled
                ),
                key=lambda row: row["grant_id"],
            ),
            "renderer": renderer_version,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def public_url(self, token: str) -> str:
        return f"{self.public_base.rstrip('/')}/s/{token}"
