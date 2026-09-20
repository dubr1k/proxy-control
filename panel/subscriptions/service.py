"""Subscriptions: a bearer URL the panel can invalidate, and an ETag that means something.

Three rules shape this module.

The URL is a bearer credential, so its hash is what `/s/{token}` looks up. With a keyring
the panel also keeps an encrypted copy so an operator can see the URL again; every such
reveal is an audit row, and a rotated or revoked URL retires its copy in the same
transaction. Rotating issues a new one and revokes the old in the same transaction —
there is never a window with two live URLs for one client.

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

from ..audit import digest, record
from ..clients.models import effective_enabled
from ..clients.store import ClientConflict
from ..secrets_store import SecretError, SecretRef
from .models import Manifest, ManifestGrant, Subscription
from .store import SubscriptionStore

TOKEN_BYTES = 32
SUBSCRIPTION_PURPOSE = "subscription"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SubscriptionService:
    def __init__(self, database, clients, secret_store, clock=time, public_base: str = "", events=None):
        self.database = database
        self.clients = clients
        self.secrets = secret_store
        self.clock = clock
        self.public_base = public_base
        # Optional `EventBus`: events ride in the same transaction as the change they report.
        self.events = events
        self.store = SubscriptionStore()

    def _emit(self, db, name: str, payload: dict) -> None:
        if self.events is not None:
            self.events.emit(db, name, payload)

    # --- lifecycle ----------------------------------------------------------------

    @property
    def escrow_enabled(self) -> bool:
        return self.secrets is not None and self.secrets.enabled

    def _issue(self, db, client_id: str, *, generation: int) -> tuple[Subscription, str]:
        now = int(self.clock.time())
        token = secret_tokens.token_urlsafe(TOKEN_BYTES)
        subscription_id = str(uuid.uuid4())
        secret_ref: SecretRef | None = None
        if self.escrow_enabled:
            # The AAD binds the ciphertext to this subscription id: a row cannot be moved
            # under another client, and the purpose keeps grant reveals from opening it.
            secret_ref = self.secrets.store(
                db, secret_id=f"subscription:{subscription_id}", version=1,
                purpose=SUBSCRIPTION_PURPOSE, grant_id=None, permitted_node_id=None,
                plaintext=token.encode(), state="active",
            )
        subscription = Subscription(
            id=subscription_id,
            client_id=client_id,
            generation=generation,
            state="active",
            update_interval_hours=12,
            last_fetched_at=None,
            created_at=now,
            updated_at=now,
            secret_ref=secret_ref,
        )
        self.store.insert(db, subscription, _hash(token))
        return subscription, token

    def _retire_escrow(self, db, subscription: Subscription) -> None:
        """A rotated or revoked URL must not be showable: the ciphertext row is revoked too.

        `transition` only flips a state column — it needs no key material — so this must
        run whenever the subscription was ever escrowed, even if the keyring has since been
        disabled. Gating on `escrow_enabled` here would leave an old row stuck `active`
        forever once the keyring goes away.
        """
        if subscription.secret_ref is not None and self.secrets is not None:
            self.secrets.transition(db, subscription.secret_ref, "revoked")

    def create(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        with self.database.transaction() as db:
            client = self.clients.store.client(db, client_id)
            if client.state != "active":
                raise ClientConflict("only an active client can hold a subscription")
            if self.store.active(db, client_id) is not None:
                raise ClientConflict("the client already has an active subscription")
            subscription, token = self._issue(db, client_id, generation=1)
            record(
                db, actor=actor, action="subscription.create", target=subscription.id,
                ip=ip, request_id=request_id, generation=subscription.generation,
                detail={"client_id": client_id},
            )
        return subscription, token

    def create_with_client(self, display_name: str, *, actor: dict, ip: str, request_id: str | None = None):
        """A client and its URL in one transaction: the operator sees the link on the same
        screen the client was made on. Without a subscription domain only the client is made."""
        now = int(self.clock.time())
        with self.database.transaction() as db:
            client = self.clients.new_client(db, display_name, now=now)
            record(
                db, actor=actor, action="client.create", target=client.id, ip=ip,
                request_id=request_id, after_digest=digest(client.model_dump()),
            )
            self.clients.notify(db, client.id)
            if not self.public_base:
                return client, None, None
            subscription, token = self._issue(db, client.id, generation=1)
            record(
                db, actor=actor, action="subscription.create", target=subscription.id,
                ip=ip, request_id=request_id, generation=subscription.generation,
                detail={"client_id": client.id},
            )
        return client, subscription, token

    def rotate(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        """A new URL and the old one's revocation land together: never two live at once."""
        with self.database.transaction() as db:
            current = self.store.active(db, client_id)
            if current is None:
                raise ClientConflict("the client has no active subscription to rotate")
            now = int(self.clock.time())
            self.store.revoke(db, client_id, now=now)
            self._retire_escrow(db, current)
            subscription, token = self._issue(db, client_id, generation=current.generation + 1)
            record(
                db, actor=actor, action="subscription.rotate", target=subscription.id,
                ip=ip, request_id=request_id, generation=subscription.generation,
                detail={"client_id": client_id, "revoked": current.id},
            )
            self._emit(db, "subscription.revoked", {
                "subscription_id": current.id, "client_id": client_id, "reason": "rotated",
            })
        return subscription, token

    def revoke(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None) -> None:
        with self.database.transaction() as db:
            current = self.store.active(db, client_id)
            if current is None:
                return
            self.store.revoke(db, client_id, now=int(self.clock.time()))
            self._retire_escrow(db, current)
            record(
                db, actor=actor, action="subscription.revoke", target=current.id,
                ip=ip, request_id=request_id, detail={"client_id": client_id},
            )
            self._emit(db, "subscription.revoked", {
                "subscription_id": current.id, "client_id": client_id, "reason": "revoked",
            })

    def reveal_token(self, client_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        """Open the escrowed token for an operator: audited, never logged, never cached."""
        with self.database.transaction() as db:
            self.clients.store.client(db, client_id)  # KeyError when the client is unknown
            current = self.store.active(db, client_id)
            if current is None:
                raise KeyError(client_id)
            if not self.escrow_enabled:
                raise SecretError("secret store is disabled: PANEL_MASTER_KEY_FILE is not configured")
            if current.secret_ref is None:
                raise ClientConflict("subscription is not escrowed: rotate it to get a URL that can be shown")
            token = self.secrets.reveal(
                db, current.secret_ref, purpose=SUBSCRIPTION_PURPOSE, grant_id=None, permitted_node_id=None,
            ).decode()
            record(
                db, actor=actor, action="subscription.reveal", target=current.id,
                ip=ip, request_id=request_id, generation=current.generation,
                detail={"client_id": client_id},
            )
        return current, token

    def get(self, client_id: str) -> Subscription | None:
        with self.database.connect() as db:
            return self.store.active(db, client_id)

    def bump_generation(self, db, client_id: str) -> None:
        """Runs inside the caller's transaction: a rolled-back change bumps nothing."""
        if not self.store.bump(db, client_id, now=int(self.clock.time())):
            return
        current = self.store.active(db, client_id)
        self._emit(db, "subscription.generation.changed", {
            "subscription_id": current.id, "client_id": client_id, "generation": current.generation,
        })

    def resolve(self, token: str) -> Subscription | None:
        """Look a bearer token up by hash; an unknown or revoked one is simply absent."""
        if not isinstance(token, str) or not token:
            return None
        with self.database.connect() as db:
            return self.store.by_hash(db, _hash(token))

    def record_fetch(self, subscription: Subscription, now: int, *, status: int, format: str) -> None:
        """One transaction: the last-fetched mark and the event that says a client came by."""
        with self.database.transaction() as db:
            self.store.record_fetch(db, subscription.id, int(now))
            self._emit(db, "subscription.fetched", {
                "subscription_id": subscription.id, "client_id": subscription.client_id,
                "status": status, "format": format,
            })

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
    def etag(manifest: Manifest, renderer_version: int, variant: str = "") -> str:
        """What the client would receive, not when it last asked.

        `generation` and `last_fetched_at` are excluded on purpose: they move for
        reasons a client cannot see in the body, and an ETag that changes without the
        body changing defeats conditional requests. `variant` names a per-client
        rendering of the same format (the sing-box feed without mieru, for one), so
        two bodies that differ never share a tag.
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
            "variant": variant,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def public_url(self, token: str) -> str:
        return f"{self.public_base.rstrip('/')}/s/{token}"
