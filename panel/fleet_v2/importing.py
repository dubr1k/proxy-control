"""Adopting users a linked panel already runs (spec §6, ADR 003 `adopted`).

Nothing on the node's runtime changes here. The central reads the node's inventory,
captures the credentials the node can reveal, and writes its own rows — client, grant
with `origin="imported"`, secret version 1 `active` where a credential came back — in one
transaction with the audit row and the generation (`ClientService.notify` → `publish`).
That generation is what makes the node mark the users as the central's (a no-op apply,
see `Reconciler._apply_resource`). A user the node cannot reveal a credential for
(mieru) is imported without one: the subscription says so, and a rotation gives it one.

`auto_import` (owner decision 2026-09-18, «как в 3x-ui»): the pusher runs it on every
heartbeat of a link that has it on — every user the node runs on its own becomes the
central's client without anyone ticking boxes. One runtime name is one person: the grants
of `alice` on mtproxy, naive and mieru join one client «alice», on this node and on every
other node the central adopts from — the same rule 3x-ui applies to an email. A user the
operator imported by hand earlier is left where it is (`already_linked`).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from ..audit import record
from ..clients.importer import DEFAULT_ENDPOINT, OPTIONS_FROM_RUNTIME
from ..clients.models import PROTOCOL_OPTIONS, AccessGrant
from ..clients.service import CREDENTIAL_PURPOSE
from ..events import SYSTEM_ACTOR
from ..secrets_store import SecretRef

NEW_CLIENT = "new"


class UnknownClient(KeyError):
    """A decision names a client id this panel does not have."""


@dataclass(frozen=True)
class ImportItem:
    protocol: str
    runtime_username: str
    client: str  # NEW_CLIENT, or an existing client id


def _label(protocol: str, username: str) -> str:
    return f"{protocol}:{username}"


async def import_resources(state, node_id: str, decisions: list[ImportItem], *, actor: dict, ip: str,
                           request_id: str | None = None, inventory: dict | None = None, auto: bool = False) -> dict:
    """Import the given users of one linked panel. `KeyError` for an unknown node,
    `UnknownClient` for an unknown client id, `ValueError` for a user the node does not
    report or one another central already owns. Returns what was imported, which grants
    have no credential, and which users were skipped because a grant already exists.
    `inventory` is the node's `protocols` map when the caller already holds it."""
    clients, secrets = state.clients, state.secrets
    client = state.links.client_for(node_id)  # KeyError: not a linked panel
    if inventory is None:
        inventory = (await client.inventory()).get("protocols") or {}
    known = {(protocol, row["runtime_username"]): row for protocol, rows in inventory.items() for row in rows}
    pending, already_linked = [], []
    with state.database.connect() as db:
        for item in decisions:
            row = known.get((item.protocol, item.runtime_username))
            if row is None:
                raise ValueError(f"the node does not run {_label(item.protocol, item.runtime_username)}")
            if clients.store.find_grant(db, item.protocol, node_id, DEFAULT_ENDPOINT, item.runtime_username) is not None:
                # This central's own grant (auto-import got there first, or a repeated import):
                # idempotent, whatever the node reports as ownership by now.
                already_linked.append(_label(item.protocol, item.runtime_username))
                continue
            if row.get("ownership") == "central":
                # Owned by a central already — this one after a restore, or another one: never
                # two masters for one account, and never a silent takeover (ADR 003).
                raise ValueError(f"{_label(item.protocol, item.runtime_username)} is already managed by a central panel")
            if item.client != NEW_CLIENT:
                try:
                    clients.store.client(db, item.client)
                except KeyError as exc:
                    raise UnknownClient(item.client) from exc
            pending.append((item, row))
    if not pending:
        return {"imported": [], "without_credential": [], "already_linked": already_linked}
    # Read before anything is written: a node that cannot answer leaves no half-imported client.
    captured = await client.capture([{"protocol": item.protocol, "runtime_username": item.runtime_username}
                                     for item, _ in pending], purpose="import")
    credentials = captured.get("credentials") or {}
    now = int(clients.clock.time())
    imported, without_credential, touched, created = [], [], set(), 0
    with state.database.transaction() as db:
        for item, row in pending:
            if item.client == NEW_CLIENT:
                client_id = clients.new_client(db, item.runtime_username, now=now).id
                created += 1
            else:
                client_id = item.client
            grant_id = str(uuid.uuid4())
            label = _label(item.protocol, item.runtime_username)
            plaintext = credentials.get(label)
            reference = None
            if plaintext:
                # The credential the node runs today, escrowed as the version the generation
                # will name; `active` from the start — nothing has to confirm what already works.
                reference = secrets.store(
                    db, secret_id=f"grant:{grant_id}", version=1, purpose=CREDENTIAL_PURPOSE, grant_id=grant_id,
                    permitted_node_id=node_id, plaintext=plaintext.encode(), state="active",
                )
            else:
                without_credential.append(label)
            state_ = "enabled" if row.get("enabled") is not False else "disabled"
            clients.store.insert_grant(db, AccessGrant(
                id=grant_id, client_id=client_id, protocol=item.protocol, node_id=node_id,
                endpoint_id=DEFAULT_ENDPOINT, runtime_username=item.runtime_username,
                secret_ref=None if reference is None else SecretRef(reference.secret_id, reference.version),
                desired_state=state_, observed_state=state_,
                options=PROTOCOL_OPTIONS[item.protocol].model_validate(
                    OPTIONS_FROM_RUNTIME[item.protocol](row.get("options") or {})),
                origin="imported", created_at=now, updated_at=now,
            ))
            imported.append({"grant_id": grant_id, "client_id": client_id, "protocol": item.protocol,
                             "runtime_username": item.runtime_username, "has_credential": reference is not None})
            touched.add(client_id)
        record(db, actor=actor, action="node.import", target=node_id, ip=ip, request_id=request_id,
               detail={"auto": auto, "created_clients": created, "imported": [entry["grant_id"] for entry in imported],
                       # Runtime usernames are already visible in the panel; nothing else is recorded.
                       "accounts": [_label(item.protocol, item.runtime_username) for item, _ in pending],
                       "without_credential": without_credential, "already_linked": already_linked})
        for client_id in touched:
            clients.notify(db, client_id)  # → publish: the node adopts these users on the next push
    return {"imported": imported, "without_credential": without_credential, "already_linked": already_linked}


def _client_named(db, clients, name: str) -> str | None:
    """The client an auto-imported account joins: the one whose display name is exactly the
    runtime name (auto-import names clients that way), never an archived one."""
    for existing in clients.store.clients(db):
        if existing.display_name == name and existing.state != "archived":
            return existing.id
    return None


def plan_auto_import(db, clients, node_id: str, inventory: dict) -> list[ImportItem]:
    """Every user the node runs on its own that has no grant here yet, each joined to the
    client of its name (or a new one). Nothing owned by a central is touched."""
    decisions: list[ImportItem] = []
    assigned: dict[str, str] = {}
    for protocol in sorted(inventory):
        for row in inventory[protocol]:
            username = row.get("runtime_username")
            if not username or row.get("ownership") == "central":
                continue
            if clients.store.find_grant(db, protocol, node_id, DEFAULT_ENDPOINT, username) is not None:
                continue
            target = assigned.get(username) or _client_named(db, clients, username) or NEW_CLIENT
            decisions.append(ImportItem(protocol, username, target))
            if target != NEW_CLIENT:
                assigned[username] = target
    return decisions


async def auto_import(state, node_id: str, *, inventory: dict | None = None) -> dict | None:
    """One heartbeat's adoption for a link with `auto_import` on: None when the node runs
    nothing new. `import_resources` creates one client per `NEW_CLIENT` decision, so a name
    that has no client yet is imported one protocol first; the client then exists and the
    name's other protocols join it in a second pass."""
    client = state.links.client_for(node_id)
    if inventory is None:
        inventory = (await client.inventory()).get("protocols") or {}
    with state.database.connect() as db:
        decisions = plan_auto_import(db, state.clients, node_id, inventory)
    if not decisions:
        return None
    first: dict[str, ImportItem] = {}
    batch: list[ImportItem] = []
    for item in decisions:
        if item.client != NEW_CLIENT:
            batch.append(item)
        elif item.runtime_username not in first:
            first[item.runtime_username] = item
            batch.append(item)
    result = await import_resources(state, node_id, batch, actor=SYSTEM_ACTOR, ip="local", inventory=inventory, auto=True)
    if len(batch) < len(decisions):
        with state.database.connect() as db:
            rest = plan_auto_import(db, state.clients, node_id, inventory)
        if rest:
            more = await import_resources(state, node_id, rest, actor=SYSTEM_ACTOR, ip="local", inventory=inventory, auto=True)
            result = {key: result[key] + more[key] for key in result}
    return result
