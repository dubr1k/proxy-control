"""Adopt what the managers already run, without touching them.

Every call here is a read. Import writes only the panel's own rows: it never creates,
rotates, enables or deletes a runtime account, so adopting an existing deployment
cannot break a link a real person is using today.

Grouping by identical username is offered as a hint and nothing more. Three managers
each having an "alice" is not evidence that they are the same person, and merging them
silently would hand one subscriber somebody else's access.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

from ..mieru import MieruError
from ..naive import NaiveError
from ..telemt import TelemtError
from .models import PROTOCOL_OPTIONS, AccessGrant, MieruOptions, MtproxyOptions, NaiveOptions
from .store import ClientStore

LOCAL_NODE_ID = "local"
DEFAULT_ENDPOINT = "default"


@dataclass(frozen=True)
class InventoryItem:
    protocol: str
    runtime_username: str
    enabled: bool
    options: dict
    imported_grant_id: str | None = None


@dataclass(frozen=True)
class ProposedClient:
    display_name: str
    items: list[InventoryItem]
    same_username_hint: bool


@dataclass(frozen=True)
class ImportDecision:
    display_name: str
    client_id: str | None
    items: list[tuple[str, str]]


@dataclass
class ImportResult:
    created_clients: int = 0
    created_grants: int = 0
    skipped: list[str] = field(default_factory=list)


def _integer(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _mtproxy_options(row: dict) -> dict:
    # Telemt reports expiration as an RFC 3339 string; MtproxyOptions holds an epoch,
    # so an imported grant carries no expiration until the operator sets one.
    return MtproxyOptions(
        data_quota_bytes=_integer(row.get("data_quota_bytes")),
        rate_limit_up_bps=_integer(row.get("rate_limit_up_bps")),
        rate_limit_down_bps=_integer(row.get("rate_limit_down_bps")),
        max_tcp_conns=_integer(row.get("max_tcp_conns")),
        max_unique_ips=_integer(row.get("max_unique_ips")),
    ).model_dump()


def _naive_options(row: dict) -> dict:
    return NaiveOptions(quota_bytes=_integer(row.get("quota_bytes"))).model_dump()


def _mieru_options(row: dict) -> dict:
    quotas = row.get("quotas")
    return MieruOptions(quotas=quotas if isinstance(quotas, list) else []).model_dump()


async def _read(call, error):
    """A manager that cannot be read contributes nothing; import is never blocked by it."""
    try:
        return await call()
    except error:
        return []


async def _nothing():
    return []


async def inventory(
    telemt, naive, mieru, *, naive_enabled: bool, mieru_enabled: bool, store: ClientStore, database, managed
) -> list[InventoryItem]:
    """What the managers run and this panel may adopt. Accounts the central panel owns
    (`managed_resources`, ADR 003) are its to import, so they never appear here."""
    telemt_rows, naive_rows, mieru_rows = await asyncio.gather(
        _read(telemt.list_users, TelemtError),
        _read(naive.list_users, NaiveError) if naive_enabled else _nothing(),
        _read(mieru.list_users, MieruError) if mieru_enabled else _nothing(),
    )
    collected: list[tuple[str, dict, dict]] = []
    for row in telemt_rows:
        if isinstance(row, dict) and isinstance(row.get("username"), str):
            collected.append(("mtproxy", row, _mtproxy_options(row)))
    for row in naive_rows:
        if isinstance(row, dict) and isinstance(row.get("username"), str):
            collected.append(("naive", row, _naive_options(row)))
    for row in mieru_rows:
        if isinstance(row, dict) and isinstance(row.get("username"), str):
            collected.append(("mieru", row, _mieru_options(row)))
    with database.connect() as db:
        central = managed.resources(db)
        return [
            InventoryItem(
                protocol=protocol,
                runtime_username=row["username"],
                enabled=row.get("enabled") is not False,
                options=options,
                imported_grant_id=_existing(store, db, protocol, row["username"]),
            )
            for protocol, row, options in collected
            if (protocol, row["username"]) not in central
        ]


def _existing(store: ClientStore, db, protocol: str, username: str) -> str | None:
    found = store.find_grant(db, protocol, LOCAL_NODE_ID, DEFAULT_ENDPOINT, username)
    return None if found is None else found.id


def propose(items: list[InventoryItem]) -> list[ProposedClient]:
    """One proposal per runtime account. A shared username only raises a flag."""
    shared = {
        item.runtime_username
        for item in items
        if len({other.protocol for other in items if other.runtime_username == item.runtime_username}) > 1
    }
    return [
        ProposedClient(
            display_name=item.runtime_username,
            items=[item],
            same_username_hint=item.runtime_username in shared,
        )
        for item in items
    ]


def confirm(
    service, decisions: list[ImportDecision], known: list[InventoryItem], *, actor: dict, ip: str, request_id: str | None
) -> ImportResult:
    """Every decision commits together: a rejected item leaves no half-imported client."""
    from ..audit import record  # noqa: PLC0415 - avoids a cycle with clients.service

    index = {(item.protocol, item.runtime_username): item for item in known}
    result = ImportResult()
    now = int(service.clock.time())
    with service.database.transaction() as db:
        for decision in decisions:
            client_id = decision.client_id
            if client_id is not None:
                service.store.client(db, client_id)
            pending = []
            for protocol, username in decision.items:
                item = index.get((protocol, username))
                if item is None:
                    raise ValueError(f"unknown runtime account: {protocol}/{username}")
                if item.imported_grant_id is not None:
                    result.skipped.append(f"{protocol}:{username}")
                    continue
                pending.append(item)
            if not pending:
                continue
            if client_id is None:
                client = service.new_client(db, decision.display_name, now=now)
                client_id = client.id
                result.created_clients += 1
            for item in pending:
                state = "enabled" if item.enabled else "disabled"
                service.store.insert_grant(
                    db,
                    AccessGrant(
                        id=str(uuid.uuid4()),
                        client_id=client_id,
                        protocol=item.protocol,
                        node_id=LOCAL_NODE_ID,
                        endpoint_id=DEFAULT_ENDPOINT,
                        runtime_username=item.runtime_username,
                        secret_ref=None,
                        desired_state=state,
                        observed_state=state,
                        options=PROTOCOL_OPTIONS[item.protocol].model_validate(item.options),
                        origin="imported",
                        created_at=now,
                        updated_at=now,
                    ),
                )
                result.created_grants += 1
            service.notify(db, client_id)
        record(
            db,
            actor=actor,
            action="client.import",
            target="import",
            ip=ip,
            request_id=request_id,
            detail={
                "created_clients": result.created_clients,
                "created_grants": result.created_grants,
                "skipped": result.skipped,
                # Runtime usernames are already visible in the panel; nothing else is recorded.
                "accounts": [f"{protocol}:{username}" for decision in decisions for protocol, username in decision.items],
            },
        )
    return result
