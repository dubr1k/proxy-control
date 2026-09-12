"""Client API: read for everyone, changes for owner/admin, import strictly read-only upstream."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Literal

from fastapi import Depends, HTTPException, Request

from .clients import importer
from .clients.models import PROTOCOL_OPTIONS, GrantIntent
from .clients.store import ClientConflict
from .protocols.base import AdapterError, ManualInterventionRequired
from .secrets_store import SecretError
from .schemas import (
    ClientCreate,
    ClientImport,
    ClientState,
    GrantAdopt,
    GrantAdoptBatch,
    GrantsCreate,
)
from .web_context import RequestContext


def _grant(grant) -> dict:
    return {**grant.model_dump(), "secret_ref": asdict(grant.secret_ref) if grant.secret_ref else None}


def _client(client, grants) -> dict:
    return {"client": client.model_dump(), "grants": [_grant(grant) for grant in grants]}


def register_client_routes(app, context: RequestContext) -> None:
    def _context(request: Request, user: dict) -> dict:
        return {
            "actor": user,
            "ip": context.client_ip(request),
            "request_id": getattr(request.state, "request_id", None),
        }

    def _listing() -> list[dict]:
        service = app.state.clients
        with service.database.connect() as db:
            return [
                _client(client, service.store.grants(db, client_id=client.id))
                for client in service.store.clients(db)
            ]

    async def _inventory() -> list[importer.InventoryItem]:
        service = app.state.clients
        return await importer.inventory(
            app.state.telemt,
            app.state.naive,
            app.state.mieru,
            naive_enabled=context.settings.naive_enabled,
            mieru_enabled=context.settings.mieru_enabled,
            store=service.store,
            database=service.database,
            managed=app.state.managed,
        )

    @app.get("/api/clients")
    async def clients(_user=Depends(context.current)):
        return {"items": await asyncio.to_thread(_listing)}

    @app.post("/api/clients", status_code=201)
    async def create(body: ClientCreate, request: Request, user=Depends(context.roles("owner", "admin"))):
        client = await asyncio.to_thread(
            app.state.clients.create_client, body.display_name, **_context(request, user)
        )
        return client.model_dump()

    @app.get("/api/clients/import/inventory")
    async def import_inventory(_user=Depends(context.read_roles("owner", "admin"))):
        items = await _inventory()
        proposals = importer.propose(items)
        return {
            "proposals": [
                {
                    "display_name": proposal.display_name,
                    "same_username_hint": proposal.same_username_hint,
                    "items": [asdict(item) for item in proposal.items],
                }
                for proposal in proposals
            ],
            "already_imported": sum(1 for item in items if item.imported_grant_id is not None),
        }

    @app.post("/api/clients/import")
    async def import_confirm(
        body: ClientImport, request: Request, user=Depends(context.roles("owner", "admin"))
    ):
        known = await _inventory()
        decisions = [
            importer.ImportDecision(
                display_name=decision.display_name,
                client_id=decision.client_id,
                items=[(protocol, username) for protocol, username in decision.items],
            )
            for decision in body.decisions
        ]
        try:
            result = await asyncio.to_thread(
                importer.confirm, app.state.clients, decisions, known, **_context(request, user)
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(404, "client not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        return asdict(result)

    async def _adopt(grant_id: str, allow_rotation: bool, request: Request, user: dict) -> dict:
        try:
            grant = await app.state.clients.adopt_credential(
                grant_id, allow_rotation=allow_rotation, **_context(request, user)
            )
        except KeyError as exc:
            raise HTTPException(404, "grant not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ManualInterventionRequired as exc:
            raise HTTPException(409, str(exc)) from exc
        except AdapterError as exc:
            raise HTTPException(502, str(exc)) from exc
        except SecretError as exc:
            # Without a master key there is nowhere to put the credential; adopting
            # anyway would rotate the subscriber's link and then drop the result.
            raise HTTPException(409, str(exc)) from exc
        return {
            "grant_id": grant.id,
            "protocol": grant.protocol,
            "runtime_username": grant.runtime_username,
            "adopted": grant.secret_ref is not None,
        }

    @app.post("/api/clients/grants/{grant_id}/adopt")
    async def adopt(
        grant_id: str, body: GrantAdopt, request: Request, user=Depends(context.roles("owner", "admin"))
    ):
        return await _adopt(grant_id, body.allow_rotation, request, user)

    @app.post("/api/clients/grants/adopt-batch")
    async def adopt_batch(
        body: GrantAdoptBatch, request: Request, user=Depends(context.roles("owner", "admin"))
    ):
        """Adopt every grant of one protocol that still has no stored credential."""
        service = app.state.clients
        with service.database.connect() as db:
            pending = [
                grant.id
                for grant in service.store.grants(db, protocol=body.protocol)
                if grant.secret_ref is None
            ]
        adopted, refused = [], []
        for grant_id in pending:
            try:
                result = await _adopt(grant_id, body.allow_rotation, request, user)
            except HTTPException as exc:
                # One refusal must not hide the grants that were adopted before it.
                refused.append({"grant_id": grant_id, "detail": exc.detail})
            else:
                adopted.append(result)
        return {"adopted": adopted, "refused": refused}

    @app.post("/api/clients/grants/{grant_id}/{action}")
    async def grant_action(
        grant_id: str,
        action: Literal["enable", "disable", "rotate", "delete"],
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        """One grant, local or on a linked panel; a remote change only records what the
        central wants and the pusher delivers it (the reply never carries a credential)."""
        service = app.state.lifecycle
        try:
            if action in ("enable", "disable"):
                grant = await service.set_enabled(grant_id, action == "enable", **_context(request, user))
            elif action == "rotate":
                grant = await service.rotate(grant_id, **_context(request, user))
            else:
                await service.delete(grant_id, **_context(request, user))
                return {"ok": True}
        except KeyError as exc:
            raise HTTPException(404, "grant not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ManualInterventionRequired as exc:
            raise HTTPException(409, str(exc)) from exc
        except AdapterError as exc:
            raise HTTPException(502, str(exc)) from exc
        except SecretError as exc:
            # Without a master key a rotated credential has nowhere to go.
            raise HTTPException(409, str(exc)) from exc
        return _grant(grant)

    @app.post("/api/clients/{client_id}/grants")
    async def create_grants(
        client_id: str, body: GrantsCreate, request: Request, user=Depends(context.roles("owner", "admin"))
    ):
        try:
            intents = [
                GrantIntent(
                    protocol=item.protocol,
                    node_id=item.node_id,
                    runtime_username=item.runtime_username,
                    options=PROTOCOL_OPTIONS[item.protocol].model_validate(item.options),
                    valid_from=item.valid_from,
                    valid_until=item.valid_until,
                )
                for item in body.grants
            ]
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        service = app.state.provisioning
        try:
            operation_id = await service.start(client_id, intents, **_context(request, user))
        except KeyError as exc:
            raise HTTPException(404, "client not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except AdapterError as exc:
            raise HTTPException(502, str(exc)) from exc
        result = await service.run(operation_id)
        return {"operation_id": operation_id, "status": result.status}

    @app.get("/api/operations/{operation_id}")
    async def operation(operation_id: str, _user=Depends(context.read_roles("owner", "admin"))):
        try:
            return await asyncio.to_thread(app.state.provisioning.status, operation_id)
        except KeyError as exc:
            raise HTTPException(404, "operation not found") from exc

    @app.post("/api/operations/{operation_id}/resume")
    async def resume(operation_id: str, _request: Request, _user=Depends(context.roles("owner", "admin"))):
        try:
            result = await app.state.provisioning.run(operation_id)
        except KeyError as exc:
            raise HTTPException(404, "operation not found") from exc
        return {"operation_id": operation_id, "status": result.status}

    @app.post("/api/operations/{operation_id}/bundle")
    async def bundle(operation_id: str, _request: Request, user=Depends(context.roles("owner", "admin"))):
        """One reveal for every artifact of the operation, rendered from escrow."""
        hosts = {
            "naive": context.settings.naive_public_host,
            "mtproxy": context.settings.allowed_hosts[0] if context.settings.allowed_hosts else "",
            "mieru": context.settings.naive_public_host,
        }
        try:
            payload = await asyncio.to_thread(
                app.state.provisioning.bundle, operation_id, public_hosts=hosts
            )
        except KeyError as exc:
            raise HTTPException(404, "operation not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"reveal_token": context.create_reveal(payload, user)}

    @app.get("/api/clients/{client_id}")
    async def client(client_id: str, _user=Depends(context.current)):
        try:
            found, grants = await asyncio.to_thread(app.state.clients.client_with_grants, client_id)
        except KeyError as exc:
            raise HTTPException(404, "client not found") from exc
        return _client(found, grants)

    @app.post("/api/clients/{client_id}/state")
    async def state(
        client_id: str, body: ClientState, request: Request, user=Depends(context.roles("owner", "admin"))
    ):
        try:
            changed = await asyncio.to_thread(
                app.state.clients.set_state, client_id, body.state, **_context(request, user)
            )
        except KeyError as exc:
            raise HTTPException(404, "client not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        return changed.model_dump()
