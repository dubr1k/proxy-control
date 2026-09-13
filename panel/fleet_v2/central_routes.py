"""The central's operator API for linked panels (spec §6): link, pause, probe, import,
versions, generations — and the per-node public hosts the subscription renderers use.

Every mutation is owner-only over a session (CSRF) or an admin API key, like the rest of
`/api/nodes`; reads are for owner and admin. Replies never carry the node's API key: the
link view says only that one is stored. What the node itself refuses is answered with a
code the UI can act on (`node_unreachable`, `node_auth_failed`, or the node's own).
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Literal

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..clients.importer import DEFAULT_ENDPOINT
from ..clients.store import ClientConflict
from ..nodes.models import LOCAL_NODE_ID
from ..schemas import NodeFingerprint, NodeImport, NodeLinkCreate, NodeLinkTest, NodeLinkUpdate, NodeVersionUpdate
from ..secrets_store import SecretError
from ..web_context import RequestContext
from .client import NodeAuthFailed, NodeRejected, NodeUnreachable, fingerprint, validate_panel_url
from .importing import ImportItem, UnknownClient, import_resources
from .links import LinkConflict

PROTOCOLS = ("mtproxy", "naive", "mieru")
# A linked panel is the only node whose credentials/versions the central operates by hand;
# the central's own runtime keeps its existing routes.
NOT_A_LINKED_PANEL = "the local node has its own routes for this"


def public_hosts_for(state, node_id: str) -> dict[str, str]:
    """Public host per protocol for the node a grant lives on: a linked panel's come from
    the identity it reported last (heartbeat), everything else from this panel's settings."""
    if node_id != LOCAL_NODE_ID:
        with state.database.connect() as db:
            try:
                link = state.links.link(db, node_id)
            except KeyError:
                link = None
        if link is not None:
            protocols = link["identity"].get("protocols") or {}
            return {protocol: str((protocols.get(protocol) or {}).get("public_host") or "") for protocol in PROTOCOLS}
    settings = state.settings
    return {
        "naive": settings.naive_public_host,
        "mtproxy": settings.mtproxy_host,
        "mieru": settings.naive_public_host,
    }


def _refusal(status: int, code: str, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail, "code": code}, status)


def register_fleet_v2_central_routes(app, context: RequestContext) -> None:
    owner = context.roles("owner")
    reader = context.read_roles("owner", "admin")

    # What the node answered — or did not — is the same failure whichever route asked.
    @app.exception_handler(NodeUnreachable)
    async def node_unreachable(_request, exc):
        return _refusal(502, "node_unreachable", f"the node is unreachable: {exc}")

    @app.exception_handler(NodeAuthFailed)
    async def node_auth_failed(_request, _exc):
        return _refusal(409, "node_auth_failed", "the node refused the API key")

    @app.exception_handler(NodeRejected)
    async def node_rejected(_request, exc):
        return _refusal(502, exc.code or "node_rejected", f"the node answered {exc.status}: {exc}")

    @app.exception_handler(LinkConflict)
    async def link_conflict(_request, exc):
        return JSONResponse({"detail": str(exc)}, 409)

    def _view(node_id: str) -> dict:
        try:
            return asdict(app.state.nodes.get(node_id))
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc

    def _linked(node_id: str) -> None:
        """Only a linked panel passes: the local node is refused, an unknown id is not found."""
        if node_id == LOCAL_NODE_ID:
            raise HTTPException(422, NOT_A_LINKED_PANEL)
        with app.state.database.connect() as db:
            try:
                app.state.links.link(db, node_id)
            except KeyError as exc:
                raise HTTPException(404, "node not found") from exc

    @app.post("/api/nodes/fingerprint")
    async def node_fingerprint(body: NodeFingerprint, _user=Depends(owner)):
        """SHA-256 of the certificate the panel at `url` presents, for pin-on-trust (spec §4)."""
        try:
            url = validate_panel_url(body.url, allow_private=True)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        try:
            return {"sha256": await asyncio.to_thread(fingerprint, url)}
        except OSError as exc:  # DNS, connect, timeout and TLS errors alike
            raise NodeUnreachable(type(exc).__name__) from exc

    @app.post("/api/nodes/test")
    async def node_test(body: NodeLinkTest, _user=Depends(owner)):
        try:
            return await app.state.links.test(body.url, body.api_key, body.tls_verify, body.pinned_sha256,
                                              body.allow_private_address)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/nodes/link", status_code=201)
    async def node_link(body: NodeLinkCreate, request: Request, user=Depends(owner)):
        try:
            node_id = await app.state.links.add(body.display_name, body.url, body.api_key, body.tls_verify,
                                                body.pinned_sha256, body.allow_private_address,
                                                **context.domain_context(request, user))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"node_id": node_id}

    @app.post("/api/nodes/{node_id}/link")
    async def node_link_update(node_id: str, body: NodeLinkUpdate, request: Request, user=Depends(owner)):
        try:
            await asyncio.to_thread(
                app.state.links.update, node_id, display_name=body.display_name, url=body.url, api_key=body.api_key,
                tls_verify=body.tls_verify, pinned_sha256=body.pinned_sha256, **context.domain_context(request, user),
            )
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return await asyncio.to_thread(_view, node_id)

    async def _set_enabled(node_id: str, enabled: bool, request: Request, user: dict) -> dict:
        try:
            await asyncio.to_thread(app.state.links.set_enabled, node_id, enabled, **context.domain_context(request, user))
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        return await asyncio.to_thread(_view, node_id)

    @app.post("/api/nodes/{node_id}/pause")
    async def node_pause(node_id: str, request: Request, user=Depends(owner)):
        return await _set_enabled(node_id, False, request, user)

    @app.post("/api/nodes/{node_id}/resume")
    async def node_resume(node_id: str, request: Request, user=Depends(owner)):
        return await _set_enabled(node_id, True, request, user)

    @app.post("/api/nodes/{node_id}/probe")
    async def node_probe(node_id: str, _user=Depends(owner)):
        """Heartbeat and delivery for this node now, not on the next tick."""
        _linked(node_id)
        await app.state.pusher.sync_node(node_id)
        return await asyncio.to_thread(_view, node_id)

    @app.delete("/api/nodes/{node_id}")
    async def node_unlink(node_id: str, request: Request, user=Depends(owner)):
        if node_id == LOCAL_NODE_ID:
            raise HTTPException(422, NOT_A_LINKED_PANEL)
        try:
            await app.state.links.delete(node_id, **context.domain_context(request, user))
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        return {"ok": True}

    @app.get("/api/nodes/{node_id}/inventory")
    async def node_inventory(node_id: str, _user=Depends(reader)):
        """The node's runtime users per protocol, each with the grant this panel already
        holds for it (`linked_grant_id`), so the import step can offer only the rest."""
        _linked(node_id)
        table = (await app.state.links.client_for(node_id).inventory()).get("protocols") or {}
        store = app.state.clients.store
        with app.state.database.connect() as db:
            for protocol, rows in table.items():
                for row in rows:
                    found = store.find_grant(db, protocol, node_id, DEFAULT_ENDPOINT, row["runtime_username"])
                    row["linked_grant_id"] = None if found is None else found.id
        return {"protocols": table}

    @app.post("/api/nodes/{node_id}/import")
    async def node_import(node_id: str, body: NodeImport, request: Request, user=Depends(owner)):
        _linked(node_id)
        decisions = [ImportItem(item.protocol, item.runtime_username, item.client) for item in body.resources]
        try:
            return await import_resources(app.state, node_id, decisions, **context.domain_context(request, user))
        except UnknownClient as exc:
            raise HTTPException(404, "client not found") from exc
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except SecretError as exc:
            # Without a master key a captured credential has nowhere to go (ADR 005).
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/nodes/{node_id}/versions/{component}")
    async def node_version_update(node_id: str, component: Literal["telemt", "naive", "mita"], body: NodeVersionUpdate,
                                  request: Request, user=Depends(owner)):
        _linked(node_id)
        result = await app.state.links.client_for(node_id).update_version(component, body.version, body.expected_current)
        await context.audit(user, "node.version.update", node_id, request,
                            {"component": component, "version": body.version})
        return result

    @app.get("/api/nodes/{node_id}/generations")
    async def node_generations(node_id: str, _user=Depends(reader)):
        """What the central wants the node to run and what the node last reported: numbers,
        digests and per-resource states — credentials travel by reference only."""
        def read() -> dict:
            with app.state.database.connect() as db:
                try:
                    app.state.links.link(db, node_id)
                except KeyError as exc:
                    raise HTTPException(404, "node not found") from exc
                desired = app.state.desired.latest(db, node_id)
                observed = app.state.desired.observed(db, node_id)
            if desired is not None:
                document = desired.pop("document")
                desired["resources"] = [item.model_dump() for item in document.resources]
                desired["created_at"] = document.created_at
            return {"desired": desired, "observed": None if observed is None else observed.model_dump()}

        return await asyncio.to_thread(read)
