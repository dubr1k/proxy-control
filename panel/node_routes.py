"""Operator-facing node API: lifecycle actions, never raw transport plumbing."""
from __future__ import annotations

import asyncio
from dataclasses import asdict

from fastapi import Depends, HTTPException, Request

from .fleet import ProtocolError
from .mieru import MieruError
from .naive import NaiveError
from .nodes.service import NodeConflict
from .schemas import NodeCreate, NodeRename, NodeRevokeAll
from .telemt import TelemtError
from .web_context import RequestContext

# What the operator still has to do by hand after registering a node. The private
# key never leaves the node, so the panel can only describe the steps.
ENROLLMENT_CHECKLIST = (
    "On the panel host, once per fleet: python -m panel.cli fleet-ca-init --ca-dir /etc/mtproxy-fleet-ca",
    "On the node: openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
    " -keyout /etc/mtproxy-agent/client.key -out /tmp/node.csr -subj \"/CN={node_id}\"",
    "Copy only the CSR to the panel host, never the key",
    "python -m panel.cli fleet-sign-csr {node_id} --ca-dir /etc/mtproxy-fleet-ca --csr /tmp/node.csr"
    " --out /tmp/node.crt",
    "python -m panel.cli fleet-bind-cert {node_id} --cert /tmp/node.crt",
    "On the node, set FLEET_NODE_ID={node_id}, FLEET_CENTRAL_URL, FLEET_CLIENT_CERT and"
    " FLEET_CLIENT_KEY in .env, then start compose.agent.yaml",
)


def _view(node) -> dict:
    return asdict(node)


async def _switched_off() -> str:
    return "disabled"


async def _probe(health, error) -> str:
    """A manager that answers at all is `ok`: every client raises on a non-2xx reply."""
    try:
        await health()
    except error:
        return "unavailable"
    return "ok"


async def _local_services(app, settings) -> dict[str, str]:
    """The local node has no transport, so its health is the health of the three managers."""
    telemt, naive, mieru = await asyncio.gather(
        _probe(app.state.telemt.health, TelemtError),
        _probe(app.state.naive.health, NaiveError) if settings.naive_enabled else _switched_off(),
        _probe(app.state.mieru.health, MieruError) if settings.mieru_enabled else _switched_off(),
    )
    return {"telemt": telemt, "naive": naive, "mieru": mieru}


def register_node_routes(app, context: RequestContext) -> None:
    def _context(request: Request, user: dict) -> dict:
        return {
            "actor": user,
            "ip": context.client_ip(request),
            "request_id": getattr(request.state, "request_id", None),
        }

    async def _rendered(node) -> dict:
        view = _view(node)
        if node.kind == "local":
            view["services"] = await _local_services(app, context.settings)
        return view

    @app.get("/api/nodes")
    async def nodes(_user=Depends(context.current)):
        items = await asyncio.to_thread(app.state.nodes.list)
        return {"items": [await _rendered(item) for item in items]}

    @app.get("/api/nodes/{node_id}")
    async def node(node_id: str, _user=Depends(context.current)):
        try:
            found = await asyncio.to_thread(app.state.nodes.get, node_id)
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        return await _rendered(found)

    @app.post("/api/nodes", status_code=201)
    async def register(
        body: NodeCreate,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            view = await asyncio.to_thread(
                app.state.nodes.register, body.node_id, body.display_name, **_context(request, user)
            )
        except NodeConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ProtocolError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {
            "node": _view(view),
            "enrollment_checklist": [step.format(node_id=body.node_id) for step in ENROLLMENT_CHECKLIST],
        }

    @app.post("/api/nodes/{node_id}/rename")
    async def rename(
        node_id: str,
        body: NodeRename,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            return _view(
                await asyncio.to_thread(
                    app.state.nodes.rename, node_id, body.display_name, **_context(request, user)
                )
            )
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except NodeConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ProtocolError as exc:
            raise HTTPException(422, str(exc)) from exc

    async def _set_disabled(node_id: str, disabled: bool, request: Request, user: dict) -> dict:
        try:
            return _view(
                await asyncio.to_thread(
                    app.state.nodes.set_disabled, node_id, disabled, **_context(request, user)
                )
            )
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except NodeConflict as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/nodes/{node_id}/disable")
    async def disable(node_id: str, request: Request, user=Depends(context.roles("owner"))):
        return await _set_disabled(node_id, True, request, user)

    @app.post("/api/nodes/{node_id}/enable")
    async def enable(node_id: str, request: Request, user=Depends(context.roles("owner"))):
        return await _set_disabled(node_id, False, request, user)

    @app.post("/api/nodes/{node_id}/certificates/revoke-all")
    async def revoke_all(
        node_id: str,
        body: NodeRevokeAll,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            revoked = await asyncio.to_thread(
                app.state.nodes.revoke_all_certificates,
                node_id,
                confirm=body.confirm,
                **_context(request, user),
            )
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except NodeConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"revoked": revoked}
