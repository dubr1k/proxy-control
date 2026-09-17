"""The routing API (spec §8.1): owner for mutations, any role for reading and previewing."""
from __future__ import annotations

from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..web_context import RequestContext
from .lanes import DEFAULT_RELAY_PORT, LaneError
from .models import LANE_SERVICE, PolicyInput, RoutingPolicy
from .service import RoutingError


class PolicyPut(PolicyInput):
    """The policy plus the revision the operator edited; None on a first save."""

    expected_revision: int | None = Field(default=None, ge=0)


class RevisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=1)


class ExplainBody(BaseModel):
    """«Куда пойдёт…» (v0.7): a host or address and a port, walked through the lane's rules."""

    model_config = ConfigDict(extra="forbid")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


class RelayEnableBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: int = Field(default=DEFAULT_RELAY_PORT, ge=1024, le=65535)


class LaneModeBody(BaseModel):
    """A grant's routing lane (v0.7): the service's, or its own."""

    model_config = ConfigDict(extra="forbid")
    mode: str = Field(pattern=r"^(service|own)$")

# The lane a policy request names: the service's (`svc`, the default) or a grant's.
LaneQuery = Query(LANE_SERVICE, max_length=72, pattern=r"^(svc|grant:[A-Za-z0-9_-]{1,64})$")


def policy_view(policy: RoutingPolicy) -> dict:
    return {**policy.model_dump(), "applied_current": policy.applied_current}


def _refusal(exc: RoutingError) -> JSONResponse:
    body = {"detail": str(exc), "code": exc.code}
    if exc.compiled is not None:
        body["compiled"] = exc.compiled.model_dump()
    return JSONResponse(body, exc.status)


def register_routing_routes(app, context: RequestContext) -> None:
    service = app.state.routing
    anyone = context.roles("owner", "admin", "viewer")
    owner = context.roles("owner")

    def _ctx(request: Request, user: dict) -> dict:
        return {"actor": user, "ip": context.client_ip(request), "request_id": getattr(request.state, "request_id", None)}

    @app.exception_handler(RoutingError)
    async def routing_error(_request, exc: RoutingError):
        return _refusal(exc)

    @app.exception_handler(LaneError)
    async def lane_error(_request, exc: LaneError):
        return JSONResponse({"detail": str(exc), "code": exc.code}, exc.status)

    @app.get("/api/routing/targets")
    async def targets(_user=Depends(context.current)):
        return {"items": await service.targets()}

    @app.get("/api/routing/policies/{node_id}/{protocol}")
    async def get_policy(node_id: str, protocol: str, lane: str = LaneQuery, _user=Depends(context.current)):
        return policy_view(service.get(node_id, protocol, lane))

    @app.put("/api/routing/policies/{node_id}/{protocol}")
    async def put_policy(node_id: str, protocol: str, body: PolicyPut, request: Request, lane: str = LaneQuery,
                         user=Depends(owner)):
        draft = PolicyInput.model_validate(body.model_dump(exclude={"expected_revision"}))
        policy = service.save(node_id, protocol, draft, expected_revision=body.expected_revision, lane=lane,
                              **_ctx(request, user))
        return policy_view(policy)

    @app.delete("/api/routing/policies/{node_id}/{protocol}", status_code=204)
    async def delete_policy(node_id: str, protocol: str, request: Request, lane: str = LaneQuery, user=Depends(owner)):
        service.delete(node_id, protocol, lane=lane, **_ctx(request, user))

    @app.post("/api/routing/policies/{node_id}/{protocol}/preview")
    async def preview(node_id: str, protocol: str, request: Request, body: PolicyInput | None = None,
                      lane: str = LaneQuery, _user=Depends(anyone)):
        return (await service.preview(node_id, protocol, body, lane)).model_dump()

    @app.post("/api/routing/policies/{node_id}/{protocol}/apply")
    async def apply(node_id: str, protocol: str, body: RevisionBody, request: Request, lane: str = LaneQuery,
                    user=Depends(owner)):
        result = await service.apply(node_id, protocol, expected_revision=body.expected_revision, lane=lane,
                                     **_ctx(request, user))
        return _outcome(result)

    @app.post("/api/routing/policies/{node_id}/{protocol}/rollback")
    async def rollback(node_id: str, protocol: str, body: RevisionBody, request: Request, lane: str = LaneQuery,
                       user=Depends(owner)):
        result = await service.rollback(node_id, protocol, expected_revision=body.expected_revision, lane=lane,
                                        **_ctx(request, user))
        return _outcome(result)

    @app.get("/api/routing/policies/{node_id}/{protocol}/history")
    async def history(node_id: str, protocol: str, lane: str = LaneQuery, _user=Depends(context.current)):
        return {"items": service.history(node_id, protocol, lane)}

    # «Куда пойдёт этот домен» (v0.7): the lane's rules walked for one destination — reads only.
    @app.post("/api/routing/policies/{node_id}/{protocol}/explain")
    async def explain_destination(node_id: str, protocol: str, body: ExplainBody, lane: str = LaneQuery,
                                  _user=Depends(anyone)):
        return service.explain_destination(node_id, protocol, body.host, body.port, lane)

    # The node's relay (v0.7): the inbound other nodes' chains arrive at, and its accounts.
    @app.post("/api/routing/relay/{node_id}/enable")
    async def relay_enable(node_id: str, request: Request, body: RelayEnableBody | None = None, user=Depends(owner)):
        port = DEFAULT_RELAY_PORT if body is None else body.port
        return await service.relay_enable(node_id, port=port, **_ctx(request, user))

    @app.post("/api/routing/relay/{node_id}/rotate")
    async def relay_rotate(node_id: str, request: Request, user=Depends(owner)):
        return await service.relay_rotate(node_id, **_ctx(request, user))

    # A grant's own lane (v0.7): the client's traffic gets its own policy on this node.
    @app.post("/api/routing/lanes/{grant_id}")
    async def grant_lane(grant_id: str, body: LaneModeBody, request: Request, user=Depends(owner)):
        lanes = app.state.lanes
        if body.mode == "own":
            return await lanes.enable(grant_id, **_ctx(request, user))
        return await lanes.disable(grant_id, **_ctx(request, user))

    # The node's Xray-router (v0.5): hand a service's whole traffic to it, or take it back.
    @app.post("/api/routing/targets/{node_id}/{protocol}/attach")
    async def attach(node_id: str, protocol: str, request: Request, user=Depends(owner)):
        return {"target": await service.attach(node_id, protocol, **_ctx(request, user))}

    @app.post("/api/routing/targets/{node_id}/{protocol}/detach")
    async def detach(node_id: str, protocol: str, request: Request, user=Depends(owner)):
        return {"target": await service.detach(node_id, protocol, **_ctx(request, user))}


def _outcome(result: dict) -> dict:
    applied = result["applied"]
    return {
        "policy": policy_view(result["policy"]),
        "applied": None if applied is None else {"revision": applied.revision, "digest": applied.digest,
                                                 "readback_sha256": applied.readback_sha256, "replayed": applied.replayed},
        "compiled": result["compiled"].model_dump(),
    }
