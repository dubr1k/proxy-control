"""What a panel exposes to the central panel that manages it (spec §5.2)."""
from __future__ import annotations

import asyncio
import logging
from typing import Literal

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..mieru import MieruError
from ..naive import NaiveError
from ..protocols.base import AdapterError, GrantRef
from ..schemas import VersionUpdate
from ..telemt import TelemtError
from ..versions import VersionAgentError
from ..web_context import RequestContext
from .protocol import GenerationConflict, ObservedGeneration, PushRequest, PushResponse, canonical_digest

# The central reads a push for 30 s (spec §6): the node answers 202 before that and the
# reconcile keeps running in the background.
APPLY_DEADLINE = 25.0
CAPABILITIES = ("generation.v1", "credentials.capture", "versions.update", "unlink")
VERSIONS_UNAVAILABLE = {"enabled": False, "components": {}, "reason": "version_agent_unavailable"}
NO_STORE = {"Cache-Control": "no-store"}
log = logging.getLogger(__name__)


class CaptureItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["mtproxy", "naive", "mieru"]
    runtime_username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resources: list[CaptureItem] = Field(max_length=200)


class VersionUpdateRequest(VersionUpdate):
    model_config = ConfigDict(extra="forbid")
    component: Literal["telemt", "naive", "mita"]


def _conflict(code: str, detail: str = "") -> JSONResponse:
    return JSONResponse({"detail": detail or code, "code": code}, 409)


def _log_late_outcome(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception() is not None:
        log.warning("fleet: background reconcile failed: %s", task.exception())


def register_fleet_v2_node_routes(app, context: RequestContext) -> None:
    settings = context.settings
    # Reconciles still running after a 202 are referenced here so the loop never drops them.
    background: set[asyncio.Task] = set()

    def _enabled(protocol: str) -> bool:
        return {"naive": settings.naive_enabled, "mieru": settings.mieru_enabled}.get(protocol, True)

    async def _daemon(client, error) -> str:
        try:
            await client.health()
        except error:
            return "down"
        return "ok"

    async def _protocol_table() -> dict:
        telemt, naive, mieru = await asyncio.gather(
            _daemon(app.state.telemt, TelemtError),
            _daemon(app.state.naive, NaiveError) if settings.naive_enabled else asyncio.sleep(0, "off"),
            _daemon(app.state.mieru, MieruError) if settings.mieru_enabled else asyncio.sleep(0, "off"),
        )
        # The public hosts are the ones this node's own subscription renderer assumes.
        return {
            "mtproxy": {"enabled": True, "public_host": settings.allowed_hosts[0] if settings.allowed_hosts else "",
                        "public_port": 443, "daemon": telemt},
            "naive": {"enabled": settings.naive_enabled, "public_host": settings.naive_public_host,
                      "public_port": 443, "daemon": naive},
            "mieru": {"enabled": settings.mieru_enabled, "public_host": settings.naive_public_host,
                      "public_port": 8443, "daemon": mieru},
        }

    async def _inventory() -> dict[str, list[dict]]:
        """Runtime users per protocol and who owns each; a dead manager contributes no rows."""
        table: dict[str, list] = {"mtproxy": [], "naive": [], "mieru": []}
        with app.state.database.connect() as db:
            managed = app.state.managed.resources(db)
        for protocol, adapter in app.state.adapters.items():
            if not _enabled(protocol):
                continue
            try:
                observed = await adapter.discover()
            except Exception:  # noqa: BLE001 — /status already reports the daemon as down
                continue
            for item in observed.items:
                record = managed.get((protocol, item.runtime_username))
                table[protocol].append({"runtime_username": item.runtime_username, "enabled": item.enabled,
                                        "options": item.options, "ownership": "central" if record else "local",
                                        "ref": record["ref"] if record else None})
        return table

    def _push_response(observed: ObservedGeneration, credentials: dict[str, str], status: int) -> JSONResponse:
        return JSONResponse(PushResponse(observed=observed, credentials=credentials).model_dump(), status,
                            headers=NO_STORE)

    async def _unlink(actor: dict, request: Request) -> dict:
        # A reconcile still running would re-register the resources it is applying.
        await asyncio.gather(*background, return_exceptions=True)
        with app.state.database.transaction() as db:
            released = app.state.managed.unlink(db)
        await context.audit(actor, "fleet.unlink", app.state.panel_guid, request, {"released": released})
        return {"released": released}

    @app.get("/api/fleet/v2/identity")
    async def identity(_key=Depends(context.fleet_key)):
        with app.state.database.connect() as db:
            master = app.state.managed.master_guid(db)
        return {"guid": app.state.panel_guid, "panel_version": app.state.panel_version, "api_version": 2,
                "master_guid": master, "protocols": await _protocol_table(), "capabilities": list(CAPABILITIES)}

    @app.get("/api/fleet/v2/status")
    async def status(_key=Depends(context.fleet_key)):
        versions, host = VERSIONS_UNAVAILABLE, {}
        try:
            versions = await app.state.versions.list_versions()
            host = await app.state.versions.host()
        except VersionAgentError:
            pass
        inventory = await _inventory()
        users = {protocol: {"central": sum(row["ownership"] == "central" for row in rows),
                            "local": sum(row["ownership"] == "local" for row in rows)}
                 for protocol, rows in inventory.items()}
        with app.state.database.connect() as db:
            managed = len(app.state.managed.resources(db))
        return {"versions": versions, "host": host, "managed_resources": managed, "users": users,
                "protocols": await _protocol_table()}

    @app.get("/api/fleet/v2/inventory")
    async def inventory(_key=Depends(context.fleet_key)):
        return {"protocols": await _inventory()}

    @app.put("/api/fleet/v2/generation")
    async def push(body: PushRequest, request: Request, key=Depends(context.fleet_key)):
        if body.expected_guid != app.state.panel_guid:
            return _conflict("guid_mismatch")
        generation = body.generation.generation
        digest = canonical_digest(body.generation)
        try:
            with app.state.database.transaction() as db:
                app.state.managed.accept(db, body.generation, digest, node_guid=app.state.panel_guid)
                await app.state.reconciler.store_secrets(db, body)
        except GenerationConflict as exc:
            return _conflict(exc.code, str(exc))
        await context.audit(key, "fleet.generation.accept", str(generation), request,
                            {"digest": digest, "resources": len(body.generation.resources)})
        # Adapter I/O never runs inside a transaction, and never gets cancelled by the
        # deadline: `asyncio.wait` leaves the task running, unlike `wait_for`.
        task = asyncio.ensure_future(app.state.reconciler.apply(generation))
        background.add(task)
        task.add_done_callback(background.discard)
        done, _ = await asyncio.wait({task}, timeout=APPLY_DEADLINE)
        if not done:
            task.add_done_callback(_log_late_outcome)
            with app.state.database.connect() as db:
                observed = app.state.managed.observed(db)
            return _push_response(observed, {}, 202)
        try:
            observed, credentials = task.result()
        except KeyError:
            # A newer generation was accepted while this one waited for the reconcile lock.
            return _conflict("stale_generation", "superseded by a newer generation")
        return _push_response(observed, credentials, 200)

    @app.get("/api/fleet/v2/observed")
    async def observed(_key=Depends(context.fleet_key)):
        with app.state.database.connect() as db:
            found = app.state.managed.observed(db)
        if found is None:
            found = ObservedGeneration(applied_generation=0, digest="", reconcile_state="idle", resources=[],
                                       reported_at=0)
        return found.model_dump()

    @app.post("/api/fleet/v2/credentials/capture")
    async def capture(body: CaptureRequest, _key=Depends(context.fleet_key)):
        credentials, unsupported = {}, []
        for item in body.resources:
            adapter = app.state.adapters[item.protocol]
            label = f"{item.protocol}:{item.runtime_username}"
            if not _enabled(item.protocol) or not adapter.capture_supported:
                unsupported.append(label)
                continue
            try:
                value = await adapter.capture(GrantRef(item.protocol, item.runtime_username))
            except AdapterError:
                value = None
            credentials[label] = None if value is None else value.decode()
        return JSONResponse({"credentials": credentials, "unsupported": unsupported}, headers=NO_STORE)

    @app.post("/api/fleet/v2/versions/update")
    async def update_version(body: VersionUpdateRequest, request: Request, key=Depends(context.fleet_key)):
        result = await app.state.versions.update(body.component, body.version, body.expected_current)
        await context.audit(key, "runtime.version.update", body.component, request, {"version": body.version})
        return result

    @app.post("/api/fleet/v2/unlink")
    async def unlink(request: Request, key=Depends(context.fleet_key)):
        return await _unlink(key, request)

    @app.post("/api/nodes/local/unlink")
    async def unlink_by_owner(request: Request, user=Depends(context.roles("owner"))):
        """The node's owner cuts the link from the UI; the runtime is left alone (spec §5.2)."""
        return await _unlink(user, request)
