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
from ..naive_routes import safe_naive_traffic
from ..protocols.base import AdapterError, GrantRef
from ..schemas import VersionUpdate
from ..secrets_store import SecretError
from ..telemt import TelemtError
from ..versions import VersionAgentError
from ..web_context import RequestContext
from .protocol import (
    CAPTURE_MAX_RESOURCES,
    GenerationConflict,
    ObservedGeneration,
    PushRequest,
    PushResponse,
    canonical_digest,
)
from .reconcile import GenerationSuperseded

# The central reads a push for 30 s (spec §6): the node answers 202 before that and the
# reconcile keeps running in the background.
APPLY_DEADLINE = 25.0
# `egress.v1` (v0.4): this node applies the `egress` section of a generation and reports
# its egress targets in `identity.protocols[*].egress`. `egress.router.v1` (v0.5) joins when
# the node runs an Xray-router: it applies `xray_router` sections (with their `companion`)
# and reports the router in `identity.router`.
# `versions.check` (v0.11): this node's agent polls upstream on request; a central hides
# the button for a node without it.
CAPABILITIES = ("generation.v1", "credentials.capture", "versions.update", "versions.check", "unlink", "egress.v1")
ROUTER_CAPABILITY = "egress.router.v1"
# v0.7 (spec §7), with a router: this node builds client lanes named by a resource's `lane`
# and applies the `relay` section, reporting both in `identity.router`.
ROUTER_CAPABILITIES = (ROUTER_CAPABILITY, "egress.lanes.v1", "relay.v1", "geodata.v1")
VERSIONS_UNAVAILABLE = {"enabled": False, "components": {}, "reason": "version_agent_unavailable"}
NO_STORE = {"Cache-Control": "no-store"}
log = logging.getLogger(__name__)


class CaptureItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["mtproxy", "naive", "mieru"]
    runtime_username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resources: list[CaptureItem] = Field(max_length=CAPTURE_MAX_RESOURCES)
    # `escrow` (the default, what a poll or re-PUT asks for) reveals only users this central
    # already owns here; `import` is the operator's explicit adoption of the node's own users
    # (spec §6) and is the only purpose that reveals a local user — audited as such.
    purpose: Literal["escrow", "import"] = "escrow"


# The manager's own refusals (a bad source, corrupt or rejected lists) are the caller's 422.
GEODATA_REFUSALS = ("geodata_invalid", "geodata_corrupt", "geodata_rejected", "geodata_busy")


class GeodataSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["xray", "loyalsoldier", "custom"]
    geosite_url: str | None = Field(default=None, max_length=1024)
    geoip_url: str | None = Field(default=None, max_length=1024)


class ExitTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exit: dict


class GeodataSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: GeodataSource | None = None
    auto_update: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=336)


class VersionUpdateRequest(VersionUpdate):
    model_config = ConfigDict(extra="forbid")
    component: Literal["telemt", "naive", "mita", "xray"]


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

    async def _egress_entry(protocol: str) -> dict | None:
        """The egress target of one protocol as the central's compiler reads it (spec §5):
        secret-free — the provider's endpoint never leaves the manager's environment. A
        manager that cannot answer contributes no target; `daemon` already says it is down."""
        adapter = app.state.adapters.get(protocol)
        if adapter is None or not _enabled(protocol):
            return None
        try:
            target = await adapter.egress_target()
        except AdapterError:
            return None
        if target is None:
            return None
        return {"backend": target.backend, "capabilities": sorted(target.capabilities), "providers": target.providers,
                "revision": target.revision, "mode": target.mode, "restart_required": target.restart_required,
                "applied_digest": target.applied["digest"] if target.applied else None,
                "warnings": list(target.warnings), "router_attached": target.router_attached}

    async def _router_entry() -> dict | None:
        """The node's Xray-router as the central's compiler reads it (v0.5): None without a
        router; unavailable with its reason; otherwise the cells, the WARP provider as the
        router sees it, and per service the section's revision and applied digest."""
        router = getattr(app.state, "router", None)
        if router is None:
            return None
        sections, lanes = {}, {}
        for service in ("naive", "mieru"):
            target = await router.target(service)
            if not target.available:
                return {"available": False, "reason": target.reason or "router_unavailable"}
            sections[service] = {"revision": target.revision,
                                 "applied_digest": target.applied["digest"] if target.applied else None}
            capabilities, providers, xray_version = target.capabilities, target.providers, target.xray_version
            try:
                lanes[service] = sorted((await router.lanes(service)).get("lanes", []))
            except AdapterError:
                lanes[service] = []
        # The relay's public part (v0.7): what another node needs to dial it; never a key.
        relay = await router.relay()
        relay_view = None if relay is None else {
            "enabled": bool(relay.get("enabled")), "port": relay.get("port"), "server_name": relay.get("server_name"),
            "public_key": relay.get("public_key"), "short_ids": list(relay.get("short_ids") or []),
            "accounts": relay.get("accounts") if isinstance(relay.get("accounts"), int) else len(relay.get("accounts") or [])}
        return {"available": True, "xray_version": xray_version, "capabilities": sorted(capabilities),
                "providers": providers, "services": sections, "relay": relay_view, "lanes": lanes}

    async def _protocol_table(*, egress: bool = False) -> dict:
        telemt, naive, mieru = await asyncio.gather(
            _daemon(app.state.telemt, TelemtError),
            _daemon(app.state.naive, NaiveError) if settings.naive_enabled else asyncio.sleep(0, "off"),
            _daemon(app.state.mieru, MieruError) if settings.mieru_enabled else asyncio.sleep(0, "off"),
        )
        # The public hosts are the ones this node's own subscription renderer assumes; a
        # grant's own `host`/`port`, learned from the link Telemt served, win over these.
        table = {
            "mtproxy": {"enabled": True, "public_host": settings.mtproxy_host, "public_port": 443, "daemon": telemt},
            "naive": {"enabled": settings.naive_enabled, "public_host": settings.naive_public_host,
                      "public_port": 443, "daemon": naive},
            "mieru": {"enabled": settings.mieru_enabled, "public_host": settings.naive_public_host,
                      "public_port": 8443, "daemon": mieru},
        }
        if egress:
            targets = await asyncio.gather(*(_egress_entry(protocol) for protocol in table))
            for protocol, entry in zip(table, targets, strict=True):
                table[protocol]["egress"] = entry
        return table

    async def _inventory() -> dict[str, list[dict]]:
        """Runtime users per protocol and who owns each; a dead manager contributes no rows."""
        table: dict[str, list] = {"mtproxy": [], "naive": [], "mieru": []}
        with app.state.database.connect() as db:
            managed = app.state.managed.owned(db)
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

    async def _traffic() -> dict[str, dict | None]:
        """Bytes per protocol, best effort: what each manager exposes, `None` where it
        exposes nothing (mita) or cannot answer right now."""

        async def mtproxy():
            try:
                items = await app.state.telemt.list_users()
            except TelemtError:
                return None
            # Telemt reports one counter per user, not a direction split (see /api/dashboard).
            total = sum(value for item in items if isinstance(item, dict)
                        for value in [item.get("total_octets")]
                        if isinstance(value, int) and not isinstance(value, bool) and value >= 0)
            return {"upload_bytes": None, "download_bytes": None, "total_bytes": total}

        async def naive():
            if not settings.naive_enabled:
                return None
            try:
                aggregate = safe_naive_traffic(await app.state.naive.traffic())["aggregate"]
            except NaiveError:
                return None
            return {key: aggregate[key] for key in ("upload_bytes", "download_bytes", "total_bytes")}

        telemt, naive_counters = await asyncio.gather(mtproxy(), naive())
        return {"mtproxy": telemt, "naive": naive_counters, "mieru": None}

    async def _unlink(actor: dict, request: Request) -> dict:
        released = await app.state.reconciler.unlink()
        await context.audit(actor, "fleet.unlink", app.state.panel_guid, request, {"released": released})
        return {"released": released}

    @app.get("/api/fleet/v2/identity")
    async def identity(_key=Depends(context.fleet_key)):
        with app.state.database.connect() as db:
            master = app.state.managed.master_guid(db)
        router = await _router_entry()
        capabilities = list(CAPABILITIES) + (list(ROUTER_CAPABILITIES) if router is not None else [])
        return {"guid": app.state.panel_guid, "panel_version": app.state.panel_version, "api_version": 2,
                "master_guid": master, "protocols": await _protocol_table(egress=True),
                "capabilities": capabilities, "router": router}

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
            managed = len(app.state.managed.owned(db))
        protocols, traffic = await asyncio.gather(_protocol_table(), _traffic())
        for protocol, counters in traffic.items():
            protocols[protocol]["traffic"] = counters
        return {"versions": versions, "host": host, "managed_resources": managed, "users": users,
                "protocols": protocols}

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
        except SecretError as exc:
            # No master key (ADR 005): the node cannot escrow what it was sent, and the
            # transaction rolled the generation back with it. A code, so the central stops retrying.
            return _conflict("secret_store_disabled", str(exc))
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
        except GenerationSuperseded:
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
    async def capture(body: CaptureRequest, request: Request, key=Depends(context.fleet_key)):
        credentials, unsupported, refused = {}, [], []
        with app.state.database.connect() as db:
            managed = app.state.managed.owned(db)
        for item in body.resources:
            adapter = app.state.adapters[item.protocol]
            label = f"{item.protocol}:{item.runtime_username}"
            if not _enabled(item.protocol) or not adapter.capture_supported:
                unsupported.append(label)
                continue
            if body.purpose != "import" and (item.protocol, item.runtime_username) not in managed:
                refused.append(label)
                continue
            try:
                value = await adapter.capture(GrantRef(item.protocol, item.runtime_username))
            except AdapterError:
                value = None
            credentials[label] = None if value is None else value.decode()
        # Usernames are what the inventory already shows; no value ever lands in the audit row.
        await context.audit(key, "fleet.credentials.capture", app.state.panel_guid, request,
                            {"purpose": body.purpose, "requested": len(body.resources),
                             "answered": sorted(label for label, value in credentials.items() if value),
                             "unanswered": sorted(label for label, value in credentials.items() if not value),
                             "unsupported": unsupported, "refused": refused})
        return JSONResponse({"credentials": credentials, "unsupported": unsupported, "refused": refused},
                            headers=NO_STORE)

    # v0.8: the router's geodata, for the central's «Маршрутизация» screen (owner actions there
    # arrive here under the node-sync key and are audited on the node as `fleet.geodata.*`).
    async def _geodata(action: str, body: dict | None = None):
        router = getattr(app.state, "router", None)
        if router is None:
            return JSONResponse({"detail": "this node runs no Xray-router", "code": "router_unavailable"}, status_code=404)
        try:
            return await router.geodata(action, body)
        except AdapterError as exc:
            code = exc.code or "router_unavailable"
            return JSONResponse({"detail": str(exc), "code": code}, status_code=422 if code in GEODATA_REFUSALS else 502)

    @app.post("/api/fleet/v2/exits/test")
    async def exit_test(body: ExitTestRequest, request: Request, key=Depends(context.fleet_key)):
        router = getattr(app.state, "router", None)
        if router is None:
            return JSONResponse({"detail": "this node runs no Xray-router", "code": "router_unavailable"}, status_code=404)
        try:
            result = await router.exit_test(body.exit)
        except AdapterError as exc:
            code = exc.code or "router_unavailable"
            return JSONResponse({"detail": str(exc), "code": code}, status_code=422 if code == "egress_invalid" else 502)
        await context.audit(key, "fleet.exit.test", app.state.panel_guid, request,
                            {"protocol": body.exit.get("protocol"), "address": body.exit.get("address"), "ok": result.get("ok")})
        return JSONResponse(result, headers=NO_STORE)

    @app.get("/api/fleet/v2/geodata")
    async def geodata_view(_key=Depends(context.fleet_key)):
        return await _geodata("view")

    @app.get("/api/fleet/v2/geodata/codes")
    async def geodata_codes(_key=Depends(context.fleet_key)):
        return await _geodata("codes")

    @app.put("/api/fleet/v2/geodata/settings")
    async def geodata_settings(body: GeodataSettings, request: Request, key=Depends(context.fleet_key)):
        result = await _geodata("settings", body.model_dump(exclude_none=True))
        if not isinstance(result, JSONResponse):
            await context.audit(key, "fleet.geodata.settings", app.state.panel_guid, request, body.model_dump(exclude_none=True))
        return result

    @app.post("/api/fleet/v2/geodata/{action}")
    async def geodata_action(action: Literal["update", "restore"], request: Request, key=Depends(context.fleet_key)):
        result = await _geodata(action)
        if not isinstance(result, JSONResponse):
            await context.audit(key, f"fleet.geodata.{action}", app.state.panel_guid, request,
                                {"origin": result.get("origin"), "version": result.get("version"), "changed": result.get("changed")})
        return result

    @app.post("/api/fleet/v2/versions/update")
    async def update_version(body: VersionUpdateRequest, request: Request, key=Depends(context.fleet_key)):
        result = await app.state.versions.update(body.component, body.version, body.expected_current)
        await context.audit(key, "runtime.version.update", body.component, request, {"version": body.version})
        return result

    @app.post("/api/fleet/v2/versions/check")
    async def check_versions(request: Request, key=Depends(context.fleet_key)):
        """v0.11: the central asks this node's agent to poll upstream."""
        result = await app.state.versions.check()
        await context.audit(key, "runtime.version.check", "upstream", request, {"checked_at": result.get("checked_at")})
        return result

    @app.post("/api/fleet/v2/unlink")
    async def unlink(request: Request, key=Depends(context.fleet_key)):
        return await _unlink(key, request)

    @app.post("/api/nodes/local/unlink")
    async def unlink_by_owner(request: Request, user=Depends(context.roles("owner"))):
        """The node's owner cuts the link from the UI; the runtime is left alone (spec §5.2)."""
        return await _unlink(user, request)
