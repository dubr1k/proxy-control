from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Literal

from fastapi import Depends, HTTPException, Request

from .fleet_v2.guard import require_unmanaged
from .mieru import MieruError
from .protocols.mieru import parse_share_url, singbox_outbounds
from .reveals import karing_client, qr_data
from .schemas import MieruQuotaUpdate, MieruRevision, MieruUserCreate
from .web_context import RequestContext


def mieru_access(value) -> dict:
    try:
        share = parse_share_url(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(409, "Mieru connection link unavailable") from exc
    username, password = share.username, share.password
    server = {"portBindings": [dict(binding) for binding in share.bindings]}
    server["ipAddress" if share.is_ip else "domainName"] = share.host
    profile_name = share.profile
    native_config = {
        "profiles": [{
            "profileName": profile_name,
            "user": {"name": username, "password": password},
            "servers": [server],
            "mtu": share.mtu,
        }],
        "activeProfile": profile_name,
        "rpcPort": 50000,
        "socks5Port": 1080,
        "socks5ListenLAN": False,
        "loggingLevel": "INFO",
    }
    native = {
        "label": "Mieru",
        "type": "config",
        "config": native_config,
        "filename": "mieru-client.json",
        "apply_command": "mieru apply config mieru-client.json",
        "simple_share_url": value,
        "qr": {"payload": value, "image": qr_data(value)},
    }
    clients = {"native": native}
    unsupported = {
        "nekobox": "Проверенный формат импорта Mieru для NekoBox+ отсутствует.",
        "shadowrocket": (
            "Проверенный формат импорта Mieru для Shadowrocket отсутствует."
        ),
    }

    outbounds = singbox_outbounds(share, tag=lambda port, protocol: f"mieru-{protocol}-{port}")
    if outbounds is not None:
        credential_generation = hashlib.sha256(password.encode()).hexdigest()[:8]
        clients["karing"] = karing_client(
            {"outbounds": outbounds},
            name=f"Mieru · {profile_name} · {credential_generation}",
            filename=f"karing-mieru-{profile_name}.json",
        )
    else:
        unsupported["karing"] = (
            "Профиль Karing доступен только для точных портов Mieru, не диапазонов."
        )

    return {
        "service": "mieru",
        "username": profile_name,
        "clients": clients,
        "unsupported_clients": unsupported,
    }


async def _domain_created(app, context, username: str, payload: dict, request, user) -> dict:
    """Provision through the domain, then answer in the shape the caller already knows."""
    from .clients.store import ClientConflict  # noqa: PLC0415 - avoids an import cycle

    try:
        credential = await app.state.domain_facade.create(
            "mieru", username, {"quotas": payload["quotas"]},
            **context.domain_context(request, user),
        )
    except ClientConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    adapter = app.state.adapters["mieru"]
    facade = app.state.domain_facade
    grant = facade.grant("mieru", username)
    health = await app.state.mieru.health()
    # The link is rebuilt from the shape mita itself reported, not from a guess.
    artifacts = adapter.render_artifacts(grant, credential, public_host=adapter.public_host)
    return {
        "username": username,
        "revision": health.get("revision"),
        "share_url": artifacts[0].value if artifacts else "",
    }


def register_mieru_routes(app, context: RequestContext) -> None:
    def require_mieru():
        if not context.settings.mieru_enabled:
            raise HTTPException(404, "feature unavailable")

    def local_only(username: str):
        with app.state.database.connect() as db:
            require_unmanaged(db, app.state.managed, "mieru", username)

    @app.get("/api/mieru/users")
    async def mieru_users(_user=Depends(context.current)):
        require_mieru()
        health, items, metrics = await asyncio.gather(
            app.state.mieru.health(),
            app.state.mieru.list_users(),
            app.state.mieru.metrics(),
        )
        metric_map = {
            row.get("username"): row
            for row in metrics.get("users", [])
            if isinstance(row, dict)
        }
        if metrics != {
            "status": "error",
            "stale": True,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }:
            raise MieruError("Invalid Mieru metrics response")
        safe = []
        for item in items:
            if not isinstance(item, dict) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,64}", str(item.get("username", ""))
            ):
                continue
            row = {
                "username": item["username"],
                "enabled": item.get("enabled") is True,
                "traffic_available": False,
                "quotas": item.get("quotas", [])
                if isinstance(item.get("quotas", []), list)
                else [],
            }
            metric = metric_map.get(item["username"], {})
            for key in (
                "upload_bytes",
                "download_bytes",
                "application_bytes",
                "stale",
            ):
                if key in metric:
                    row[key] = metric[key]
            safe.append(row)
        return {
            "items": safe,
            "metrics": {
                "capability": "unavailable",
                "reason": "typed_histories_unavailable",
            },
            "service": {
                "ready": health.get("ready") is True,
                "status": health.get("status"),
                "revision": health.get("revision"),
            },
            "quota_semantics": "rolling application-byte admission quota (approximate)",
        }

    @app.post("/api/mieru/users", status_code=201)
    async def mieru_create(
        body: MieruUserCreate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        local_only(body.username)
        payload = body.model_dump()
        payload["quotas"] = [item.model_dump() for item in body.quotas]
        payload["elevated"] = user["role"] == "owner" and (
            body.allow_private_ip or body.allow_loopback_ip
        )
        if context.settings.vnext_writer == "domain" and not payload["elevated"]:
            # The SSRF flags are an elevated, deliberately manual path: they stay on the
            # legacy call rather than being smuggled through a generic domain intent.
            data = await _domain_created(app, context, body.username, payload, request, user)
        else:
            data = await app.state.mieru.create(payload)
        await context.audit(
            user,
            "mieru.create",
            body.username,
            request,
            {
                "quotas": payload["quotas"],
                "ssrf_flags": bool(payload["elevated"]),
            },
        )
        return {
            "username": body.username,
            "revision": data.get("revision"),
            "reveal_token": context.create_reveal(
                mieru_access(data.get("share_url")), user
            ),
        }

    @app.post("/api/mieru/users/{username}/quotas")
    async def mieru_quotas(
        username: str,
        body: MieruQuotaUpdate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        local_only(username)
        payload = {
            "expected_revision": body.expected_revision,
            "quotas": [item.model_dump() for item in body.quotas],
        }
        data = await app.state.mieru.set_quotas(username, payload)
        await context.audit(
            user,
            "mieru.quotas",
            username,
            request,
            {"quotas": payload["quotas"]},
        )
        return data

    @app.post("/api/mieru/users/{username}/reset-metrics")
    async def mieru_reset(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        local_only(username)
        data = await app.state.mieru.reset_metrics(username)
        await context.audit(user, "mieru.metrics.baseline", username, request)
        return data

    @app.post("/api/mieru/users/{username}/{operation}")
    async def mieru_operation(
        username: str,
        operation: Literal["enable", "disable", "rotate"],
        body: MieruRevision,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        local_only(username)
        data = await app.state.mieru.operation(
            username, operation, body.expected_revision
        )
        if context.settings.vnext_writer == "domain" and operation in {"enable", "disable"}:
            await app.state.domain_facade.set_enabled(
                "mieru", username, operation == "enable", observed={"quotas": []},
                **context.domain_context(request, user),
            )
        await context.audit(user, f"mieru.{operation}", username, request)
        if operation == "rotate":
            return {
                "username": username,
                "revision": data.get("revision"),
                "reveal_token": context.create_reveal(
                    mieru_access(data.get("share_url")), user
                ),
            }
        return data

    @app.delete("/api/mieru/users/{username}")
    async def mieru_delete(
        username: str,
        body: MieruRevision,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        local_only(username)
        data = await app.state.mieru.delete(username, body.expected_revision)
        await context.audit(user, "mieru.delete", username, request)
        return data
