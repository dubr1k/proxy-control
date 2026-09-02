from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
from typing import Literal
from urllib.parse import parse_qsl, unquote, urlsplit

from fastapi import Depends, HTTPException, Request

from .mieru import MieruError
from .reveals import karing_client, qr_data
from .schemas import MieruQuotaUpdate, MieruRevision, MieruUserCreate
from .web_context import RequestContext


def mieru_access(value) -> dict:
    if not isinstance(value, str) or len(value) > 4096:
        raise HTTPException(409, "Mieru connection link unavailable")
    try:
        parts = urlsplit(value)
        query = parse_qsl(parts.query, keep_blank_values=True)
        authority_port = parts.port
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(409, "Mieru connection link unavailable") from exc
    values: dict[str, list[str]] = {}
    for key, item in query:
        values.setdefault(key, []).append(item)
    ports = values.get("port", [])
    protocols = values.get("protocol", [])
    if (
        parts.scheme != "mierus"
        or not parts.username
        or not parts.password
        or not parts.hostname
        or authority_port is not None
        or parts.path not in ("", "/")
        or parts.fragment
        or len(values.get("profile", [])) != 1
        or not values["profile"][0]
        or not ports
        or len(ports) != len(protocols)
        or any(protocol not in {"TCP", "UDP"} for protocol in protocols)
    ):
        raise HTTPException(409, "Mieru connection link unavailable")

    username = unquote(parts.username)
    password = unquote(parts.password)
    bindings = []
    for port, protocol in zip(ports, protocols, strict=True):
        if re.fullmatch(r"[0-9]{1,5}", port) and 1 <= int(port) <= 65535:
            binding = {"port": int(port), "protocol": protocol}
        else:
            match = re.fullmatch(r"([0-9]{1,5})-([0-9]{1,5})", port)
            if not match or not 1 <= int(match[1]) <= int(match[2]) <= 65535:
                raise HTTPException(409, "Mieru connection link unavailable")
            binding = {"portRange": port, "protocol": protocol}
        bindings.append(binding)

    mtu_values = values.get("mtu", [])
    if len(mtu_values) > 1 or (
        mtu_values and not re.fullmatch(r"[0-9]{4,5}", mtu_values[0])
    ):
        raise HTTPException(409, "Mieru connection link unavailable")
    mtu = int(mtu_values[0]) if mtu_values else 1400
    if not 1280 <= mtu <= 1500:
        raise HTTPException(409, "Mieru connection link unavailable")

    server = {"portBindings": bindings}
    server_host = parts.hostname
    try:
        server_host = str(ipaddress.ip_address(parts.hostname))
        server["ipAddress"] = server_host
    except ValueError:
        server["domainName"] = server_host
    profile_name = values["profile"][0]
    native_config = {
        "profiles": [{
            "profileName": profile_name,
            "user": {"name": username, "password": password},
            "servers": [server],
            "mtu": mtu,
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

    exact_ports = [binding["port"] for binding in bindings if "port" in binding]
    if len(exact_ports) == len(bindings):
        outbounds = [
            {
                "type": "mieru",
                "tag": f"mieru-{protocol}-{port}",
                "server": server_host,
                "server_port": port,
                "transport": protocol,
                "username": username,
                "password": password,
            }
            for port, protocol in zip(exact_ports, protocols, strict=True)
        ]
        credential_generation = hashlib.sha256(password.encode()).hexdigest()[:8]
        clients["karing"] = karing_client(
            {"outbounds": outbounds},
            name=f"Mieru · {values['profile'][0]} · {credential_generation}",
            filename=f"karing-mieru-{values['profile'][0]}.json",
        )
    else:
        unsupported["karing"] = (
            "Профиль Karing доступен только для точных портов Mieru, не диапазонов."
        )

    return {
        "service": "mieru",
        "username": values["profile"][0],
        "clients": clients,
        "unsupported_clients": unsupported,
    }


def register_mieru_routes(app, context: RequestContext) -> None:
    def require_mieru():
        if not context.settings.mieru_enabled:
            raise HTTPException(404, "feature unavailable")

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
        payload = body.model_dump()
        payload["quotas"] = [item.model_dump() for item in body.quotas]
        payload["elevated"] = user["role"] == "owner" and (
            body.allow_private_ip or body.allow_loopback_ip
        )
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
        data = await app.state.mieru.operation(
            username, operation, body.expected_revision
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
        data = await app.state.mieru.delete(username, body.expected_revision)
        await context.audit(user, "mieru.delete", username, request)
        return data
