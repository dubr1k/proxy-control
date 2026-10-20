"""The AmneziaWG screen: what this server's manager runs, joined with who holds each access.

Read-only on purpose (v2.3.0 adds the egress state, read from the manager). Every change to an access (issue, switch off, new keys, delete, show the config)
is a grant operation and goes through the clients' API, because the panel owns the client keys; this
route only answers «what is running and for whom». It carries no key and no obfuscation parameter.
"""
from __future__ import annotations

import asyncio

from fastapi import Depends, HTTPException

from .amneziawg import AmneziawgError
from .web_context import RequestContext


def register_amneziawg_routes(app, context: RequestContext) -> None:
    settings = context.settings

    def _holders() -> dict[str, dict]:
        """Accesses of this server by account name, with the client that holds each."""
        with app.state.database.connect() as db:
            clients = {client.id: client for client in app.state.clients.store.clients(db)}
            grants = app.state.clients.store.grants(db, node_id="local")
        return {
            grant.runtime_username: {
                "grant_id": grant.id, "client_id": grant.client_id,
                "client_name": clients[grant.client_id].display_name if grant.client_id in clients else "",
                "desired_state": grant.desired_state, "version": grant.options.version,
            }
            for grant in grants if grant.protocol == "amneziawg" and grant.desired_state != "deleted"
        }

    @app.get("/api/amneziawg/overview")
    async def overview(_user=Depends(context.current)):
        if not settings.amneziawg_enabled:
            raise HTTPException(404, "feature unavailable")
        public_host = settings.amneziawg_public_host or settings.naive_public_host
        holders = await asyncio.to_thread(_holders)
        try:
            health, instances, peers = await asyncio.gather(
                app.state.amneziawg.health(), app.state.amneziawg.instances(), app.state.amneziawg.peers())
        except AmneziawgError:
            return {"status": "down", "ip_forward": None, "public_host": public_host, "versions": [], "peers": [],
                    "pending": [{"username": name, **holder} for name, holder in sorted(holders.items())]}
        running = health.get("instances") or {}
        live = {row["username"]: row for row in peers if isinstance(row, dict) and isinstance(row.get("username"), str)}
        versions = []
        for item in instances:
            mine = [row for row in live.values() if row.get("version") == item["version"]]
            versions.append({
                "version": item["version"], "interface": item["interface"], "port": item["port"],
                "subnet": item["subnet"], "mtu": item.get("mtu"), "dns": list(item.get("dns") or []),
                "running": bool((running.get(item["version"]) or {}).get("running")),
                "peers": len(mine), "active": sum(row.get("enabled") is True for row in mine),
            })
        rows = []
        for name, row in sorted(live.items()):
            holder = holders.get(name)
            rows.append({
                "username": name, "version": row.get("version"), "address": row.get("address"),
                "enabled": row.get("enabled") is True, "latest_handshake": row.get("latest_handshake") or None,
                "rx": int(row.get("rx") or 0), "tx": int(row.get("tx") or 0),
                "grant_id": holder["grant_id"] if holder else None,
                "client_id": holder["client_id"] if holder else None,
                "client_name": holder["client_name"] if holder else None,
            })
        # accesses the panel holds that the manager has not (yet) got: waiting for it, or lost
        pending = [{"username": name, **holder} for name, holder in sorted(holders.items()) if name not in live]
        return {"status": health.get("status") or "degraded", "ip_forward": health.get("ip_forward"),
                "public_host": public_host, "versions": versions, "peers": rows, "pending": pending,
                "egress": await _egress()}

    async def _egress() -> dict | None:
        """Where the tunnels' traffic leaves (v2.3.0): direct, or the manager's WARP tunnel with its
        state. Secret-free: the WARP account's keys and token never leave the manager. None from a
        manager older than v2.3.0."""
        try:
            view = await app.state.amneziawg.egress()
        except AmneziawgError:
            return None
        warp = view.get("warp") if isinstance(view.get("warp"), dict) else {}
        document = view.get("document") if isinstance(view.get("document"), dict) else {}
        provider = (document.get("upstream") or {}).get("provider") if isinstance(document.get("upstream"), dict) else None
        router = view.get("router") if isinstance(view.get("router"), dict) else None
        if provider == "router":
            return {"mode": "proxy", "provider": "router", "tunnel": "up" if (router or {}).get("attached") else "down",
                    "registered": warp.get("registered") is True, "address": None, "endpoint": None,
                    "latest_handshake": None, "rx": 0, "tx": 0}
        return {"mode": view.get("mode"), "provider": provider, "tunnel": warp.get("tunnel"), "registered": warp.get("registered") is True,
                "address": warp.get("address"), "endpoint": warp.get("endpoint"),
                "latest_handshake": warp.get("latest_handshake"), "rx": int(warp.get("rx") or 0),
                "tx": int(warp.get("tx") or 0)}
