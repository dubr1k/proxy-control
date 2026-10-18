"""The TrustTunnel screen: what this server's manager runs, joined with who holds each access.

Read-only on purpose, like the AmneziaWG screen. Every change to an access (issue, switch off, new
password, delete, show the link and the config) is a grant operation and goes through the clients'
API, because the panel owns the password; this route only answers «what is running and for
whom». It carries no password, no link and no certificate.
"""
from __future__ import annotations

import asyncio

from fastapi import Depends, HTTPException

from .trusttunnel import TrusttunnelError
from .web_context import RequestContext


def register_trusttunnel_routes(app, context: RequestContext) -> None:
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
                "desired_state": grant.desired_state, "name": grant.options.name,
            }
            for grant in grants if grant.protocol == "trusttunnel" and grant.desired_state != "deleted"
        }

    @app.get("/api/trusttunnel/overview")
    async def overview(_user=Depends(context.current)):
        if not settings.trusttunnel_enabled:
            raise HTTPException(404, "feature unavailable")
        public_host = settings.trusttunnel_public_host or settings.naive_public_host
        holders = await asyncio.to_thread(_holders)
        try:
            health, endpoint, clients = await asyncio.gather(
                app.state.trusttunnel.health(), app.state.trusttunnel.endpoint(), app.state.trusttunnel.clients())
        except TrusttunnelError:
            return {"status": "down", "public_host": public_host, "endpoint": None, "clients": [],
                    "totals": {"clients": 0, "active": 0, "sessions": 0, "upload_bytes": 0, "download_bytes": 0},
                    "pending": [{"username": name, **holder} for name, holder in sorted(holders.items())]}
        live = {row["username"]: row for row in clients if isinstance(row, dict) and isinstance(row.get("username"), str)}
        rows = []
        for name, row in sorted(live.items()):
            holder = holders.get(name)
            rows.append({
                "username": name, "enabled": row.get("enabled") is True, "sessions": int(row.get("sessions") or 0),
                # measured on a real endpoint: the manager's rx is what the client uploaded
                # (the endpoint's `outbound`), tx is what the client downloaded (`inbound`)
                "download_bytes": int(row.get("tx") or 0), "upload_bytes": int(row.get("rx") or 0),
                "grant_id": holder["grant_id"] if holder else None,
                "client_id": holder["client_id"] if holder else None,
                "client_name": holder["client_name"] if holder else None,
                "name": holder["name"] if holder else None,
            })
        running = bool((health.get("endpoint") or {}).get("running"))
        # accesses the panel holds that the manager has not (yet) got: waiting for it, or lost
        pending = [{"username": name, **holder} for name, holder in sorted(holders.items()) if name not in live]
        return {
            "status": health.get("status") or "degraded", "public_host": public_host,
            "endpoint": {
                "hostname": endpoint.get("hostname"), "port": endpoint.get("public_port") or 443,
                "version": endpoint.get("version"), "running": running,
                "certificate_trusted": endpoint.get("certificate_trusted") is True,
                "fingerprint": endpoint.get("fingerprint"),
            },
            "clients": rows,
            "totals": {"clients": len(rows), "active": sum(row["enabled"] for row in rows),
                       "sessions": sum(row["sessions"] for row in rows),
                       "upload_bytes": sum(row["upload_bytes"] for row in rows),
                       "download_bytes": sum(row["download_bytes"] for row in rows)},
            "pending": pending,
        }
