"""`GET|HEAD /s/{token}` — the one endpoint a subscriber's client talks to.

The token is a bearer credential, so the route is built so that nothing about it leaks:
it answers only on the subscription host (on the panel's own domain the path does not
exist), every refusal — wrong host, malformed token, unknown format, unknown or revoked
token — is the same 404 from the same branch, and the path is never written to a log or
an audit row. Rate limiting is per client address across all tokens and runs before the
token is looked up, so guessing tokens costs the guesser their budget.

The ETag is the effective set of grants, not the fetch time: a client that asks with
`If-None-Match` gets a 304 until something it would receive actually changes.
"""
from __future__ import annotations

import asyncio
import dataclasses
import re

from fastapi import Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from .clients.models import effective_enabled
from .clients.store import ClientConflict
from .events import MAX_PAGE
from .reveals import qr_data
from .subscriptions.compatibility import MATRIX, NOTES
from .subscriptions.renderers import RENDERERS, resolve_artifacts
from .subscriptions.service import SubscriptionService
from .web_context import RequestContext

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,64}$")
# Content negotiation when `format` is absent; anything else falls through to `raw`.
ACCEPT_FORMATS = (
    ("text/html", "html"),
    ("application/vnd.proxy-control.subscription+json", "manifest"),
    ("text/yaml", "clash"),
    ("application/yaml", "clash"),
    ("application/json", "singbox"),
)
FETCHES_PER_MINUTE = 60


def negotiate(accept: str) -> str:
    for media_type, name in ACCEPT_FORMATS:
        if media_type in accept:
            return name
    return "raw"


# The link variants an operator can hand out: one token, a format and (for the
# sing-box JSON) the client it is cut for. The keys are what the dialog shows.
SHARE_VARIANTS = {
    "raw": "?format=raw",
    "singbox": "?format=singbox",
    "singbox-official": "?format=singbox&client=singbox",
    "clash": "?format=clash",
}
# Which `client` values a format understands; anything else is the same 404 as an
# unknown format.
FORMAT_CLIENTS = {"singbox": ("karing", "singbox")}


def register_subscription_admin_routes(app, context: RequestContext) -> None:
    """The operator's side: one subscription per client, its URL shown exactly once."""

    def service() -> SubscriptionService:
        return app.state.subscriptions

    def overview(client_id: str) -> dict:
        clients = app.state.clients
        now = int(app.state.clock.time())
        with clients.database.connect() as db:
            client = clients.store.client(db, client_id)
            grants = clients.store.grants(db, client_id=client_id)
            current = service().store.active(db, client_id)
        return {
            "configured": bool(service().public_base),
            "subscription": dataclasses.asdict(current) if current else None,
            "grants": [
                {
                    "grant_id": grant.id,
                    "protocol": grant.protocol,
                    "runtime_username": grant.runtime_username,
                    "enabled": effective_enabled(grant, client, now),
                    "has_credential": grant.secret_ref is not None,
                }
                for grant in grants
            ],
        }

    def reveal_payload(subscription, token: str) -> dict:
        """Everything the dialog shows once: the URL, its variants and their QR codes."""
        url = service().public_url(token)
        return {
            "subscription_id": subscription.id,
            "generation": subscription.generation,
            "url": url,
            "qr": qr_data(url),
            "variants": {
                name: {"url": f"{url}{query}", "qr": qr_data(f"{url}{query}")}
                for name, query in SHARE_VARIANTS.items()
            },
        }

    async def issue(operation, client_id: str, request: Request, user: dict) -> dict:
        if not service().public_base:
            raise HTTPException(409, "PANEL_SUBSCRIPTION_URL is not configured: there is no URL to hand out")
        try:
            subscription, token = await asyncio.to_thread(
                operation, client_id, **context.domain_context(request, user)
            )
        except KeyError as exc:
            raise HTTPException(404, "client not found") from exc
        except ClientConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        # The plaintext token lives only inside this reveal; the row keeps its hash.
        return {"reveal_token": context.create_reveal(reveal_payload(subscription, token), user)}

    @app.get("/api/subscriptions/compatibility")
    async def compatibility(_user=Depends(context.current)):
        return {"matrix": MATRIX, "notes": NOTES}

    @app.get("/api/events")
    async def events(
        after: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=MAX_PAGE),
        _user=Depends(context.current),
    ):
        """Subscription events only, oldest first, paged by row id; every role may read them."""
        items = await asyncio.to_thread(app.state.events.since, after, limit)
        return {"items": items, "next_after": items[-1]["id"] if items else after}

    @app.get("/api/clients/{client_id}/subscription")
    async def read(client_id: str, _user=Depends(context.current)):
        try:
            return await asyncio.to_thread(overview, client_id)
        except KeyError as exc:
            raise HTTPException(404, "client not found") from exc

    @app.post("/api/clients/{client_id}/subscription", status_code=201)
    async def create(client_id: str, request: Request, user=Depends(context.roles("owner", "admin"))):
        return await issue(service().create, client_id, request, user)

    @app.post("/api/clients/{client_id}/subscription/rotate")
    async def rotate(client_id: str, request: Request, user=Depends(context.roles("owner", "admin"))):
        return await issue(service().rotate, client_id, request, user)

    @app.post("/api/clients/{client_id}/subscription/revoke")
    async def revoke(client_id: str, request: Request, user=Depends(context.roles("owner", "admin"))):
        def run() -> bool:
            with app.state.database.connect() as db:
                existed = service().store.active(db, client_id) is not None
            service().revoke(client_id, **context.domain_context(request, user))
            return existed

        return {"revoked": await asyncio.to_thread(run)}


def register_subscription_routes(app, context: RequestContext) -> None:
    settings = context.settings

    def public_hosts() -> dict[str, str]:
        """Fallback hosts for grants provisioned before the saga learned the endpoint."""
        return {
            "naive": settings.naive_public_host,
            "mtproxy": settings.allowed_hosts[0] if settings.allowed_hosts else "",
            "mieru": settings.naive_public_host,
        }

    def refuse(status: int = 404, detail: str = "not found") -> JSONResponse:
        # One body and one branch for every refusal, so none of them says more than
        # "no such thing here".
        return JSONResponse(
            {"detail": detail}, status,
            headers={"Cache-Control": "private, no-cache", "Vary": "Accept", "X-Robots-Tag": "noindex"},
        )

    def render(manifest, renderer, client: str | None) -> bytes:
        """Reveal and render in one thread; the plaintext never outlives this call."""
        with app.state.database.connect() as db:
            artifacts = resolve_artifacts(
                manifest, app.state.secrets, app.state.adapters, db, public_hosts=public_hosts()
            )
        if client is not None:
            return renderer.render(manifest, artifacts, client=client)
        return renderer.render(manifest, artifacts)

    @app.api_route("/s/{token}", methods=["GET", "HEAD"], include_in_schema=False)
    async def subscription(token: str, request: Request):
        host = request.headers.get("host", "").rsplit(":", 1)[0].lower()
        if not settings.subscription_host or host != settings.subscription_host:
            return refuse()
        if not TOKEN_RE.fullmatch(token):
            return refuse()
        name = request.query_params.get("format") or negotiate(request.headers.get("accept", ""))
        renderer = RENDERERS.get(name)
        if renderer is None:
            return refuse()
        client = request.query_params.get("client")
        if client is not None and client not in FORMAT_CLIENTS.get(name, ()):
            return refuse()
        reservation = await asyncio.to_thread(
            app.state.store.reserve_login_attempt,
            [f"subscription:{context.client_ip(request)}"], FETCHES_PER_MINUTE, 60,
        )
        if reservation is None:
            return refuse(429, "too many requests")
        found = await asyncio.to_thread(app.state.subscriptions.resolve, token)
        if found is None:
            return refuse()

        now = int(app.state.clock.time())
        headers = {
            "Cache-Control": "private, no-cache",
            "Vary": "Accept",
            "Profile-Update-Interval": str(found.update_interval_hours),
            "X-Robots-Tag": "noindex",
        }
        service: SubscriptionService = app.state.subscriptions
        manifest = await asyncio.to_thread(service.effective_manifest, found, now)
        etag = f'"{service.etag(manifest, renderer.version, client or "")}"'
        headers["ETag"] = etag
        if etag in [value.strip() for value in request.headers.get("if-none-match", "").split(",")]:
            await asyncio.to_thread(service.record_fetch, found, now, status=304, format=name)
            return Response(status_code=304, headers=headers)
        body = await asyncio.to_thread(render, manifest, renderer, client)
        await asyncio.to_thread(service.record_fetch, found, now, status=200, format=name)
        return Response(
            content=b"" if request.method == "HEAD" else body,
            media_type=renderer.media_type,
            headers=headers,
        )
