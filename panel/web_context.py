from __future__ import annotations

import asyncio
import secrets
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders

from .settings import Settings


class KeyRateLimiter:
    """Per-key sliding window, in-process (spec §5.1)."""

    def __init__(self, limit: int, window: float = 60.0, clock=time):
        self.limit, self.window, self.clock = limit, window, clock
        self.hits: dict[int, deque] = defaultdict(deque)

    def allow(self, key_id: int) -> bool:
        now = self.clock.monotonic()
        window = self.hits[key_id]
        while window and now - window[0] > self.window:
            window.popleft()
        if len(window) >= self.limit:
            return False
        window.append(now)
        return True


class RequestContext:
    def __init__(self, app, settings: Settings) -> None:
        self.app = app
        self.settings = settings

        async def current(request: Request):
            header = request.headers.get("authorization", "")
            if header.lower().startswith("bearer "):
                user = await asyncio.to_thread(
                    self.app.state.api_keys.authenticate, header[7:].strip()
                )
                if not user:
                    raise HTTPException(401, "invalid API key")
                if not self.app.state.key_rate.allow(user["key_id"]):
                    raise HTTPException(429, "API key rate limit exceeded")
                if user["scope"] == "node-sync" and not request.url.path.startswith(
                    "/api/fleet/v2/"
                ):
                    raise HTTPException(403, "node-sync key is limited to the fleet API")
                # Bearer users have no session, so `create_reveal`/`consume_reveal`
                # (keyed on `owner["token_hash"]`) need a stand-in that stays unique
                # per key without ever colliding with a real session token hash.
                return {**user, "token_hash": f"key:{user['key_id']}"}
            value = await asyncio.to_thread(
                self.app.state.store.session,
                request.cookies.get("panel_session"),
            )
            if not value:
                raise HTTPException(401, "authentication required")
            return value

        async def mutation(request: Request, user=Depends(current)):
            if user.get("via") == "api-key":
                # A bearer request carries no cookie, so there is no CSRF state to check.
                return user
            supplied = request.headers.get("X-CSRF-Token")
            cookie = request.cookies.get("panel_csrf")
            if not self.app.state.store.csrf_valid(user, supplied, cookie):
                if supplied and cookie and secrets.compare_digest(supplied, cookie):
                    await asyncio.to_thread(
                        self.app.state.store.delete_session,
                        request.cookies.get("panel_session"),
                    )
                    raise HTTPException(401, "session CSRF state invalid")
                raise HTTPException(403, "CSRF validation failed")
            return user

        async def fleet_key(user=Depends(current)):
            if user.get("via") != "api-key" or user["scope"] not in ("node-sync", "admin"):
                raise HTTPException(403, "a node-sync or admin API key is required")
            return user

        # `gate` names what each dependency enforces, for the route audit
        # (`scripts/dev/route-coverage.py`): it never changes the behaviour.
        current.gate = ("current",)  # type: ignore[attr-defined]
        mutation.gate = ("mutation",)  # type: ignore[attr-defined]
        fleet_key.gate = ("fleet_key",)  # type: ignore[attr-defined]
        self.current = current
        self.mutation = mutation
        self.fleet_key = fleet_key

    def roles(self, *allowed: str):
        async def check(user=Depends(self.mutation)):
            if user["role"] not in allowed:
                raise HTTPException(403, "insufficient role")
            return user

        check.gate = ("roles", *allowed)  # type: ignore[attr-defined]
        return check

    def read_roles(self, *allowed: str):
        """A role gate for reads. CSRF protects state changes, and a GET carries no
        token, so `roles()` would reject every reader before its role is even looked at."""

        async def check(user=Depends(self.current)):
            if user["role"] not in allowed:
                raise HTTPException(403, "insufficient role")
            return user

        check.gate = ("read_roles", *allowed)  # type: ignore[attr-defined]
        return check

    @staticmethod
    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def domain_context(self, request: Request, user: dict) -> dict:
        """Who did it, from where, under which request — the audit fields every
        domain write needs, built once instead of in every route."""
        return {
            "actor": user,
            "ip": self.client_ip(request),
            "request_id": getattr(request.state, "request_id", None),
        }

    async def audit(
        self,
        user: dict,
        action: str,
        target: str,
        request: Request,
        detail: dict | None = None,
    ) -> None:
        await asyncio.to_thread(
            self.app.state.store.audit,
            user,
            action,
            target,
            self.client_ip(request),
            detail,
            getattr(request.state, "request_id", None),
        )

    def create_reveal(self, data: dict, owner: dict) -> str:
        now = self.app.state.clock.monotonic()
        for expired_token, value in list(self.app.state.reveals.items()):
            if value[0] < now:
                self.app.state.reveals.pop(expired_token, None)
        token = secrets.token_urlsafe(32)
        self.app.state.reveals[token] = (
            now + self.settings.reveal_ttl_seconds,
            owner["token_hash"],
            data,
        )
        return token

    def consume_reveal(self, token: str, user: dict) -> dict:
        value = self.app.state.reveals.get(token)
        if not value or value[0] < self.app.state.clock.monotonic():
            self.app.state.reveals.pop(token, None)
            raise HTTPException(410, "reveal expired or consumed")
        if not secrets.compare_digest(value[1], user["token_hash"]):
            raise HTTPException(403, "reveal belongs to another session")
        self.app.state.reveals.pop(token, None)
        return value[2]


class BoundedBodyMiddleware:
    """Read at most the configured limit before dispatching to a handler.

    The transport owns the current chunk; oversized chunks are never appended.
    Replaying through ASGI keeps downstream body/JSON/form readers unchanged.
    """

    def __init__(self, app, limit: int):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        lengths = Headers(scope=scope).getlist("content-length")
        try:
            invalid = any(not value.isdecimal() or int(value) > self.limit for value in lengths)
        except ValueError:
            invalid = True
        if invalid:
            return await JSONResponse({"detail": "request body too large"}, 413)(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return await JSONResponse({"detail": "incomplete request body"}, 400)(scope, receive, send)
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.limit:
                return await JSONResponse({"detail": "request body too large"}, 413)(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        pending = True

        async def replay():
            nonlocal pending
            if pending:
                pending = False
                message = {"type": "http.request", "body": bytes(body), "more_body": False}
                body.clear()
                return message
            return await receive()

        await self.app(scope, replay, send)


class SecurityHeadersMiddleware:
    """Wrap ASGI directly so body cancellation never becomes a missing-response 500."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # One id per request, echoed to the client and stored on every audit row the
        # request writes, so a response can be traced to its trail and back.
        request_id = secrets.token_hex(8)
        scope.setdefault("state", {})["request_id"] = request_id
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store",
            "X-Request-Id": request_id,
        }
        if scope["path"].startswith("/s/"):
            # A subscription is fetched by clients that revalidate with `If-None-Match`,
            # so the route sets `private, no-cache` itself and it must survive; and the
            # human-readable page carries its own inline stylesheet and QR images, but
            # no script and nothing from anywhere else.
            headers.pop("Cache-Control")
            headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        async def secured_send(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).update(headers)
            await send(message)

        await self.app(scope, receive, secured_send)


def install_security_middleware(app, settings: Settings) -> None:
    app.add_middleware(BoundedBodyMiddleware, limit=settings.body_limit_bytes)
    # Registered last so headers also wrap early body-limit/disconnect responses.
    app.add_middleware(SecurityHeadersMiddleware)
