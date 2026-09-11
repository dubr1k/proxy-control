from __future__ import annotations

import asyncio
import secrets
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

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

        self.current = current
        self.mutation = mutation
        self.fleet_key = fleet_key

    def roles(self, *allowed: str):
        async def check(user=Depends(self.mutation)):
            if user["role"] not in allowed:
                raise HTTPException(403, "insufficient role")
            return user

        return check

    def read_roles(self, *allowed: str):
        """A role gate for reads. CSRF protects state changes, and a GET carries no
        token, so `roles()` would reject every reader before its role is even looked at."""

        async def check(user=Depends(self.current)):
            if user["role"] not in allowed:
                raise HTTPException(403, "insufficient role")
            return user

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


def install_security_middleware(app, settings: Settings) -> None:
    @app.middleware("http")
    async def security(request: Request, call_next):
        # One id per request, echoed to the client and stored on every audit row the
        # request writes, so a response can be traced to its trail and back.
        request.state.request_id = secrets.token_hex(8)
        length = request.headers.get("content-length")
        try:
            declared_too_large = bool(
                length and int(length) > settings.body_limit_bytes
            )
        except ValueError:
            declared_too_large = True
        if declared_too_large:
            response = JSONResponse({"detail": "request body too large"}, 413)
        else:
            body = await request.body()
            response = (
                JSONResponse({"detail": "request body too large"}, 413)
                if len(body) > settings.body_limit_bytes
                else await call_next(request)
            )
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store",
            "X-Request-Id": request.state.request_id,
        }
        if request.url.path.startswith("/s/"):
            # A subscription is fetched by clients that revalidate with `If-None-Match`,
            # so the route sets `private, no-cache` itself and it must survive; and the
            # human-readable page carries its own inline stylesheet and QR images, but
            # no script and nothing from anywhere else.
            headers.pop("Cache-Control")
            headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        response.headers.update(headers)
        return response
