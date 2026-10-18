"""Server-sent events for the live meters: framing, stream limits and the stream loop."""
from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict

PER_SESSION = 4
GLOBAL = 24
RETRY_MS = 3000
PING_SECONDS = 15.0
MAX_AGE_SECONDS = 55 * 60.0
RECHECK_SECONDS = 60.0


def frame(event: str, payload) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, separators=(',', ':'), allow_nan=False)}\n\n"


class Lease:
    def __init__(self, registry: "StreamRegistry", key: str):
        self._registry, self._key, self._open = registry, key, True

    def release(self) -> None:
        if self._open:
            self._open = False
            self._registry._release(self._key)


class StreamRegistry:
    """Open streams per session and in total; a stream beyond either limit is refused."""

    def __init__(self, per_session: int = PER_SESSION, total: int = GLOBAL):
        self.per_session, self.total = per_session, total
        self._count: dict[str, int] = defaultdict(int)

    def acquire(self, key: str) -> Lease | None:
        if self._count[key] >= self.per_session or sum(self._count.values()) >= self.total:
            return None
        self._count[key] += 1
        return Lease(self, key)

    def _release(self, key: str) -> None:
        self._count[key] -= 1
        if self._count[key] <= 0:
            self._count.pop(key, None)

    def open_streams(self) -> int:
        return sum(self._count.values())


async def event_stream(request, lease: Lease, *, build, version, next_event, alive, clock=time,
                       ping_seconds: float = PING_SECONDS, max_age: float = MAX_AGE_SECONDS,
                       recheck_seconds: float = RECHECK_SECONDS, poll: float = 1.0):
    """Yield SSE text: `retry`, a snapshot at once and after every collector tick, `: ping`
    when quiet, `event: bye` at the age limit or when the session is gone. Ends when the
    client leaves; always gives its lease back."""
    try:
        yield f"retry: {RETRY_MS}\n\n"
        started = last_sent = last_check = clock.monotonic()
        seen = None
        while True:
            now = clock.monotonic()
            if await request.is_disconnected():
                return
            if now - started >= max_age:
                yield frame("bye", {"reason": "max_age"})
                return
            if now - last_check >= recheck_seconds:
                last_check = now
                if not await alive():
                    yield frame("bye", {"reason": "session_ended"})
                    return
            current = version()
            if current != seen:
                payload = await build()
                if payload is not None:
                    seen = current
                    last_sent = now
                    yield frame("snapshot", payload)
                    continue
            if now - last_sent >= ping_seconds:
                last_sent = now
                yield ": ping\n\n"
            try:
                await asyncio.wait_for(next_event().wait(), timeout=poll)
            except asyncio.TimeoutError:
                pass
    finally:
        lease.release()
