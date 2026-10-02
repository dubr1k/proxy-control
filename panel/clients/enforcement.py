"""Deadline enforcement is local to each panel and survives loss of its central."""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


class AccessEnforcer:
    def __init__(self, clients, reconciler, *, interval=15.0):
        self.clients, self.reconciler, self.interval = clients, reconciler, interval
        self._stop = asyncio.Event()

    async def tick(self, *, force=False):
        # Independent failure boundaries: a managed-node error cannot skip local expiry.
        for enforce in (lambda: self.clients.reconcile_access(force=force), self.reconciler.run_pending):
            try:
                await enforce()
            except Exception:  # noqa: BLE001 — retry next tick, never abandon the timer
                log.warning("access enforcement tick failed; retrying")

    async def run_forever(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                await self.tick()

    def stop(self):
        self._stop.set()
