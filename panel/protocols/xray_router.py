"""The node's Xray-router as the routing service drives it (v0.5): one adapter over the
router manager's client, per service section. Not a protocol adapter — the router owns no
grants — but it speaks the egress vocabulary of `ProtocolAdapter` for one `service`."""
from __future__ import annotations

from ..xray_router import XrayRouterError
from .base import AdapterError, AppliedEgress, RouterTarget, applied_egress_from_view, egress_error, router_target_from_view

UNAVAILABLE_REASONS = {503: "manual_intervention_required"}


class RouterAdapter:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def _error(exc: XrayRouterError) -> AdapterError:
        return egress_error("Xray-router", exc.status_code, exc.code)

    async def target(self, service: str) -> RouterTarget:
        """The service's section, or an unavailable target with the reason — never raises:
        an absent router is a fact the compiler reports, not an outage of the panel."""
        try:
            view = await self.client.egress(service)
        except XrayRouterError as exc:
            reason = exc.code or ("router_unavailable" if exc.status_code == 502 else UNAVAILABLE_REASONS.get(
                exc.status_code, "router_unavailable"))
            return RouterTarget(available=False, service=service, reason=reason)
        return router_target_from_view(service, view)

    async def status(self) -> dict | None:
        try:
            return await self.client.status()
        except XrayRouterError:
            return None

    async def plan(self, service: str, document: dict, *, expected_revision: str) -> dict:
        try:
            return await self.client.egress_plan(service, expected_revision, document)
        except XrayRouterError as exc:
            raise self._error(exc) from exc

    async def apply(self, service: str, document: dict, *, expected_revision: str, operation_id: str) -> AppliedEgress:
        try:
            view = await self.client.egress_apply(service, expected_revision, document, operation_id)
        except XrayRouterError as exc:
            raise self._error(exc) from exc
        return applied_egress_from_view(view)

    async def rollback(self, service: str, *, expected_revision: str) -> AppliedEgress:
        try:
            view = await self.client.egress_rollback(service, expected_revision)
        except XrayRouterError as exc:
            raise self._error(exc) from exc
        return applied_egress_from_view(view)

    # -- v0.7: lanes and the relay --------------------------------------------------

    async def lane_issue(self, service: str, lane: str) -> dict:
        try:
            return await self.client.lane_issue(service, lane)
        except XrayRouterError as exc:
            raise self._error(exc) from exc

    async def lane_forget(self, service: str, lane: str) -> dict:
        try:
            return await self.client.lane_forget(service, lane)
        except XrayRouterError as exc:
            raise self._error(exc) from exc

    async def relay(self) -> dict | None:
        try:
            return await self.client.relay()
        except XrayRouterError:
            return None

    async def relay_enable(self, server_name: str, port: int) -> dict:
        try:
            return await self.client.relay_enable(server_name, port)
        except XrayRouterError as exc:
            raise self._error(exc) from exc

    async def relay_disable(self) -> dict:
        try:
            return await self.client.relay_disable()
        except XrayRouterError as exc:
            raise self._error(exc) from exc

    async def relay_set_accounts(self, accounts: list[dict]) -> dict:
        try:
            return await self.client.relay_set_accounts(accounts)
        except XrayRouterError as exc:
            raise self._error(exc) from exc
