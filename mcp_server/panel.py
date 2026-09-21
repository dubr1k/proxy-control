"""The panel as the MCP server sees it: one HTTP client inside the Compose network with the
panel's own `Host` and an admin API key. A refusal from the panel is a `PanelError` that
carries the panel's `{detail, code}` — the tools turn it into an error result, never into
a crash of the MCP session."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from .config import Config

TIMEOUT = httpx.Timeout(60.0, connect=5.0)


class PanelError(Exception):
    def __init__(self, status: int, detail: str, code: str | None = None):
        super().__init__(detail)
        self.status, self.detail, self.code = status, detail, code

    def payload(self) -> dict[str, Any]:
        return {"status": self.status, "detail": self.detail, "code": self.code}


def encode_path(template: str, values: dict[str, Any]) -> str:
    """`/api/clients/{client_id}` with its parameters substituted, each one URL-encoded so
    a value can never add a path segment."""
    path = template
    for name, value in values.items():
        path = path.replace("{" + name + "}", quote(str(value), safe=""))
    return path


class PanelClient:
    def __init__(self, config: Config, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.panel_url,
            headers={"Host": config.panel_host, "Authorization": f"Bearer {config.panel_key}",
                     "Accept": "application/json", "User-Agent": "proxy-control-mcp"},
            transport=transport,
            timeout=TIMEOUT,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, path: str, *, params: dict[str, Any] | None = None,
                      json: Any = None) -> Any:
        """The decoded JSON of a 2xx answer (None for an empty body); anything else raises
        `PanelError` with the panel's own words."""
        try:
            response = await self._client.request(method, path, params=params or None, json=json)
        except httpx.HTTPError as exc:
            raise PanelError(502, f"panel unreachable: {exc.__class__.__name__}", "panel_unreachable") from exc
        body: Any = None
        if response.content:
            try:
                body = response.json()
            except ValueError:
                body = response.text
        if response.is_success:
            return body
        if isinstance(body, dict):
            detail = body.get("detail", response.reason_phrase)
            code = body.get("code")
        else:
            detail, code = (body or response.reason_phrase), None
        raise PanelError(response.status_code, detail if isinstance(detail, str) else _json_text(detail), code)

    async def get(self, path: str, **params: Any) -> Any:
        return await self.request("GET", path, params={k: v for k, v in params.items() if v is not None})

    async def post(self, path: str, json: Any = None, **params: Any) -> Any:
        return await self.request("POST", path, json=json, params={k: v for k, v in params.items() if v is not None})


def _json_text(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)
