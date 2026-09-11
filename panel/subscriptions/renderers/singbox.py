"""`singbox`: the JSON Karing and sing-box ≥ 1.13 import.

Only two outbound types exist here — `naive` (official sing-box on Apple, Android,
Windows and some Linux builds; Karing) and `mieru` (Karing's fork) — in exactly the
shapes the panel's one-time reveal has shipped since v0.1.0. MTProxy has no sing-box
outbound and is listed under `proxy_control.unsupported` with that reason; so is a
Mieru grant whose link carries a port range, because the outbound shape has no field
for one and dropping bindings silently is not an option.

The same JSON has two consumers with different vocabularies, so the renderer takes a
`client`: `karing` (the default) gets both types, `singbox` gets naive only — an
official sing-box refuses a configuration with an outbound type it does not know,
and a feed it cannot load is worse than one that names what it left out.
"""
from __future__ import annotations

import json
from urllib.parse import unquote, urlsplit

from ...protocols.mieru import parse_share_url, singbox_outbounds
from ..compatibility import MATRIX, NOTES
from ..models import Manifest, ManifestGrant
from .base import RenderError, check, credential_reason, finish, link_of

RANGE_REASON = "the sing-box mieru outbound has no field for a port range"
CLIENTS = ("karing", "singbox")


def _naive_outbound(grant: ManifestGrant, proxy_url: str) -> dict:
    parts = urlsplit(proxy_url)
    return {
        "type": "naive",
        "tag": f"naive-{grant.runtime_username}",
        "server": parts.hostname,
        "server_port": parts.port or 443,
        "username": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
        "tls": {"enabled": True, "server_name": parts.hostname},
    }


def _mieru_outbounds(grant: ManifestGrant, share_link: str) -> list[dict] | None:
    try:
        share = parse_share_url(share_link)
    except ValueError as exc:
        # The message names the grant, never the link: the link carries the password.
        raise RenderError(f"mieru {grant.runtime_username}: share link is not renderable") from exc
    return singbox_outbounds(
        share, tag=lambda port, protocol: f"mieru-{grant.runtime_username}-{protocol}-{port}"
    )


def _place(grant: ManifestGrant, artifacts: dict, client: str) -> tuple[list[dict], str | None]:
    """Either outbounds for the grant or the reason it has none — never both, never neither."""
    reason = credential_reason(grant, artifacts)
    if reason is not None:
        return [], reason
    if MATRIX.get(grant.protocol, {}).get(client) != "supported":
        # The matrix is the source: what this client cannot load is named, not shipped.
        return [], NOTES.get(grant.protocol, {}).get(client, f"{client} cannot consume {grant.protocol}")
    if grant.protocol == "naive":
        return [_naive_outbound(grant, link_of(grant, artifacts))], None
    if grant.protocol == "mieru":
        outbounds = _mieru_outbounds(grant, link_of(grant, artifacts))
        return (outbounds, None) if outbounds is not None else ([], RANGE_REASON)
    return [], f"no sing-box outbound for {grant.protocol}"


class SingboxRenderer:
    name = "singbox"
    media_type = "application/json"
    version = 1

    def render(self, manifest: Manifest, artifacts: dict, *, client: str = "karing") -> bytes:
        if client not in CLIENTS:
            raise RenderError(f"unknown sing-box client: {client}")
        check(manifest)
        outbounds: list[dict] = []
        unsupported: list[dict] = []
        for grant in manifest.grants:
            if not grant.enabled:
                continue
            placed, reason = _place(grant, artifacts, client)
            outbounds.extend(placed)
            if reason is not None:
                unsupported.append(
                    {"protocol": grant.protocol, "runtime_username": grant.runtime_username, "reason": reason}
                )
        payload = {
            "outbounds": outbounds,
            "proxy_control": {"generation": manifest.generation, "client": client, "unsupported": unsupported},
        }
        return finish(json.dumps(payload, ensure_ascii=False, indent=2).encode() + b"\n")
