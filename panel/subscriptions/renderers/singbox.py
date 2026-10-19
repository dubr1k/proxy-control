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

The `karing` cut is also what Throne takes: ThroneCore is a sing-box fork with a mieru
outbound, and Throne's parser reads `outbounds[]` of both types as they are (checked
with Throne 1.3.1 on the lab host). Its Clash parser has neither type.

TrustTunnel has no outbound in upstream sing-box (planned: SagerNet/sing-box#3723, milestone
1.14), and a config with an unknown outbound type is dropped whole, so no generic cut carries
it. Two fork cores do: hiddify-sing-box ("Since sing-box 1.14.0", used by Hiddify) and the
NekoBox fork NyameBox. Only a request that names one of them (`client=hiddify|nekobox`) gets the
`trusttunnel` outbound; `karing`, `singbox` and every other request keep the "no outbound" note.
The cells come from the compatibility matrix as for every other protocol.
"""
from __future__ import annotations

import json
from urllib.parse import unquote, urlsplit

from ...protocols.mieru import parse_share_url, singbox_outbounds
from ..compatibility import MATRIX, NOTES
from ..models import Manifest, ManifestGrant
from ..names import grant_names
from .base import RenderError, check, credential_reason, finish, link_of, trusttunnel_fields

RANGE_REASON = "the sing-box mieru outbound has no field for a port range"
# `throne`, `hiddify`, `nekobox`: fork cores with a TrustTunnel outbound. `fork`: a client the owner added
# through PANEL_SINGBOX_FORK_CLIENTS — the Karing cut plus TrustTunnel.
CLIENTS = ("karing", "singbox", "hiddify", "nekobox", "throne", "fork")
TRUSTTUNNEL_CLIENTS = ("hiddify", "nekobox", "throne", "fork")


def _naive_outbound(grant: ManifestGrant, proxy_url: str, name: str) -> dict:
    parts = urlsplit(proxy_url)
    return {
        "type": "naive",
        "tag": name,
        "server": parts.hostname,
        "server_port": parts.port or 443,
        "username": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
        "tls": {"enabled": True, "server_name": parts.hostname},
    }


def _trusttunnel_outbound(grant: ManifestGrant, link: str, name: str) -> dict:
    """The fork cores' `trusttunnel` outbound, from the access's own deep link. TCP only: HTTP/2 over
    TLS, QUIC off. `insecure` only where the link carries a certificate (the system store does not
    trust the endpoint's own), because the outbound has no field to pin one. No `health_check`: with it on,
    hiddify-sing-box (sing-trusttunnel v0.3.2) panicked in the first dial on the lab host (2026-10-19)."""
    fields = trusttunnel_fields(link)
    try:
        _, _, port = fields["addresses"][0].rpartition(":")
        tls = {"enabled": True, "server_name": fields["hostname"]}
        if fields.get("certificate") or fields["skip_verification"]:
            tls["insecure"] = True
        return {
            "type": "trusttunnel", "tag": name, "server": fields["hostname"], "server_port": int(port),
            "username": fields["username"], "password": fields["password"],
            "quic": False, "tls": tls,
        }
    except (KeyError, IndexError, ValueError) as exc:
        raise RenderError(f"trusttunnel {grant.runtime_username}: link is not renderable") from exc


def _mieru_outbounds(grant: ManifestGrant, share_link: str, name: str) -> list[dict] | None:
    try:
        share = parse_share_url(share_link)
    except ValueError as exc:
        # The message names the grant, never the link: the link carries the password.
        raise RenderError(f"mieru {grant.runtime_username}: share link is not renderable") from exc
    return singbox_outbounds(
        share, tag=lambda port, protocol: f"{name} · {protocol} {port}"
    )


def _place(grant: ManifestGrant, artifacts: dict, client: str, name: str) -> tuple[list[dict], str | None]:
    """Either outbounds for the grant or the reason it has none — never both, never neither."""
    reason = credential_reason(grant, artifacts)
    if reason is not None:
        return [], reason
    if grant.protocol == "trusttunnel":
        if client not in TRUSTTUNNEL_CLIENTS:
            return [], NOTES["trusttunnel"].get(client, f"no sing-box outbound for {grant.protocol}")
        return [_trusttunnel_outbound(grant, link_of(grant, artifacts), name)], None
    if MATRIX.get(grant.protocol, {}).get(client if client != "fork" else "karing") != "supported":
        # The matrix is the source: what this client cannot load is named, not shipped.
        return [], NOTES.get(grant.protocol, {}).get(client if client != "fork" else "karing", f"{client} cannot consume {grant.protocol}")
    if grant.protocol == "naive":
        return [_naive_outbound(grant, link_of(grant, artifacts), name)], None
    if grant.protocol == "mieru":
        outbounds = _mieru_outbounds(grant, link_of(grant, artifacts), name)
        return (outbounds, None) if outbounds is not None else ([], RANGE_REASON)
    return [], f"no sing-box outbound for {grant.protocol}"


class SingboxRenderer:
    name = "singbox"
    media_type = "application/json"
    version = 3

    def render(self, manifest: Manifest, artifacts: dict, *, client: str = "karing") -> bytes:
        if client not in CLIENTS:
            raise RenderError(f"unknown sing-box client: {client}")
        check(manifest)
        names = grant_names(manifest)
        outbounds: list[dict] = []
        unsupported: list[dict] = []
        for grant in manifest.grants:
            if not grant.enabled:
                continue
            placed, reason = _place(grant, artifacts, client, names[grant.grant_id])
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
