"""`raw`: one link per line, plain text, no base64.

Base64 is a v2ray-subscription convention whose parsers accept only
`vmess/vless/trojan/ss/hysteria/hysteria2/tuic`; neither `naive+https://` nor `mierus://`
is among them, so wrapping would gain no client and would break `curl`, QR codes and
human reading (owner decision 6). A grant that cannot be rendered is a comment line
that says why, never a link that does not work.
"""
from __future__ import annotations

from ..models import Manifest
from ..names import grant_names
from .base import check, credential_reason, finish, link_of, named_share_url


class RawRenderer:
    name = "raw"
    media_type = "text/plain; charset=utf-8"
    version = 2

    def render(self, manifest: Manifest, artifacts: dict) -> bytes:
        check(manifest)
        names = grant_names(manifest)
        lines = []
        for grant in manifest.grants:
            if not grant.enabled:
                lines.append(f"# disabled {grant.protocol} {grant.runtime_username}")
                continue
            reason = credential_reason(grant, artifacts)
            if reason is not None:
                lines.append(f"# unsupported {grant.protocol} {grant.runtime_username}: {reason}")
                continue
            link = link_of(grant, artifacts)
            link = named_share_url(grant, link, names[grant.grant_id])
            lines.append(link)
        return finish(("\n".join(lines) + "\n").encode())
