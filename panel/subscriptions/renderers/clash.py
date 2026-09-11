"""`clash`: the YAML mihomo (Clash.Meta) and Karing's clash core import.

Only `type: mieru` proxies live here — mihomo has no naive type (an open feature
request) and no MTProto type — so naive and MTProxy grants go under
`proxy-control.unsupported` with those reasons.

The YAML is written by hand on purpose: PyYAML is not a dependency of the panel, and a
subscription does not need a YAML library. Every string is a single-quoted scalar, every
number and boolean a plain one, and a string the writer cannot prove safe inside single
quotes (a quote character, a control character, a line separator) is a `RenderError`
rather than an escape sequence someone would have to get right.
"""
from __future__ import annotations

from ...protocols.mieru import MieruShare, parse_share_url
from ..compatibility import NOTES
from ..models import Manifest, ManifestGrant
from .base import RenderError, check, credential_reason, finish, link_of


def scalar(value) -> str:
    """One YAML scalar: quoted strings, plain ints and booleans, nothing else."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str) or not value.isprintable() or "'" in value:
        raise RenderError("a value cannot be written as a safe YAML scalar")
    return f"'{value}'"


def _proxies(grant: ManifestGrant, share: MieruShare) -> list[list[tuple[str, object]]]:
    """One mihomo proxy per port binding, as ordered key/value pairs."""
    proxies = []
    for binding in share.bindings:
        port = binding.get("port")
        port_key, port_value = ("port", port) if port is not None else ("port-range", binding["portRange"])
        name = f"mieru-{grant.runtime_username}-{binding['protocol']}-{port_value}"
        proxies.append([
            ("name", name),
            ("type", "mieru"),
            ("server", share.host),
            (port_key, port_value),
            ("transport", binding["protocol"]),
            ("username", share.username),
            ("password", share.password),
            ("udp", True),
        ])
    return proxies


def _mapping_item(pairs: list[tuple[str, object]], indent: str) -> str:
    first, *rest = pairs
    lines = [f"{indent}- {first[0]}: {scalar(first[1])}"]
    lines.extend(f"{indent}  {key}: {scalar(value)}" for key, value in rest)
    return "\n".join(lines)


class ClashRenderer:
    name = "clash"
    media_type = "text/yaml; charset=utf-8"
    version = 1

    def render(self, manifest: Manifest, artifacts: dict) -> bytes:
        check(manifest)
        proxies: list[list[tuple[str, object]]] = []
        unsupported: list[tuple[str, str, str]] = []
        for grant in manifest.grants:
            if not grant.enabled:
                continue
            reason = credential_reason(grant, artifacts)
            if reason is None and grant.protocol == "mieru":
                try:
                    share = parse_share_url(link_of(grant, artifacts))
                except ValueError as exc:
                    raise RenderError(f"mieru {grant.runtime_username}: share link is not renderable") from exc
                proxies.extend(_proxies(grant, share))
                continue
            if reason is None:
                reason = NOTES.get(grant.protocol, {}).get("mihomo", f"no mihomo proxy type for {grant.protocol}")
            unsupported.append((grant.protocol, grant.runtime_username, reason))

        lines = ["proxies:" if proxies else "proxies: []"]
        lines.extend(_mapping_item(pairs, "  ") for pairs in proxies)
        lines.append("proxy-groups:")
        lines.append(_mapping_item([("name", "proxy-control"), ("type", "select")], "  "))
        if proxies:
            lines.append("    proxies:")
            lines.extend(f"      - {scalar(dict(pairs)['name'])}" for pairs in proxies)
        else:
            lines.append("    proxies: []")
        lines.append("proxy-control:")
        lines.append(f"  generation: {scalar(manifest.generation)}")
        lines.append("  unsupported:" if unsupported else "  unsupported: []")
        lines.extend(
            _mapping_item([("protocol", protocol), ("runtime_username", user), ("reason", reason)], "    ")
            for protocol, user, reason in unsupported
        )
        return finish(("\n".join(lines) + "\n").encode())
