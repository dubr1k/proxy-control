"""`clash`: the YAML mihomo (Clash.Meta) and Karing's clash core import.

Only `type: mieru` and `type: trusttunnel` proxies live here — mihomo has no naive type
(an open feature request) and no MTProto type — so naive and MTProxy grants go under
`proxy-control.unsupported` with those reasons. Not for Throne: its Clash parser has no
mieru type and imports nothing from this feed (it takes the sing-box `karing` cut).

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
from ..names import grant_names
from .base import RenderError, check, credential_reason, finish, link_of, trusttunnel_fields


def scalar(value) -> str:
    """One YAML scalar: quoted strings, plain ints and booleans, nothing else."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str) or not value.isprintable() or "'" in value:
        raise RenderError("a value cannot be written as a safe YAML scalar")
    return f"'{value}'"


def _proxies(grant: ManifestGrant, share: MieruShare, label: str) -> list[list[tuple[str, object]]]:
    """One mihomo proxy per port binding, as ordered key/value pairs."""
    proxies = []
    for binding in share.bindings:
        port = binding.get("port")
        port_key, port_value = ("port", port) if port is not None else ("port-range", binding["portRange"])
        name = f"{label} · {binding['protocol']} {port_value}"
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


def _trusttunnel_proxy(grant: ManifestGrant, link: str, label: str) -> list[tuple[str, object]]:
    """The mihomo `trusttunnel` proxy, from the access's own deep link (the one place the
    password is held). TCP only: `udp` and `quic` are off. mihomo cannot pin a certificate, so an
    endpoint whose certificate the system store does not trust (the link then carries it) is
    reached with `skip-cert-verify`."""
    fields = trusttunnel_fields(link)
    try:
        host, _, port = fields["addresses"][0].rpartition(":")
        pairs: list[tuple[str, object]] = [
            ("name", label), ("type", "trusttunnel"), ("server", fields["hostname"]), ("port", int(port)),
            ("username", fields["username"]), ("password", fields["password"]), ("udp", False), ("quic", False),
        ]
    except (KeyError, IndexError, ValueError) as exc:
        raise RenderError(f"trusttunnel {grant.runtime_username}: link is not renderable") from exc
    if fields.get("certificate") or fields["skip_verification"]:
        pairs.append(("skip-cert-verify", True))
    return pairs


def _mapping_item(pairs: list[tuple[str, object]], indent: str) -> str:
    first, *rest = pairs
    lines = [f"{indent}- {first[0]}: {scalar(first[1])}"]
    lines.extend(f"{indent}  {key}: {scalar(value)}" for key, value in rest)
    return "\n".join(lines)


class ClashRenderer:
    name = "clash"
    media_type = "text/yaml; charset=utf-8"
    version = 2

    def render(self, manifest: Manifest, artifacts: dict) -> bytes:
        check(manifest)
        names = grant_names(manifest)
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
                proxies.extend(_proxies(grant, share, names[grant.grant_id]))
                continue
            if reason is None and grant.protocol == "trusttunnel":
                proxies.append(_trusttunnel_proxy(grant, link_of(grant, artifacts), names[grant.grant_id]))
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
