"""What every renderer shares: the contract, the bounds, and the one reveal.

A renderer is a pure function of a `Manifest` and the artifacts already rendered for it.
Credentials enter the picture exactly once, in `resolve_artifacts`, which reveals each
effective grant's secret in memory and hands the adapter's artifacts back; nothing here
writes, logs, or embeds a plaintext in an error message.

Two bounds protect the subscriber and the panel alike: a manifest with more than
`MAX_GRANTS` grants or a body over `MAX_BYTES` is refused outright, never truncated —
a silently shortened profile is worse than an honest error.
"""
from __future__ import annotations

from typing import Protocol
from urllib.parse import quote, urlsplit

from ...clients.store import ClientStore
from ...protocols.base import AccessArtifact
from ...secrets_store import SecretRef
from ..models import Manifest, ManifestGrant

MEDIA_TYPE_MANIFEST = "application/vnd.proxy-control.subscription+json;version=1"
MAX_GRANTS = 64
MAX_BYTES = 512 * 1024
CREDENTIAL_PURPOSE = "grant.credential"
NO_CREDENTIAL = "no stored credential"


class RenderError(ValueError):
    """A manifest the renderer refuses. The message never carries a credential."""


class Renderer(Protocol):
    name: str
    media_type: str
    version: int

    def render(self, manifest: Manifest, artifacts: dict[str, list[AccessArtifact]]) -> bytes: ...


def check(manifest: Manifest) -> None:
    if len(manifest.grants) > MAX_GRANTS:
        raise RenderError(f"too many grants: {len(manifest.grants)} > {MAX_GRANTS}")


def finish(body: bytes) -> bytes:
    if len(body) > MAX_BYTES:
        raise RenderError(f"rendered subscription is too large: {len(body)} > {MAX_BYTES} bytes")
    return body


def resolve_artifacts(
    manifest: Manifest, secrets, adapters: dict, db, *, public_hosts: dict[str, str]
) -> dict[str, list[AccessArtifact]]:
    """Reveal each effective grant's credential in memory and render its artifacts.

    Only grants that are enabled right now and point at a stored secret are revealed:
    a suspended or credential-less grant gets no artifacts, so no renderer can turn it
    into a link by accident. The grant row comes from the database rather than being
    rebuilt from the manifest, because adapters render from the row's typed options.
    """
    result: dict[str, list[AccessArtifact]] = {}
    for grant in manifest.grants:
        if not grant.enabled or grant.secret_version < 1:
            continue
        adapter = adapters.get(grant.protocol)
        if adapter is None:
            continue
        row = ClientStore.grant(db, grant.grant_id)
        plaintext = secrets.reveal(
            db,
            SecretRef(f"grant:{grant.grant_id}", grant.secret_version),
            purpose=CREDENTIAL_PURPOSE,
            grant_id=grant.grant_id,
            permitted_node_id=grant.node_id,
        )
        result[grant.grant_id] = adapter.render_artifacts(
            row, plaintext, public_host=public_hosts.get(grant.protocol, "")
        )
    return result


def credential_reason(grant: ManifestGrant, artifacts: dict[str, list[AccessArtifact]]) -> str | None:
    """Why an effective grant still has no link — or None when it does."""
    if grant.secret_version < 1 or not artifacts.get(grant.grant_id):
        return NO_CREDENTIAL
    return None


def link_of(grant: ManifestGrant, artifacts: dict[str, list[AccessArtifact]]) -> str:
    """The adapter's connection link: the first `text/uri-list` artifact."""
    for artifact in artifacts.get(grant.grant_id, []):
        if artifact.media_type == "text/uri-list":
            return artifact.value
    raise RenderError(f"{grant.protocol} {grant.runtime_username}: no link artifact")


def naive_share_url(proxy_url: str, username: str) -> str:
    """`naive+https://…` — what NekoBox-family clients and QR scanners actually import.

    The adapter's artifact is NaiveProxy's own `https://user:pass@host`; the share form
    adds the scheme prefix, the explicit port and a display name.
    """
    parts = urlsplit(proxy_url)
    return (
        f"naive+https://{parts.username}:{parts.password}@{parts.hostname}:{parts.port or 443}"
        f"#{quote(f'Naive · {username}', safe='')}"
    )
