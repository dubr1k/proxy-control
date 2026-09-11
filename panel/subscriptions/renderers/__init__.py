"""Subscription formats: `manifest | singbox | clash | raw | html` (owner decision 2).

Every renderer is a pure function over a `Manifest` and the artifacts resolved for it,
and none of them emits a link the target client is not known to parse: what a client
cannot take is listed as `unsupported` with the reason, never handed over as if it worked.
"""
from __future__ import annotations

from .base import (
    MAX_BYTES,
    MAX_GRANTS,
    MEDIA_TYPE_MANIFEST,
    Renderer,
    RenderError,
    resolve_artifacts,
)
from .clash import ClashRenderer
from .html import HtmlRenderer
from .manifest import ManifestRenderer
from .raw import RawRenderer
from .singbox import SingboxRenderer

RENDERERS: dict[str, Renderer] = {
    renderer.name: renderer
    for renderer in (ManifestRenderer(), SingboxRenderer(), ClashRenderer(), RawRenderer(), HtmlRenderer())
}

__all__ = [
    "MAX_BYTES",
    "MAX_GRANTS",
    "MEDIA_TYPE_MANIFEST",
    "RENDERERS",
    "RenderError",
    "Renderer",
    "resolve_artifacts",
]
