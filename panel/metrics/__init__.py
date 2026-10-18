"""Live monitoring (v2.0): the collector samples the host agent and the protocol managers,
keeps a ring of recent points, rolls them up into SQLite and serves live, history and summary."""
from __future__ import annotations

import time

from .collector import MetricsCollector
from .model import LOCAL_NODE, NodeMetricsSource
from .ring import SeriesRing
from .routes import register_metrics_routes
from .sse import StreamRegistry
from .store import MetricsStore

__all__ = ["LOCAL_NODE", "MetricsCollector", "MetricsStore", "NodeMetricsSource", "SeriesRing",
           "StreamRegistry", "register_metrics_routes", "setup_metrics"]


def setup_metrics(app, settings, *, source: NodeMetricsSource | None = None, clock=time) -> None:
    """Attach the collector, its store and the stream registry to `app.state`.

    `source` is the wave-2 hook: an object serving the linked nodes' meters."""
    ring = SeriesRing(settings.metrics_ring_points)
    interval = max(0.5, float(settings.metrics_interval_seconds))
    store = MetricsStore(app.state.database, ring, interval=interval, clock=clock)
    app.state.metrics_ring = ring
    app.state.metrics_store = store
    app.state.metrics_source = source
    app.state.metrics_streams = StreamRegistry()
    app.state.metrics_collector = (
        MetricsCollector(app.state, settings, store=store, ring=ring, interval=interval, clock=clock)
        if settings.metrics_enabled else None
    )
