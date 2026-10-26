"""Rollups, history resolution and gaps, summary maths and alert thresholds with synthetic data."""
from __future__ import annotations

import pytest

from panel.metrics.fakes import MetricsRig as Rig
from panel.metrics.store import percentile

pytestmark = pytest.mark.anyio


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path, trusttunnel_enabled=True)


def put(store, series, bucket, avg, *, count=1, peak=None, resolution=60):
    store.write({(resolution, bucket, series): [avg * count, count, avg if peak is None else peak, avg]})


def rollups(rig, resolution=60, series="host.cpu"):
    with rig.database.connect() as db:
        return [tuple(r) for r in db.execute(
            "SELECT bucket,sum,count,max,last FROM metric_rollups WHERE resolution=? AND series=? ORDER BY bucket",
            (resolution, series))]


def test_percentile_is_nearest_rank():
    assert percentile(list(range(1, 101)), 0.95) == 95
    assert percentile([], 0.95) is None





def _distinct(rig, column):
    with rig.database.connect() as db:
        return [tuple(r) for r in db.execute(f"SELECT DISTINCT {column} FROM metric_rollups")]

































