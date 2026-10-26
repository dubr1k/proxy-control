"""The monitor's sampler: counter arithmetic, the node snapshot, manager fallback and cadence."""
from __future__ import annotations

import pytest

from panel.metrics.fakes import MetricsRig as Rig
from panel.metrics.rates import ClientRates, fold

pytestmark = pytest.mark.anyio


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path, trusttunnel_enabled=True, amneziawg_enabled=True, naive_enabled=True, mieru_enabled=True)













































