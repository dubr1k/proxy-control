"""Deterministic, credential-free Fleet capacity model (not a live Fleet test)."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/lab/fleet-measure.py"
spec = importlib.util.spec_from_file_location("fleet_measure", SCRIPT)
fm = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fm
spec.loader.exec_module(fm)


def test_metrics_and_eight_slot_cap():
    report = fm.measure(nodes=20, profile="lan", seed=1, failure_every=0)
    assert report["nodes"] == 20
    assert report["slots"] == 8
    assert report["peak_active"] == 8
    assert report["failures"] == 0
    assert report["queue_ms"]["max"] > 0
    assert report["cycle_ms"]["p95"] >= report["cycle_ms"]["p50"]
    assert report["convergence_ms"]["p95"] >= report["cycle_ms"]["p95"]


def test_retries_failures_and_threshold_policy():
    report = fm.measure(nodes=12, profile="wan", seed=4, failure_every=3)
    assert report["failures"] == 4
    assert report["retry_ms"]["count"] == 4
    assert report["convergence_ms"]["count"] == 8
    assert report["policy"]["pass"] is False
    relaxed = fm.measure(nodes=12, profile="wan", seed=4, failure_every=0,
                         max_p95_convergence_ms=100000, max_failures=0)
    assert relaxed["policy"]["pass"] is True


def test_report_contains_only_aggregate_numbers_and_known_profile():
    report = fm.measure(nodes=3, profile="lan", seed=1)
    serialized = json.dumps(report)
    assert "node-" not in serialized and "secret" not in serialized and "token" not in serialized
    assert fm.measure(nodes=3, profile="lan", seed=1) == report
    with pytest.raises(ValueError):
        fm.measure(nodes=3, profile="bogus", seed=1)
    with pytest.raises(ValueError):
        fm.measure(nodes=0, profile="lan", seed=1)
