#!/usr/bin/env python3
"""Synthetic Fleet capacity model; never contacts a panel or proves live convergence.

The model assigns one cycle per node to eight shared slots. Latency profiles are
explicit millisecond ranges (request, apply, retry backoff); the seeded generator
makes repeated runs comparable. A failed first attempt retries once. --failure-every
injects a terminal failure at every Nth node to exercise failure reporting.
"""
from __future__ import annotations

import argparse
import heapq
import json
import math
import random

SLOTS = 8  # FleetPusher's default global max_concurrent; never user-overridden here.
PROFILES = {
    "lan": {"request_ms": (4, 12), "apply_ms": (15, 35), "retry_ms": (20, 40)},
    "wan": {"request_ms": (80, 250), "apply_ms": (40, 100), "retry_ms": (250, 750)},
    "degraded": {"request_ms": (500, 1500), "apply_ms": (100, 400), "retry_ms": (1000, 3000)},
}


def distribution(values: list[int]) -> dict[str, int]:
    """Nearest-rank percentiles, with zero-valued empty distributions."""
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "min": 0, "p50": 0, "p95": 0, "max": 0}
    def rank(percent: float) -> int:
        return ordered[math.ceil(len(ordered) * percent) - 1]
    return {"count": len(ordered), "min": ordered[0], "p50": rank(.50),
            "p95": rank(.95), "max": ordered[-1]}


def measure(*, nodes: int, profile: str, seed: int, failure_every: int = 0,
            max_p95_convergence_ms: int = 30000, max_failures: int = 0) -> dict:
    if nodes < 1 or failure_every < 0 or max_p95_convergence_ms < 0 or max_failures < 0:
        raise ValueError("nodes must be positive; failure/threshold values cannot be negative")
    if profile not in PROFILES:
        raise ValueError("unknown latency profile")
    rng = random.Random(seed)
    latencies = PROFILES[profile]
    # Earliest-free slot first. All nodes are queued at t=0, as in one tick.
    slots = [(0, index) for index in range(min(nodes, SLOTS))]
    heapq.heapify(slots)
    queue, cycle, retry, convergence = [], [], [], []
    failures = 0
    for index in range(nodes):
        start, slot = heapq.heappop(slots)
        request = rng.randint(*latencies["request_ms"])
        apply = rng.randint(*latencies["apply_ms"])
        first = request + apply
        is_failure = failure_every > 0 and (index + 1) % failure_every == 0
        backoff = rng.randint(*latencies["retry_ms"]) if is_failure else 0
        elapsed = first + (backoff + request + apply if is_failure else 0)
        queue.append(start)
        cycle.append(elapsed)
        if is_failure:
            retry.append(backoff)
            failures += 1
        else:
            convergence.append(start + elapsed)
        heapq.heappush(slots, (start + elapsed, slot))
    p95 = distribution(convergence)["p95"]
    return {
        "schema": 1, "kind": "synthetic-model-not-live-evidence", "nodes": nodes,
        "profile": profile, "latency_profile_ms": latencies, "seed": seed,
        "slots": SLOTS, "peak_active": min(nodes, SLOTS), "failures": failures,
        "queue_ms": distribution(queue), "cycle_ms": distribution(cycle),
        "retry_ms": distribution(retry), "convergence_ms": distribution(convergence),
        "policy": {"max_p95_convergence_ms": max_p95_convergence_ms,
                   "max_failures": max_failures,
                   "pass": failures <= max_failures and p95 <= max_p95_convergence_ms},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--nodes", type=int, required=True)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--failure-every", type=int, default=0)
    parser.add_argument("--max-p95-convergence-ms", type=int, default=30000)
    parser.add_argument("--max-failures", type=int, default=0)
    args = parser.parse_args()
    try:
        report = measure(**vars(args))
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["policy"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
