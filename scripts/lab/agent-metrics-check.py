#!/usr/bin/env python3
"""Real check of the agent's metrics sampler (run on a lab host as root, from the repo root).

Starts MetricsSampler against the real /proc and a real nftables table for one throw-away port
(tcp 45999, protocol name `probe`), pushes ~20 MB through a local echo server on 127.0.0.1:45999 in
both directions and asserts that the kernel counters (up = to the port, down = from it) match the
bytes moved within 10 % (L3 headers included). `--perf N` additionally measures the CPU the whole
process (the sampler thread, nothing else running) spends over N seconds. The table is removed at
the end.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from version_agent.hostmetrics import TABLE, MetricsSampler  # noqa: E402

PORT = 45999
TOTAL = 20 * 1024 * 1024


def echo_server(ready: threading.Event) -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", PORT))
        listener.listen(1)
        ready.set()
        conn, _ = listener.accept()
        with conn:
            while data := conn.recv(65536):
                conn.sendall(data)


def push_through() -> None:
    chunk = b"x" * 65536
    with socket.create_connection(("127.0.0.1", PORT)) as client:
        received = 0

        def drain() -> None:
            nonlocal received
            while received < TOTAL and (data := client.recv(65536)):
                received += len(data)

        reader = threading.Thread(target=drain)
        reader.start()
        for _ in range(TOTAL // len(chunk)):
            client.sendall(chunk)
        reader.join(timeout=60)
        assert received == TOTAL, f"echo returned {received} of {TOTAL}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--perf", type=int, default=0, help="seconds of idle sampling to measure CPU")
    args = parser.parse_args()
    sampler = MetricsSampler(ports=lambda: {"probe": {"tcp": [PORT], "udp": []}})
    try:
        sampler.start()
        deadline = time.monotonic() + 15
        while sampler.latest() is None and time.monotonic() < deadline:
            time.sleep(0.2)
        assert sampler.latest(), "no sample within 15 s"
        assert sampler.latest()["kernel_counters"] == "ok", "nft counters unavailable"
        ready = threading.Event()
        server = threading.Thread(target=echo_server, args=(ready,), daemon=True)
        server.start()
        ready.wait(5)
        push_through()
        time.sleep(2.5)  # two ticks so the final deltas are folded in
        probe = sampler.latest()["protocols"]["probe"]
        print(json.dumps({"moved_each_way": TOTAL, "counted": probe}, indent=2))
        for direction in ("up_bytes", "down_bytes"):
            ratio = probe[direction] / TOTAL
            assert 0.9 <= ratio <= 1.1, f"{direction} {probe[direction]} is {ratio:.3f}x of {TOTAL}"
        print("host:", json.dumps(sampler.latest()["host"], indent=2))
        if args.perf:
            import resource

            def cpu() -> float:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                return usage.ru_utime + usage.ru_stime

            before_cpu, before = cpu(), time.monotonic()
            time.sleep(args.perf)
            used, wall = cpu() - before_cpu, time.monotonic() - before
            print(f"perf: {used:.3f} s CPU over {wall:.1f} s = {100 * used / wall:.2f} % of one core")
        print("OK: kernel counters match the bytes moved")
        return 0
    finally:
        sampler.stop()
        subprocess.run(["nft", "delete", "table", "inet", TABLE], check=False, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
