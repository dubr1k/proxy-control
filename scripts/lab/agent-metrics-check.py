#!/usr/bin/env python3
"""Real native-agent telemetry proof on the disposable Ubuntu lab host as root.

An isolated network/mount namespace keeps the nft table and port override away
from installed services. Pushes 20 MiB each way over loopback and queries the
actual version-agent Unix HTTP endpoint. --perf N measures the agent's CPU only.
Python is an external controller, never the sampler implementation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

import httpx

PORT = 45999
TOTAL = 20 * 1024 * 1024


def echo_server(ready):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", PORT))
        listener.listen(1)
        ready.set()
        conn, _ = listener.accept()
        with conn:
            while data := conn.recv(65536):
                conn.sendall(data)


def push_through():
    chunk = b"x" * 65536
    with socket.create_connection(("127.0.0.1", PORT)) as client:
        received = 0

        def drain():
            nonlocal received
            while received < TOTAL and (data := client.recv(65536)):
                received += len(data)

        reader = threading.Thread(target=drain)
        reader.start()
        for _ in range(TOTAL // len(chunk)):
            client.sendall(chunk)
        reader.join(timeout=60)
        if received != TOTAL:
            raise AssertionError("echo byte count mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--perf", type=int, default=0)
    parser.add_argument("--agent", type=Path, default=Path(os.environ.get("PC_VERSION_AGENT_BIN", "version_agent/bin/linux-amd64/proxy-control-version-agent")))
    parser.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("run on the disposable lab host as root")
    agent = args.agent.resolve(strict=True)
    if not args.isolated:
        os.execvp("unshare", ["unshare", "--mount", "--net", "--fork", "--propagation", "private",
                              sys.executable, str(Path(__file__).resolve()), "--isolated", "--agent", str(agent), "--perf", str(args.perf)])
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/etc"], check=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    Path("/etc/proxy-control").mkdir()
    Path("/etc/proxy-control/metrics-ports.json").write_text(json.dumps({"mtproxy": {"tcp": [PORT], "udp": []}}))
    with tempfile.TemporaryDirectory(prefix="native-metrics-") as directory:
        work = Path(directory)
        env = {**os.environ, "PROXY_CONTROL_VERSION_SOCKET": str(work / "agent.sock"),
               "PROXY_CONTROL_VERSION_SOCKET_GID": str(os.getgid()),
               "PROXY_CONTROL_VERSION_STATE": str(work / "state.json"),
               "PROXY_CONTROL_VERSION_CATALOG": str(work / "catalog.json"),
               "PROXY_CONTROL_COMPOSE_DIR": str(work), "PROXY_CONTROL_UPSTREAM_CHECK": "off"}
        process = subprocess.Popen([str(agent)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with httpx.Client(transport=httpx.HTTPTransport(uds=str(work / "agent.sock")), base_url="http://agent", timeout=5) as client:
                def sample():
                    response = client.get("/v1/metrics")
                    if response.status_code != 200:
                        raise RuntimeError(f"native metrics endpoint: HTTP {response.status_code}")
                    return response.json()

                deadline = time.monotonic() + 20
                while not (work / "agent.sock").exists() and time.monotonic() < deadline and process.poll() is None:
                    time.sleep(0.1)
                latest = {}
                while time.monotonic() < deadline:
                    response = client.get("/v1/metrics")
                    if response.status_code == 200:
                        latest = response.json()
                        if latest.get("kernel_counters") == "ok":
                            break
                    elif response.status_code != 503:
                        raise RuntimeError(f"native metrics readiness: HTTP {response.status_code}")
                    time.sleep(0.2)
                if latest.get("kernel_counters") != "ok":
                    raise AssertionError("native kernel counters unavailable")
                ready = threading.Event()
                server = threading.Thread(target=echo_server, args=(ready,), daemon=True)
                server.start()
                if not ready.wait(5):
                    raise AssertionError("echo listener unavailable")
                push_through()
                server.join(timeout=5)
                time.sleep(2.5)
                latest = sample()
                probe = latest["protocols"]["mtproxy"]
                for direction in ("up_bytes", "down_bytes"):
                    ratio = probe[direction] / TOTAL
                    if not 0.9 <= ratio <= 1.1:
                        raise AssertionError(f"{direction} is {ratio:.3f}x of transferred bytes")
                print(json.dumps({"moved_each_way": TOTAL, "counted": probe, "host": latest["host"]}))
                if args.perf:
                    def cpu():
                        fields = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
                        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

                    before_cpu, before = cpu(), time.monotonic()
                    time.sleep(args.perf)
                    used, wall = cpu() - before_cpu, time.monotonic() - before
                    print(f"perf: agent {used:.3f}s CPU over {wall:.1f}s = {100 * used / wall:.2f}% of one core")
                print("NATIVE_AGENT_METRICS_OK: kernel counters match transferred bytes")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
