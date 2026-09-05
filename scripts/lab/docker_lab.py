#!/usr/bin/env python3
"""Container-hosted release acceptance for the Proxy Control installer.

This is the part of the release matrix that a disposable systemd container can
prove honestly: the exact release archive is the only input, systemd is PID 1 so
the installer drives real units, and the foreign topology and identity fixtures
are materialized inside the container and hashed before and after.

It deliberately does not claim the scenarios that need nested Docker or public
network access. The report it writes records exactly which scenarios ran, so
`qemu_lab.validate_report` treats it as the partial run it is: it can never
stand in for a full release report.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
IMAGE = "proxy-control-acceptance:ubuntu-24.04"
CONTAINER = "proxy-control-acceptance"
REMOTE_ROOT = "/opt/acceptance"

_spec = importlib.util.spec_from_file_location("qemu_lab", HERE / "qemu_lab.py")
if _spec is None or _spec.loader is None:
    raise ImportError("the QEMU lab controller could not be loaded")
qemu_lab = importlib.util.module_from_spec(_spec)
sys.modules["qemu_lab"] = qemu_lab
_spec.loader.exec_module(qemu_lab)

MODE = "container"
# Everything a container without nested Docker or public DNS can prove.
CONTAINER_SCENARIOS = (
    "environment-preflight",
    "release-artifact-integrity",
    "audit",
    "plan",
    "nginx-multi-map",
    "coexist-existing-xui",
    "uninstall-foreign-identity",
    "dns-tls-preflight",
    "secrets-scan",
)
qemu_lab.SCENARIOS[MODE] = CONTAINER_SCENARIOS


class DockerLabError(RuntimeError):
    """The container acceptance run cannot proceed safely."""


def run(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(list(command), check=True, text=True, **kwargs)


def build_image() -> str:
    """Build the pinned systemd host image and return its identity."""
    run(
        (
            "docker",
            "build",
            "-q",
            "-f",
            str(HERE / "Dockerfile.acceptance"),
            "-t",
            IMAGE,
            str(HERE),
        ),
        capture_output=True,
    )
    identity = subprocess.run(
        ("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"),
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    if not identity.startswith("sha256:"):
        raise DockerLabError("the acceptance image has no identity")
    return identity


def start_container() -> None:
    subprocess.run(
        ("docker", "rm", "-f", CONTAINER),
        check=False,
        capture_output=True,
    )
    run(
        (
            "docker",
            "run",
            "-d",
            "--name",
            CONTAINER,
            # systemd needs a writable cgroup hierarchy and its own /run.
            "--privileged",
            "--cgroupns=host",
            "-v",
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            IMAGE,
        ),
        capture_output=True,
    )
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = subprocess.run(
            ("docker", "exec", CONTAINER, "systemctl", "is-system-running"),
            check=False,
            text=True,
            capture_output=True,
        ).stdout.strip()
        if state in {"running", "degraded"}:
            return
        time.sleep(2)
    raise DockerLabError("systemd did not come up inside the acceptance container")


def stop_container() -> None:
    subprocess.run(
        ("docker", "rm", "-f", CONTAINER),
        check=False,
        capture_output=True,
    )


def copy_inputs(archive: Path, digest: str, staging: Path) -> str:
    """Place the release and its digest inside the container and extract it."""
    run(
        ("docker", "cp", str(archive), f"{CONTAINER}:/tmp/proxy-control-release.tar.gz"),
        capture_output=True,
    )
    digest_file = staging / "release.sha256"
    digest_file.write_text(digest + "\n")
    run(
        (
            "docker",
            "cp",
            str(digest_file),
            f"{CONTAINER}:/tmp/proxy-control-release.sha256",
        ),
        capture_output=True,
    )
    run(
        (
            "docker",
            "exec",
            CONTAINER,
            "bash",
            "-lc",
            f"set -eu; rm -rf {REMOTE_ROOT}; mkdir -p {REMOTE_ROOT}; "
            f"tar -xzf /tmp/proxy-control-release.tar.gz -C {REMOTE_ROOT}",
        ),
        capture_output=True,
    )
    return f"{REMOTE_ROOT}/proxy-control"


def guest_command(root: str, digest: str, only: Sequence[str]) -> tuple[str, ...]:
    for name in only:
        if not re.fullmatch(r"[a-z0-9-]{1,64}", name):
            raise DockerLabError(f"unknown scenario filter: {name}")
    script = (
        f"set -eu; bash {root}/scripts/lab/guest-runner.sh {MODE} "
        f"{digest} {' '.join(only)}"
    ).rstrip()
    return ("docker", "exec", CONTAINER, "bash", "-lc", script)


def run_acceptance(
    *,
    release_archive: Path,
    release_sha256: str,
    output: Path,
    only: Sequence[str] = (),
    keep: bool = False,
) -> int:
    digest = qemu_lab.verify_release_archive(Path(release_archive), release_sha256)
    selected = tuple(only)
    unknown = [name for name in selected if name not in CONTAINER_SCENARIOS]
    if unknown:
        raise DockerLabError(f"unknown scenario filter: {unknown[0]}")

    image = build_image()
    start_container()
    try:
        Path(output).mkdir(parents=True, exist_ok=True)
        root = copy_inputs(Path(release_archive), digest, Path(output))

        started = time.monotonic()
        completed = subprocess.run(
            guest_command(root, digest, selected),
            check=False,
            text=True,
            capture_output=True,
        )
        elapsed = time.monotonic() - started
    finally:
        if not keep:
            stop_container()

    log = qemu_lab.sanitize(completed.stdout + completed.stderr)
    results: list[dict] = []
    plan_digest = None
    for line in completed.stdout.splitlines():
        if line.startswith("LAB_PLAN_DIGEST\t"):
            candidate = line.split("\t", 1)[1].strip()
            if re.fullmatch(r"[0-9a-f]{64}", candidate):
                plan_digest = candidate
            continue
        if not line.startswith("LAB_RESULT\t"):
            continue
        _label, name, status, seconds, message = (line.split("\t", 4) + [""])[:5]
        del _label
        results.append(
            {
                "name": name,
                "status": status,
                "seconds": float(seconds),
                "message": qemu_lab.sanitize(message),
            }
        )
    results = qemu_lab.finalize_results(
        MODE,
        results,
        completed.returncode,
        elapsed,
        expected=selected or None,
    )
    payload = {
        "schema": 2,
        "mode": MODE,
        "architecture": _architecture(),
        "image": {"reference": IMAGE, "id": image},
        "archive_sha256": digest,
        "release_sha256": digest,
        "plan_digest": plan_digest,
        "elapsed_seconds": round(elapsed, 3),
        # A container run is always partial: it never claims the full matrix.
        "filtered_scenarios": list(selected or CONTAINER_SCENARIOS),
        "results": results,
    }
    output = Path(output)
    (output / "report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    )
    (output / "report.xml").write_text(qemu_lab.junit_xml(results))
    (output / "guest.log").write_text(log)
    verdict = qemu_lab.validate_report(payload)
    for item in results:
        print(f"{item['status']:>7}  {item['name']}  {item.get('message', '')[:120]}")
    print(f"report: {output / 'report.json'}")
    return 0 if verdict.ok else 1


def _architecture() -> str:
    machine = subprocess.run(
        ("uname", "-m"), check=False, text=True, capture_output=True
    ).stdout.strip()
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine, machine
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-archive", type=Path, required=True)
    parser.add_argument("--release-sha256", required=True)
    parser.add_argument("--output", type=Path, default=REPO / "lab-results-container")
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--keep", action="store_true", help="leave the container up")
    arguments = parser.parse_args(argv)
    if shutil.which("docker") is None:
        print("LAB FAILED: docker is unavailable", file=sys.stderr)
        return 1
    try:
        return run_acceptance(
            release_archive=arguments.release_archive,
            release_sha256=arguments.release_sha256,
            output=arguments.output,
            only=tuple(arguments.scenario),
            keep=arguments.keep,
        )
    except (DockerLabError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"LAB FAILED: {qemu_lab.sanitize(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
