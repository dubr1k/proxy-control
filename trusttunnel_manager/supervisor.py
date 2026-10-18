"""Runs the pinned trusttunnel_endpoint binary as a child process."""
from __future__ import annotations

import logging
import signal
import subprocess
from pathlib import Path
from typing import Protocol

LOGGER = logging.getLogger("trusttunnel_manager")
STOP_TIMEOUT = 10.0


class Supervisor(Protocol):
    def start(self, vpn_toml: Path, hosts_toml: Path) -> None: ...
    def stop(self) -> None: ...
    def running(self) -> bool: ...
    def reload(self) -> None: ...
    def pid(self) -> int | None: ...


class ProcessSupervisor:
    def __init__(self, binary: Path):
        self.binary = binary
        self._proc: subprocess.Popen | None = None

    def start(self, vpn_toml: Path, hosts_toml: Path) -> None:
        self.stop()
        # The endpoint reads its settings at start only; relative paths inside them are
        # avoided by the manager, so the working directory does not matter.
        self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, pinned binary
            [str(self.binary), str(vpn_toml), str(hosts_toml)],
            stdin=subprocess.DEVNULL,
            cwd=str(vpn_toml.parent),
        )

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            LOGGER.warning("endpoint ignored SIGTERM, killing it")
            proc.kill()
            proc.wait(STOP_TIMEOUT)

    def reload(self) -> None:
        """SIGHUP: the endpoint re-reads hosts.toml and its certificates without dropping sessions."""
        if self._proc is None or self._proc.poll() is not None:
            raise OSError("endpoint is not running")
        self._proc.send_signal(signal.SIGHUP)

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def pid(self) -> int | None:
        return self._proc.pid if self.running() else None
