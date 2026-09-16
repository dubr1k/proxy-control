"""The Xray-router manager: one supervised Xray process, generations, a journal per service.

Every change goes the same way (spec §5): validate the intent → render generation n+1 from
the intents of *all* services → `xray run -test` → stop the running process → start the new
one → wait until both ingresses accept → commit `current.json` and the service's journal.
A generation that does not come up hands the ingress back to the last known good one; if
that fails too the manager stays `broken` and says so until a person looks. A crash between
the swap and the commit is recovered at start from `state.json`. The Xray binary and its
geodata are checked against the release digests before anything runs.

Files under the state directory (all `0600`, directory `0700`):

    generations/<n>.json   the config Xray runs for generation n (ingress accounts inside)
    current.json           {generation, digest, since, services: {svc: {document, digest, revision}}}
    journal.json           {svc: {current, previous, history[≤10]}}
    state.json             {phase: idle|swapping|broken, candidate, failures}
"""
from __future__ import annotations

import copy
import difflib
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import intent as intent_module
from .intent import (
    CAPABILITIES,
    PORTS,
    SERVICES,
    EgressInvalid,
    EgressUnreachable,
    canonical,
    direct_document,
    document_digest,
    uses_provider,
    validate_document,
)
from .render import RENDER_VERSION, Ingress, config_bytes, generation_digest, render_config

OPERATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
CREDENTIAL = re.compile(r"([A-Za-z0-9._-]{1,64}):([A-Za-z0-9._~-]{16,128})")
HISTORY_LIMIT = 10
MAX_START_FAILURES = 3
_UNKNOWN_CODE = re.compile(r"code not found in (geosite|geoip)\.dat", re.IGNORECASE)


class XrayError(RuntimeError):
    """The Xray binary refused a config or a generation did not come up."""


class ArtifactMismatch(RuntimeError):
    """A binary or a geodata file is not the one the release pinned."""


class ManagerConflict(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class ManualInterventionRequired(RuntimeError):
    """Neither the new nor the previous generation came up: the router is down until a
    person restores it (the last known good generation file is named in the message)."""


class ValidationError(ValueError):
    pass


class XrayRunner(Protocol):
    def version(self) -> str: ...
    def test(self, config_path: Path) -> None: ...
    def start(self, config_path: Path) -> object: ...
    def stop(self, handle: object) -> None: ...
    def alive(self, handle: object) -> bool: ...
    def wait_ready(self, ports: list[int], timeout: float) -> None: ...


class SubprocessXrayRunner:
    """The real thing: `xray run -test` for the gate, a child process for the runtime."""

    def __init__(self, binary: Path, asset_dir: Path, *, test_timeout: float = 20.0, stop_timeout: float = 5.0):
        self.binary, self.asset_dir = Path(binary), Path(asset_dir)
        self.test_timeout, self.stop_timeout = test_timeout, stop_timeout
        self.env = {"XRAY_LOCATION_ASSET": str(self.asset_dir), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}

    def version(self) -> str:
        try:
            completed = subprocess.run([str(self.binary), "version"], capture_output=True, text=True, timeout=10,
                                       check=False, env=self.env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise XrayError(f"xray version: {exc}") from exc
        first = (completed.stdout or completed.stderr).strip().splitlines()
        return first[0][:120] if first else "unknown"

    def test(self, config_path: Path) -> None:
        try:
            completed = subprocess.run([str(self.binary), "run", "-test", "-config", str(config_path)],
                                       capture_output=True, text=True, timeout=self.test_timeout, check=False, env=self.env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise XrayError(f"xray -test did not finish: {exc}") from exc
        if completed.returncode != 0:
            raise XrayError((completed.stdout + completed.stderr).strip()[-600:])

    def start(self, config_path: Path) -> object:
        try:
            # Nothing of Xray's own output is kept: `-test` already said everything a config
            # has to say, and a pipe nobody drains would stall the process.
            return subprocess.Popen([str(self.binary), "run", "-config", str(config_path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env)
        except OSError as exc:
            raise XrayError(f"xray did not start: {exc}") from exc

    def stop(self, handle: object) -> None:
        process: subprocess.Popen = handle  # type: ignore[assignment]
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=self.stop_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=self.stop_timeout)

    def alive(self, handle: object) -> bool:
        process: subprocess.Popen = handle  # type: ignore[assignment]
        return process.poll() is None

    def wait_ready(self, ports: list[int], timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(_port_open(port) for port in ports):
                return
            time.sleep(0.05)
        raise XrayError("the ingress ports did not open in time")


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def revision_of(generation: int, document: dict) -> str:
    return hashlib.sha256(canonical({"generation": generation, "document": document})).hexdigest()


def _test_failure(exc: XrayError) -> EgressInvalid:
    match = _UNKNOWN_CODE.search(str(exc))
    code = f"{match.group(1).lower()}_unknown" if match else "egress_invalid"
    return EgressInvalid(f"xray refused the generation: {str(exc)[-300:]}", code)


@dataclass
class _Journal:
    current: dict | None
    previous: dict | None
    history: list[dict]


class XrayRouterManager:
    def __init__(self, *, state_dir: Path, runner: XrayRunner, ingress_files: dict[str, Path], warp_url: str | None,
                 artifacts: dict[str, tuple[Path, str]], ports: dict[str, int] | None = None,
                 ready_timeout: float = 10.0, reachability=None):
        self.state_dir = Path(state_dir)
        self.runner = runner
        self.ingress_files = {tag: Path(path) for tag, path in ingress_files.items()}
        self.warp_url = warp_url or None
        self.artifacts = {name: (Path(path), digest) for name, (path, digest) in artifacts.items()}
        self.ports = dict(ports or PORTS)
        self.ready_timeout = ready_timeout
        self.reachability = reachability or intent_module.check_reachable
        self.lock = threading.RLock()
        self.handle: object | None = None
        self.artifact_error: str | None = None
        self.artifact_report: dict = {}
        self.xray_version: str | None = None
        self.started_at: str | None = None

    # ------------------------------------------------------------------ files

    @property
    def generations_dir(self) -> Path:
        return self.state_dir / "generations"

    def _generation_path(self, generation: int) -> Path:
        return self.generations_dir / f"{generation}.json"

    def _read_json(self, name: str, default):
        path = self.state_dir / name
        if not path.exists():
            return copy.deepcopy(default)
        try:
            return json.loads(path.read_text())
        except ValueError as exc:
            raise ManualInterventionRequired(f"{path} is not valid JSON") from exc

    def _write_json(self, name: str, value) -> None:
        _atomic_write(self.state_dir / name, json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def _state(self) -> dict:
        return self._read_json("state.json", {"phase": "idle", "candidate": None, "failures": 0})

    def _set_state(self, phase: str, *, candidate: int | None = None, failures: int = 0) -> None:
        self._write_json("state.json", {"phase": phase, "candidate": candidate, "failures": failures})

    def _current(self) -> dict | None:
        return self._read_json("current.json", None)

    def _journal(self) -> dict[str, dict]:
        journal = self._read_json("journal.json", {})
        for tag in SERVICES:
            journal.setdefault(tag, {"current": None, "previous": None, "history": []})
        return journal

    # ------------------------------------------------------------- credentials

    def _ingresses(self) -> list[Ingress]:
        ingresses = []
        for tag in SERVICES:
            path = self.ingress_files[tag]
            try:
                text = path.read_text().strip()
            except OSError as exc:
                raise ManualInterventionRequired(f"ingress credential for {tag} is unreadable") from exc
            match = CREDENTIAL.fullmatch(text)
            if match is None:
                raise ManualInterventionRequired(f"ingress credential for {tag} is malformed")
            ingresses.append(Ingress(tag=tag, port=self.ports[tag], user=match.group(1), password=match.group(2)))
        return ingresses

    # --------------------------------------------------------------- artifacts

    def verify_artifacts(self) -> dict:
        report = {}
        for name, (path, expected) in self.artifacts.items():
            try:
                actual = _sha256_file(path)
            except OSError:
                actual = None
            report[name] = {"sha256": actual, "verified": actual is not None and secrets.compare_digest(actual, expected)}
        return report

    # ------------------------------------------------------------- lifecycle

    def bootstrap(self) -> None:
        """Verify, recover, then run the current generation (or the first one)."""
        with self.lock:
            report = self.artifact_report = self.verify_artifacts()
            failed = sorted(name for name, entry in report.items() if not entry["verified"])
            if failed:
                self.artifact_error = f"artifact digest mismatch: {', '.join(failed)}"
                raise ArtifactMismatch(self.artifact_error)
            self.artifact_error = None
            self.xray_version = self.runner.version()
            self._recover()
            current = self._current()
            if current is None:
                intents = {tag: direct_document() for tag in SERVICES}
                self._commit_generation(1, intents, operation_ids={}, rollback_of=None)
                return
            intents = {tag: entry["document"] for tag, entry in current["services"].items()}
            config = render_config(intents, self._ingresses(), warp_url=self.warp_url, ports=self.ports)
            if generation_digest(config) != current["digest"] or not self._generation_path(current["generation"]).exists():
                # The credential files (or the renderer) changed since this generation was
                # written: the same intents, re-rendered, as a new generation.
                self._commit_generation(current["generation"] + 1, intents, operation_ids={}, rollback_of=None,
                                        keep_journal=True)
                return
            self._start_generation(current["generation"])

    def _recover(self) -> None:
        state = self._state()
        if state.get("phase") == "swapping":
            candidate = state.get("candidate")
            current = self._current()
            if isinstance(candidate, int) and (current is None or current["generation"] != candidate):
                self._generation_path(candidate).unlink(missing_ok=True)
            self._set_state("idle")
        elif state.get("phase") == "broken":
            # A person restarted us after a broken swap: try the current generation again.
            self._set_state("idle")

    def _start_generation(self, generation: int) -> None:
        path = self._generation_path(generation)
        if not path.exists():
            raise ManualInterventionRequired(f"generation file is missing: {path}")
        handle = self.runner.start(path)
        try:
            self.runner.wait_ready([self.ports[tag] for tag in SERVICES], self.ready_timeout)
        except XrayError:
            self.runner.stop(handle)
            raise
        self.handle = handle
        self.started_at = _now()

    def close(self) -> None:
        with self.lock:
            if self.handle is not None:
                self.runner.stop(self.handle)
                self.handle = None

    def watchdog_tick(self) -> None:
        """Restart the current generation when the process died on its own; after
        `MAX_START_FAILURES` attempts in a row the router is `broken` and stays so."""
        with self.lock:
            state = self._state()
            if state.get("phase") != "idle" or self.artifact_error:
                return
            if self.handle is not None and self.runner.alive(self.handle):
                return
            current = self._current()
            if current is None:
                return
            try:
                self._start_generation(current["generation"])
            except (XrayError, ManualInterventionRequired):
                failures = int(state.get("failures", 0)) + 1
                self._set_state("broken" if failures >= MAX_START_FAILURES else "idle", failures=failures)
                return
            self._set_state("idle")

    # ------------------------------------------------------------------ views

    def _service_view(self, current: dict | None, tag: str) -> dict:
        if current is None:
            return {"revision": None, "digest": None, "document": None}
        entry = current["services"][tag]
        return {"revision": entry["revision"], "digest": entry["digest"], "document": entry["document"]}

    def _providers(self, *, probe: bool) -> dict:
        if not self.warp_url:
            return {}
        return {"warp": {"reachable": self.reachability(self.warp_url, 3.0) if probe else None}}

    def status(self) -> dict:
        with self.lock:
            state = self._state()
            current = self._current()
            running = None
            if current is not None and self.handle is not None and self.runner.alive(self.handle):
                running = {"generation": current["generation"], "digest": current["digest"], "since": self.started_at}
            return {
                "version": RENDER_VERSION, "xray_version": self.xray_version, "artifacts": self.artifact_report,
                "artifact_error": self.artifact_error, "phase": state.get("phase", "idle"), "running": running,
                "services": {tag: self._service_view(current, tag) for tag in SERVICES},
                "providers": self._providers(probe=True), "capabilities": list(CAPABILITIES), "restart_required": True,
            }

    def egress(self, service: str) -> dict:
        self._service(service)
        with self.lock:
            current = self._current()
            journal = self._journal()[service]
            view = self._service_view(current, service)
            document = view["document"]
            return {
                "revision": view["revision"], "document": document,
                "mode": "proxy" if document is not None and uses_provider(document) else "direct",
                "generation": None if current is None else current["generation"],
                "providers": self._providers(probe=True), "capabilities": list(CAPABILITIES), "restart_required": True,
                "warnings": [], "runtime_version": self.xray_version,
                "previous": None if journal["previous"] is None else {"revision": journal["previous"]["revision"]},
                "current": None if journal["current"] is None else {
                    key: journal["current"].get(key) for key in ("revision", "digest", "generation", "operation_id", "applied_at")},
            }

    # ----------------------------------------------------------- transactions

    @staticmethod
    def _service(service: str) -> None:
        if service not in SERVICES:
            raise ValidationError("unknown service")

    def _target(self, service: str, expected_revision: str, document: object) -> tuple[dict, dict, dict[str, dict]]:
        normalised = validate_document(document)
        current = self._current()
        if current is None:
            raise ManualInterventionRequired("the router has no current generation")
        if self._state().get("phase") != "idle":
            raise ManualInterventionRequired(f"the router is {self._state().get('phase')}")
        actual = current["services"][service]["revision"]
        if not isinstance(expected_revision, str) or not secrets.compare_digest(actual, expected_revision):
            raise ManagerConflict("egress revision does not match", "egress_conflict")
        intents = {tag: entry["document"] for tag, entry in current["services"].items()}
        intents[service] = normalised
        return current, normalised, intents

    def _diff(self, before: dict | None, after: dict) -> list[str]:
        old = json.dumps(before, indent=1, sort_keys=True).splitlines()
        new = json.dumps(after, indent=1, sort_keys=True).splitlines()
        return [line for line in difflib.unified_diff(old, new, "current", "planned", lineterm="", n=0)
                if not line.startswith(("---", "+++", "@@"))]

    def egress_plan(self, service: str, expected_revision: str, document: object) -> dict:
        self._service(service)
        with self.lock:
            current, normalised, intents = self._target(service, expected_revision, document)
            config = render_config(intents, self._ingresses(), warp_url=self.warp_url, ports=self.ports)
            candidate = self.state_dir / ".plan.json"
            _atomic_write(candidate, config_bytes(config))
            try:
                self.runner.test(candidate)
            except XrayError as exc:
                raise _test_failure(exc) from exc
            finally:
                candidate.unlink(missing_ok=True)
            reachability = {}
            if uses_provider(normalised):
                reachability["warp"] = self.reachability(self.warp_url, 3.0)
            generation = current["generation"] + 1
            return {
                "revision": current["services"][service]["revision"],
                "target_revision": revision_of(generation, normalised),
                "generation_digest": generation_digest(config), "rendered_sha256": generation_digest(config),
                "diff": self._diff(current["services"][service]["document"], normalised),
                "warnings": [], "reachability": reachability, "restart_required": True,
            }

    def egress_apply(self, service: str, expected_revision: str, document: object, operation_id: str) -> dict:
        self._service(service)
        if not isinstance(operation_id, str) or OPERATION_ID.fullmatch(operation_id) is None:
            raise ValidationError("invalid operation id")
        with self.lock:
            normalised = validate_document(document)
            journal = self._journal()[service]
            current_entry = journal["current"]
            if current_entry is not None and current_entry.get("operation_id") == operation_id:
                if current_entry["document"] != normalised:
                    raise ManagerConflict("operation id already used for another request", "operation_conflict")
                return {"revision": current_entry["revision"], "applied": current_entry["document"],
                        "readback_sha256": current_entry["generation_digest"], "generation": current_entry["generation"],
                        "replayed": True}
            current, normalised, intents = self._target(service, expected_revision, document)
            if uses_provider(normalised) and not self.reachability(self.warp_url, 3.0):
                raise EgressUnreachable("egress provider warp is unreachable")
            entry = self._commit_generation(current["generation"] + 1, intents, operation_ids={service: operation_id},
                                            rollback_of=None, keep_journal=True)[service]
            return {"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["generation_digest"],
                    "generation": entry["generation"], "replayed": False}

    def egress_rollback(self, service: str, expected_revision: str) -> dict:
        self._service(service)
        with self.lock:
            current = self._current()
            if current is None:
                raise ManualInterventionRequired("the router has no current generation")
            actual = current["services"][service]["revision"]
            if not isinstance(expected_revision, str) or not secrets.compare_digest(actual, expected_revision):
                raise ManagerConflict("egress revision does not match", "egress_conflict")
            journal = self._journal()[service]
            previous = journal["previous"]
            if previous is None:
                raise ManagerConflict("no previous egress to roll back to", "egress_no_previous")
            intents = {tag: entry["document"] for tag, entry in current["services"].items()}
            intents[service] = previous["document"]
            if uses_provider(previous["document"]) and not self.reachability(self.warp_url, 3.0):
                raise EgressUnreachable("egress provider warp is unreachable")
            entry = self._commit_generation(current["generation"] + 1, intents, operation_ids={},
                                            rollback_of=service, keep_journal=True)[service]
            return {"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["generation_digest"],
                    "generation": entry["generation"]}

    def _commit_generation(self, generation: int, intents: dict[str, dict], *, operation_ids: dict[str, str],
                           rollback_of: str | None, keep_journal: bool = False) -> dict[str, dict]:
        """Render → test → swap → `current.json` → journal. The journal entry per service."""
        config = render_config(intents, self._ingresses(), warp_url=self.warp_url, ports=self.ports)
        path = self._generation_path(generation)
        _atomic_write(path, config_bytes(config))
        try:
            self.runner.test(path)
        except XrayError as exc:
            path.unlink(missing_ok=True)
            raise _test_failure(exc) from exc
        digest = generation_digest(config)
        previous_current = self._current()
        self._swap(generation, previous_current)
        services = {}
        for tag in SERVICES:
            services[tag] = {"document": intents[tag], "digest": document_digest(intents[tag]),
                             "revision": revision_of(generation, intents[tag])}
        self._write_json("current.json", {"generation": generation, "digest": digest, "since": _now(), "services": services})
        journal = self._journal() if keep_journal else {tag: {"current": None, "previous": None, "history": []} for tag in SERVICES}
        entries = {}
        for tag in SERVICES:
            entry = {"document": intents[tag], "digest": services[tag]["digest"], "revision": services[tag]["revision"],
                     "generation": generation, "generation_digest": digest, "operation_id": operation_ids.get(tag),
                     "applied_at": _now()}
            book = journal[tag]
            changed = (book["current"] is None or book["current"]["document"] != intents[tag] or tag == rollback_of
                       or tag in operation_ids)
            if not changed:
                # Another service's apply re-rendered this one unchanged: same document, new
                # generation — the current entry moves on, the stack does not grow.
                book["current"] = {**book["current"], "revision": entry["revision"], "generation": generation,
                                   "generation_digest": digest}
                if book["history"]:
                    book["history"][-1] = book["current"]
            elif tag == rollback_of:
                history = book["history"][:-1]
                if history:
                    history[-1] = entry
                else:
                    history = [entry]
                book["history"] = history
                book["current"] = history[-1]
                book["previous"] = history[-2] if len(history) > 1 else None
            else:
                history = [*book["history"], entry][-HISTORY_LIMIT:]
                book["history"] = history
                book["current"] = entry
                book["previous"] = history[-2] if len(history) > 1 else None
            entries[tag] = book["current"]
        self._write_json("journal.json", journal)
        self._set_state("idle")
        return entries

    def _swap(self, generation: int, previous_current: dict | None) -> None:
        """Stop the running process, start `generation`; on failure, back to the last known
        good generation — or `broken` when even that will not come up."""
        self._set_state("swapping", candidate=generation)
        if self.handle is not None:
            self.runner.stop(self.handle)
            self.handle = None
        try:
            self._start_generation(generation)
        except XrayError as exc:
            self._generation_path(generation).unlink(missing_ok=True)
            if previous_current is None:
                self._set_state("broken", failures=MAX_START_FAILURES)
                raise ManualInterventionRequired(f"generation {generation} did not come up and there is no previous one") from exc
            try:
                self._start_generation(previous_current["generation"])
            except XrayError as restore_error:
                self._set_state("broken", failures=MAX_START_FAILURES)
                raise ManualInterventionRequired(
                    f"generation {generation} did not come up and generation {previous_current['generation']} "
                    f"({self._generation_path(previous_current['generation'])}) could not be restored") from restore_error
            self._set_state("idle")
            raise XrayError(f"generation {generation} did not come up; generation {previous_current['generation']} restored") from exc
