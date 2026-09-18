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
    lanes.json             {svc: {lane: {user, password, issued_at}}} — the grant lanes' accounts (v0.7)
    relay.json             {enabled, port, server_name, private_key, public_key, short_ids, accounts} (v0.7)

Lanes, the relay and chains (v0.7, spec §4): a lane account is minted here, shown once and put
on the ingress with a new generation at once; the relay keypair is minted once per node; a chain
hop is checked (TCP + a TLS hello against its Reality cover) before an intent naming it applies.
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
import shutil
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
    SCHEMA_V2,
    SERVICES,
    EgressInvalid,
    EgressUnreachable,
    canonical,
    direct_document,
    document_digest,
    redact_intent,
    uses_provider,
    validate_document,
)
from .geodata import GeodataError, GeodataStore
from .render import RENDER_VERSION, Ingress, LaneAccount, Relay, config_bytes, generation_digest, render_config

OPERATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
CREDENTIAL = re.compile(r"([A-Za-z0-9._-]{1,64}):([A-Za-z0-9._~-]{16,128})")
GRANT_LANE = re.compile(r"grant:([A-Za-z0-9_-]{1,64})\Z")
RELAY_EMAIL = re.compile(r"relay:[A-Za-z0-9_-]{1,64}:(direct|warp)\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PRIVATE_KEY_LINE = re.compile(r"^Private ?[Kk]ey:[ \t]*([A-Za-z0-9_-]{43})[ \t]*$", re.MULTILINE)
_PUBLIC_KEY_LINE = re.compile(r"^(?:Public ?[Kk]ey|Password \(PublicKey\)):[ \t]*([A-Za-z0-9_-]{43})[ \t]*$", re.MULTILINE)
# v0.7: what this manager enforces beyond CAPABILITIES (docs/spikes/CHAINS_PER_CLIENT.md)
CAPABILITIES_V2 = ("lanes", "chains", "relay")
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
    def x25519(self) -> tuple[str, str]: ...
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

    def x25519(self) -> tuple[str, str]:
        """A fresh Reality keypair from the pinned binary (`xray x25519`), read off its labelled
        lines: "PrivateKey:" / "Password (PublicKey):" on 26.x, "Private key:" / "Public key:"
        on older builds — anything else is an error, never an empty key."""
        try:
            completed = subprocess.run([str(self.binary), "x25519"], capture_output=True, text=True,
                                       timeout=self.test_timeout, check=False, env=self.env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise XrayError(f"xray x25519 did not finish: {exc}") from exc
        private = _PRIVATE_KEY_LINE.search(completed.stdout)
        public = _PUBLIC_KEY_LINE.search(completed.stdout)
        if completed.returncode != 0 or private is None or public is None:
            raise XrayError("xray x25519 printed no keypair")
        return private.group(1), public.group(1)

    def test(self, config_path: Path, asset_dir: Path | None = None) -> None:
        """`asset_dir` points Xray at candidate geodata files instead of the live ones."""
        env = self.env if asset_dir is None else {**self.env, "XRAY_LOCATION_ASSET": str(asset_dir)}
        try:
            completed = subprocess.run([str(self.binary), "run", "-test", "-config", str(config_path)],
                                       capture_output=True, text=True, timeout=self.test_timeout, check=False, env=env)
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


def check_hop_reachable(address: str, port: int, server_name: str, timeout: float = 3.0) -> bool:
    """A TLS hello with the hop's SNI against its relay port: Reality answers with its cover's
    real certificate, so a completed handshake proves the port and the cover — never raises."""
    import ssl

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((address, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            with context.wrap_socket(stream, server_hostname=server_name) as tls:
                return tls.version() is not None
    except (OSError, ssl.SSLError, ValueError):
        return False


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
        self.hop_reachability = check_hop_reachable
        self.lock = threading.RLock()
        # v0.8: the geodata the router resolves codes against — seeded from the pinned pair.
        self.geodata = GeodataStore(self.state_dir / "geodata",
                                    {name: self.artifacts[name][0] for name in ("geosite", "geoip") if name in self.artifacts})
        self._geodata_busy = threading.Lock()
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

    # ------------------------------------------------------ lanes and relay (v0.7)

    def _lanes(self) -> dict[str, dict[str, dict]]:
        lanes = self._read_json("lanes.json", {})
        return {tag: dict(lanes.get(tag, {})) for tag in SERVICES}

    def _lane_accounts(self) -> dict[str, list[LaneAccount]]:
        return {tag: [LaneAccount(lane, entry["user"], entry["password"]) for lane, entry in lanes.items()]
                for tag, lanes in self._lanes().items()}

    @staticmethod
    def _without_lanes(intent: dict, known: set[str]) -> dict:
        """A schema-2 intent minus the grant lanes not in `known`: a lane whose account is gone
        (forgotten, or lost before a restart) cannot route anyone, so its rules go with it and
        the intent keeps rendering; the chains its rules named are dropped when unused."""
        if intent.get("schema") != SCHEMA_V2:
            return intent
        lanes = {lane: body for lane, body in intent["lanes"].items() if lane.startswith("svc:") or lane in known}
        if lanes == intent["lanes"]:
            return intent
        used = {rule["egress"] for body in lanes.values() for rule in body["rules"] if isinstance(rule.get("egress"), str)}
        used |= {body["default"].get("egress") for body in lanes.values()}
        chains = {chain_id: chain for chain_id, chain in intent.get("chains", {}).items() if f"chain:{chain_id}" in used}
        return {**intent, "lanes": lanes, "chains": chains}

    def _current_intents(self, current: dict) -> dict[str, dict]:
        """The running intents with every lane that has no account any more stripped out."""
        known = {tag: set(lanes) for tag, lanes in self._lanes().items()}
        return {tag: self._without_lanes(entry["document"], known.get(tag, set())) for tag, entry in current["services"].items()}

    def _relay_record(self) -> dict | None:
        return self._read_json("relay.json", None)

    def _relay(self) -> Relay | None:
        record = self._relay_record()
        if not record or not record.get("enabled"):
            return None
        return Relay(port=record["port"], server_name=record["server_name"], private_key=record["private_key"],
                     short_ids=list(record["short_ids"]), accounts=[(a["email"], a["uuid"]) for a in record["accounts"]])

    def _relay_view(self) -> dict:
        record = self._relay_record()
        if not record:
            return {"enabled": False, "port": None, "server_name": None, "public_key": None, "short_ids": [], "accounts": 0}
        # `emails` names the accounts the inbound carries — the node's report to the central
        # confirms exactly these (never a UUID).
        return {"enabled": bool(record["enabled"]), "port": record["port"], "server_name": record["server_name"],
                "public_key": record["public_key"], "short_ids": list(record["short_ids"]), "accounts": len(record["accounts"]),
                "emails": sorted(account["email"] for account in record["accounts"])}

    def _rerender_current(self) -> None:
        """Commit a new generation with the same intents: what changed is what the accounts and
        the relay say, not any service's document."""
        current = self._current()
        if current is None:
            raise ManualInterventionRequired("the router has no current generation")
        if self._state().get("phase") != "idle":
            raise ManualInterventionRequired(f"the router is {self._state().get('phase')}")
        intents = self._current_intents(current)
        self._commit_generation(current["generation"] + 1, intents, operation_ids={}, rollback_of=None, keep_journal=True)

    def lane_issue(self, service: str, lane: str) -> dict:
        """Mint (or rotate) a grant lane's account, put it on the ingress now, return it once."""
        self._service(service)
        match = GRANT_LANE.fullmatch(lane) if isinstance(lane, str) else None
        if match is None:
            raise ValidationError("invalid lane")
        with self.lock:
            lanes = self._lanes()
            account = {"user": f"grant-{match.group(1)}", "password": secrets.token_urlsafe(32), "issued_at": _now()}
            lanes[service][lane] = account
            self._write_json("lanes.json", lanes)
            self._rerender_current()
            return {"lane": lane, "user": account["user"], "password": account["password"]}

    def lane_forget(self, service: str, lane: str) -> dict:
        """Forget a lane's account: the running intent loses the lane's rules in the same
        generation, so nothing ever refers to an account that is gone. The file is written
        after the commit — a failed swap leaves the account (and the intent) as they were."""
        self._service(service)
        with self.lock:
            lanes = self._lanes()
            if lane not in lanes[service]:
                raise ManagerConflict("unknown lane", "lane_unknown")
            del lanes[service][lane]
            current = self._current()
            if current is None:
                raise ManualInterventionRequired("the router has no current generation")
            if self._state().get("phase") != "idle":
                raise ManualInterventionRequired(f"the router is {self._state().get('phase')}")
            known = {tag: set(entries) for tag, entries in lanes.items()}
            intents = {tag: self._without_lanes(entry["document"], known.get(tag, set()))
                       for tag, entry in current["services"].items()}
            previous = self._read_json("lanes.json", {})
            self._write_json("lanes.json", lanes)
            try:
                self._commit_generation(current["generation"] + 1, intents, operation_ids={}, rollback_of=None, keep_journal=True)
            except Exception:
                self._write_json("lanes.json", previous)
                raise
            return {"lane": lane, "forgotten": True}

    def lanes(self, service: str) -> dict:
        self._service(service)
        with self.lock:
            return {"lanes": sorted(self._lanes()[service])}

    def relay_enable(self, server_name: str, port: int) -> dict:
        if not isinstance(server_name, str) or not server_name or len(server_name) > 253 or any(c.isspace() for c in server_name):
            raise ValidationError("invalid relay server name")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValidationError("invalid relay port")
        with self.lock:
            record = self._relay_record() or {}
            if not record.get("private_key"):
                private_key, public_key = self.runner.x25519()
                record.update({"private_key": private_key, "public_key": public_key, "short_ids": [secrets.token_hex(4)],
                               "accounts": []})
            record.update({"enabled": True, "port": port, "server_name": server_name})
            self._write_json("relay.json", record)
            self._rerender_current()
            return self._relay_view()

    def relay_disable(self) -> dict:
        with self.lock:
            record = self._relay_record()
            if record:
                record["enabled"] = False
                self._write_json("relay.json", record)
                self._rerender_current()
            return self._relay_view()

    def relay_set_accounts(self, accounts: object) -> dict:
        if not isinstance(accounts, list) or len(accounts) > 256:
            raise ValidationError("invalid relay accounts")
        cleaned = []
        for account in accounts:
            if not isinstance(account, dict) or set(account) != {"email", "uuid"}:
                raise ValidationError("invalid relay account")
            if not isinstance(account["email"], str) or RELAY_EMAIL.fullmatch(account["email"]) is None:
                raise ValidationError("invalid relay account")
            if not isinstance(account["uuid"], str) or UUID.fullmatch(account["uuid"]) is None:
                raise ValidationError("invalid relay account")
            cleaned.append({"email": account["email"], "uuid": account["uuid"]})
        if not self.warp_url:
            # The central mints a `direct` and a `warp` account for every source. Without a WARP
            # provider this node cannot serve the warp one: it carries the rest and names only
            # what it carries, so a chain through its direct exit converges and «via warp»
            # stays `relay_no_warp` on the central — instead of refusing the whole set.
            cleaned = [account for account in cleaned if not account["email"].endswith(":warp")]
        with self.lock:
            record = self._relay_record()
            if not record or not record.get("enabled"):
                raise ManagerConflict("the relay is not enabled", "relay_disabled")
            previous = list(record["accounts"])
            record["accounts"] = cleaned
            self._write_json("relay.json", record)
            try:
                self._rerender_current()
            except EgressInvalid:
                record["accounts"] = previous
                self._write_json("relay.json", record)
                raise
            return self._relay_view()

    def relay(self) -> dict:
        with self.lock:
            return self._relay_view()

    def _check_hops(self, normalised: dict) -> dict[str, bool]:
        """Reachability of every hop an intent's chains name, keyed `chain:<id>:<n>`."""
        results: dict[str, bool] = {}
        if normalised.get("schema") != SCHEMA_V2:
            return results
        for chain_id, chain in normalised["chains"].items():
            for index, hop in enumerate(chain["hops"], 1):
                results[f"chain:{chain_id}:{index}"] = self.hop_reachability(hop["address"], hop["port"], hop["server_name"], 3.0)
        return results

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
            if len(self.geodata.seed) == 2:
                self.geodata.ensure_seed()
            self._recover()
            current = self._current()
            if current is None:
                intents = {tag: direct_document() for tag in SERVICES}
                self._commit_generation(1, intents, operation_ids={}, rollback_of=None)
                return
            intents = self._current_intents(current)
            config = render_config(intents, self._ingresses(), warp_url=self.warp_url, ports=self.ports,
                                   lanes=self._lane_accounts(), relay=self._relay())
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
        self.geodata_tick()
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
        return {"revision": entry["revision"], "digest": entry["digest"], "document": redact_intent(entry["document"])}

    def _providers(self, *, probe: bool) -> dict:
        if not self.warp_url:
            return {}
        return {"warp": {"reachable": self.reachability(self.warp_url, 3.0) if probe else None}}

    # --------------------------------------------------------------- geodata

    def geodata_view(self) -> dict:
        return self.geodata.view()

    def geodata_codes(self) -> dict:
        return {"codes": self.geodata.codes()}

    def geodata_settings(self, body: dict) -> dict:
        from .geodata import parse_source
        source = parse_source(body["source"]) if "source" in body else None
        auto = body.get("auto_update")
        if auto is not None and not isinstance(auto, bool):
            raise GeodataError("auto_update must be a boolean")
        interval = body.get("interval_hours")
        return self.geodata.settings(source=source, auto_update=auto, interval_hours=interval)

    def geodata_update(self, fetcher=None) -> dict:
        """Fetch the source's pair, prove the running config still compiles against it,
        swap the files and restart the router on them. Serialised; the result view says
        `changed`."""
        if not self._geodata_busy.acquire(blocking=False):
            raise ManagerConflict("a geodata update is already running", "geodata_busy")
        try:
            try:
                staged = self.geodata.stage(fetcher) if fetcher is not None else self.geodata.stage()
            except GeodataError as exc:
                self.geodata.record_failure(exc)
                raise
            if staged is None:
                return {**self.geodata.view(), "changed": False}
            return self._install_geodata(staged)
        finally:
            self._geodata_busy.release()

    def geodata_restore(self) -> dict:
        """Back to the installer's pinned pair — the source becomes `xray` again."""
        if not self._geodata_busy.acquire(blocking=False):
            raise ManagerConflict("a geodata update is already running", "geodata_busy")
        try:
            from .geodata import Source
            self.geodata.settings(source=Source("xray"), auto_update=False)
            staged = {}
            for name, path in self.geodata.seed.items():
                fd, tmp = tempfile.mkstemp(prefix=f"{name}.", suffix=".dat.tmp", dir=self.geodata.directory)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(path.read_bytes())
                os.chmod(tmp, 0o644)
                staged[name] = {"tmp": Path(tmp), "version": None}
            return self._install_geodata(staged, origin="seed")
        finally:
            self._geodata_busy.release()

    def _install_geodata(self, staged: dict, *, origin: str = "download") -> dict:
        with self.lock:
            current = self._current()
            test_dir = self.geodata.staged_dir(staged)
            try:
                if current is not None:
                    try:
                        self.runner.test(self._generation_path(current["generation"]), asset_dir=test_dir)
                    except XrayError as exc:
                        failure = GeodataError(f"the running config does not compile against the new lists: {exc}"[:300],
                                               "geodata_rejected")
                        self.geodata.record_failure(failure)
                        raise failure from exc
            finally:
                shutil.rmtree(test_dir, ignore_errors=True)
            try:
                view = self.geodata.commit(staged, origin=origin)
            except OSError as exc:
                self.geodata.discard(staged)
                failure = GeodataError(f"could not install the lists: {exc}"[:300], "geodata_install_failed")
                self.geodata.record_failure(failure)
                raise failure from exc
            if current is not None and self.handle is not None:
                # Xray reads the .dat files at start: the running process still holds the old ones.
                self.runner.stop(self.handle)
                self.handle = None
                self._start_generation(current["generation"])
            return {**view, "changed": True}

    def geodata_tick(self) -> None:
        """Automatic updates at the configured interval, off the watchdog thread; a failure
        is recorded and tried again after the interval."""
        if self.artifact_error or not self.geodata.due():
            return
        try:
            self.geodata_update()
        except (GeodataError, ManagerConflict, XrayError, ManualInterventionRequired):
            return

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
                "providers": self._providers(probe=True), "capabilities": [*CAPABILITIES, *CAPABILITIES_V2],
                "restart_required": True,
                "lanes": {tag: sorted(lanes) for tag, lanes in self._lanes().items()}, "relay": self._relay_view(),
                "geodata": self._geodata_summary(),
            }

    def _geodata_summary(self) -> dict:
        """What identity/status carries to a central: the source and version, never the codes."""
        meta = self.geodata.meta()
        files = meta.get("files") or {}
        return {"source": meta["source"], "origin": meta.get("origin"), "version": meta.get("version"),
                "updated_at": meta.get("updated_at"), "auto_update": bool(meta.get("auto_update")),
                "interval_hours": meta.get("interval_hours"), "last_error": meta.get("last_error"),
                "files": {name: {"sha256": (entry or {}).get("sha256"), "codes": (entry or {}).get("codes")}
                          for name, entry in files.items()}}

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
                "providers": self._providers(probe=True), "capabilities": [*CAPABILITIES, *CAPABILITIES_V2],
                "restart_required": True, "warnings": [], "runtime_version": self.xray_version,
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
            config = render_config(intents, self._ingresses(), warp_url=self.warp_url, ports=self.ports,
                                   lanes=self._lane_accounts(), relay=self._relay())
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
            reachability.update(self._check_hops(normalised))
            generation = current["generation"] + 1
            return {
                "revision": current["services"][service]["revision"],
                "target_revision": revision_of(generation, normalised),
                "generation_digest": generation_digest(config), "rendered_sha256": generation_digest(config),
                "diff": self._diff(redact_intent(current["services"][service]["document"]), redact_intent(normalised)),
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
            for key, reachable in self._check_hops(normalised).items():
                if not reachable:
                    _prefix, chain_id, index = key.split(":")
                    raise EgressUnreachable(f"chain {chain_id} hop {index} is unreachable")
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
            # A previous entry may name a lane forgotten since: it goes back without that lane
            # (an account that is gone cannot route anyone), like a start or a re-render would.
            intents = self._current_intents(current)
            known = set(self._lanes().get(service, {}))
            intents[service] = self._without_lanes(previous["document"], known)
            if uses_provider(intents[service]) and not self.reachability(self.warp_url, 3.0):
                raise EgressUnreachable("egress provider warp is unreachable")
            entry = self._commit_generation(current["generation"] + 1, intents, operation_ids={},
                                            rollback_of=service, keep_journal=True)[service]
            return {"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["generation_digest"],
                    "generation": entry["generation"]}

    def _commit_generation(self, generation: int, intents: dict[str, dict], *, operation_ids: dict[str, str],
                           rollback_of: str | None, keep_journal: bool = False) -> dict[str, dict]:
        """Render → test → swap → `current.json` → journal. The journal entry per service."""
        config = render_config(intents, self._ingresses(), warp_url=self.warp_url, ports=self.ports,
                               lanes=self._lane_accounts(), relay=self._relay())
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
