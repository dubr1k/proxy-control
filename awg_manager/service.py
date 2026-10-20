"""The manager core: instances per protocol version, peers, reconciliation."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import obfuscation
from .config import KNOWN_VERSIONS, Config, interface_name
from .egress import Egress, EgressError
from .host import Host, HostError, Process, UapiError
from .keys import b64, generate_private, hexkey, public_key, unb64
from .state import StateError, StateStore

LOGGER = logging.getLogger("awg_manager")
USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
OPERATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
FULL_RECONCILE_SECONDS = 30.0
DEVICE_READY_SECONDS = 10.0
MAX_BACKOFF_SECONDS = 30.0
STABLE_SECONDS = 60.0
ZERO_KEY = "0" * 64


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


@dataclass
class Instance:
    version: str
    iface: str
    port: int
    subnet: ipaddress.IPv4Network
    process: Process | None = None
    configured: bool = False
    dirty: bool = True
    failures: int = 0
    started_at: float = 0.0
    next_start: float = 0.0
    last_full: float = 0.0
    extra: dict = field(default_factory=dict)

    @property
    def gateway(self) -> ipaddress.IPv4Address:
        return self.subnet.network_address + 1


def peer_lines(pub_hex: str, psk_hex: str, address: str) -> list[str]:
    return [
        f"public_key={pub_hex}",
        f"preshared_key={psk_hex}",
        "replace_allowed_ips=true",
        f"allowed_ip={address}/32",
    ]


def parse_uapi(text: str) -> tuple[dict, dict[str, dict]]:
    """Split a `get=1` reply into device keys and peers keyed by hex public key."""
    device: dict[str, str] = {}
    peers: dict[str, dict] = {}
    current: dict | None = None
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "public_key":
            current = {"allowed_ips": [], "preshared_key": ZERO_KEY, "rx": 0, "tx": 0, "handshake": 0}
            peers[value] = current
        elif current is None:
            device[key] = value
        elif key == "allowed_ip":
            current["allowed_ips"].append(value)
        elif key == "preshared_key":
            current["preshared_key"] = value
        elif key in ("rx_bytes", "tx_bytes", "last_handshake_time_sec"):
            name = {"rx_bytes": "rx", "tx_bytes": "tx", "last_handshake_time_sec": "handshake"}[key]
            try:
                current[name] = int(value)
            except ValueError:
                pass
    return device, peers


class AwgManager:
    def __init__(
        self,
        config: Config,
        host: Host,
        *,
        overrides: dict[str, dict[str, str]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        rng=None,
        warp_opener=None,
        sleep=None,
    ):
        self.config, self.host = config, host
        self.overrides = overrides or {}
        self.clock, self.wall, self.rng = clock, wall, rng
        self.store = StateStore(config.state_dir)
        self.lock = threading.RLock()
        self.instances: dict[str, Instance] = {
            v: Instance(v, interface_name(v), config.ports[v], config.subnets[v])
            for v in config.versions
        }
        self.last_nft = 0.0
        # Where the clients' traffic leaves the node (v2.3.0): direct, or a WARP tunnel of its own.
        self.egress = Egress(self, opener=warp_opener, sleep=sleep)

    # ----- lifecycle -------------------------------------------------------------------

    def bootstrap(self) -> None:
        with self.lock:
            self.store.load()
            self.egress.load()
            changed = False
            for version in self.config.versions:
                changed |= self._ensure_instance_state(version)
            # A peer stored for an enabled version must still fit its subnet.
            for name, rec in self.store.peers.items():
                inst = self.instances.get(rec["version"])
                if inst and ipaddress.ip_address(rec["address"]) not in inst.subnet:
                    raise StateError(f"peer {name} address is outside the configured subnet")
            if changed:
                self.store.save()
            self._apply_nft()
            self.tick()

    def _ensure_instance_state(self, version: str) -> bool:
        existing = self.store.instances.get(version)
        mtu = self.config.mtu
        if existing is not None:
            try:
                obfuscation.validate(version, existing["obfuscation"], mtu)
                if b64(public_key(unb64(existing["private_key"]))) != existing["public_key"]:
                    raise ValueError("key pair mismatch")
            except (KeyError, ValueError) as exc:
                raise StateError(f"stored instance {version} is invalid: {exc}") from exc
            return False
        private = generate_private()
        params = obfuscation.generate(version, mtu, self.rng)
        if version in self.overrides:
            params = obfuscation.apply_overrides(version, params, self.overrides[version], mtu)
        self.store.instances[version] = {
            "private_key": b64(private),
            "public_key": b64(public_key(private)),
            "obfuscation": params,
            "created_at": int(self.wall()),
        }
        return True

    def shutdown(self) -> None:
        with self.lock:
            for inst in self.instances.values():
                proc, inst.process, inst.configured = inst.process, None, False
                if proc is None:
                    continue
                proc.terminate()
                try:
                    proc.wait(5)
                except Exception:  # noqa: BLE001 - escalate whatever the wait failed with
                    proc.kill()
            self.egress.teardown()
            self.host.nft_delete()

    # ----- supervision -----------------------------------------------------------------

    def tick(self) -> None:
        """One supervision pass: restart dead processes, configure, reconcile periodically."""
        with self.lock:
            now = self.clock()
            for inst in self.instances.values():
                try:
                    self._supervise(inst, now)
                except Exception:  # noqa: BLE001 - one instance must not stop the others
                    LOGGER.exception("supervision of %s failed", inst.iface)
            if now - self.last_nft >= FULL_RECONCILE_SECONDS:
                self._apply_nft()
            try:
                self.egress.converge(now)
            except Exception:  # noqa: BLE001 - the egress must not stop the tunnels
                LOGGER.exception("egress supervision failed")

    def _supervise(self, inst: Instance, now: float) -> None:
        proc = inst.process
        if proc is not None and proc.poll() is not None:
            LOGGER.warning("%s exited with %s", inst.iface, proc.poll())
            if now - inst.started_at > STABLE_SECONDS:
                inst.failures = 0
            inst.failures += 1
            inst.process, inst.configured = None, False
            inst.next_start = now + min(MAX_BACKOFF_SECONDS, 2 ** (inst.failures - 1))
        if inst.process is None:
            if now < inst.next_start:
                return
            try:
                inst.process = self.host.start_process(inst.iface, self.config.log_level)
            except OSError as exc:
                inst.failures += 1
                inst.next_start = now + min(MAX_BACKOFF_SECONDS, 2 ** (inst.failures - 1))
                LOGGER.error("cannot start %s: %s", inst.iface, exc)
                return
            inst.started_at, inst.configured, inst.dirty = now, False, True
        if not inst.configured:
            self._configure(inst, now)
        elif inst.dirty or now - inst.last_full >= FULL_RECONCILE_SECONDS:
            self._reconcile_peers(inst, now)

    def device_lines(self, inst: Instance) -> list[str]:
        stored = self.store.instances[inst.version]
        return [
            f"private_key={hexkey(stored['private_key'])}",
            f"listen_port={inst.port}",
            *obfuscation.uapi_lines(stored["obfuscation"]),
        ]

    def _configure(self, inst: Instance, now: float) -> None:
        try:
            self.host.uapi_set(inst.iface, "\n".join(self.device_lines(inst)) + "\n")
        except UapiError as exc:
            if now - inst.started_at > DEVICE_READY_SECONDS:
                LOGGER.error("%s control socket not usable (%s); restarting", inst.iface, exc)
                inst.process.kill()  # type: ignore[union-attr]
            return
        try:
            net = inst.subnet
            self.host.ip("addr", "replace", f"{inst.gateway}/{net.prefixlen}", "dev", inst.iface)
            self.host.ip("link", "set", inst.iface, "mtu", str(self.config.mtu), "up")
        except HostError as exc:
            LOGGER.error("cannot set up %s: %s", inst.iface, exc)
            return
        inst.configured = True
        self._reconcile_peers(inst, now)

    def _desired(self, inst: Instance) -> dict[str, tuple[str, str]]:
        return {
            hexkey(rec["public_key"]): (hexkey(rec["preshared_key"]), rec["address"])
            for rec in self.store.peers.values()
            if rec["version"] == inst.version and rec["enabled"]
        }

    def _reconcile_peers(self, inst: Instance, now: float) -> None:
        try:
            _, live = parse_uapi(self.host.uapi_get(inst.iface))
            desired = self._desired(inst)
            lines: list[str] = []
            for pub in live:
                if pub not in desired:
                    lines += [f"public_key={pub}", "remove=true"]
            for pub, (psk, address) in desired.items():
                have = live.get(pub)
                if have is None or have["preshared_key"] != psk or have["allowed_ips"] != [f"{address}/32"]:
                    lines += peer_lines(pub, psk, address)
            if lines:
                self.host.uapi_set(inst.iface, "\n".join(lines) + "\n")
            inst.dirty, inst.last_full = False, now
        except UapiError as exc:
            LOGGER.warning("%s reconcile failed: %s", inst.iface, exc)
            inst.configured = False  # the process may be gone or wedged: configure again

    def _apply_nft(self) -> None:
        self.last_nft = self.clock()
        names = ", ".join(f'"{i.iface}"' for i in self.instances.values())
        rules = ""
        if self.config.nat:
            rules = "\n".join(
                f'    ip saddr {i.subnet} oifname != "{i.iface}" masquerade'
                for i in self.instances.values()
            )
        script = (
            "table inet awg_manager\n"
            "delete table inet awg_manager\n"
            "table inet awg_manager {\n"
            "  chain forward {\n"
            "    type filter hook forward priority 0; policy accept;\n"
            f"    iifname {{ {names} }} accept\n"
            f"    oifname {{ {names} }} accept\n"
            "  }\n"
            "  chain postrouting {\n"
            "    type nat hook postrouting priority srcnat; policy accept;\n"
            f"{rules}\n"
            "  }\n"
            "}\n"
        )
        try:
            self.host.nft_apply(script)
        except HostError as exc:
            LOGGER.error("nft apply failed: %s", exc)

    def _live_change(self, inst: Instance | None, lines: list[str]) -> None:
        """Best effort live apply; the state is the truth and the next tick converges."""
        if inst is None or not inst.configured or not lines:
            return
        try:
            self.host.uapi_set(inst.iface, "\n".join(lines) + "\n")
        except UapiError as exc:
            LOGGER.warning("%s live update failed: %s", inst.iface, exc)
            inst.dirty = True

    # ----- views -----------------------------------------------------------------------

    def _instance_view(self, inst: Instance) -> dict:
        stored = self.store.instances[inst.version]
        return {
            "version": inst.version,
            "interface": inst.iface,
            "port": inst.port,
            "server_public_key": stored["public_key"],
            "gateway": str(inst.gateway),
            "subnet": str(inst.subnet),
            "mtu": self.config.mtu,
            "dns": list(self.config.dns),
            "obfuscation": obfuscation.client_view(stored["obfuscation"]),
        }

    def _stats(self, inst: Instance) -> dict[str, dict]:
        if not inst.configured:
            return {}
        try:
            return parse_uapi(self.host.uapi_get(inst.iface))[1]
        except UapiError:
            return {}

    def _peer_view(self, name: str, rec: dict, stats: dict[str, dict] | None = None) -> dict:
        live = (stats or {}).get(hexkey(rec["public_key"]), {})
        return {
            "username": name,
            "version": rec["version"],
            "enabled": rec["enabled"],
            "address": rec["address"],
            "public_key": rec["public_key"],
            "revision": rec["revision"],
            "rx": live.get("rx", 0),
            "tx": live.get("tx", 0),
            "latest_handshake": live.get("handshake") or None,
        }

    def health(self) -> dict:
        with self.lock:
            forward = self.host.ip_forward_enabled()
            out = {}
            for v, inst in self.instances.items():
                alive = inst.process is not None and inst.process.poll() is None
                out[v] = {
                    "interface": inst.iface,
                    "running": bool(alive and inst.configured),
                    "port": inst.port,
                    "peers": sum(1 for r in self.store.peers.values() if r["version"] == v),
                }
            ok = forward and all(i["running"] for i in out.values())
            # The egress is reported beside the status, not folded into it: a WARP tunnel without a
            # handshake keeps the clients' traffic dropped (fail-closed), the tunnels themselves run.
            return {"status": "ok" if ok else "degraded", "ip_forward": forward, "instances": out,
                    "egress": self.egress.health()}

    # ----- egress (v2.3.0) -----------------------------------------------------------

    def egress_view(self) -> dict:
        with self.lock:
            return self.egress.view()

    def egress_plan(self, body: dict) -> dict:
        self._fields(body, {"expected_revision", "document"})
        with self.lock:
            return self._egress_call(self.egress.plan, body["expected_revision"], body["document"])

    def egress_apply(self, body: dict) -> dict:
        self._fields(body, {"expected_revision", "document", "operation_id"})
        with self.lock:
            return self._egress_call(self.egress.apply, body["expected_revision"], body["document"], body["operation_id"])

    def egress_rollback(self, body: dict) -> dict:
        self._fields(body, {"expected_revision"})
        with self.lock:
            return self._egress_call(self.egress.rollback, body["expected_revision"])

    @staticmethod
    def _egress_call(method, *args) -> dict:
        try:
            return method(*args)
        except EgressError as exc:
            raise ApiError(exc.status, exc.code, exc.detail) from exc

    def list_instances(self) -> dict:
        with self.lock:
            return {"instances": [self._instance_view(i) for i in self.instances.values()]}

    def list_peers(self) -> dict:
        with self.lock:
            stats = {v: self._stats(i) for v, i in self.instances.items()}
            return {
                "peers": [
                    self._peer_view(n, r, stats.get(r["version"]))
                    for n, r in sorted(self.store.peers.items())
                ]
            }

    # ----- peer operations -------------------------------------------------------------

    def _instance(self, version) -> Instance:
        if not isinstance(version, str) or version not in KNOWN_VERSIONS:
            raise ApiError(422, "unknown_version", "unknown protocol version")
        inst = self.instances.get(version)
        if inst is None:
            raise ApiError(409, "version_disabled", "protocol version is not enabled on this node")
        return inst

    @staticmethod
    def _fields(body: dict, required: set[str]) -> None:
        if set(body) != required:
            raise ApiError(422, "invalid_request", "invalid request fields")

    @staticmethod
    def _operation_id(value) -> str:
        if not isinstance(value, str) or not OPERATION_ID.fullmatch(value):
            raise ApiError(422, "invalid_request", "invalid operation_id")
        return value

    @staticmethod
    def _key(value, name: str) -> str:
        try:
            raw = unb64(value)
        except ValueError as exc:
            raise ApiError(422, "invalid_request", f"invalid {name}") from exc
        if not any(raw):
            raise ApiError(422, "invalid_request", f"invalid {name}")
        return value

    @staticmethod
    def _digest(kind: str, **fields) -> str:
        blob = json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def _commit(self, mutate: Callable[[], None]) -> None:
        snapshot = copy.deepcopy(self.store.doc)
        try:
            mutate()
            self.store.save()
        except BaseException:
            self.store.doc = snapshot
            raise

    def _replayed(self, op_id: str, digest: str) -> str | None:
        """The username of an identical earlier operation, or None for a new one."""
        known = self.store.operations.get(op_id)
        if known is None:
            return None
        if known["digest"] != digest:
            raise ApiError(409, "operation_conflict", "operation id was used with a different request")
        return known["username"] if known["username"] in self.store.peers else None

    def _free_address(self, inst: Instance) -> str:
        used = {r["address"] for r in self.store.peers.values() if r["version"] == inst.version}
        for ip in list(inst.subnet.hosts())[1:]:
            if str(ip) not in used:
                return str(ip)
        raise ApiError(409, "address_pool_exhausted", "no free address in the subnet")

    def _pubkey_taken(self, version: str, public: str, except_user: str | None = None) -> bool:
        return any(
            r["version"] == version and r["public_key"] == public and n != except_user
            for n, r in self.store.peers.items()
        )

    def create_peer(self, body: dict) -> tuple[int, dict]:
        self._fields(body, {"operation_id", "username", "version", "public_key", "preshared_key"})
        op_id = self._operation_id(body["operation_id"])
        username = body["username"]
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ApiError(422, "invalid_request", "invalid username")
        public = self._key(body["public_key"], "public_key")
        psk = self._key(body["preshared_key"], "preshared_key")
        with self.lock:
            inst = self._instance(body["version"])
            digest = self._digest("create", username=username, version=inst.version, pub=public, psk=psk)
            again = self._replayed(op_id, digest)
            if again is not None:
                return 200, self._peer_response(again, inst)
            if username in self.store.peers:
                raise ApiError(409, "username_taken", "username already exists")
            if self._pubkey_taken(inst.version, public):
                raise ApiError(409, "public_key_in_use", "public key already in use")
            record = {
                "version": inst.version,
                "public_key": public,
                "preshared_key": psk,
                "address": self._free_address(inst),
                "enabled": True,
                "revision": 1,
                "created_at": int(self.wall()),
                "operation_id": op_id,
            }

            def mutate():
                self.store.peers[username] = record
                self.store.operations[op_id] = {"digest": digest, "username": username}

            self._commit(mutate)
            self._live_change(inst, peer_lines(hexkey(public), hexkey(psk), record["address"]))
            return 201, self._peer_response(username, inst)

    def _peer_response(self, username: str, inst: Instance) -> dict:
        rec = self.store.peers[username]
        return {
            "peer": self._peer_view(username, rec, self._stats(inst)),
            "instance": self._instance_view(inst),
        }

    def _record(self, username: str) -> dict:
        rec = self.store.peers.get(username)
        if rec is None:
            raise ApiError(404, "not_found", "peer not found")
        return rec

    def set_enabled(self, username: str, enabled: bool) -> dict:
        with self.lock:
            rec = self._record(username)
            inst = self.instances.get(rec["version"])
            if enabled and inst is None:
                raise ApiError(409, "version_disabled", "protocol version is not enabled on this node")
            if rec["enabled"] != enabled:
                def mutate():
                    rec["enabled"] = enabled
                    rec["revision"] += 1

                self._commit(mutate)
                pub = hexkey(rec["public_key"])
                self._live_change(
                    inst,
                    peer_lines(pub, hexkey(rec["preshared_key"]), rec["address"])
                    if enabled
                    else [f"public_key={pub}", "remove=true"],
                )
            return {"peer": self._peer_view(username, rec, self._stats(inst) if inst else None)}

    def rotate(self, username: str, body: dict) -> dict:
        self._fields(body, {"operation_id", "public_key", "preshared_key"})
        op_id = self._operation_id(body["operation_id"])
        public = self._key(body["public_key"], "public_key")
        psk = self._key(body["preshared_key"], "preshared_key")
        with self.lock:
            rec = self._record(username)
            inst = self.instances.get(rec["version"])
            digest = self._digest("rotate", username=username, pub=public, psk=psk)
            if self._replayed(op_id, digest) is not None:
                return {"peer": self._peer_view(username, rec, self._stats(inst) if inst else None)}
            if self._pubkey_taken(rec["version"], public, username):
                raise ApiError(409, "public_key_in_use", "public key already in use")
            old_pub = hexkey(rec["public_key"])

            def mutate():
                rec.update(public_key=public, preshared_key=psk, operation_id=op_id)
                rec["revision"] += 1
                self.store.operations[op_id] = {"digest": digest, "username": username}

            self._commit(mutate)
            lines = [f"public_key={old_pub}", "remove=true"]
            if rec["enabled"]:
                lines += peer_lines(hexkey(public), hexkey(psk), rec["address"])
            self._live_change(inst, lines)
            return {"peer": self._peer_view(username, rec, self._stats(inst) if inst else None)}

    def delete_peer(self, username: str) -> None:
        with self.lock:
            rec = self._record(username)
            inst = self.instances.get(rec["version"])
            self._commit(lambda: self.store.peers.pop(username))
            if rec["enabled"]:
                self._live_change(inst, [f"public_key={hexkey(rec['public_key'])}", "remove=true"])
