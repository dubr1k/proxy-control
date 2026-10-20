"""Where AmneziaWG clients' traffic leaves the node (v2.3.0): directly, or through WARP.

The panel sends the compiled document `{"schema": 1, "upstream": {"provider": "warp"} | null}`, in
the same vocabulary as the NaiveProxy and Mieru managers (`GET /v1/egress`, plan, apply, rollback).
Through WARP, the manager runs one more amneziawg-go device, `awgwarp`, as a plain WireGuard client
of a WARP account of its own (`warp.py`), and steers every AmneziaWG subnet into it by source:

    ip rule  from <subnet> lookup 51870 priority 5150      (one per enabled version)
    table 51870: default dev awgwarp · blackhole default (metric 1024) · throw <private ranges>

The blackhole keeps the egress fail-closed: while the tunnel is down, client traffic is dropped, never
sent from the server's own address. Private, CGNAT and link-local destinations are thrown back to the
main table, so the server, its containers and an overlay network stay reachable. The nft masquerade
the manager already installs (`oifname != <awg iface>`) rewrites the source to the tunnel address.
TCP and UDP both go through: this is WireGuard, not a proxy.

An apply that sets WARP waits for the tunnel's first handshake; without one it puts the previous
document back and fails, so a broken account never black-holes the clients.

Through the Xray-router (`{"provider": "router"}`, variant 2): the same rules and table, the default
route into a persistent TUN device (`awgxr`, owned by the router's uid, 198.18.0.1/30) the manager
keeps; the router reads it as a `tun` inbound and routes by the panel's rules (domains by sniffing,
geodata, ports, custom exits, other nodes), its `warp` a WireGuard outbound — TCP and UDP. An apply
waits until the router reads the device (the link shows LOWER_UP); while the router is down the
device has no reader and the traffic is dropped, never sent from the server's address.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone

from . import warp
from .keys import hexkey

LOGGER = logging.getLogger("awg_manager")
SCHEMA = 1
IFACE = "awgwarp"
TABLE = "51870"
PRIORITY = "5150"
BLACKHOLE_METRIC = "1024"
MTU = 1280
KEEPALIVE = 25
HANDSHAKE_FRESH = 180
HANDSHAKE_WAIT = 12.0
NETWORK_RECHECK = 30.0
MAX_BACKOFF = 30.0
MAX_HISTORY = 10
CAPABILITIES = ("whole_direct", "whole_warp")
THROWN = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
          "127.0.0.0/8", "224.0.0.0/4")
DIRECT = {"schema": SCHEMA, "upstream": None}
PROVIDERS = ("warp", "router")
ROUTER_ADDRESS = "198.18.0.1/30"
OPERATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class EgressError(Exception):
    """An egress refusal in the managers' shared vocabulary (`egress_*` codes)."""

    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


def validate_document(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {"schema", "upstream"} or document["schema"] != SCHEMA:
        raise EgressError(422, "egress_invalid", "egress document must be {schema: 1, upstream}")
    upstream = document["upstream"]
    if upstream is not None and (not isinstance(upstream, dict) or set(upstream) != {"provider"}
                                 or upstream["provider"] not in PROVIDERS):
        raise EgressError(422, "egress_invalid", "AmneziaWG's upstream is warp or router")
    return {"schema": SCHEMA, "upstream": None if upstream is None else {"provider": upstream["provider"]}}


def document_digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Egress:
    """The egress section of the manager's state and the `awgwarp` data plane. The manager holds
    its lock around every call."""

    def __init__(self, manager, *, opener=None, sleep=None):
        self.m = manager
        self.opener = opener
        self.sleep = sleep
        self.proc = None
        self.configured = False
        self.failures = 0
        self.next_start = 0.0
        self.started_at = 0.0
        self.last_network = -NETWORK_RECHECK
        self.network_ok = False

    # ----- state ---------------------------------------------------------------------

    @property
    def section(self) -> dict:
        return self.m.store.doc.setdefault("egress", {"revision": 0, "history": [], "warp": None})

    def load(self) -> None:
        section = self.section
        if (not isinstance(section.get("revision"), int) or not isinstance(section.get("history"), list)
                or (section.get("warp") is not None and not warp.valid_account(section["warp"]))):
            from .state import StateError
            raise StateError("stored egress section is malformed")
        for entry in section["history"]:
            validate_document(entry.get("document") if isinstance(entry, dict) else None)

    def document(self) -> dict:
        history = self.section["history"]
        return copy.deepcopy(history[-1]["document"]) if history else copy.deepcopy(DIRECT)

    def provider(self) -> str | None:
        upstream = self.document()["upstream"]
        return None if upstream is None else upstream["provider"]

    def wants_warp(self) -> bool:
        return self.provider() == "warp"

    # ----- the router's device (variant 2) -----------------------------------------------

    @property
    def router_tun(self) -> str | None:
        return getattr(self.m.config, "router_tun", None)

    def router_flags(self) -> list[str] | None:
        """The router device's link flags, or None when it does not exist."""
        if self.router_tun is None:
            return None
        try:
            links = self.m.host.ip_json("link", "show", "dev", self.router_tun)
        except Exception:  # noqa: BLE001 - absent device
            return None
        return list((links[0] if links else {}).get("flags", [])) if links else None

    def router_attached(self) -> bool:
        """The router reads the device: a TUN with a reader is LOWER_UP, without one NO-CARRIER."""
        flags = self.router_flags()
        return flags is not None and "LOWER_UP" in flags

    def ensure_router_device(self) -> None:
        """The persistent device the router opens (made once, kept across restarts of either side)."""
        if self.router_tun is None:
            return
        host = self.m.host
        try:
            if self.router_flags() is None:
                uid = str(self.m.config.router_uid)
                host.ip("tuntap", "add", "dev", self.router_tun, "mode", "tun", "user", uid, "group", uid)
            host.ip("addr", "replace", ROUTER_ADDRESS, "dev", self.router_tun)
            host.ip("link", "set", self.router_tun, "mtu", str(MTU), "up")
        except Exception as exc:  # noqa: BLE001 - retried on the next pass
            LOGGER.error("the router device %s is not ready: %s", self.router_tun, exc)

    def revision(self) -> str:
        return str(self.section["revision"])

    def _check_revision(self, expected) -> None:
        if not isinstance(expected, str) or expected != self.revision():
            raise EgressError(409, "egress_conflict", "the egress revision changed")

    # ----- views ---------------------------------------------------------------------

    def stats(self) -> dict:
        if self.proc is None or not self.configured:
            return {}
        try:
            text = self.m.host.uapi_get(IFACE)
        except Exception:  # noqa: BLE001 - a wedged device reads as no stats
            return {}
        out = {}
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key in ("last_handshake_time_sec", "rx_bytes", "tx_bytes"):
                try:
                    out[key] = int(value)
                except ValueError:
                    pass
        return out

    def _fresh(self, stats: dict) -> bool:
        handshake = stats.get("last_handshake_time_sec") or 0
        return bool(handshake) and self.m.wall() - handshake <= HANDSHAKE_FRESH

    def tunnel_state(self) -> str:
        if self.provider() == "router":
            return "up" if self.network_ok and self.router_attached() else "down"
        if not self.wants_warp():
            return "off"
        stats = self.stats()
        return "up" if self.network_ok and self._fresh(stats) else "down"

    def view(self) -> dict:
        document = self.document()
        history = self.section["history"]
        account = self.section["warp"]
        stats = self.stats() if self.wants_warp() else {}
        reachable = None
        if self.wants_warp():
            reachable = self.network_ok and self._fresh(stats)
        providers = {"warp": {"reachable": reachable}}
        router = None
        if self.router_tun is not None:
            attached = self.router_attached()
            providers["router"] = {"reachable": attached}
            router = {"device": self.router_tun, "present": self.router_flags() is not None, "attached": attached}
        return {
            "revision": self.revision(),
            "mode": "proxy" if document["upstream"] else "direct",
            "document": document,
            "managed": bool(history),
            "providers": providers,
            "router": router,
            "capabilities": list(CAPABILITIES),
            "restart_required": False,
            "warnings": [],
            "current": None if not history else {k: history[-1].get(k) for k in ("operation_id", "applied_at", "digest")},
            "warp": {
                "registered": account is not None,
                "address": None if account is None else account["address"],
                "endpoint": None if account is None else account["endpoint"],
                "account_type": None if account is None else account.get("account_type"),
                "tunnel": self.tunnel_state(),
                "latest_handshake": stats.get("last_handshake_time_sec") or None,
                "rx": stats.get("rx_bytes", 0),
                "tx": stats.get("tx_bytes", 0),
            },
        }

    def health(self) -> dict:
        provider = self.provider()
        return {"mode": "router" if provider == "router" else "proxy" if provider else "direct", "tunnel": self.tunnel_state()}

    # ----- operations ----------------------------------------------------------------

    def plan(self, expected_revision, document) -> dict:
        target = validate_document(document)
        self._check_revision(expected_revision)
        before = json.dumps(self.document(), indent=1, sort_keys=True).splitlines()
        after = json.dumps(target, indent=1, sort_keys=True).splitlines()
        import difflib
        diff = [line for line in difflib.unified_diff(before, after, "current", "planned", lineterm="", n=0)
                if not line.startswith(("---", "+++", "@@"))]
        reachability = {}
        if target["upstream"] == {"provider": "warp"}:
            reachability["warp"] = self.section["warp"] is not None
        elif target["upstream"] == {"provider": "router"}:
            reachability["router"] = self.router_attached()
        return {"revision": self.revision(), "target": target, "diff": diff, "reachability": reachability,
                "restart_required": False, "warnings": []}

    def apply(self, expected_revision, document, operation_id) -> dict:
        if not isinstance(operation_id, str) or OPERATION_ID.fullmatch(operation_id) is None:
            raise EgressError(422, "egress_invalid", "invalid operation id")
        target = validate_document(document)
        history = self.section["history"]
        if history and history[-1].get("operation_id") == operation_id:
            if history[-1]["document"] != target:
                raise EgressError(409, "egress_conflict", "operation id already used for another request")
            return {"revision": self.revision(), "applied": target, "replayed": True}
        self._check_revision(expected_revision)
        entry = {"document": target, "digest": document_digest(target), "operation_id": operation_id,
                 "applied_at": _now()}
        self._switch([*history, entry][-MAX_HISTORY:], target)
        return {"revision": self.revision(), "applied": target, "replayed": False}

    def rollback(self, expected_revision) -> dict:
        self._check_revision(expected_revision)
        history = self.section["history"]
        if not history:
            raise EgressError(409, "egress_no_previous", "no previous egress to roll back to")
        rest = history[:-1]
        target = rest[-1]["document"] if rest else copy.deepcopy(DIRECT)
        self._switch(rest, target)
        return {"revision": self.revision(), "applied": target, "replayed": False}

    def _switch(self, history: list, target: dict) -> None:
        """Commit the new history, converge the data plane, and for WARP wait for a handshake;
        without one, put the previous history back and fail."""
        section = self.section
        previous = copy.deepcopy(section)
        if target["upstream"] == {"provider": "router"} and self.router_tun is None:
            raise EgressError(422, "egress_invalid", "this node's AmneziaWG has no Xray-router device")
        if target["upstream"] == {"provider": "warp"} and section["warp"] is None:
            try:
                section["warp"] = warp.register(self.opener)
            except warp.WarpError as exc:
                raise EgressError(503, "egress_unreachable", str(exc)) from exc
        section["history"] = history
        section["revision"] += 1
        self.m.store.save()
        self.reset_dataplane()
        self.converge(self.m.clock(), force=True)
        if target["upstream"] is None or self._await_ready(target["upstream"]["provider"]):
            return
        LOGGER.error("the %s egress did not come up; egress goes back to the previous document",
                     target["upstream"]["provider"])
        account = section["warp"]
        section.clear()
        section.update(previous)
        section["warp"] = account  # the registration stays: it may work on the next attempt
        section["revision"] += 2
        self.m.store.save()
        self.reset_dataplane()
        self.converge(self.m.clock(), force=True)
        if target["upstream"]["provider"] == "router":
            raise EgressError(503, "egress_unreachable", "the Xray-router does not read the AmneziaWG device")
        raise EgressError(503, "egress_unreachable", "the WARP tunnel did not complete a handshake")

    def _await_ready(self, provider: str) -> bool:
        if provider == "warp":
            return self._await_handshake()
        waited = 0.0
        while waited <= HANDSHAKE_WAIT:
            self.converge(self.m.clock())
            if self.network_ok and self.router_attached():
                return True
            (self.sleep or __import__("time").sleep)(0.5)
            waited += 0.5
        return False

    def _await_handshake(self) -> bool:
        """The caller holds the manager's lock, so the supervisor cannot run meanwhile: this loop
        keeps converging itself (a freshly started amneziawg-go needs a moment before its control
        socket takes the configuration)."""
        waited = 0.0
        while waited <= HANDSHAKE_WAIT:
            self.converge(self.m.clock())
            if self._fresh(self.stats()):
                return True
            if self.sleep is None:
                import time
                time.sleep(0.5)
            else:
                self.sleep(0.5)
            waited += 0.5
        return False

    # ----- data plane ----------------------------------------------------------------

    def reset_dataplane(self) -> None:
        """Forget what was configured so the next converge sets the device and network again."""
        self.configured = False
        self.last_network = -NETWORK_RECHECK

    def converge(self, now: float, *, force: bool = False) -> None:
        account = self.section["warp"]
        if self.router_tun is not None and (force or now - self.last_network >= NETWORK_RECHECK or self.provider() == "router"
                                            and not self.network_ok):
            self.ensure_router_device()
        if self.provider() == "router":
            self._stop_process()
            if force or not self.network_ok or now - self.last_network >= NETWORK_RECHECK:
                self._network(now, device=self.router_tun)
            return
        if not self.wants_warp() or account is None:
            # Cheap when already direct: a full sweep (stale rules after a crash) every 30 s.
            if force or self.proc is not None or now - self.last_network >= NETWORK_RECHECK:
                self.teardown()
                self.last_network = now
            return
        self._supervise(account, now)
        if force or not self.network_ok or now - self.last_network >= NETWORK_RECHECK:
            self._network(now)

    def _supervise(self, account: dict, now: float) -> None:
        host = self.m.host
        if self.proc is not None and self.proc.poll() is not None:
            LOGGER.warning("%s exited with %s", IFACE, self.proc.poll())
            self.proc, self.configured = None, False
            self.failures += 1
            self.next_start = now + min(MAX_BACKOFF, 2 ** (self.failures - 1))
        if self.proc is None:
            if now < self.next_start:
                return
            try:
                self.proc = host.start_process(IFACE, self.m.config.log_level)
            except OSError as exc:
                self.failures += 1
                self.next_start = now + min(MAX_BACKOFF, 2 ** (self.failures - 1))
                LOGGER.error("cannot start %s: %s", IFACE, exc)
                return
            self.started_at, self.configured = now, False
        if self.configured:
            return
        lines = [
            f"private_key={hexkey(account['private_key'])}",
            "replace_peers=true",
            f"public_key={hexkey(account['peer_public_key'])}",
            f"endpoint={account['endpoint']}",
            f"persistent_keepalive_interval={KEEPALIVE}",
            "replace_allowed_ips=true",
            "allowed_ip=0.0.0.0/0",
        ]
        try:
            host.uapi_set(IFACE, "\n".join(lines) + "\n")
            host.ip("addr", "replace", f"{account['address']}/32", "dev", IFACE)
            host.ip("link", "set", IFACE, "mtu", str(MTU), "up")
        except Exception as exc:  # noqa: BLE001 - not ready yet: the next tick tries again
            LOGGER.warning("%s not configured yet: %s", IFACE, exc)
            if now - self.started_at > 10 and self.proc is not None:
                self.proc.kill()
            return
        self.configured, self.failures = True, 0
        self.last_network = -NETWORK_RECHECK

    def _subnets(self) -> set[str]:
        return {str(inst.subnet) for inst in self.m.instances.values()}

    def _rules(self) -> set[str]:
        """Sources that already have our rule (in our table at our priority)."""
        found = set()
        for rule in self.m.host.ip_json("-4", "rule", "show", "table", TABLE):
            if str(rule.get("priority")) != PRIORITY or "src" not in rule:
                continue
            length = rule.get("srclen", 32)
            found.add(str(ipaddress.ip_network(f"{rule['src']}/{length}", strict=False)))
        return found

    def _network(self, now: float, device: str | None = None) -> None:
        host = self.m.host
        device = device or IFACE
        routed = device != IFACE or self.configured
        self.last_network = now
        try:
            # The blackhole first: from here on nothing in the table can fall through to a leak.
            host.ip("route", "replace", "blackhole", "default", "table", TABLE, "metric", BLACKHOLE_METRIC)
            for net in THROWN:
                host.ip("route", "replace", "throw", net, "table", TABLE)
            if routed:
                host.ip("route", "replace", "default", "dev", device, "table", TABLE)
            have, want = self._rules(), self._subnets()
            for source in sorted(want - have):
                host.ip("rule", "add", "from", source, "lookup", TABLE, "priority", PRIORITY)
            for source in sorted(have - want):
                host.ip("rule", "del", "from", source, "lookup", TABLE, "priority", PRIORITY)
            self.network_ok = routed
        except Exception as exc:  # noqa: BLE001 - retried on the next pass
            LOGGER.error("WARP egress routing not applied: %s", exc)
            self.network_ok = False
            self.last_network = -NETWORK_RECHECK

    def teardown(self) -> None:
        """Back to direct: rules out, table flushed, the tunnel stopped. Idempotent."""
        host = self.m.host
        try:
            for source in sorted(self._rules()):
                host.ip("rule", "del", "from", source, "lookup", TABLE, "priority", PRIORITY)
        except Exception as exc:  # noqa: BLE001
            LOGGER.error("cannot remove the WARP egress rules: %s", exc)
        try:
            host.ip("route", "flush", "table", TABLE)
        except Exception:  # noqa: BLE001 - an empty table answers with an error on some kernels
            pass
        self._stop_process()
        self.network_ok = False

    def _stop_process(self) -> None:
        if self.proc is not None:
            proc, self.proc = self.proc, None
            proc.terminate()
            try:
                proc.wait(5)
            except Exception:  # noqa: BLE001
                proc.kill()
        self.configured = False
