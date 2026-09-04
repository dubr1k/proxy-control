from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from installer.model import HostMode, InstallerConfig, ThreeXuiMode
from installer.planner import Action, AuditFacts, Evidence

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_STATUS_COMMAND = ("ufw", "status", "numbered")
_HEADER = (
    "To                         Action      From",
    "--                         ------      ----",
)
_RULE = re.compile(
    r"^\[\s*(?P<number>[1-9][0-9]*)\]\s+"
    r"(?P<port>[1-9][0-9]{0,4})/(?P<protocol>tcp|udp)(?P<to_v6> \(v6\))?\s+"
    r"(?P<action>ALLOW IN)\s+"
    r"(?P<source>[^#]+?)(?:\s+#\s+(?P<comment>[^\r\n]+))?\s*$"
)
_COMMENT = re.compile(r"[A-Za-z0-9_.:+-]{1,128}\Z")


class FirewallError(RuntimeError):
    """The local firewall cannot be changed within an exact ownership boundary."""


@dataclass(frozen=True, order=True)
class UfwRule:
    port: int
    protocol: str
    action: str
    source: str
    ipv6: bool
    comment: str | None = None

    @property
    def logical_key(self) -> str:
        return f"{self.protocol}:{self.port}"


class FirewallAdapter:
    """Own exact comment-scoped UFW rules on audited fresh hosts only."""

    name = "firewall"
    requires = frozenset({"packages"})

    def __init__(
        self,
        *,
        runner: CommandRunner | object | None = None,
        ssh_ports: set[int] | frozenset[int] | None = None,
    ) -> None:
        if runner is None:
            from installer.audit import CommandRunner

            runner = CommandRunner(timeout=30.0)
        if ssh_ports is not None:
            _validate_ports(ssh_ports)
            if len(ssh_ports) != 1:
                raise ValueError("exactly one SSH port must be selected")
            self.ssh_ports = frozenset(ssh_ports)
        else:
            self.ssh_ports = None
        self.runner = runner

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if config.host_mode is not HostMode.FRESH or not config.firewall.manage_ufw:
            return ()
        if getattr(facts, "hard_stops", ()):
            raise FirewallError("host audit contains blocking findings")
        self._validate_ownership(facts)
        ssh_port = self._ssh_port(facts)
        rules = self._status()
        ipv6_enabled = _ipv6_enabled(facts)
        _assert_ssh_preserved(rules, ssh_port, ipv6_enabled)
        desired = _selected_ports(config)
        return (
            Action(
                id="firewall.ufw",
                adapter=self.name,
                owner="proxy-control:firewall",
                mutations=(
                    f"ssh={ssh_port}",
                    f"ipv6={'true' if ipv6_enabled else 'false'}",
                    *(f"rule={key}" for key in desired),
                ),
                preconditions=(
                    f"active SSH listener on tcp/{ssh_port} has one unambiguous UFW allow rule",
                    "external cloud firewall reachability remains operator-verified",
                ),
                verification=("exact selected-profile UFW rules are active",),
                inverse=("delete exact comment-scoped rules added by this action",),
                credentials_required=False,
            ),
        )

    def prepare(self, action: Action) -> Mapping[str, object]:
        desired = _action_rules(action)
        rules = self._status()
        ipv6_enabled = _action_ipv6_enabled(action)
        _assert_ssh_preserved(rules, _action_ssh_port(action), ipv6_enabled)
        preexisting = tuple(
            key
            for key in desired
            if _is_covered(rules, *_split_key(key), ipv6_enabled)
        )
        return {
            "initial_fingerprints": _fingerprints(rules),
            "installer_added": (),
            "owner": action.owner,
            "ownership": {},
            "preexisting": preexisting,
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        desired = _action_rules(action)
        initial, preexisting, recorded_added = _firewall_checkpoint(
            checkpoint,
            desired,
        )
        current = self._status()
        ipv6_enabled = _action_ipv6_enabled(action)
        _assert_foreign_preserved(initial, current)
        _assert_ssh_preserved(
            current,
            _action_ssh_port(action),
            ipv6_enabled,
        )
        _assert_owned_rules_recognized(current)
        for key in desired:
            protocol, port = _split_key(key)
            if _is_covered(current, protocol, port, ipv6_enabled):
                continue
            self._run_checked(
                (
                    "ufw",
                    "allow",
                    "proto",
                    protocol,
                    "from",
                    "any",
                    "to",
                    "any",
                    "port",
                    str(port),
                    "comment",
                    _owned_comment(key),
                ),
                "UFW rule creation failed",
            )
            current = self._status()
            _assert_foreign_preserved(initial, current)
            if not _has_exact_owned(current, key):
                raise FirewallError("owned UFW rule was not created exactly")
        after = self._status()
        _assert_foreign_preserved(initial, after)
        installer_added = tuple(
            key
            for key in desired
            if key not in preexisting and _has_exact_owned(after, key)
        )
        if recorded_added and not set(recorded_added) <= set(installer_added):
            raise FirewallError("owned UFW rule has drifted")
        if any(
            not _is_covered(after, *_split_key(key), ipv6_enabled)
            for key in desired
        ):
            raise FirewallError("selected-profile UFW rule is absent")
        return {
            "initial_fingerprints": initial,
            "installer_added": installer_added,
            "owner": action.owner,
            "ownership": {},
            "preexisting": preexisting,
        }

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.apply(action, checkpoint)

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        desired = _action_rules(action)
        initial, preexisting, installer_added = _firewall_checkpoint(
            checkpoint,
            desired,
        )
        current = self._status()
        ipv6_enabled = _action_ipv6_enabled(action)
        _assert_foreign_preserved(initial, current)
        _assert_owned_rules_recognized(current)
        _assert_ssh_preserved(
            current,
            _action_ssh_port(action),
            ipv6_enabled,
        )
        for key in installer_added:
            protocol, port = _split_key(key)
            if _is_covered(current, protocol, port, ipv6_enabled):
                continue
            self._run_checked(
                (
                    "ufw",
                    "allow",
                    "proto",
                    protocol,
                    "from",
                    "any",
                    "to",
                    "any",
                    "port",
                    str(port),
                    "comment",
                    _owned_comment(key),
                ),
                "UFW rule repair failed",
            )
            current = self._status()
            _assert_foreign_preserved(initial, current)
            if not _has_exact_owned(current, key) or not _is_covered(
                current,
                protocol,
                port,
                ipv6_enabled,
            ):
                raise FirewallError("owned UFW rule was not repaired exactly")
        if any(
            not _is_covered(current, *_split_key(key), ipv6_enabled)
            for key in desired
        ):
            raise FirewallError("selected-profile UFW rule is absent")
        return {
            "initial_fingerprints": initial,
            "installer_added": installer_added,
            "owner": action.owner,
            "ownership": {},
            "preexisting": preexisting,
        }

    def verify(self, action: Action) -> Evidence:
        desired = _action_rules(action)
        try:
            current = self._status()
            ipv6_enabled = _action_ipv6_enabled(action)
            _assert_owned_rules_recognized(current)
            _assert_ssh_preserved(
                current,
                _action_ssh_port(action),
                ipv6_enabled,
            )
            success = all(
                _is_covered(current, *_split_key(key), ipv6_enabled)
                for key in desired
            )
        except FirewallError:
            success = False
        return Evidence(
            action_id=action.id,
            success=success,
            observations=(
                "selected-profile UFW rules are active"
                if success
                else "selected-profile UFW rules are absent or ambiguous",
            ),
            details={"rules": desired},
        )

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        del purge_data
        if rollback_target not in {"rolled_back", "uninstalled"}:
            raise ValueError("invalid rollback target")
        desired = _action_rules(action)
        initial, _preexisting, installer_added = _firewall_checkpoint(
            checkpoint,
            desired,
        )
        current = self._status()
        _assert_foreign_preserved(initial, current)
        _assert_owned_rules_recognized(current)
        for key in reversed(installer_added):
            if not _has_exact_owned(current, key):
                continue
            protocol, port = _split_key(key)
            self._run_checked(
                (
                    "ufw",
                    "--force",
                    "delete",
                    "allow",
                    "proto",
                    protocol,
                    "from",
                    "any",
                    "to",
                    "any",
                    "port",
                    str(port),
                    "comment",
                    _owned_comment(key),
                ),
                "UFW rule rollback failed",
            )
            current = self._status()
            _assert_foreign_preserved(initial, current)
            if _has_exact_owned(current, key):
                raise FirewallError("owned UFW rule remains after rollback")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("exact installer-owned UFW rules were removed",),
            details={"removed": installer_added},
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        desired = _action_rules(action)
        initial, preexisting, installer_added = _firewall_checkpoint(
            checkpoint,
            desired,
        )
        current = self._status()
        _assert_foreign_preserved(initial, current)
        recovered = set(installer_added)
        recovered.update(
            key
            for key in desired
            if key not in preexisting and _has_exact_owned(current, key)
        )
        recovered_checkpoint = {
            "initial_fingerprints": initial,
            "installer_added": tuple(key for key in desired if key in recovered),
            "owner": action.owner,
            "ownership": {},
            "preexisting": preexisting,
        }
        return self.rollback(
            action,
            recovered_checkpoint,
            purge_data=purge_data,
            rollback_target=rollback_target,
        )

    def _status(self) -> tuple[UfwRule, ...]:
        result = self.runner.run(_STATUS_COMMAND)
        if result.returncode != 0:
            raise FirewallError("UFW status query failed")
        return parse_ufw_status(result.stdout)

    def _run_checked(self, argv: tuple[str, ...], message: str) -> None:
        result = self.runner.run(argv)
        if result.returncode != 0:
            raise FirewallError(message)

    def _ssh_port(self, facts: AuditFacts) -> int:
        tcp = _fact_ports(facts.listeners.get("tcp", ()))
        socket_ports = _fact_ports(facts.listeners.get("ssh_socket_tcp", ()))
        owners = facts.listeners.get("owners")
        if not isinstance(owners, Mapping):
            raise FirewallError("active SSH listener is not observed")
        discovered: set[int] = set()
        for port in tcp:
            raw_names = owners.get(str(port), ())
            if not isinstance(raw_names, (tuple, list)):
                continue
            names = {
                name.lower() for name in raw_names if isinstance(name, str)
            }
            if names & {"ssh", "sshd"} or (
                port in socket_ports and "systemd" in names
            ):
                discovered.add(port)
        selected = set(self.ssh_ports) if self.ssh_ports is not None else discovered
        if not selected or not selected <= tcp or not selected <= discovered:
            raise FirewallError("active SSH listener is not observed")
        if len(selected) != 1 or discovered != selected:
            raise FirewallError("SSH listener preservation is ambiguous")
        return next(iter(selected))

    @staticmethod
    def _validate_ownership(facts: AuditFacts) -> None:
        ufw = facts.ownership.get("ufw")
        if not isinstance(ufw, Mapping) or any(
            ufw.get(key) != value
            for key, value in {
                "active": True,
                "available": True,
                "mode": "managed",
                "observation": "observed",
            }.items()
        ):
            raise FirewallError("active managed UFW ownership is not established")
        foreign = facts.ownership.get("firewall")
        if foreign is not None:
            if not isinstance(foreign, Mapping) or foreign.get("backend") not in {
                None,
                "ufw",
            }:
                raise FirewallError("foreign firewall ownership is present")


def parse_ufw_status(text: str) -> tuple[UfwRule, ...]:
    """Parse only canonical active numbered UFW port-rule output."""
    if not isinstance(text, str) or "\x00" in text:
        raise FirewallError("UFW status output is malformed")
    lines = text.splitlines()
    if not lines or lines[0] != "Status: active":
        raise FirewallError("UFW is inactive or its status is unknown")
    cursor = 1
    while cursor < len(lines) and not lines[cursor].strip():
        cursor += 1
    if cursor + 1 >= len(lines) or tuple(line.strip() for line in lines[cursor:cursor + 2]) != _HEADER:
        raise FirewallError("UFW status output is nonstandard")
    cursor += 2
    rules: list[UfwRule] = []
    expected_number = 1
    for line in lines[cursor:]:
        if not line.strip():
            continue
        match = _RULE.fullmatch(line)
        if match is None or int(match.group("number")) != expected_number:
            raise FirewallError("UFW status output is nonstandard")
        expected_number += 1
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            raise FirewallError("UFW status output is nonstandard")
        source_text = match.group("source").strip()
        to_v6 = match.group("to_v6") is not None
        source_v6 = source_text.endswith(" (v6)")
        if source_v6:
            source_text = source_text[:-5]
        if to_v6 != source_v6:
            raise FirewallError("UFW status output is nonstandard")
        source = _canonical_source(source_text)
        comment = match.group("comment")
        if comment is not None:
            comment = comment.strip()
            if not comment or len(comment) > 256 or any(ord(char) < 32 for char in comment):
                raise FirewallError("UFW status output is nonstandard")
        rules.append(
            UfwRule(
                port=port,
                protocol=match.group("protocol"),
                action=match.group("action"),
                source=source,
                ipv6=to_v6,
                comment=comment,
            )
        )
    return tuple(rules)


def _canonical_source(value: str) -> str:
    if value == "Anywhere":
        return value
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise FirewallError("UFW status output is nonstandard") from None


def _selected_ports(config: InstallerConfig) -> tuple[str, ...]:
    selected: set[tuple[str, int]] = {("tcp", 80), ("tcp", 443)}
    if config.profile.includes_mieru:
        if config.mieru is None:
            raise FirewallError("Mieru ports are missing")
        selected.update(("tcp", port) for port in config.mieru.tcp_ports)
        selected.update(("udp", port) for port in config.mieru.udp_ports)
    if (
        config.three_xui.mode is ThreeXuiMode.MANAGED_NEW
        and config.three_xui.hysteria_domain is not None
    ):
        selected.add(("udp", 443))
    for _protocol, port in selected:
        _validate_ports({port})
    return tuple(f"{protocol}:{port}" for protocol, port in sorted(selected))


def _validate_ports(ports: set[int] | frozenset[int]) -> None:
    if any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("ports must be integers in 1..65535")


def _fact_ports(value: object) -> set[int]:
    if not isinstance(value, (tuple, list)):
        return set()
    ports = {
        port
        for port in value
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
    }
    return ports if len(ports) == len(value) else set()


def _ipv6_enabled(facts: AuditFacts) -> bool:
    ufw = facts.ownership.get("ufw")
    if not isinstance(ufw, Mapping):
        raise FirewallError("active managed UFW ownership is not established")
    observed = ufw.get("ipv6_enabled")
    if not isinstance(observed, bool):
        raise FirewallError("UFW IPv6 state is unknown")
    return observed

def _assert_ssh_preserved(
    rules: tuple[UfwRule, ...],
    port: int,
    ipv6_enabled: bool,
) -> None:
    for family in (False, True) if ipv6_enabled else (False,):
        candidates = {
            (rule.port, rule.protocol, rule.action, rule.source, rule.comment)
            for rule in rules
            if rule.port == port
            and rule.protocol == "tcp"
            and rule.action == "ALLOW IN"
            and rule.source == "Anywhere"
            and rule.ipv6 is family
        }
        if not candidates:
            label = "IPv6" if family else "IPv4"
            raise FirewallError(
                f"active SSH listener has no preserving {label} UFW rule"
            )
        if len(candidates) != 1:
            raise FirewallError("SSH listener preservation is ambiguous")


def _action_rules(action: Action) -> tuple[str, ...]:
    if action.adapter != "firewall" or action.id != "firewall.ufw":
        raise FirewallError("firewall action is invalid")
    values: list[str] = []
    ssh_seen = False
    ipv6_seen = False
    for mutation in action.mutations:
        key, separator, value = mutation.partition("=")
        if separator != "=":
            raise FirewallError("firewall action is invalid")
        if key == "ssh" and not ssh_seen:
            ssh_seen = True
            _parse_port(value)
            continue
        if key == "ipv6" and not ipv6_seen:
            ipv6_seen = True
            _parse_boolean(value)
            continue
        if key != "rule":
            raise FirewallError("firewall action is invalid")
        _split_key(value)
        values.append(value)
    if not ssh_seen or not ipv6_seen:
        raise FirewallError("firewall action is invalid")
    normalized = tuple(sorted(set(values), key=lambda item: _split_key(item)))
    if tuple(values) != normalized:
        raise FirewallError("firewall action is invalid")
    return normalized

def _action_ssh_port(action: Action) -> int:
    if action.adapter != "firewall" or action.id != "firewall.ufw":
        raise FirewallError("firewall action is invalid")
    values = [
        mutation.partition("=")[2]
        for mutation in action.mutations
        if mutation.partition("=")[0] == "ssh"
        and mutation.partition("=")[1] == "="
    ]
    if len(values) != 1:
        raise FirewallError("firewall action is invalid")
    return _parse_port(values[0])

def _action_ipv6_enabled(action: Action) -> bool:
    if action.adapter != "firewall" or action.id != "firewall.ufw":
        raise FirewallError("firewall action is invalid")
    values = [
        mutation.partition("=")[2]
        for mutation in action.mutations
        if mutation.partition("=")[0] == "ipv6"
        and mutation.partition("=")[1] == "="
    ]
    if len(values) != 1:
        raise FirewallError("firewall action is invalid")
    return _parse_boolean(values[0])


def _parse_boolean(value: str) -> bool:
    if value not in {"false", "true"}:
        raise FirewallError("firewall action is invalid")
    return value == "true"


def _parse_port(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,4}", value) is None:
        raise FirewallError("firewall action is invalid")
    port = int(value)
    if not 1 <= port <= 65535:
        raise FirewallError("firewall action is invalid")
    return port


def _split_key(key: str) -> tuple[str, int]:
    match = re.fullmatch(r"(tcp|udp):([1-9][0-9]{0,4})", key)
    if match is None or not 1 <= int(match.group(2)) <= 65535:
        raise FirewallError("firewall rule is invalid")
    return match.group(1), int(match.group(2))


def _owned_comment(key: str) -> str:
    comment = f"proxy-control:firewall:{key}"
    if _COMMENT.fullmatch(comment) is None:
        raise FirewallError("firewall ownership comment is invalid")
    return comment


def _is_covered(
    rules: tuple[UfwRule, ...],
    protocol: str,
    port: int,
    ipv6_enabled: bool,
) -> bool:
    families = {
        rule.ipv6
        for rule in rules
        if rule.port == port
        and rule.protocol == protocol
        and rule.action == "ALLOW IN"
        and rule.source == "Anywhere"
    }
    return False in families and (not ipv6_enabled or True in families)


def _has_exact_owned(rules: tuple[UfwRule, ...], key: str) -> bool:
    protocol, port = _split_key(key)
    expected = _owned_comment(key)
    matches = [rule for rule in rules if rule.comment == expected]
    if any(
        rule.port != port
        or rule.protocol != protocol
        or rule.action != "ALLOW IN"
        or rule.source != "Anywhere"
        for rule in matches
    ):
        raise FirewallError("owned UFW rule has drifted")
    logical = {(rule.port, rule.protocol, rule.action, rule.source) for rule in matches}
    if len(logical) > 1:
        raise FirewallError("owned UFW rule is ambiguous")
    return bool(matches)


def _assert_owned_rules_recognized(rules: tuple[UfwRule, ...]) -> None:
    prefix = "proxy-control:firewall:"
    for rule in rules:
        if rule.comment is None or not rule.comment.startswith(prefix):
            continue
        key = rule.comment.removeprefix(prefix)
        _split_key(key)
        _has_exact_owned(rules, key)


def _rule_fingerprint(rule: UfwRule) -> str:
    canonical = "\0".join(
        (
            str(rule.port),
            rule.protocol,
            rule.action,
            rule.source,
            "v6" if rule.ipv6 else "v4",
            rule.comment or "",
        )
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _fingerprints(rules: tuple[UfwRule, ...]) -> tuple[str, ...]:
    return tuple(sorted(_rule_fingerprint(rule) for rule in rules))


def _assert_foreign_preserved(
    initial: tuple[str, ...],
    current: tuple[UfwRule, ...],
) -> None:
    remaining = list(_fingerprints(current))
    for expected in initial:
        try:
            remaining.remove(expected)
        except ValueError:
            raise FirewallError("pre-existing UFW rule changed or disappeared") from None


def _firewall_checkpoint(
    checkpoint: Mapping[str, object],
    desired: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    required = {
        "initial_fingerprints",
        "installer_added",
        "owner",
        "ownership",
        "preexisting",
    }
    if (
        set(checkpoint) != required
        or checkpoint["owner"] != "proxy-control:firewall"
        or checkpoint["ownership"] != {}
    ):
        raise FirewallError("firewall checkpoint is invalid")
    initial = _string_tuple(checkpoint["initial_fingerprints"], unique=False)
    if (
        initial != tuple(sorted(initial))
        or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in initial)
    ):
        raise FirewallError("firewall checkpoint is invalid")
    preexisting = _string_tuple(checkpoint["preexisting"])
    installer_added = _string_tuple(checkpoint["installer_added"])
    if (
        preexisting
        != tuple(key for key in desired if key in set(preexisting))
        or installer_added
        != tuple(key for key in desired if key in set(installer_added))
        or set(preexisting) & set(installer_added)
    ):
        raise FirewallError("firewall checkpoint is invalid")
    for key in (*preexisting, *installer_added):
        _split_key(key)
    return initial, preexisting, installer_added


def _string_tuple(value: object, *, unique: bool = True) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or any(
        not isinstance(item, str) for item in value
    ):
        raise FirewallError("firewall checkpoint is invalid")
    parsed = tuple(value)
    if unique and len(parsed) != len(set(parsed)):
        raise FirewallError("firewall checkpoint is invalid")
    return parsed


__all__ = ["FirewallAdapter", "FirewallError", "UfwRule", "parse_ufw_status"]
