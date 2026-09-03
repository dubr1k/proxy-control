from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from installer.adapters.base import Adapter
from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.planner import (
    Action,
    AuditFacts,
    Evidence,
    PlanError,
    ReleaseIdentity,
    StalePlanError,
    build_plan,
)


def config() -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=Profile.CORE,
        acme_email="admin@example.com",
        initial_user="owner",
        domains=DomainConfig(
            panel="panel.example.com",
            mtproxy="relay.example.com",
        ),
        mieru=None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE),
        firewall=FirewallConfig(manage_ufw=False),
    )


def facts(*, reverse: bool = False, free_ports: set[int] | None = None) -> AuditFacts:
    listener_items = [
        ("free_ports", free_ports if free_ports is not None else {443, 8443}),
        ("owners", {443: "nginx", 22: "sshd"}),
    ]
    topology_items = [
        ("systemd_units", {"nginx.service", "ssh.service"}),
        ("nginx_stream", {"includes": ["/etc/nginx/streams-enabled/*"]}),
    ]
    transient_items = [("scan_sequence", [1, 2]), ("elapsed_ms", 17)]
    if reverse:
        listener_items.reverse()
        topology_items.reverse()
        transient_items.reverse()
    return AuditFacts(
        platform={"os": "ubuntu", "version": "24.04", "arch": "arm64"},
        listeners=dict(listener_items),
        ownership={"/etc/nginx/nginx.conf": "foreign"},
        topology=dict(topology_items),
        prerequisites={"dns": {"panel.example.com", "relay.example.com"}},
        transient=dict(transient_items),
    )


def release() -> ReleaseIdentity:
    return ReleaseIdentity(
        tag="v1.2.3",
        commit="0123456789abcdef",
        manifest_sha256="a" * 64,
        components={"proxy-control": "1.2.3", "nginx": "1.26.3"},
        artifacts={"proxy-control-arm64.tar.gz": "b" * 64},
    )


def action(action_id: str, adapter: str) -> Action:
    return Action(
        id=action_id,
        adapter=adapter,
        owner=f"proxy-control:{adapter}",
        mutations=(f"create {adapter} state",),
        preconditions=(f"{adapter} state is absent",),
        verification=(f"{adapter} state is healthy",),
        inverse=(f"remove {adapter} state",),
        credentials_required=False,
    )


@dataclass(frozen=True)
class FakeAdapter:
    name: str
    requires: frozenset[str] = frozenset()
    action_id: str | None = None
    leaked_mutation: str | None = None

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        del config, facts
        planned = action(self.action_id or f"{self.name}.install", self.name)
        if self.leaked_mutation is not None:
            planned = Action(
                id=planned.id,
                adapter=planned.adapter,
                owner=planned.owner,
                mutations=(self.leaked_mutation,),
                preconditions=planned.preconditions,
                verification=planned.verification,
                inverse=planned.inverse,
                credentials_required=True,
            )
        return (planned,)

    def verify(self, action: Action) -> Evidence:
        return Evidence(action_id=action.id, success=True, observations=("healthy",))

    def rollback(self, action: Action, checkpoint: dict[str, object]) -> Evidence:
        del checkpoint
        return Evidence(action_id=action.id, success=True, observations=("restored",))


def adapters(*, reverse: bool = False) -> tuple[Adapter, ...]:
    values: list[Adapter] = [
        FakeAdapter("nginx", frozenset({"packages"})),
        FakeAdapter("packages"),
        FakeAdapter("core", frozenset({"nginx"})),
    ]
    if reverse:
        values.reverse()
    return tuple(values)


def test_equivalent_unordered_inputs_have_identical_plan_bytes_and_digest():
    first = build_plan(config(), facts(), adapters(), release())
    second = build_plan(config(), facts(reverse=True), adapters(reverse=True), release())

    assert first.to_canonical_json() == second.to_canonical_json()
    assert first.digest == second.digest
    assert first.to_canonical_json().startswith(b'{"actions":')
    assert b"password" not in first.to_canonical_json().lower()


def test_transient_audit_facts_do_not_affect_plan_or_freshness():
    initial = facts()
    current = AuditFacts(
        platform=initial.platform,
        listeners=initial.listeners,
        ownership=initial.ownership,
        topology=initial.topology,
        prerequisites=initial.prerequisites,
        transient={"elapsed_ms": 999, "scan_sequence": [9, 8, 7]},
    )

    first = build_plan(config(), initial, adapters(), release())
    second = build_plan(config(), current, adapters(), release())

    assert first.to_canonical_json() == second.to_canonical_json()
    assert first.digest == second.digest
    first.assert_fresh(current)


def test_apply_rejects_changed_relevant_fact():
    plan = build_plan(config(), facts(free_ports={8443}), adapters(), release())

    with pytest.raises(StalePlanError, match="listener facts changed"):
        plan.assert_fresh(facts(free_ports=set()))


def test_adapter_dependencies_are_topologically_sorted_with_stable_ties():
    unordered: tuple[Adapter, ...] = (
        FakeAdapter("core", frozenset({"nginx", "firewall"})),
        FakeAdapter("nginx", frozenset({"packages"})),
        FakeAdapter("packages"),
        FakeAdapter("firewall", frozenset({"packages"})),
    )

    plan = build_plan(config(), facts(), unordered, release())

    assert plan.adapter_order == ("packages", "firewall", "nginx", "core")
    assert tuple(item.adapter for item in plan.actions) == plan.adapter_order


def test_adapter_dependency_cycle_fails_closed():
    cyclic: tuple[Adapter, ...] = (
        FakeAdapter("first", frozenset({"second"})),
        FakeAdapter("second", frozenset({"first"})),
    )

    with pytest.raises(PlanError, match="adapter dependency cycle"):
        build_plan(config(), facts(), cyclic, release())


def test_missing_adapter_dependency_fails_closed():
    with pytest.raises(PlanError, match="requires missing adapter"):
        build_plan(
            config(),
            facts(),
            (FakeAdapter("core", frozenset({"nginx"})),),
            release(),
        )


def test_duplicate_action_ids_fail_closed():
    duplicate: tuple[Adapter, ...] = (
        FakeAdapter("first", action_id="shared.install"),
        FakeAdapter("second", action_id="shared.install"),
    )

    with pytest.raises(PlanError, match="duplicate action id: shared.install"):
        build_plan(config(), facts(), duplicate, release())


def test_action_declares_transaction_and_credential_metadata():
    plan = build_plan(config(), facts(), (FakeAdapter("packages"),), release())

    planned = plan.actions[0]
    assert planned.owner == "proxy-control:packages"
    assert planned.mutations == ("create packages state",)
    assert planned.preconditions == ("packages state is absent",)
    assert planned.verification == ("packages state is healthy",)
    assert planned.inverse == ("remove packages state",)
    assert planned.credentials_required is False


def test_secret_assignment_is_rejected_before_canonical_serialization():
    leaking: tuple[Adapter, ...] = (
        FakeAdapter("packages", leaked_mutation="write password=hunter2"),
    )

    with pytest.raises(PlanError, match="secret material"):
        build_plan(config(), facts(), leaking, release())


def test_reordered_topology_rules_make_plan_stale():
    initial = facts()
    planned = AuditFacts(
        platform=initial.platform,
        listeners=initial.listeners,
        ownership=initial.ownership,
        topology={"nginx_rules": ["route-a", "route-b"]},
        prerequisites=initial.prerequisites,
    )
    reordered = AuditFacts(
        platform=initial.platform,
        listeners=initial.listeners,
        ownership=initial.ownership,
        topology={"nginx_rules": ["route-b", "route-a"]},
        prerequisites=initial.prerequisites,
    )
    plan = build_plan(config(), planned, adapters(), release())

    with pytest.raises(StalePlanError, match="topology facts changed"):
        plan.assert_fresh(reordered)


@pytest.mark.parametrize(
    "leaked_mutation",
    [
        "bootstrap --password hunter2",
        'write settings {\"token\":\"abc\"}',
    ],
)
def test_secret_flag_and_quoted_key_forms_are_rejected(leaked_mutation: str):
    leaking: tuple[Adapter, ...] = (
        FakeAdapter("packages", leaked_mutation=leaked_mutation),
    )

    with pytest.raises(PlanError, match="secret material"):
        build_plan(config(), facts(), leaking, release())


def test_secret_words_in_innocent_prose_are_allowed():
    harmless: tuple[Adapter, ...] = (
        FakeAdapter(
            "packages",
            leaked_mutation="verify the password login mechanism is disabled",
        ),
    )

    build_plan(config(), facts(), harmless, release())


@pytest.mark.parametrize(
    "field_name",
    ["mutations", "preconditions", "verification", "inverse"],
)
def test_action_operation_fields_reject_scalar_strings(field_name: str):
    values = {
        "id": "packages.install",
        "adapter": "packages",
        "owner": "proxy-control:packages",
        "mutations": ("create packages state",),
        "preconditions": ("packages state is absent",),
        "verification": ("packages state is healthy",),
        "inverse": ("remove packages state",),
        "credentials_required": False,
    }
    values[field_name] = "not-a-sequence-of-operations"

    with pytest.raises(PlanError, match="must be a non-string sequence"):
        Action(**values)


@pytest.mark.parametrize(
    "nonfinite",
    [float("nan"), float("inf"), float("-inf")],
)
def test_nonfinite_stable_audit_facts_are_rejected(nonfinite: float):
    with pytest.raises(PlanError, match="non-finite float"):
        AuditFacts(topology={"capacity_ratio": nonfinite})


@pytest.mark.parametrize(
    "nonfinite",
    [float("nan"), float("inf"), float("-inf")],
)
def test_nonfinite_config_values_are_rejected(nonfinite: float):
    unsafe_config = replace(config(), acme_email=nonfinite)

    with pytest.raises(PlanError, match="non-finite float"):
        build_plan(unsafe_config, facts(), adapters(), release())


@pytest.mark.parametrize(
    "nonfinite",
    [float("nan"), float("inf"), float("-inf")],
)
def test_nonfinite_adapter_evidence_is_rejected(nonfinite: float):
    with pytest.raises(PlanError, match="non-finite float"):
        Evidence(
            action_id="packages.install",
            success=True,
            observations=("checked",),
            details={"capacity_ratio": nonfinite},
        )
