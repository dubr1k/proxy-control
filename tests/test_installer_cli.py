from __future__ import annotations

import io
import json
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import installer.cli as cli
from installer.config import load_config
from installer.model import InstallerConfig
from installer.planner import AuditFacts, InstallPlan, ReleaseIdentity, build_plan
from installer.transaction import TransactionState


ROOT = Path(__file__).parents[1]
CORE_CONFIG = ROOT / "examples" / "installer" / "core.toml"


class RecordingEngine:
    def __init__(self, state: TransactionState):
        self.state = state
        self.calls: list[tuple[object, ...]] = []

    def apply(self, plan: InstallPlan, accepted_digest: str) -> TransactionState:
        self.calls.append(("apply", plan, accepted_digest))
        return self.state

    def resume(self) -> TransactionState:
        self.calls.append(("resume",))
        return self.state

    def repair(self) -> TransactionState:
        self.calls.append(("repair",))
        return self.state

    def uninstall(self, purge_data: bool) -> TransactionState:
        self.calls.append(("uninstall", purge_data))
        return self.state


class RecordingStore:
    def __init__(self, state: TransactionState):
        self.state = state
        self.state_path = Path("state.json")

    def read_state(self) -> TransactionState:
        return self.state


@dataclass
class ReturningWizard:
    config: InstallerConfig

    def run(self, facts: AuditFacts) -> InstallerConfig:
        assert isinstance(facts, AuditFacts)
        return self.config


def _state(*, status: str = "active") -> TransactionState:
    digest = "a" * 64
    return TransactionState(
        transaction_id="b" * 32,
        status=status,
        plan_digest=digest,
        accepted_digest=digest,
        error="SafeError: password=hunter2",
        legacy={"private_token": "must-not-be-rendered"},
    )


def _plan(config: InstallerConfig) -> InstallPlan:
    return build_plan(
        config,
        AuditFacts(platform={"os": "ubuntu"}),
        (),
        ReleaseIdentity(
            tag="v0.1.0",
            commit="c" * 40,
            manifest_sha256="d" * 64,
        ),
    )


def _services(
    config: InstallerConfig,
    *,
    wizard: object | None = None,
) -> tuple[cli.CliServices, RecordingEngine]:
    plan = _plan(config)
    state = _state()
    engine = RecordingEngine(state)
    services = cli.CliServices(
        audit=lambda _config: plan.facts,
        plan=lambda actual, facts: _plan(actual),
        engine=engine,
        store=RecordingStore(state),
        wizard=lambda _io, _locale, _output: wizard or ReturningWizard(config),
    )
    return services, engine


def _run(
    argv: list[str],
    services: cli.CliServices,
    *,
    input_text: str = "",
) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    terminal = cli.TerminalIO(io.StringIO(input_text), stdout)
    result = cli.run(argv, services=services, io=terminal, stdout=stdout, stderr=stderr)
    return result, stdout.getvalue(), stderr.getvalue()


def test_toml_plan_uses_the_same_typed_config_and_canonical_plan():
    config = load_config(CORE_CONFIG)
    services, _engine = _services(config)

    result, stdout, stderr = _run(
        ["plan", "--config", str(CORE_CONFIG), "--json"], services
    )

    payload = json.loads(stdout)
    assert result == 0, stderr
    assert payload["config"] == config.canonical_dict()
    assert payload["digest"] == _plan(config).digest


def test_automated_install_requires_complete_exact_digest(monkeypatch):
    config = load_config(CORE_CONFIG)
    services, engine = _services(config)
    digest = _plan(config).digest
    compared: list[tuple[str, str]] = []
    real_compare = cli.secrets.compare_digest

    def recording_compare(left: str, right: str) -> bool:
        compared.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(cli.secrets, "compare_digest", recording_compare)

    abbreviated, _stdout, abbreviated_error = _run(
        ["install", "--config", str(CORE_CONFIG), "--accept-plan", digest[:12]],
        services,
    )
    wrong, _stdout, wrong_error = _run(
        ["install", "--config", str(CORE_CONFIG), "--accept-plan", "0" * 64],
        services,
    )
    accepted, _stdout, accepted_error = _run(
        ["install", "--config", str(CORE_CONFIG), "--accept-plan", digest],
        services,
    )

    assert abbreviated == wrong == 2
    assert "complete plan digest" in abbreviated_error
    assert "does not match" in wrong_error
    assert accepted == 0, accepted_error
    assert compared == [("0" * 64, digest), (digest, digest)]
    assert engine.calls == [("apply", _plan(config), digest)]


@pytest.mark.parametrize("confirmation", ["", "0" * 12, "A" * 12, "a" * 11, "a" * 13])
def test_interactive_confirmation_accepts_exactly_first_twelve_lowercase_hex(
    confirmation: str,
):
    config = load_config(CORE_CONFIG)
    plan = _plan(config)
    services, engine = _services(config)
    expected = plan.digest[:12]
    value = expected if confirmation == "" else confirmation

    result, _stdout, _stderr = _run(["wizard"], services, input_text=value + "\n")

    if confirmation == "":
        assert result == 0
        assert engine.calls == [("apply", plan, plan.digest)]
    else:
        assert result == 2
        assert engine.calls == []


def test_interactive_quit_at_digest_does_not_call_engine():
    config = load_config(CORE_CONFIG)
    services, engine = _services(config)

    result, stdout, stderr = _run(["wizard"], services, input_text="quit\n")

    assert result == 0, stderr
    assert "No changes were made" in stdout
    assert engine.calls == []


def test_interactive_wizard_rejects_a_plan_for_different_config():
    config = load_config(CORE_CONFIG)
    other_plan = _plan(replace(config, initial_user="other"))
    services, engine = _services(config)
    mismatched = cli.CliServices(
        audit=services.audit,
        plan=lambda _config, _facts: other_plan,
        engine=services.engine,
        store=services.store,
        wizard=services.wizard,
    )

    result, _stdout, stderr = _run(
        ["wizard"], mismatched, input_text=other_plan.digest[:12] + "\n"
    )

    assert result == 2
    assert "different configuration" in stderr
    assert engine.calls == []


def test_status_json_is_deterministic_and_omits_legacy_payload():
    config = load_config(CORE_CONFIG)
    services, _engine = _services(config)

    first = _run(["status", "--json"], services)
    second = _run(["status", "--json"], services)

    assert first == second
    assert first[0] == 0
    payload = json.loads(first[1])
    assert payload == {
        "checkpoints": [],
        "error": "SafeError: password=[REDACTED]",
        "origin": "installer-v1",
        "plan_digest": "a" * 64,
        "schema": 1,
        "status": "active",
    }
    assert "must-not-be-rendered" not in first[1]
    assert "hunter2" not in first[1]


def test_explicit_lifecycle_commands_share_the_transaction_engine():
    config = load_config(CORE_CONFIG)
    services, engine = _services(config)

    assert _run(["resume"], services)[0] == 0
    assert _run(["repair"], services)[0] == 0
    assert _run(["uninstall"], services)[0] == 0
    assert _run(["uninstall", "--purge-data"], services)[0] == 0

    assert engine.calls == [
        ("resume",),
        ("repair",),
        ("uninstall", False),
        ("uninstall", True),
    ]


def test_wrappers_and_proxyctl_dispatch_to_the_unified_cli(monkeypatch):
    install = (ROOT / "install.sh").read_text()
    uninstall = (ROOT / "uninstall.sh").read_text()
    expected_path = 'PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"'
    assert expected_path in install
    assert expected_path in uninstall
    assert 'python3 -m installer.cli wizard' in install
    assert 'python3 -m installer.cli "$@"' in install
    assert 'python3 -m installer.cli uninstall "$@"' in uninstall

    from scripts import proxyctl

    calls: list[list[str] | None] = []
    monkeypatch.setattr(cli, "main", lambda argv=None: calls.append(argv) or 17)
    assert proxyctl.main(["status"]) == 17
    assert calls == [["status"]]
