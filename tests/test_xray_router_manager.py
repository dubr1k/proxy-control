"""The Xray-router manager (v0.5): generations, the journal per service, the swap and its
failure modes, recovery after a crash, the watchdog — against a fake Xray runner."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from xray_router_manager.intent import EgressInvalid, EgressUnreachable, direct_document
from xray_router_manager.service import (
    ArtifactMismatch,
    ManagerConflict,
    ManualInterventionRequired,
    XrayError,
    XrayRouterManager,
)

WARP = "socks5://127.0.0.1:45000"
WARP_DOC = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}
BLOCK_DOC = {"schema": 1, "default": {"action": "direct", "egress": None},
             "rules": [{"domains": ["example.com"], "action": "block"}]}
SECRET_NAIVE = "naive-a1b2c3d4:" + "N" * 40
SECRET_MIERU = "mieru-e5f6a7b8:" + "M" * 40


class FakeRunner:
    """Records every call; `fail_test` refuses the next -test with the given text,
    `fail_ready` makes the next N starts never open their ports, `die` marks the
    current process dead."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.fail_test: str | None = None
        self.fail_ready = 0
        self.handles: list[dict] = []
        self.configs: list[dict] = []

    def version(self) -> str:
        return "Xray 26.3.27 (fake)"

    def test(self, config_path: Path) -> None:
        self.calls.append(("test", config_path.name))
        json.loads(config_path.read_text())
        if self.fail_test:
            message, self.fail_test = self.fail_test, None
            raise XrayError(message)

    def start(self, config_path: Path) -> object:
        self.calls.append(("start", config_path.name))
        handle = {"path": config_path, "alive": True, "config": json.loads(config_path.read_text())}
        self.handles.append(handle)
        self.configs.append(handle["config"])
        return handle

    def stop(self, handle) -> None:
        self.calls.append(("stop", handle["path"].name))
        handle["alive"] = False

    def alive(self, handle) -> bool:
        return handle["alive"]

    def wait_ready(self, ports, timeout) -> None:
        self.calls.append(("ready", tuple(ports)))
        if self.fail_ready:
            self.fail_ready -= 1
            self.handles[-1]["alive"] = False
            raise XrayError("the ingress ports did not open in time")

    @property
    def running(self) -> dict | None:
        alive = [handle for handle in self.handles if handle["alive"]]
        assert len(alive) <= 1, "two xray processes alive at once"
        return alive[0] if alive else None


def _artifact(tmp_path: Path, name: str, data: bytes) -> tuple[Path, str]:
    path = tmp_path / "bin" / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def manager(tmp_path: Path, runner: FakeRunner | None = None, *, warp: str | None = WARP, reachable: bool = True,
            bad_digest: bool = False) -> tuple[XrayRouterManager, FakeRunner]:
    runner = runner or FakeRunner()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    for name, secret in (("naive", SECRET_NAIVE), ("mieru", SECRET_MIERU)):
        if not (secrets_dir / name).exists():  # a second manager over the same files keeps them
            (secrets_dir / name).write_text(secret + "\n")
    artifacts = {"xray": _artifact(tmp_path, "xray", b"ELF"), "geoip": _artifact(tmp_path, "geoip.dat", b"ip"),
                 "geosite": _artifact(tmp_path, "geosite.dat", b"site")}
    if bad_digest:
        artifacts["geosite"] = (artifacts["geosite"][0], "0" * 64)
    instance = XrayRouterManager(
        state_dir=tmp_path / "state", runner=runner, warp_url=warp,
        ingress_files={"naive": secrets_dir / "naive", "mieru": secrets_dir / "mieru"}, artifacts=artifacts,
        ports={"naive": 45101, "mieru": 45102}, reachability=lambda url, timeout=3.0: reachable,
    )
    return instance, runner


def _state(instance: XrayRouterManager) -> dict:
    return json.loads((instance.state_dir / "state.json").read_text())


def test_bootstrap_verifies_artifacts_and_starts_generation_1_direct(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    assert runner.calls[:3] == [("test", "1.json"), ("start", "1.json"), ("ready", (45101, 45102))]
    status = instance.status()
    assert status["running"]["generation"] == 1 and status["phase"] == "idle"
    assert all(entry["verified"] for entry in status["artifacts"].values())
    assert status["xray_version"].startswith("Xray 26.3.27")
    assert status["services"]["naive"]["document"] == direct_document()
    assert (instance.state_dir / "generations" / "1.json").stat().st_mode & 0o777 == 0o600
    config = runner.running["config"]
    assert config["inbounds"][0]["settings"]["accounts"] == [{"user": "naive-a1b2c3d4", "pass": "N" * 40}]
    assert [item["tag"] for item in config["outbounds"]] == ["block", "direct"]


def test_bootstrap_artifact_mismatch_refuses_to_start(tmp_path):
    instance, runner = manager(tmp_path, bad_digest=True)
    with pytest.raises(ArtifactMismatch, match="geosite"):
        instance.bootstrap()
    assert runner.calls == [] and instance.status()["artifact_error"]
    assert instance.status()["artifacts"]["geosite"]["verified"] is False


def test_egress_plan_runs_test_without_mutation(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    before = sorted(path.name for path in (instance.state_dir / "generations").iterdir())
    revision = instance.egress("naive")["revision"]
    plan = instance.egress_plan("naive", revision, WARP_DOC)
    assert runner.calls[-1] == ("test", ".plan.json")
    assert sorted(path.name for path in (instance.state_dir / "generations").iterdir()) == before
    assert not (instance.state_dir / ".plan.json").exists()
    assert plan["revision"] == revision and plan["target_revision"] != revision
    assert plan["reachability"] == {"warp": True} and plan["restart_required"] is True
    assert any('"action": "egress"' in line for line in plan["diff"])
    assert instance.status()["running"]["generation"] == 1


def test_apply_renders_tests_swaps_and_commits(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    revision = instance.egress("naive")["revision"]
    result = instance.egress_apply("naive", revision, WARP_DOC, "routing:p1:1")
    assert runner.calls[-4:] == [("test", "2.json"), ("stop", "1.json"), ("start", "2.json"), ("ready", (45101, 45102))]
    assert result["generation"] == 2 and result["applied"] == WARP_DOC and result["replayed"] is False
    current = json.loads((instance.state_dir / "current.json").read_text())
    assert current["generation"] == 2 and result["readback_sha256"] == current["digest"]
    assert result["readback_sha256"] == hashlib.sha256((instance.state_dir / "generations" / "2.json").read_bytes()).hexdigest()
    view = instance.egress("naive")
    assert view["document"] == WARP_DOC and view["mode"] == "proxy" and view["revision"] == result["revision"]
    assert view["previous"]["revision"] == revision and view["current"]["operation_id"] == "routing:p1:1"
    assert [item["tag"] for item in runner.running["config"]["outbounds"]] == ["block", "direct", "warp"]
    assert _state(instance)["phase"] == "idle"


def test_apply_conflict_on_stale_revision(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_apply("naive", "0" * 64, WARP_DOC, "op-1")
    assert caught.value.code == "egress_conflict"
    assert instance.status()["running"]["generation"] == 1 and runner.calls[-1] == ("ready", (45101, 45102))


def test_apply_idempotent_by_operation_id(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    first = instance.egress_apply("naive", instance.egress("naive")["revision"], WARP_DOC, "op-same")
    calls = len(runner.calls)
    again = instance.egress_apply("naive", "stale-does-not-matter", WARP_DOC, "op-same")
    assert again["replayed"] is True and again["revision"] == first["revision"] and len(runner.calls) == calls
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_apply("naive", first["revision"], BLOCK_DOC, "op-same")
    assert caught.value.code == "operation_conflict"


def test_apply_unreachable_warp_refuses_without_changes(tmp_path):
    instance, runner = manager(tmp_path, reachable=False)
    instance.bootstrap()
    calls = len(runner.calls)
    with pytest.raises(EgressUnreachable):
        instance.egress_apply("naive", instance.egress("naive")["revision"], WARP_DOC, "op-1")
    assert len(runner.calls) == calls and instance.status()["running"]["generation"] == 1
    # A document that does not use warp still applies.
    instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-2")
    assert instance.status()["running"]["generation"] == 2


def test_apply_without_warp_provider_is_invalid(tmp_path):
    instance, _ = manager(tmp_path, warp=None)
    instance.bootstrap()
    with pytest.raises(EgressInvalid, match="warp"):
        instance.egress_apply("naive", instance.egress("naive")["revision"], WARP_DOC, "op-1")
    assert instance.status()["providers"] == {}


def test_apply_test_failure_reports_geosite_unknown_and_keeps_generation(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    runner.fail_test = "infra/conf: failed to load geosite: NOPE > infra/conf: code not found in geosite.dat: NOPE"
    with pytest.raises(EgressInvalid) as caught:
        instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-1")
    assert caught.value.code == "geosite_unknown"
    assert not (instance.state_dir / "generations" / "2.json").exists()
    assert instance.status()["running"]["generation"] == 1 and runner.running["path"].name == "1.json"
    runner.fail_test = "code not found in geoip.dat: ZZ"
    with pytest.raises(EgressInvalid) as caught:
        instance.egress_plan("naive", instance.egress("naive")["revision"], BLOCK_DOC)
    assert caught.value.code == "geoip_unknown"


def test_apply_ready_failure_restores_last_known_good(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    runner.fail_ready = 1
    with pytest.raises(XrayError, match="restored"):
        instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-1")
    assert runner.running["path"].name == "1.json"
    assert not (instance.state_dir / "generations" / "2.json").exists()
    assert instance.status()["running"]["generation"] == 1 and _state(instance)["phase"] == "idle"
    assert instance.egress("naive")["document"] == direct_document()


def test_apply_lkg_failure_is_manual_intervention_and_broken_phase(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    runner.fail_ready = 2
    with pytest.raises(ManualInterventionRequired, match="1.json"):
        instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-1")
    assert _state(instance)["phase"] == "broken" and instance.status()["running"] is None
    with pytest.raises(ManualInterventionRequired):
        instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-2")
    # The watchdog does not fight a broken router; a restart of the manager tries again.
    instance.watchdog_tick()
    assert instance.status()["running"] is None
    fresh, runner2 = manager(tmp_path, FakeRunner())
    fresh.bootstrap()
    assert fresh.status()["running"]["generation"] == 1 and _state(fresh)["phase"] == "idle"


def test_other_service_intent_survives_apply(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    instance.egress_apply("mieru", instance.egress("mieru")["revision"], WARP_DOC, "op-m")
    mieru_before = instance.egress("mieru")
    instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-n")
    mieru_after = instance.egress("mieru")
    assert mieru_after["document"] == WARP_DOC and mieru_after["previous"] == mieru_before["previous"]
    assert mieru_after["revision"] != mieru_before["revision"]  # a new generation, the same document
    rules = runner.running["config"]["routing"]["rules"]
    assert [r["outboundTag"] for r in rules if r["inboundTag"] == ["mieru"]][-1] == "warp"
    assert any(r.get("domain") == ["domain:example.com"] for r in rules if r["inboundTag"] == ["naive"])


def test_rollback_pops_journal_and_creates_new_generation(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    instance.egress_apply("naive", instance.egress("naive")["revision"], WARP_DOC, "op-1")
    instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-2")
    rolled = instance.egress_rollback("naive", instance.egress("naive")["revision"])
    assert rolled["applied"] == WARP_DOC and rolled["generation"] == 4
    view = instance.egress("naive")
    assert view["document"] == WARP_DOC and view["previous"]["revision"] is not None
    rolled = instance.egress_rollback("naive", view["revision"])
    assert rolled["applied"] == direct_document() and instance.egress("naive")["previous"] is None
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_rollback("naive", instance.egress("naive")["revision"])
    assert caught.value.code == "egress_no_previous"
    assert runner.running["path"].name == "5.json"


def test_rollback_conflict_on_stale_revision(tmp_path):
    instance, _ = manager(tmp_path)
    instance.bootstrap()
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_rollback("naive", "nope")
    assert caught.value.code == "egress_conflict"


def test_recover_after_crash_in_swapping_discards_candidate(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    # A crash after generation 2 was written and the phase recorded, before the commit.
    (instance.state_dir / "generations" / "2.json").write_text("{}")
    (instance.state_dir / "state.json").write_text(json.dumps({"phase": "swapping", "candidate": 2, "failures": 0}))
    fresh, runner2 = manager(tmp_path, FakeRunner())
    fresh.bootstrap()
    assert not (fresh.state_dir / "generations" / "2.json").exists()
    assert fresh.status()["running"]["generation"] == 1 and _state(fresh)["phase"] == "idle"
    assert runner2.calls[-2:] == [("start", "1.json"), ("ready", (45101, 45102))]


def test_watchdog_restarts_dead_process(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    runner.running["alive"] = False
    assert instance.status()["running"] is None
    instance.watchdog_tick()
    assert instance.status()["running"]["generation"] == 1 and runner.calls[-2][0] == "start"
    calls = len(runner.calls)
    instance.watchdog_tick()
    assert len(runner.calls) == calls  # alive: nothing to do
    runner.running["alive"] = False
    runner.fail_ready = 3
    for _ in range(3):
        instance.watchdog_tick()
    assert _state(instance)["phase"] == "broken"
    instance.watchdog_tick()
    assert instance.status()["running"] is None


def test_status_and_egress_views_have_no_credentials(tmp_path):
    instance, _ = manager(tmp_path)
    instance.bootstrap()
    instance.egress_apply("naive", instance.egress("naive")["revision"], WARP_DOC, "op-1")
    revision = instance.egress("naive")["revision"]
    texts = [json.dumps(instance.status()), json.dumps(instance.egress("naive")), json.dumps(instance.egress("mieru")),
             json.dumps(instance.egress_plan("naive", revision, BLOCK_DOC))]
    for text in texts:
        assert "N" * 40 not in text and "M" * 40 not in text and "naive-a1b2c3d4" not in text
    assert "N" * 40 not in (instance.state_dir / "journal.json").read_text()
    assert "N" * 40 not in (instance.state_dir / "current.json").read_text()
    assert "N" * 40 in (instance.state_dir / "generations" / "1.json").read_text()


def test_credential_files_reread_on_bootstrap(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-1")
    fresh, runner2 = manager(tmp_path, FakeRunner())
    (tmp_path / "secrets" / "naive").write_text("naive-a1b2c3d4:" + "R" * 40 + "\n")  # rotated before the restart
    fresh.bootstrap()
    assert fresh.status()["running"]["generation"] == 3
    assert runner2.running["config"]["inbounds"][0]["settings"]["accounts"][0]["pass"] == "R" * 40
    # The intents survive the re-render, the journal keeps its history.
    assert fresh.egress("naive")["document"]["rules"][0]["domains"] == ["example.com"]
    assert fresh.egress("naive")["previous"] is not None
    # Unchanged files: the same generation starts again, no new one.
    again, runner3 = manager(tmp_path, FakeRunner())
    again.bootstrap()
    assert again.status()["running"]["generation"] == 3 and runner3.calls[0] == ("start", "3.json")


def test_malformed_credential_is_manual_intervention(tmp_path):
    instance, _ = manager(tmp_path)
    (tmp_path / "secrets" / "naive").write_text("no colon here\n")
    with pytest.raises(ManualInterventionRequired, match="malformed"):
        instance.bootstrap()


def test_unknown_service_and_bad_operation_id_are_validation_errors(tmp_path):
    from xray_router_manager.service import ValidationError

    instance, _ = manager(tmp_path)
    instance.bootstrap()
    with pytest.raises(ValidationError):
        instance.egress("mtproxy")
    with pytest.raises(ValidationError):
        instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "bad id with spaces")
