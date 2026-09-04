from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from installer.planner import Evidence
from installer.report import (
    AcceptanceReport,
    CredentialHandoff,
    ReportError,
    ReportWriter,
)


PANEL_PASSWORD = "operator-panel-password"
MANAGER_TOKEN = "0123456789abcdef0123456789abcdef"
CLIENT_UUID = "6f2c1d4e-6a2b-4c8f-9f0d-2a7b5c8e1d33"


def sensitive_values() -> set[str]:
    return {PANEL_PASSWORD, MANAGER_TOKEN, CLIENT_UUID}


def report_with_evidence() -> AcceptanceReport:
    return AcceptanceReport.from_evidence(
        profile="full",
        release_tag="v2.0.0",
        release_digest="a" * 64,
        evidence=(
            Evidence(
                action_id="core.runtime",
                success=True,
                observations=("Core acceptance passed",),
                details={
                    "healthy_services": 3,
                    "expected_services": 3,
                    "panel_login_ok": True,
                    "respq_verified": 2,
                    "respq_expected": 2,
                    # Outside the allowlist, and carrying a credential value:
                    # the public report must drop it entirely.
                    "operator_handoff": PANEL_PASSWORD,
                },
            ),
            Evidence(
                action_id="naive.runtime",
                success=True,
                observations=("Naive acceptance passed",),
                details={
                    "connect_bytes": 4096,
                    "recorded_bytes": 8192,
                    "certificate_sans": ["naive.example.com"],
                    "listener_owner": "nginx",
                    "response_status": 204,
                },
            ),
        ),
        operator_notes=("verify the cloud firewall allows UDP/443",),
    )


def handoff_with_secrets() -> CredentialHandoff:
    return CredentialHandoff(
        entries={
            "panel_owner_password": PANEL_PASSWORD,
            "naive_manager_token": MANAGER_TOKEN,
            "three_xui_client_id": CLIENT_UUID,
        }
    )


def public_report_values(root: Path) -> set[str]:
    document = json.loads((root / "report.json").read_text())
    values: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                values.add(str(key))
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        else:
            values.add(str(value))

    walk(document)
    return values


def test_public_report_and_credential_handoff_are_schema_disjoint(tmp_path):
    writer = ReportWriter(tmp_path)
    writer.write_public(report_with_evidence())
    writer.write_credentials(handoff_with_secrets())
    assert sensitive_values().isdisjoint(public_report_values(tmp_path))
    assert stat.S_IMODE((tmp_path / "credentials/handoff.json").stat().st_mode) == 0o600


def test_public_report_is_world_readable_and_the_handoff_directory_is_not(tmp_path):
    writer = ReportWriter(tmp_path)
    writer.write_public(report_with_evidence())
    writer.write_credentials(handoff_with_secrets())

    assert stat.S_IMODE((tmp_path / "report.json").stat().st_mode) == 0o644
    assert stat.S_IMODE((tmp_path / "credentials").stat().st_mode) == 0o700


def test_public_report_keeps_only_named_acceptance_facts(tmp_path):
    writer = ReportWriter(tmp_path)
    writer.write_public(report_with_evidence())

    document = json.loads((tmp_path / "report.json").read_text())
    core = next(
        item for item in document["actions"] if item["action_id"] == "core.runtime"
    )
    naive = next(
        item for item in document["actions"] if item["action_id"] == "naive.runtime"
    )
    assert core["facts"] == {
        "expected_services": 3,
        "healthy_services": 3,
        "panel_login_ok": True,
        "respq_expected": 2,
        "respq_verified": 2,
    }
    assert naive["facts"]["certificate_sans"] == ["naive.example.com"]
    assert naive["facts"]["response_status"] == 204
    assert document["release"] == {"digest": "a" * 64, "tag": "v2.0.0"}


def test_public_report_refuses_to_name_a_credential():
    report = AcceptanceReport(
        profile="core",
        release_tag="v2.0.0",
        release_digest="a" * 64,
        operator_notes=("the panel password is stored in the handoff",),
    )
    with pytest.raises(ReportError, match="must not describe a credential"):
        report.public_document()


def test_credential_handoff_requires_named_string_entries():
    with pytest.raises(ReportError, match="named strings"):
        CredentialHandoff(entries={"panel_owner_password": ""})


def test_reports_can_be_rewritten_in_place(tmp_path):
    writer = ReportWriter(tmp_path)
    writer.write_public(report_with_evidence())
    writer.write_credentials(handoff_with_secrets())

    writer.write_public(report_with_evidence())
    writer.write_credentials(CredentialHandoff(entries={"panel": "second"}))

    handoff = json.loads((tmp_path / "credentials/handoff.json").read_text())
    assert handoff["credentials"] == {"panel": "second"}
    assert stat.S_IMODE((tmp_path / "credentials/handoff.json").stat().st_mode) == 0o600
