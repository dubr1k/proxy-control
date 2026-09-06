"""Operator-chosen credentials travel beside the configuration, never in it."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from installer.credentials import (
    CredentialError,
    OperatorCredentials,
    credentials_path,
    read_credentials,
    write_credentials,
)


def test_credentials_live_next_to_the_configuration_under_a_predictable_name():
    assert credentials_path(Path("/etc/pc/install.toml")) == Path(
        "/etc/pc/install.credentials"
    )


def test_a_written_file_is_private_and_reads_back_unchanged(tmp_path: Path):
    target = tmp_path / "install.toml"
    given = OperatorCredentials(
        panel_username="owner",
        panel_password="a-long-enough-password",
        three_xui_username="xui-owner",
        three_xui_password="another-long-password",
    )

    path = write_credentials(target, given)

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert read_credentials(target) == given


def test_absent_credentials_are_not_an_error(tmp_path: Path):
    """Everything stays generated when the operator chose nothing, which is the
    behaviour every existing installation already has."""
    assert read_credentials(tmp_path / "install.toml") is None


def test_a_group_or_world_readable_file_is_refused(tmp_path: Path):
    target = tmp_path / "install.toml"
    path = write_credentials(
        target,
        OperatorCredentials(panel_username="owner", panel_password="a-long-password"),
    )
    os.chmod(path, 0o640)

    with pytest.raises(CredentialError, match="readable"):
        read_credentials(target)


def test_an_unknown_key_is_refused_rather_than_ignored(tmp_path: Path):
    target = tmp_path / "install.toml"
    credentials_path(target).write_text('panel_password = "x"\nsurprise = "y"\n')
    os.chmod(credentials_path(target), 0o600)

    with pytest.raises(CredentialError, match="unknown"):
        read_credentials(target)


@pytest.mark.parametrize("password", ["", "short", "         "])
def test_a_password_too_weak_to_be_meant_is_refused(tmp_path: Path, password: str):
    with pytest.raises(CredentialError):
        OperatorCredentials(panel_username="owner", panel_password=password)


def test_a_username_must_be_a_safe_name():
    with pytest.raises(CredentialError):
        OperatorCredentials(panel_username="owner; rm -rf /", panel_password="a-long-password")


def test_the_configuration_never_carries_a_credential(tmp_path: Path):
    """The plan, the digest, and every report are derived from the config, so a
    password in it would leak into all three."""
    target = tmp_path / "install.toml"
    target.write_text("schema = 1\n")
    write_credentials(
        target,
        OperatorCredentials(
            panel_username="owner",
            panel_password="a-long-enough-password",
        ),
    )
    assert "a-long-enough-password" not in target.read_text()
