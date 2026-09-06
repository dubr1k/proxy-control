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


def test_staging_hands_the_installer_a_private_copy_it_can_find(tmp_path: Path):
    """The adapters run far from the configuration path, so the CLI stages the
    credentials once at a fixed private location instead of threading a secret
    through every signature it would otherwise pass."""
    from installer.credentials import stage_credentials, staged_credentials

    config = tmp_path / "install.toml"
    root = tmp_path / "state"
    root.mkdir()
    given = OperatorCredentials(
        panel_username="owner",
        panel_password="a-long-enough-password",
    )
    write_credentials(config, given)

    staged = stage_credentials(root, config)

    assert stat.S_IMODE(os.stat(staged).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(staged.parent).st_mode) == 0o700
    assert staged_credentials(root) == given


def test_nothing_is_staged_when_the_operator_chose_generated_credentials(tmp_path: Path):
    from installer.credentials import stage_credentials, staged_credentials

    root = tmp_path / "state"
    root.mkdir()
    assert stage_credentials(root, tmp_path / "install.toml") is None
    assert staged_credentials(root) is None


def test_discarding_staged_credentials_leaves_nothing_behind(tmp_path: Path):
    """A password is needed while installing and never afterwards."""
    from installer.credentials import (
        discard_staged_credentials,
        stage_credentials,
        staged_credentials,
    )

    config = tmp_path / "install.toml"
    root = tmp_path / "state"
    root.mkdir()
    write_credentials(
        config,
        OperatorCredentials(panel_username="owner", panel_password="a-long-password"),
    )
    staged = stage_credentials(root, config)
    assert staged is not None

    discard_staged_credentials(root)

    assert not staged.exists()
    assert staged_credentials(root) is None
    discard_staged_credentials(root)  # discarding twice is not an error
