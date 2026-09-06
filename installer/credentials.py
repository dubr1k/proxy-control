"""Credentials the operator chose, kept beside the configuration.

The configuration file is not a place for secrets: it is read to build the
plan, the plan is digested and shown, and reports are derived from the same
values, so a password in it would reach all three. Operator-chosen passwords
therefore travel in a private file next to the configuration, and the
installer reads them only while applying.

Choosing nothing stays valid. Every credential the operator does not supply
is generated during installation exactly as before.
"""
from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

_SAFE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
# Short enough to type, long enough that it was meant rather than mistyped.
_MINIMUM_PASSWORD = 12
_MAXIMUM_PASSWORD = 256
_FIELDS = (
    "panel_username",
    "panel_password",
    "three_xui_username",
    "three_xui_password",
)


class CredentialError(RuntimeError):
    """A supplied credential cannot be used safely."""


@dataclass(frozen=True)
class OperatorCredentials:
    """What the operator typed, or nothing where they chose a generated value."""

    panel_username: str | None = None
    panel_password: str | None = None
    three_xui_username: str | None = None
    three_xui_password: str | None = None

    def __post_init__(self) -> None:
        for field in ("panel_username", "three_xui_username"):
            value = getattr(self, field)
            if value is not None and _SAFE_NAME.fullmatch(value) is None:
                raise CredentialError(f"{field} must be a safe name")
        for field in ("panel_password", "three_xui_password"):
            value = getattr(self, field)
            if value is None:
                continue
            if len(value.strip()) < _MINIMUM_PASSWORD:
                raise CredentialError(
                    f"{field} must be at least {_MINIMUM_PASSWORD} characters"
                )
            if len(value) > _MAXIMUM_PASSWORD or "\n" in value or "\r" in value:
                raise CredentialError(f"{field} is not a usable password")

    def is_empty(self) -> bool:
        return all(getattr(self, field) is None for field in _FIELDS)


def credentials_path(config_path: Path) -> Path:
    """The private file that belongs to this configuration."""
    return Path(config_path).with_suffix(".credentials")


def write_credentials(config_path: Path, values: OperatorCredentials) -> Path:
    """Write the supplied credentials privately, replacing any earlier file."""
    path = credentials_path(config_path)
    lines = [
        "# Written by the Proxy Control wizard. Anyone who can read this file",
        "# can sign in to the panels it describes. Delete it once the",
        "# installation has finished.",
    ]
    for field in _FIELDS:
        value = getattr(values, field)
        if value is not None:
            lines.append(f"{field} = {_toml_string(value)}")
    body = "\n".join(lines) + "\n"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, body.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    return path


def read_credentials(config_path: Path) -> OperatorCredentials | None:
    """Read the operator's credentials, or None when they chose none."""
    path = credentials_path(config_path)
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CredentialError("the credentials file cannot be read") from exc
    if not stat.S_ISREG(info.st_mode):
        raise CredentialError("the credentials file is not a regular file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise CredentialError(
            "the credentials file is readable beyond its owner; run chmod 600 on it"
        )
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise CredentialError("the credentials file is not valid TOML") from exc
    unknown = sorted(set(document) - set(_FIELDS))
    if unknown:
        raise CredentialError(f"unknown credential key: {unknown[0]}")
    values: dict[str, str] = {}
    for field in _FIELDS:
        if field not in document:
            continue
        value = document[field]
        if not isinstance(value, str):
            raise CredentialError(f"{field} must be a string")
        values[field] = value
    return OperatorCredentials(**values)


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# Adapters run far from the configuration path, so the CLI stages the operator's
# credentials once at this fixed private location rather than threading a secret
# through every signature between the two.
_STAGED_ANCHOR = "operator.toml"


def _anchor(root: Path) -> Path:
    """The staging location, inside the installer's own private directory."""
    from installer.transaction import INSTALLER_PATH, _root_path

    return _root_path(Path(root), INSTALLER_PATH) / _STAGED_ANCHOR


def staged_path(root: Path) -> Path:
    """The private file the adapters read while an installation is running."""
    return credentials_path(_anchor(root))


def stage_credentials(root: Path, config_path: Path) -> Path | None:
    """Copy the operator's credentials where the adapters will look.

    Returns None when the operator chose generated credentials, in which case
    nothing is written and nothing is left behind.
    """
    values = read_credentials(config_path)
    if values is None or values.is_empty():
        return None
    anchor = _anchor(root)
    anchor.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(anchor.parent, 0o700)
    return write_credentials(anchor, values)


def staged_credentials(root: Path) -> OperatorCredentials | None:
    """Read what the CLI staged, or None when it staged nothing."""
    return read_credentials(_anchor(root))


def discard_staged_credentials(root: Path) -> None:
    """Remove the staged copy: a password is needed while installing, and
    never afterwards."""
    staged_path(root).unlink(missing_ok=True)
