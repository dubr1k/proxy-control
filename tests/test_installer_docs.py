"""Documentation contract for the interactive release installer.

Every command block marked `installer-check` is extracted and run through the
real argument parser and configuration loader in a no-mutation mode, so a
documented command cannot drift from the shipped CLI. The remaining tests hold
the guarantees the documentation is required to state.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

import pytest

from installer.cli import _parser
from installer.config import load_config


ROOT = Path(__file__).parents[1]
LANGUAGES = ("ru", "en")
REFERENCES = {
    "ru": ROOT / "docs/INSTALLER_REFERENCE.ru.md",
    "en": ROOT / "docs/INSTALLER_REFERENCE.en.md",
}
INSTALL_GUIDES = {
    "ru": ROOT / "INSTALL.ru.md",
    "en": ROOT / "INSTALL.en.md",
}
READMES = {
    "ru": ROOT / "README.md",
    "en": ROOT / "README.en.md",
}
PROFILES = ("core", "core-naive", "core-mieru", "full")
_BLOCK = re.compile(r"```[a-z]*\s+installer-check\n(.*?)```", re.DOTALL)


def tracked(pattern: str) -> list[Path]:
    """Files this repository actually ships, matching one pathspec.

    The documentation describes the release, so the inventory is taken from
    what is tracked: a virtual environment, a linked worktree holding another
    revision, or an operator's untracked scratch file is none of its business.
    """
    completed = subprocess.run(
        ("git", "-C", str(ROOT), "ls-files", "-z", pattern),
        capture_output=True,
        check=True,
    )
    return sorted(
        ROOT / name
        for name in completed.stdout.decode().split("\0")
        if name
    )


def reference(language: str) -> str:
    return REFERENCES[language].read_text(encoding="utf-8")


def install_text(language: str) -> str:
    return INSTALL_GUIDES[language].read_text(encoding="utf-8")


def readme(language: str) -> str:
    return READMES[language].read_text(encoding="utf-8")


def documented_files() -> tuple[Path, ...]:
    return (
        *REFERENCES.values(),
        *INSTALL_GUIDES.values(),
        *READMES.values(),
        ROOT / "MIERU.ru.md",
        ROOT / "MIERU.en.md",
        ROOT / "PANEL.ru.md",
        ROOT / "PANEL.en.md",
        ROOT / "docs/UPGRADING.md",
        ROOT / "docs/VALIDATION.md",
    )


def checked_commands() -> list[tuple[Path, str]]:
    commands: list[tuple[Path, str]] = []
    for path in documented_files():
        text = path.read_text(encoding="utf-8")
        for block in _BLOCK.findall(text):
            joined = block.replace("\\\n", " ")
            for line in joined.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                commands.append((path, stripped))
    return commands


def install_steps(language: str) -> list[str]:
    """The ordered command lines of the documented primary install path."""
    text = install_text(language)
    return [
        line.strip()
        for block in _BLOCK.findall(text)
        for line in block.replace("\\\n", " ").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# ----------------------------------------------------------------------
# every documented command matches the shipped CLI
# ----------------------------------------------------------------------


def test_documentation_declares_checked_command_blocks():
    commands = checked_commands()
    assert commands, "no installer-check command block is documented"


def test_every_checked_command_parses_against_the_shipped_cli():
    parser = _parser()
    for path, command in checked_commands():
        argv = shlex.split(command)
        while argv and argv[0] in {"sudo", "env"}:
            argv = argv[1:]
        if argv[:3] == ["python3", "-m", "installer.cli"]:
            arguments = argv[3:]
        elif argv[:1] == ["./install.sh"] or argv[:1] == ["install.sh"]:
            arguments = argv[1:]
        elif argv[:1] == ["./install-bootstrap"]:
            continue
        else:
            continue
        parsed = parser.parse_args(arguments)
        assert parsed.command, f"{path.name}: {command}"


def test_every_documented_configuration_file_exists_and_loads():
    seen = 0
    for path, command in checked_commands():
        argv = shlex.split(command)
        for index, token in enumerate(argv):
            if token != "--config":
                continue
            candidate = ROOT / argv[index + 1]
            assert candidate.is_file(), f"{path.name}: missing {candidate}"
            load_config(candidate)
            seen += 1
    assert seen, "no documented command loads a configuration file"


def test_no_documented_command_pipes_a_download_into_a_shell():
    for path in documented_files():
        text = path.read_text(encoding="utf-8")
        for forbidden in ("curl |", "curl -", "wget |"):
            if forbidden == "curl -":
                continue
            assert forbidden not in text, path.name
        assert "| sudo bash" not in text, path.name
        assert "| bash" not in text, path.name


# ----------------------------------------------------------------------
# the reference states what the installer actually does
# ----------------------------------------------------------------------


@pytest.mark.parametrize("language", LANGUAGES)
def test_every_profile_has_russian_english_example_and_acceptance_section(language):
    text = reference(language)
    for profile in PROFILES:
        assert f'profile = "{profile}"' in text, profile
    assert "VLESS Reality TCP" in text
    assert "VLESS Reality XHTTP" in text
    assert "Hysteria2" in text


@pytest.mark.parametrize("language", LANGUAGES)
def test_reference_documents_every_cli_subcommand(language):
    text = reference(language)
    for command in (
        "wizard",
        "plan",
        "install",
        "status",
        "resume",
        "repair",
        "report",
        "uninstall",
    ):
        assert f"`{command}`" in text, command


@pytest.mark.parametrize("language", LANGUAGES)
def test_reference_documents_every_configuration_field(language):
    text = reference(language)
    for field in (
        "schema",
        "host_mode",
        "profile",
        "acme_email",
        "initial_user",
        "domains",
        "mieru",
        "three_xui",
        "firewall",
        "tcp_ports",
        "udp_ports",
        "manage_ufw",
        "warp_domains",
    ):
        assert field in text, field


@pytest.mark.parametrize("language", LANGUAGES)
def test_reference_documents_the_adapter_order_and_ownership(language):
    text = reference(language)
    for adapter in (
        "packages",
        "nginx",
        "certificates",
        "firewall",
        "core",
        "naive",
        "mieru",
        "three_xui",
    ):
        assert adapter in text, adapter


@pytest.mark.parametrize("language", LANGUAGES)
def test_reference_documents_recovery_and_report_boundaries(language):
    text = reference(language)
    assert "report.json" in text
    assert "handoff.json" in text
    assert "0600" in text


def test_primary_install_path_verifies_attestation_before_sudo():
    for language in LANGUAGES:
        steps = install_steps(language)
        joined = "\n".join(steps)
        attestation = joined.index("gh attestation verify")
        dispatch = joined.index("./install-bootstrap")
        assert attestation < dispatch, language
        assert "curl |" not in install_text(language)


# ----------------------------------------------------------------------
# WARP: one SOCKS5 endpoint, and a per-protocol egress split
# ----------------------------------------------------------------------


@pytest.mark.parametrize("language", LANGUAGES)
def test_warp_is_documented_as_one_socks5_endpoint(language):
    for text in (reference(language), readme(language)):
        assert "SOCKS5" in text
        assert "127.0.0.1:45000" in text


@pytest.mark.parametrize("language", LANGUAGES)
def test_the_per_protocol_egress_split_is_stated(language):
    text = reference(language)
    section = text.split("WARP", 1)[1]
    for protocol in ("Xray", "NaiveProxy", "Mieru"):
        assert protocol in section, protocol
    assert "warp_domains" in section


# ----------------------------------------------------------------------
# the package inventory is complete
# ----------------------------------------------------------------------


def python_requirements() -> set[str]:
    names: set[str] = set()
    for path in tracked("**/requirements*.txt"):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            # `-r other.txt` includes another file this loop already reads,
            # and option lines name no package at all.
            if not stripped or stripped.startswith(("#", "-")):
                continue
            names.add(re.split(r"[=<>\[;]", stripped, maxsplit=1)[0].strip())
    return names


@pytest.mark.parametrize("language", LANGUAGES)
def test_readme_lists_every_python_dependency(language):
    text = readme(language)
    missing = sorted(name for name in python_requirements() if name not in text)
    assert not missing, missing


@pytest.mark.parametrize("language", LANGUAGES)
def test_readme_lists_every_pinned_external_artifact(language):
    import json

    text = readme(language)
    manifest = json.loads(
        (ROOT / "release/external-artifacts.json").read_text(encoding="utf-8")
    )
    for entry in manifest["artifacts"]:
        assert entry["name"].replace("_", "-") in text or entry["name"] in text
        assert entry["version"] in text, entry["name"]
        assert entry["spdx_license"] in text, entry["name"]


@pytest.mark.parametrize("language", LANGUAGES)
def test_readme_lists_every_container_base_image(language):
    text = readme(language)
    dockerfiles = tracked("**/Dockerfile*")
    assert dockerfiles
    for path in dockerfiles:
        relative = path.relative_to(ROOT).as_posix()
        assert relative in text, relative


@pytest.mark.parametrize("language", LANGUAGES)
def test_readme_lists_every_host_package_the_installer_requires(language):
    from installer.adapters.packages import DEFAULT_PACKAGES

    text = readme(language)
    missing = sorted(name for name in DEFAULT_PACKAGES if name not in text)
    assert not missing, missing


def test_every_documented_panel_health_check_sends_a_host_header():
    """The installer sets PANEL_ALLOWED_HOSTS to the panel domain alone, so a
    health check aimed at 127.0.0.1 without a Host header is rejected."""
    offenders = []
    for path in (*documented_files(), *INSTALL_GUIDES.values()):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "8787/healthz" in line and "Host:" not in line:
                offenders.append(f"{path.name}: {line.strip()}")
    assert not offenders, offenders


# ----------------------------------------------------------------------
# cross-document consistency
# ----------------------------------------------------------------------


def test_the_two_references_cover_the_same_sections():
    headings = {
        language: [
            line.strip()
            for line in reference(language).splitlines()
            if line.startswith("## ")
        ]
        for language in LANGUAGES
    }
    assert len(headings["ru"]) == len(headings["en"])
    assert len(headings["ru"]) >= 10


def test_the_documentation_index_links_both_references():
    index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
    assert "INSTALLER_REFERENCE.ru.md" in index
    assert "INSTALLER_REFERENCE.en.md" in index


def test_the_changelog_records_the_installer():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "installer" in changelog.lower()
    assert (ROOT / "VERSION").read_text().strip() in changelog
