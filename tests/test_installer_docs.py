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


@pytest.mark.parametrize("language", LANGUAGES)
def test_reference_documents_the_optional_amneziawg_addon(language):
    """The add-on is an optional section of any profile: every TOML key, the adapter and its
    owned paths, the firewall rules, the fixed ports, the no-new-domain rule and the update note."""
    text = reference(language)
    for needle in (
        "[amneziawg]", "versions", "ports", "mtu", "dns", "host", "`amneziawg`", "/var/lib/awg-manager",
        "secrets/awg-manager-token", ".env.amneziawg", "99-proxy-control-amneziawg.conf", "compose.amneziawg.yaml",
        "ufw route allow in on awg15|awg20|awg31", "/dev/net/tun", "10240", "32000", "machine-id", "10.66.15.0/24",
        "AMNEZIAWG.", "--purge-data",
    ):
        assert needle in text, needle
    assert "no domain of its own" in text or "своего домена" in text.lower()


@pytest.mark.parametrize("language", LANGUAGES)
def test_readmes_describe_the_amneziawg_addon_and_its_installer_pieces(language):
    text = readme(language)
    for needle in ("[amneziawg]", "/dev/net/tun", "awg_manager/Dockerfile", "amneziawg-go", "core-amneziawg.toml",
                   "/var/lib/awg-manager"):
        assert needle in text, needle
    assert re.search(r"\bv0\.\d", text) is None


def test_the_amneziawg_example_is_listed_with_the_other_examples():
    for language in LANGUAGES:
        assert "core-amneziawg.toml" in readme(language)
    assert (ROOT / "examples/installer/core-amneziawg.toml").is_file()


@pytest.mark.parametrize("language", LANGUAGES)
def test_reference_documents_the_optional_trusttunnel_addon(language):
    """The add-on is an optional section of any profile with a domain of its own: every TOML key, the
    adapter and its owned paths, the loopback ports, the no-firewall-rule statement and the update note."""
    text = reference(language)
    for needle in (
        "[trusttunnel]", "listen_port", "domains.trusttunnel", "`trusttunnel`", "/var/lib/trusttunnel-manager",
        "secrets/trusttunnel-manager-token", ".env.trusttunnel", "compose.trusttunnel.yaml", "trusttunnel_manager/",
        "127.0.0.1:1987", "127.0.0.1:45104", "4453", "scripts/enable-trusttunnel.sh", "TRUSTTUNNEL.", "--purge-data",
        "core-trusttunnel.toml",
    ):
        assert needle in text, needle
    assert "CDN" in text


@pytest.mark.parametrize("language", LANGUAGES)
def test_readmes_describe_the_trusttunnel_addon_and_its_installer_pieces(language):
    text = readme(language)
    for needle in ("[trusttunnel]", "trusttunnel_manager/Dockerfile", "trusttunnel_endpoint", "core-trusttunnel.toml",
                   "/var/lib/trusttunnel-manager", "TRUSTTUNNEL.", "scripts/enable-trusttunnel.sh", "domains.trusttunnel",
                   "`trusttunnel`"):
        assert needle in text, needle
    assert re.search(r"\bv0\.\d", text) is None


def test_the_trusttunnel_example_is_listed_and_loads():
    for language in LANGUAGES:
        assert "core-trusttunnel.toml" in readme(language)
    example = (ROOT / "examples/installer/core-trusttunnel.toml").read_text(encoding="utf-8")
    assert "[trusttunnel]" in example and "trusttunnel = " in example


@pytest.mark.parametrize("language", LANGUAGES)
def test_the_domain_count_names_trusttunnel_as_the_twelfth_name(language):
    """The complete set is now twelve names; the table lists the TrustTunnel one and says it is not proxied."""
    text = readme(language)
    assert "**12 разных доменов**" in text or "**12 different\ndomains**" in text
    assert "| `trusttunnel`" in text


def test_primary_install_path_verifies_release_assets_before_sudo():
    command_documents = (*INSTALL_GUIDES.values(), *READMES.values(), *REFERENCES.values())
    for path in command_documents:
        joined = path.read_text(encoding="utf-8")
        checksum = joined.index("sha256sum --check SHA256SUMS")
        extraction = re.search(
            r"tar -xOf (proxy-control-v[0-9][\w.-]*\.tar\.gz) proxy-control/install-bootstrap",
            joined,
        )
        assert extraction is not None, path
        extract_bootstrap = extraction.start()
        dispatch = joined.index("./install-bootstrap")
        assert checksum < extract_bootstrap < dispatch, path
        dispatch_line = joined[dispatch:].splitlines()[0]
        assert f"--archive {extraction[1]} " in dispatch_line, path
        # v1.0.3: the short path — the install script published beside the archive — is
        # checked against its own published checksum before it runs, never piped to a shell.
        script_checksum = joined.index("sha256sum --check install-release.sh.sha256")
        assert joined.index("releases/latest/download/install-release.sh.sha256") < script_checksum, path
        assert script_checksum < joined.index("bash install-release.sh"), path
        assert "curl |" not in joined, path
        assert "SHA256SUMS" in joined
        assert "sbom.spdx.json" in joined


def test_release_integrity_limit_is_stated_in_every_install_document():
    documents = (*INSTALL_GUIDES.values(), *READMES.values(), *REFERENCES.values())
    for path in documents:
        text = path.read_text(encoding="utf-8")
        assert "attestation" in text, path
        assert any(phrase in text for phrase in ("three payload", "три payload", "три файла")), path
        assert "checksum file itself" in text or "сам файл контрольных сумм" in text, path
        stale = (
            "the attestation is checked first",
            "сначала проверяется аттестация",
            "SHA256SUMS` and the attestation",
            "`SHA256SUMS` и\nаттестации",
            "integrity of all four",
            "целостность всех четырёх",
        )
        assert not any(claim in text for claim in stale), path


def test_install_guides_distinguish_fresh_and_coexist_nginx_requirements():
    for path in INSTALL_GUIDES.values():
        requirements = path.read_text(encoding="utf-8").split("## ", 2)[2]
        assert "coexist" in requirements, path
        assert "fresh" in requirements, path
        assert "Nginx" in requirements, path
        assert "443" in requirements, path


def test_readmes_document_the_actual_warp_wizard_branches():
    for path in READMES.values():
        text = path.read_text(encoding="utf-8")
        assert "managed-new" in text, path
        assert "none" in text and "existing" in text, path
        assert "NaiveProxy" in text and "Mieru" in text, path
        assert "non-empty" in text or "непустой" in text, path
        assert "127.0.0.1:40000" in text, path
        assert "manually with" not in text, path
        assert "задаётся вручную" not in text, path


def test_readmes_state_the_current_installer_contract():
    stale_claims = (
        "Ставить 3x-ui с нуля он пока не умеет",
        "cannot yet install 3x-ui from scratch",
        "Подписка 3x-ui наружу пока **не публикуется**",
        "The 3x-ui subscription is **not published** yet",
        "Если WARP-клиента там нет, отвечайте",
        "If no WARP client is listening there, answer no",
    )
    for path in READMES.values():
        text = path.read_text(encoding="utf-8")
        assert not any(claim in text for claim in stale_claims), path
        assert "managed-new" in text, path
        assert "127.0.0.1:40000" in text, path


def test_readmes_keep_separate_human_and_ai_agent_installation_sections():
    """A person installs through the wizard; an AI agent follows its own non-interactive
    section (TOML, plan digest confirmed by the owner). The history before 1.0.0 is gone."""
    sections = {
        "ru": ("## Установка человеком", "## Установка ИИ-агентом"),
        "en": ("## Installation by a human", "## Installation by an AI agent"),
    }
    for language, (human, agent) in sections.items():
        text = readme(language)
        assert text.index(human) < text.index(agent), language
        agent_section = text[text.index(agent):].split("\n## ", 1)[0]
        assert "--accept-plan" in agent_section, language
        assert "install-release.sh --no-wizard" in agent_section, language
        assert re.search(r"\bv0\.\d", text) is None, language


# ----------------------------------------------------------------------
# WARP: one SOCKS5 endpoint, and a per-protocol egress split
# ----------------------------------------------------------------------


@pytest.mark.parametrize("language", LANGUAGES)
def test_warp_is_documented_as_one_socks5_endpoint(language):
    for text in (reference(language), readme(language)):
        assert "SOCKS5" in text
        assert "127.0.0.1:40000" in text


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


def test_the_mtproto_probe_reports_why_it_failed_without_echoing_a_secret():
    """A bare "verification failed" cannot tell a broken proxy from a host that
    never reached Telegram, and that is the question an operator has to answer.
    TDLib echoes back what it was given, so anything shaped like a proxy secret
    is removed on the way out."""
    source = (ROOT / "probe/src/index.cjs").read_text(encoding="utf-8")

    assert "describe(error)" in source
    assert "[REDACTED]" in source
    assert "main().catch(() => fail(" not in source


@pytest.mark.parametrize("language", LANGUAGES)
def test_no_document_presents_the_well_known_amneziawg_ports_as_a_default(language):
    """The ports are random per server; 51820-51822 appear only as the ones NOT to use."""
    for text in (readme(language), reference(language)):
        assert "UDP 51820" not in text and "51820, 51821, 51822" not in text and "51820/51821/51822" not in text
    guide = (ROOT / ("AMNEZIAWG.en.md" if language == "en" else "AMNEZIAWG.ru.md")).read_text(encoding="utf-8")
    assert "· 51820 ·" not in guide and "--ports" in guide and "10240" in guide
    example = (ROOT / "examples/installer/core-amneziawg.toml").read_text(encoding="utf-8")
    assert "\nports = " not in example and '# ports = { "1.5"' in example


def test_the_router_requirement_names_trusttunnel_in_both_languages():
    """v1.6: a TrustTunnel-only node may install the Xray-router, so no document still says that
    NaiveProxy or Mieru alone feed it."""
    root = Path(__file__).resolve().parent.parent
    for name, phrase in (("docs/INSTALLER_REFERENCE.en.md", "or an enabled `[trusttunnel]`"),
                         ("docs/INSTALLER_REFERENCE.ru.md", "либо включённый `[trusttunnel]`"),
                         ("docs/UPGRADING.md", "or `[trusttunnel]` must be enabled"),
                         ("docs/UPGRADING.ru.md", "либо включённый `[trusttunnel]`")):
        assert phrase in (root / name).read_text(encoding="utf-8"), name
    script = (root / "scripts" / "install-release.sh").read_text(encoding="utf-8")
    assert "NaiveProxy or Mieru (and a node with TrustTunnel)" in script and "NaiveProxy или Mieru (и узлу с TrustTunnel)" in script


MONITORING_GUIDES = {"ru": ROOT / "MONITORING.ru.md", "en": ROOT / "MONITORING.en.md"}


@pytest.mark.parametrize("language", LANGUAGES)
def test_the_monitoring_guide_states_what_the_code_does(language):
    """v2.0: the numbers the guide promises are the constants of the code, not a copy that drifts."""
    from panel.metrics.model import RANGES, RETENTION
    from panel.metrics.sse import GLOBAL, MAX_AGE_SECONDS, PER_SESSION
    from version_agent.hostmetrics import TABLE
    from version_agent.metrics_ports import DEFAULT_NAIVE_PORT, OVERRIDE_FILE

    text = MONITORING_GUIDES[language].read_text(encoding="utf-8")
    assert f"inet {TABLE}" in text and f"nft delete table inet {TABLE}" in text
    assert str(OVERRIDE_FILE) in text and f"{DEFAULT_NAIVE_PORT}/tcp" in text
    for needle in ("/api/metrics/live", "/api/metrics/stream", "/api/metrics/history", "/api/metrics/summary",
                   "/api/fleet/v2/metrics", "metrics.v1", "PANEL_METRICS_ENABLED", "metric_rollups", "get_metrics_live",
                   "X-Accel-Buffering", "L3", "429"):
        assert needle in text, needle
    for name in RANGES:
        assert name in text, name
    assert f"{PER_SESSION}" in text and f"{GLOBAL}" in text and str(int(MAX_AGE_SECONDS // 60)) in text
    assert {60, 900, 3600} == set(RETENTION)
    assert str(RETENTION[3600] // 86400) in text and str(RETENTION[900] // 86400) in text
    assert re.search(r"\bv0\.\d", text) is None


@pytest.mark.parametrize("language", LANGUAGES)
def test_the_monitoring_guide_is_reachable_from_the_readme_and_the_index(language):
    guide = "MONITORING.ru.md" if language == "ru" else "MONITORING.en.md"
    assert guide in readme(language)
    index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
    assert f"../{guide}" in index
    assert guide in (ROOT / ("FLEET.ru.md" if language == "ru" else "FLEET.en.md")).read_text(encoding="utf-8")
    assert guide in (ROOT / ("PANEL.ru.md" if language == "ru" else "PANEL.en.md")).read_text(encoding="utf-8")


def test_the_release_note_for_2_0_names_the_installer_boundary():
    note = (ROOT / "docs/releases/v2.0.0.md").read_text(encoding="utf-8")
    assert "v2.0.0" in note and "v1.6.0" in note
    assert "Установщик в этом выпуске изменён одной правкой" in note and "The installer has one fix in this release" in note
    assert "MTU 1400" in note and "an MTU of 1400" in note
    assert "install-release.sh --update" in note
    assert "--update" in (ROOT / "docs/UPGRADING.md").read_text(encoding="utf-8")


def test_the_release_note_for_2_0_1_is_a_patch_and_says_the_installer_did_not_change():
    note = (ROOT / "docs/releases/v2.0.1.md").read_text(encoding="utf-8")
    assert "v2.0.1" in note and "v2.0.0" in note
    assert "Установщик в этом выпуске не менялся" in note and "The installer did not change in this release" in note
    assert "install-release.sh --update" in note and "releases/download/v2.0.1/install-release.sh.sha256" in note
    assert "releases/download/v2.0.0" not in note
    assert "(releases/v2.0.1.md)" in (ROOT / "docs/README.md").read_text(encoding="utf-8")


def test_the_release_note_for_2_1_0_is_additive_and_says_the_installer_did_not_change():
    note = (ROOT / "docs/releases/v2.1.0.md").read_text(encoding="utf-8")
    assert "v2.1.0" in note and "v2.0.1" in note
    assert "Установщик в этом выпуске не менялся" in note and "The installer did not change in this release" in note
    assert "install-release.sh --update" in note and "releases/download/v2.1.0/install-release.sh.sha256" in note
    assert "releases/download/v2.0.1" not in note and "не проверено нами" in note
    assert "(releases/v2.1.0.md)" in (ROOT / "docs/README.md").read_text(encoding="utf-8")
