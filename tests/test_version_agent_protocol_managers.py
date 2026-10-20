"""3.2 (owner: the Versions screen shows AmneziaWG and TrustTunnel and installs them): the upstream
probes, the catalog's validation of the two new build kinds, the shared version override and the
agent's rebuild of a manager image with its rollback — against fakes of GitHub and Docker."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from version_agent.catalog import CatalogError, entry_from_dict
from version_agent.service import RolledBackError, VersionAgent
from version_agent.upstream import UpstreamError, check_all, check_component

AWG_TAGS = [
    {"name": "v3.1.20260814", "commit": {"sha": "1b86b2ae0e49" + "0" * 28}},
    {"name": "v3.1.20260828", "commit": {"sha": "b5928efb6ca19f0153958460c3d141f04abc5c2e"}},
    {"name": "not-a-version", "commit": {"sha": "f" * 40}},
    {"name": "v3.1.20260812", "commit": {"sha": "short"}},
]
TT = "https://github.com/TrustTunnel/TrustTunnel/releases/download"


def _tt_release(tag, *, prerelease=False, digest: str | None = "sha256:" + "a" * 64, size=10_608_905):
    name = f"trusttunnel-{tag}-linux-x86_64.tar.gz"
    return {"tag_name": tag, "draft": False, "prerelease": prerelease, "published_at": "2026-09-01T11:56:46Z",
            "assets": [{"name": name, "browser_download_url": f"{TT}/{tag}/{name}", "digest": digest, "size": size},
                       {"name": f"trusttunnel-{tag}-linux-aarch64.tar.gz", "digest": "sha256:" + "b" * 64}]}


def _fetcher(table):
    def fetch(url, headers=None, maximum=0):
        if url not in table:
            raise UpstreamError(f"unexpected url {url}")
        return table[url]
    return fetch


AWG_URL = "https://api.github.com/repos/amnezia-vpn/amneziawg-go/tags?per_page=30"
TT_URL = "https://api.github.com/repos/TrustTunnel/TrustTunnel/releases?per_page=10"


def test_amneziawg_offers_tags_with_their_commits_newest_first_and_keeps_the_installed_one():
    """The installed tag stays a candidate: after a step back the operator returns to it at once."""
    fetch = _fetcher({AWG_URL: (200, {}, json.dumps(AWG_TAGS).encode())})
    probe = check_component("amneziawg", "3.1.20260814", fetcher=fetch, router_enabled=False)
    assert probe["latest"] == "3.1.20260828" and probe["installable"] is True
    candidate, installed = probe["candidates"]
    assert installed["version"] == "3.1.20260814" and installed["build"]["commit"].startswith("1b86b2ae0e49")
    assert candidate == {"version": "3.1.20260828", "tag": "v3.1.20260828", "kind": "build", "source": "upstream",
                         "build": {"commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e", "tag": "v3.1.20260828"},
                         "published_at": None}
    current = check_component("amneziawg", "3.1.20260828", fetcher=fetch, router_enabled=False)
    assert current["installable"] is False
    assert [c["version"] for c in current["candidates"]] == ["3.1.20260828", "3.1.20260814"]


def test_trusttunnel_offers_stable_releases_with_the_x86_64_digest_and_never_a_beta():
    releases = [_tt_release("v1.3.0-beta.2", prerelease=True), _tt_release("v1.2.0"),
                _tt_release("v1.1.0", digest="sha256:" + "9" * 64)]
    fetch = _fetcher({TT_URL: (200, {}, json.dumps(releases).encode())})
    probe = check_component("trusttunnel", "1.1.0", fetcher=fetch, router_enabled=False)
    assert probe["latest"] == "1.2.0" and probe["installable"] is True
    candidate, installed = probe["candidates"]
    assert installed["version"] == "1.1.0" and installed["sha256"] == "9" * 64
    assert candidate["version"] == "1.2.0" and candidate["sha256"] == "a" * 64 and candidate["kind"] == "build"
    assert candidate["url"] == f"{TT}/v1.2.0/trusttunnel-v1.2.0-linux-x86_64.tar.gz"


def test_a_trusttunnel_release_without_a_digest_is_visible_but_not_installable():
    fetch = _fetcher({TT_URL: (200, {}, json.dumps([_tt_release("v1.2.0", digest=None), _tt_release("v1.1.0")]).encode())})
    probe = check_component("trusttunnel", "1.1.0", fetcher=fetch, router_enabled=False)
    assert probe["installable"] is False and probe["reason"] == "no_published_digest"
    assert [c["version"] for c in probe["candidates"]] == ["1.1.0"]


def test_a_trusttunnel_asset_outside_its_repository_is_refused():
    bad = _tt_release("v1.2.0")
    bad["assets"][0]["browser_download_url"] = "https://github.com/someone/else/releases/download/v1.2.0/x.tar.gz"
    with pytest.raises(UpstreamError):
        check_component("trusttunnel", "1.1.0", fetcher=_fetcher({TT_URL: (200, {}, json.dumps([bad]).encode())}),
                        router_enabled=False)


def test_check_all_probes_the_protocol_managers_only_on_a_host_that_runs_them():
    fetch = _fetcher({})
    without = check_all({"telemt": None}, fetcher=fetch, router_enabled=False)
    assert "amneziawg" not in without and "trusttunnel" not in without
    with_awg = check_all({"telemt": None, "amneziawg": "3.1.20260828"}, fetcher=fetch, router_enabled=False)
    assert "unexpected url" in with_awg["amneziawg"]["last_error"] and "trusttunnel" not in with_awg


@pytest.mark.parametrize(("component", "raw"), [
    ("amneziawg", {"version": "3.1.20260828", "kind": "build", "build": {"commit": "g" * 40, "tag": "v3.1.20260828"}}),
    ("amneziawg", {"version": "3.1.20260828", "kind": "build", "build": {"commit": "a" * 40, "tag": "v3.1.20260814"}}),
    ("amneziawg", {"version": "master", "kind": "build", "build": {"commit": "a" * 40, "tag": "vmaster"}}),
    ("trusttunnel", {"version": "1.2.0", "kind": "build", "url": f"{TT}/v1.2.0/evil.tar.gz", "sha256": "a" * 64}),
    ("trusttunnel", {"version": "1.2.0", "kind": "build", "url": "https://example.com/trusttunnel-v1.2.0-linux-x86_64.tar.gz", "sha256": "a" * 64}),
    ("trusttunnel", {"version": "1.2.0", "kind": "build", "url": f"{TT}/v1.2.0/trusttunnel-v1.2.0-linux-x86_64.tar.gz", "sha256": "XYZ"}),
])
def test_the_catalog_refuses_a_malformed_manager_build(component, raw):
    with pytest.raises(CatalogError):
        entry_from_dict(component, raw)


def test_the_catalog_takes_a_well_formed_manager_build():
    awg = entry_from_dict("amneziawg", {"version": "3.1.20260828", "kind": "build", "source": "upstream",
                                        "build": {"commit": "b" * 40, "tag": "v3.1.20260828"}})
    tt = entry_from_dict("trusttunnel", {"version": "1.3.0-beta.2", "kind": "build", "source": "catalog",
                                         "url": f"{TT}/v1.3.0-beta.2/trusttunnel-v1.3.0-beta.2-linux-x86_64.tar.gz",
                                         "sha256": "c" * 64})
    assert awg.build == {"commit": "b" * 40, "tag": "v3.1.20260828"} and tt.sha256 == "c" * 64


class Host:
    """Docker for the agent: the manager containers report the version their image env carries."""

    def __init__(self, tmp_path: Path, *, fail_build=False, env_version=None):
        self.compose = tmp_path / "compose"
        self.compose.mkdir()
        (self.compose / "version-overrides").mkdir()
        self.commands: list[list[str]] = []
        self.fail_build = fail_build
        self.versions = {"proxy-control-awg-manager": "3.1.20260814", "proxy-control-trusttunnel-manager": "v1.1.0"}
        self.env_version = env_version
        self.original = dict(self.versions)

    def run(self, command, *, env=None, cwd=None, timeout=None):
        self.commands.append(list(command))
        if command[:3] == ["docker", "inspect", "--format"] and "com.docker.compose.project" in command[3]:
            return "proxy_panel_by_dubr1k"
        if command[:3] == ["docker", "inspect", "--format"] and "Config.Env" in command[3]:
            container = command[-1]
            key = "AWG_GO_VERSION" if "awg" in container else "TT_VERSION"
            return f"PATH=/usr/bin\n{key}={self.versions[container]}\n"
        if command[:3] == ["docker", "inspect", "--format"] and command[3] == "{{.Image}}":
            return "sha256:" + "d" * 64
        if command[:2] == ["docker", "ps"]:
            return "c1"
        if command[:3] == ["docker", "inspect", "--format"]:
            return "healthy"
        if command[:2] == ["docker", "compose"] and "--no-build" in command:
            self.versions = dict(self.original)  # the rollback image runs again
            return ""
        if command[:2] == ["docker", "compose"] and "--build" in command:
            if self.fail_build:
                raise RuntimeError("build failed")
            text = (self.compose / "version-overrides" / "compose.versions.yaml").read_text()
            if "AWG_GO_VERSION" in text and "awg-manager" in command:
                self.versions["proxy-control-awg-manager"] = self.env_version or text.split('AWG_GO_VERSION: "')[1].split('"')[0]
            if "TT_VERSION" in text and "trusttunnel-manager" in command:
                self.versions["proxy-control-trusttunnel-manager"] = text.split('TT_VERSION: "')[1].split('"')[0]
        return ""


def _agent(tmp_path, host, files=("compose.yaml", "compose.amneziawg.yaml", "compose.trusttunnel.yaml")):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {
        "amneziawg": [{"version": "3.1.20260828", "kind": "build", "build": {"commit": "b" * 40, "tag": "v3.1.20260828"}}],
        "trusttunnel": [{"version": "1.2.0", "kind": "build", "url": f"{TT}/v1.2.0/trusttunnel-v1.2.0-linux-x86_64.tar.gz",
                         "sha256": "a" * 64}],
    }}))
    return VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", compose_dir=host.compose,
                        compose_files=files, runner=host.run, sleep=lambda _s: None, manager_health_timeout=4)


def test_the_components_follow_the_installed_overlays_and_read_the_running_versions(tmp_path):
    host = Host(tmp_path)
    listed = _agent(tmp_path, host).list_versions()["components"]
    assert listed["amneziawg"]["current"] == "3.1.20260814" and listed["trusttunnel"]["current"] == "1.1.0"
    bare = _agent(tmp_path, host, files=("compose.yaml",)).list_versions()["components"]
    assert "amneziawg" not in bare and "trusttunnel" not in bare


def test_an_update_rebuilds_the_manager_with_build_args_and_keeps_the_other_overrides(tmp_path):
    host = Host(tmp_path)
    override = host.compose / "version-overrides" / "compose.versions.yaml"
    override.write_text("# Generated by proxy-control version-agent; do not edit manually.\n"
                        "services:\n  mtproxy:\n    image: proxy-control-telemt:3.5.14-abc\n")
    agent = _agent(tmp_path, host)
    assert agent.update("amneziawg", "3.1.20260828", expected_current="3.1.20260814")["changed"] is True
    assert agent.update("trusttunnel", "1.2.0", expected_current="1.1.0")["changed"] is True
    text = override.read_text()
    assert "  mtproxy:\n    image: proxy-control-telemt:3.5.14-abc\n" in text  # Telemt's pin kept
    assert f'  awg-manager:\n    build:\n      args:\n        AWG_GO_VERSION: "3.1.20260828"\n        AWG_GO_COMMIT: "{"b" * 40}"\n' in text
    assert f'  trusttunnel-manager:\n    build:\n      args:\n        TT_VERSION: "v1.2.0"\n        TT_SHA256_X86_64: "{"a" * 64}"\n' in text
    builds = [c for c in host.commands if c[:2] == ["docker", "compose"] and "--build" in c]
    assert [c[-1] for c in builds] == ["awg-manager", "trusttunnel-manager"]
    assert all("--project-name" in c and "proxy_panel_by_dubr1k" in c and str(override) in c for c in builds)
    tags = [c for c in host.commands if c[:2] == ["docker", "tag"]]
    assert tags[0][3].startswith("proxy_panel_by_dubr1k-awg-manager:rollback-")
    state = agent.list_versions()["components"]
    assert state["amneziawg"]["current"] == "3.1.20260828" and state["trusttunnel"]["current"] == "1.2.0"


def test_a_failed_build_restores_the_override_and_the_image_and_proves_the_old_version(tmp_path):
    host = Host(tmp_path, fail_build=True)
    override = host.compose / "version-overrides" / "compose.versions.yaml"
    override.write_text("# Generated by proxy-control version-agent; do not edit manually.\nservices:\n  mtproxy:\n    image: x\n")
    before = override.read_bytes()
    with pytest.raises(RolledBackError):
        _agent(tmp_path, host).update("amneziawg", "3.1.20260828", expected_current="3.1.20260814")
    assert override.read_bytes() == before
    restore = [c for c in host.commands if c[:2] == ["docker", "tag"] and c[-1] == "proxy_panel_by_dubr1k-awg-manager:latest"]
    assert restore and any("--no-build" in c for c in host.commands if c[:2] == ["docker", "compose"])


def test_a_rebuild_that_reports_another_version_is_rolled_back(tmp_path):
    host = Host(tmp_path, env_version="3.1.20260812")
    with pytest.raises(RolledBackError):
        _agent(tmp_path, host).update("amneziawg", "3.1.20260828", expected_current="3.1.20260814")
    assert not (host.compose / "version-overrides" / "compose.versions.yaml").exists()  # there was none before


def test_the_installer_adapters_rebuild_the_managers_with_the_agents_pins(tmp_path):
    """A repair rebuilds AWG and TrustTunnel with the version override, so the agent's pin holds."""
    from installer.adapters.amneziawg import AmneziaWgAdapter
    from installer.adapters.trusttunnel import TrustTunnelAdapter

    project = tmp_path / "opt" / "mtproxy-shared443"
    (project / "version-overrides").mkdir(parents=True)
    (project / ".env.trusttunnel").write_text("TT=1\n")
    for adapter_type in (AmneziaWgAdapter, TrustTunnelAdapter):
        assert "/opt/mtproxy-shared443/version-overrides/compose.versions.yaml" not in adapter_type(root=tmp_path)._compose_argv("up")
    (project / "version-overrides" / "compose.versions.yaml").write_text("services:\n")
    for adapter_type in (AmneziaWgAdapter, TrustTunnelAdapter):
        argv = adapter_type(root=tmp_path)._compose_argv("up")
        assert argv.index("/opt/mtproxy-shared443/version-overrides/compose.versions.yaml") > argv.index(
            "/opt/mtproxy-shared443/compose.trusttunnel.yaml"), adapter_type.__name__


def test_removing_a_manager_drops_only_its_block_from_the_override():
    from installer.compose_project import without_override_service

    text = ("# Generated by proxy-control version-agent; do not edit manually.\nservices:\n"
            "  mtproxy:\n    image: x\n"
            '  awg-manager:\n    build:\n      args:\n        AWG_GO_VERSION: "3.1.20260814"\n'
            '  trusttunnel-manager:\n    build:\n      args:\n        TT_VERSION: "v1.0.33"\n')
    assert without_override_service(text, "awg-manager") == (
        "# Generated by proxy-control version-agent; do not edit manually.\nservices:\n"
        "  mtproxy:\n    image: x\n"
        '  trusttunnel-manager:\n    build:\n      args:\n        TT_VERSION: "v1.0.33"\n')
    assert without_override_service(text, "absent") == text
