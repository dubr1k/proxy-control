from __future__ import annotations

import json
from urllib.error import HTTPError

import pytest

from version_agent.upstream import (
    ALLOWED_HOSTS,
    UpstreamError,
    check_all,
    check_component,
    compare_versions,
    fetch_https,
    parse_dgst,
    parse_sha256_txt,
)

XRAY_RELEASES = [
    {"tag_name": "v26.4.1", "prerelease": False, "draft": False, "published_at": "2026-04-01T00:00:00Z",
     "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip"},
                {"name": "Xray-linux-64.zip.dgst", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip.dgst"}]},
    # XTLS marks every release a pre-release: it must count. A draft never does.
    {"tag_name": "v26.5.3", "prerelease": True, "draft": False, "published_at": "2026-05-03T00:00:00Z",
     "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip"},
                {"name": "Xray-linux-64.zip.dgst", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip.dgst"}]},
    {"tag_name": "v26.6.0", "prerelease": True, "draft": True, "published_at": "2026-06-01T00:00:00Z", "assets": []},
]
MIERU_RELEASES = [
    {"tag_name": "v3.37.0", "prerelease": False, "draft": False, "published_at": "2026-03-01T00:00:00Z",
     "assets": [{"name": "mita_3.37.0_linux_amd64.tar.gz", "browser_download_url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz"},
                {"name": "mita_3.37.0_linux_amd64.tar.gz.sha256.txt", "browser_download_url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz.sha256.txt"}]},
]


def fetcher_from(table: dict[str, tuple[int, dict, bytes]]):
    seen: list[str] = []

    def fetch(url, headers=None, maximum=0):
        seen.append(url)
        if url not in table:
            raise UpstreamError(f"unexpected url {url}")
        return table[url]

    fetch.seen = seen
    return fetch


def test_parsers_read_the_published_digests():
    assert parse_dgst("MD5= x\nSHA1= y\nSHA2-256= " + "a" * 64 + "\nSHA2-512= z\n") == "a" * 64
    assert parse_dgst("SHA256= " + "A" * 64) == "a" * 64
    assert parse_sha256_txt("b" * 64 + "  mita_3.37.0_linux_amd64.tar.gz\n") == "b" * 64
    with pytest.raises(UpstreamError):
        parse_dgst("nothing here")
    with pytest.raises(UpstreamError):
        parse_sha256_txt("nothing here")


def test_compare_versions_orders_numerically_and_prereleases_lower():
    assert compare_versions("26.4.1", "26.3.27") > 0
    assert compare_versions("3.37.0", "3.37.0") == 0
    assert compare_versions("2.12.0-beta.1", "2.12.0") < 0
    assert compare_versions("3.4", "3.4.0") == 0
    assert compare_versions("3.10.0", "3.9.9") > 0


def test_xray_candidate_carries_the_dgst_hash_and_counts_xtls_prereleases_but_no_draft():
    fetch = fetcher_from({
        "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10": (200, {}, json.dumps(XRAY_RELEASES).encode()),
        "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip.dgst": (200, {}, b"SHA2-256= " + b"a" * 64 + b"\n"),
        "https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip.dgst": (200, {}, b"SHA2-256= " + b"b" * 64 + b"\n"),
    })
    result = check_component("xray", "26.3.27", fetcher=fetch, router_enabled=True)
    assert result["latest"] == "26.5.3" and result["installable"] is True and result["reason"] is None
    assert [c["version"] for c in result["candidates"]] == ["26.5.3", "26.4.1"]
    candidate = result["candidates"][1]
    assert candidate["sha256"] == "a" * 64 and candidate["source"] == "upstream"
    assert candidate["archive"] == {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}
    assert candidate["url"].endswith("/v26.4.1/Xray-linux-64.zip")
    assert candidate["tag"] == "v26.4.1" and candidate["published_at"] == "2026-04-01T00:00:00Z"


def test_mita_candidate_reads_sha256_txt_and_names_the_tar_member():
    fetch = fetcher_from({
        "https://api.github.com/repos/enfein/mieru/releases?per_page=10": (200, {}, json.dumps(MIERU_RELEASES).encode()),
        "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz.sha256.txt": (200, {}, b"b" * 64 + b"  mita_3.37.0_linux_amd64.tar.gz\n"),
    })
    result = check_component("mita", "3.36.0", fetcher=fetch, router_enabled=False)
    [candidate] = result["candidates"]
    assert candidate["archive"] == {"format": "tar.gz", "member": "mita"} and candidate["sha256"] == "b" * 64


def test_mita_newer_than_the_manager_supports_is_shown_but_not_offered():
    """The manager refuses a mita line it was not verified against; the agent must not
    hand it an update it would crash-loop on (found live on ams-test with 3.37 before the
    manager learnt it). The two patterns move together."""
    from mieru_manager.service import SUPPORTED_VERSION
    from version_agent.upstream import MITA_SUPPORTED
    for version in ("3.35.0", "3.36.2", "3.37.0", "3.38.0", "4.0.0"):
        assert bool(MITA_SUPPORTED.fullmatch(version)) == bool(SUPPORTED_VERSION.fullmatch(version)), version
    releases = [{**MIERU_RELEASES[0], "tag_name": "v3.38.0",
                 "assets": [{"name": "mita_3.38.0_linux_amd64.tar.gz", "browser_download_url": "https://github.com/enfein/mieru/releases/download/v3.38.0/mita_3.38.0_linux_amd64.tar.gz"},
                            {"name": "mita_3.38.0_linux_amd64.tar.gz.sha256.txt", "browser_download_url": "https://github.com/enfein/mieru/releases/download/v3.38.0/mita_3.38.0_linux_amd64.tar.gz.sha256.txt"}]}]
    fetch = fetcher_from({"https://api.github.com/repos/enfein/mieru/releases?per_page=10": (200, {}, json.dumps(releases).encode())})
    result = check_component("mita", "3.37.0", fetcher=fetch, router_enabled=False)
    assert result == {"latest": "3.38.0", "installable": False, "reason": "manager_unsupported", "candidates": []}
    assert fetch.seen == ["https://api.github.com/repos/enfein/mieru/releases?per_page=10"]  # the digest is never fetched


def test_release_without_a_digest_file_is_visible_but_not_installable():
    releases = [{**MIERU_RELEASES[0], "assets": MIERU_RELEASES[0]["assets"][:1]}]
    fetch = fetcher_from({"https://api.github.com/repos/enfein/mieru/releases?per_page=10": (200, {}, json.dumps(releases).encode())})
    result = check_component("mita", "3.36.0", fetcher=fetch, router_enabled=False)
    assert result == {"latest": "3.37.0", "installable": False, "reason": "no_published_digest", "candidates": []}


def test_asset_hosted_outside_the_repository_download_path_is_refused():
    releases = [{**MIERU_RELEASES[0], "assets": [
        {"name": "mita_3.37.0_linux_amd64.tar.gz", "browser_download_url": "https://github.com/evil/repo/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz"},
        MIERU_RELEASES[0]["assets"][1]]}]
    fetch = fetcher_from({"https://api.github.com/repos/enfein/mieru/releases?per_page=10": (200, {}, json.dumps(releases).encode())})
    with pytest.raises(UpstreamError, match="release download"):
        check_component("mita", "3.36.0", fetcher=fetch, router_enabled=False)


def test_telemt_candidate_is_the_registry_manifest_digest():
    fetch = fetcher_from({
        "https://ghcr.io/token?scope=repository:samnet-dev/mtproxymax-telemt:pull": (200, {}, b'{"token": "t"}'),
        # The registry tags `<version>-<short commit>`; a bare version tag is accepted too.
        "https://ghcr.io/v2/samnet-dev/mtproxymax-telemt/tags/list?n=100": (200, {}, b'{"tags": ["3.4.24", "3.4.25-51e58b5", "latest"]}'),
        "https://ghcr.io/v2/samnet-dev/mtproxymax-telemt/manifests/3.4.25-51e58b5": (200, {"Docker-Content-Digest": "sha256:" + "c" * 64}, b"{}"),
    })
    result = check_component("telemt", "3.4.24", fetcher=fetch, router_enabled=False)
    [candidate] = result["candidates"]
    assert candidate == {"version": "3.4.25", "kind": "image", "source": "upstream", "tag": "3.4.25-51e58b5",
                         "image": "ghcr.io/samnet-dev/mtproxymax-telemt@sha256:" + "c" * 64, "published_at": None}
    assert result["latest"] == "3.4.25" and result["installable"] is True


def test_naive_candidate_is_a_build_with_the_builder_digest_and_forwardproxy_commit():
    fetch = fetcher_from({
        "https://api.github.com/repos/caddyserver/caddy/releases?per_page=10": (200, {}, json.dumps([{"tag_name": "v2.12.0", "prerelease": False, "draft": False, "published_at": "2026-02-01T00:00:00Z", "assets": []}]).encode()),
        "https://api.github.com/repos/klzgrad/forwardproxy/commits/caddy2": (200, {}, json.dumps({"sha": "d" * 40}).encode()),
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/caddy:pull": (200, {}, b'{"token": "t"}'),
        "https://registry-1.docker.io/v2/library/caddy/manifests/2.12.0-builder": (200, {"Docker-Content-Digest": "sha256:" + "e" * 64}, b"{}"),
    })
    result = check_component("naive", "2.11.4", fetcher=fetch, router_enabled=False)
    [candidate] = result["candidates"]
    assert candidate["kind"] == "build" and candidate["build"] == {
        "caddy_version": "2.12.0", "builder_image": "caddy:2.12.0-builder@sha256:" + "e" * 64, "forwardproxy_commit": "d" * 40}
    assert candidate["source"] == "upstream" and candidate["version"] == "2.12.0"


def test_only_newer_than_current_are_candidates_and_xray_is_off_without_the_router():
    fetch = fetcher_from({"https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10": (200, {}, json.dumps(XRAY_RELEASES).encode())})
    assert check_component("xray", "26.5.3", fetcher=fetch, router_enabled=True)["candidates"] == []
    assert check_component("xray", "26.3.27", fetcher=fetch, router_enabled=False) == {
        "latest": None, "installable": False, "reason": "router_not_installed", "candidates": []}
    assert fetch.seen == ["https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10"]


def test_rate_limited_github_becomes_an_error_and_check_all_keeps_going():
    fetch = fetcher_from({
        "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10": (403, {}, b""),
        "https://api.github.com/repos/enfein/mieru/releases?per_page=10": (200, {}, json.dumps(MIERU_RELEASES).encode()),
        "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz.sha256.txt": (200, {}, b"b" * 64 + b"\n"),
    })
    result = check_all({"xray": "26.3.27", "mita": "3.36.0", "telemt": None, "naive": None}, fetcher=fetch, router_enabled=True)
    assert set(result) == {"telemt", "naive", "mita", "xray"}
    assert "403" in result["xray"]["last_error"] and result["xray"]["candidates"] == []
    assert result["mita"]["candidates"][0]["version"] == "3.37.0" and "last_error" not in result["mita"]
    assert "unexpected url" in result["telemt"]["last_error"]


def test_fetch_https_refuses_hosts_outside_the_allowlist():
    with pytest.raises(UpstreamError, match="host"):
        fetch_https("https://example.com/x", None, 10)
    with pytest.raises(UpstreamError, match="host"):
        fetch_https("http://api.github.com/x", None, 10)
    with pytest.raises(UpstreamError, match="host"):
        fetch_https("https://user:pw@api.github.com/x", None, 10)
    assert "api.github.com" in ALLOWED_HOSTS


def test_redirect_handler_refuses_a_hop_outside_the_allowlist():
    from version_agent.upstream import _AllowedRedirects

    handler = _AllowedRedirects(frozenset({"github.com"}))
    request = object()
    with pytest.raises(HTTPError):
        handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/asset")
    with pytest.raises(HTTPError):
        handler.redirect_request(request, None, 302, "Found", {}, "http://github.com/asset")
