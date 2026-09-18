"""Geodata of the router (v0.8): the .dat code parser, the download transaction, the manager's
swap-and-restart, automatic updates, the seed fallback, and the Unix-socket routes."""
from __future__ import annotations

import hashlib
import json
import threading

import httpx
import pytest

from tests.test_xray_router_manager import BLOCK_DOC, manager
from xray_router_manager.geodata import (
    LOYALSOLDIER_URLS,
    GeodataError,
    GeodataStore,
    Source,
    download_pair,
    parse_codes,
    parse_source,
)
from xray_router_manager.server import ManagerHTTPServer
from xray_router_manager.service import ManagerConflict


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, payload: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(payload)) + payload


def geodata_file(codes: list[str], *, extra_fields: bool = True) -> bytes:
    """A `GeoSiteList` with one entry per code; entries carry a second field (a domain or
    a CIDR) and a varint the parser has to skip, exactly as real files do."""
    entries = b""
    for code in codes:
        entry = _field(1, code.encode())
        if extra_fields:
            entry += _field(2, _field(2, b"example.com") + _varint((1 << 3) | 0) + _varint(2))
            entry += _varint((3 << 3) | 0) + _varint(1)
        entries += _field(1, entry)
    return entries


def test_parse_codes_reads_country_codes_and_skips_the_rest():
    data = geodata_file(["CN", "category-ads-all", "ru"])
    assert parse_codes(data) == ["category-ads-all", "cn", "ru"]
    with pytest.raises(GeodataError, match="no entries"):
        parse_codes(b"")
    with pytest.raises(GeodataError):
        parse_codes(b"\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")


def test_parse_source_and_interval_validate_the_operator_input():
    assert parse_source({"kind": "loyalsoldier"}).urls() == LOYALSOLDIER_URLS
    custom = parse_source({"kind": "custom", "geosite_url": "https://mirror.example/geosite.dat ",
                           "geoip_url": "https://mirror.example/geoip.dat"})
    assert custom.urls() == {"geosite": "https://mirror.example/geosite.dat", "geoip": "https://mirror.example/geoip.dat"}
    with pytest.raises(GeodataError, match="https"):
        parse_source({"kind": "custom", "geosite_url": "http://mirror.example/a", "geoip_url": "https://m/b"})
    with pytest.raises(GeodataError, match="kind"):
        parse_source({"kind": "github"})
    assert Source("xray").urls() is None


class Fetcher:
    """A publisher: files by URL, `.sha256sum` sidecars where told, a log of what was asked."""

    def __init__(self, files: dict[str, bytes], *, sidecars: bool = True, final: dict[str, str] | None = None):
        self.files, self.sidecars, self.final = files, sidecars, final or {}
        self.asked: list[str] = []

    def __call__(self, url: str, *, max_bytes: int = 64 * 1024 * 1024, **_kw) -> tuple[bytes, str]:
        self.asked.append(url)
        if url.endswith(".sha256sum"):
            base = url[:-len(".sha256sum")]
            if not self.sidecars or base not in self.files:
                raise GeodataError("404", "geodata_fetch_failed")
            return f"{hashlib.sha256(self.files[base]).hexdigest()}  file\n".encode(), url
        if url not in self.files:
            raise GeodataError("404", "geodata_fetch_failed")
        data = self.files[url]
        if len(data) > max_bytes:
            raise GeodataError("file larger than the limit", "geodata_too_large")
        return data, self.final.get(url, url)


def test_download_pair_checks_the_published_digest_and_reads_the_release_tag():
    site, ip = geodata_file(["cn"]), geodata_file(["ru"])
    urls = dict(LOYALSOLDIER_URLS)
    fetcher = Fetcher({urls["geosite"]: site, urls["geoip"]: ip},
                      final={urls["geosite"]: "https://objects.githubusercontent.com/releases/download/202609172350/geosite.dat"})
    result = download_pair(urls, fetcher)
    assert result["geosite"]["verified"] and result["geosite"]["codes"] == ["cn"] and result["geosite"]["version"] == "202609172350"
    assert result["geoip"]["sha256"] == hashlib.sha256(ip).hexdigest()
    # A mirror without sidecars is accepted; a sidecar that disagrees is not.
    assert download_pair(urls, Fetcher({urls["geosite"]: site, urls["geoip"]: ip}, sidecars=False))["geosite"]["verified"] is False

    class Lying(Fetcher):
        def __call__(self, url, **kw):
            if url.endswith(".sha256sum"):
                return b"0" * 64 + b"  file\n", url
            return super().__call__(url, **kw)

    with pytest.raises(GeodataError, match="published sha256"):
        download_pair(urls, Lying({urls["geosite"]: site, urls["geoip"]: ip}))
    with pytest.raises(GeodataError, match="geoip.dat"):
        download_pair(urls, Fetcher({urls["geosite"]: site, urls["geoip"]: b"garbage"}))


def test_bootstrap_seeds_the_geodata_directory_from_the_pinned_pair(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    directory = instance.state_dir / "geodata"
    assert (directory / "geosite.dat").read_bytes() == b"site" and (directory / "geoip.dat").read_bytes() == b"ip"
    view = instance.geodata_view()
    assert view["origin"] == "seed" and view["source"]["kind"] == "xray" and view["auto_update"] is False
    assert view["files"]["geosite"]["sha256"] == hashlib.sha256(b"site").hexdigest()
    assert instance.status()["geodata"]["origin"] == "seed"
    # The seed is not copied again over an operator's files.
    (directory / "geosite.dat").write_bytes(b"mine")
    instance.bootstrap()
    assert (directory / "geosite.dat").read_bytes() == b"mine"


def _loyal(tmp_path, codes=("cn", "category-ads-all")):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    site, ip = geodata_file(list(codes)), geodata_file(["cn", "ru"])
    fetcher = Fetcher({LOYALSOLDIER_URLS["geosite"]: site, LOYALSOLDIER_URLS["geoip"]: ip},
                      final={LOYALSOLDIER_URLS["geosite"]: "https://x/releases/download/v1/geosite.dat"})
    instance.geodata_settings({"source": {"kind": "loyalsoldier"}})
    return instance, runner, fetcher, site, ip


def test_update_tests_the_running_config_against_the_candidates_then_swaps_and_restarts(tmp_path):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    before = len(runner.calls)
    view = instance.geodata_update(fetcher)
    assert view["changed"] is True and view["origin"] == "download" and view["version"] == "v1"
    assert (instance.state_dir / "geodata" / "geosite.dat").read_bytes() == site
    assert view["files"]["geosite"]["codes"] == 2 and view["last_error"] is None
    # -test against the staged directory, then a stop and a fresh start of the same generation.
    tail = runner.calls[before:]
    assert tail[0][0] == "test" and tail[0][2] is not None and tail[1:] == [("stop", "1.json"), ("start", "1.json"), ("ready", (45101, 45102))]
    assert instance.geodata_codes()["codes"] == {"geosite": ["category-ads-all", "cn"], "geoip": ["cn", "ru"]}
    assert not list((instance.state_dir / "geodata").glob("*.tmp")) and not list((instance.state_dir / "geodata").glob("geodata-test.*"))
    # The same files again: nothing changes, no restart.
    calls = len(runner.calls)
    assert instance.geodata_update(fetcher)["changed"] is False and len(runner.calls) == calls


def test_update_refuses_lists_the_running_config_does_not_compile_against(tmp_path):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    runner.fail_test = "geosite: code not found in geosite.dat: cn"
    with pytest.raises(GeodataError, match="does not compile"):
        instance.geodata_update(fetcher)
    view = instance.geodata_view()
    assert view["origin"] == "seed" and "geodata_rejected" in view["last_error"]
    assert (instance.state_dir / "geodata" / "geosite.dat").read_bytes() == b"site"
    assert runner.running is not None and runner.running["path"].name == "1.json"


def test_update_failures_are_recorded_and_leave_the_files_alone(tmp_path):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    broken = Fetcher({LOYALSOLDIER_URLS["geosite"]: site})
    with pytest.raises(GeodataError, match="404"):
        instance.geodata_update(broken)
    view = instance.geodata_view()
    assert view["last_error"].startswith("geodata_fetch_failed") and view["origin"] == "seed"
    assert instance.geodata_update(fetcher)["changed"] is True


def test_automatic_updates_run_at_the_interval_from_the_watchdog(tmp_path, monkeypatch):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    clock = {"now": 1_000_000.0}
    instance.geodata.clock = type("Clock", (), {"time": staticmethod(lambda: clock["now"])})()
    monkeypatch.setattr(instance.geodata, "stage", lambda fetcher_=None: GeodataStore.stage(instance.geodata, fetcher))
    instance.geodata_settings({"auto_update": True, "interval_hours": 6})
    assert instance.geodata.due() is True
    instance.watchdog_tick()
    assert instance.geodata_view()["origin"] == "download"
    assert instance.geodata.due() is False
    clock["now"] += 6 * 3600 - 1
    assert instance.geodata.due() is False
    clock["now"] += 2
    assert instance.geodata.due() is True
    # The seed source never phones anywhere.
    instance.geodata_settings({"source": {"kind": "xray"}})
    assert instance.geodata.due() is False


def test_restore_returns_to_the_pinned_pair_and_turns_auto_update_off(tmp_path):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    instance.geodata_settings({"auto_update": True})
    instance.geodata_update(fetcher)
    view = instance.geodata_restore()
    assert view["origin"] == "seed" and view["source"]["kind"] == "xray" and view["auto_update"] is False
    assert (instance.state_dir / "geodata" / "geosite.dat").read_bytes() == b"site"


def test_settings_are_validated(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    with pytest.raises(GeodataError):
        instance.geodata_settings({"interval_hours": 0})
    with pytest.raises(GeodataError):
        instance.geodata_settings({"auto_update": "yes"})
    view = instance.geodata_settings({"source": {"kind": "custom", "geosite_url": "https://m.example/a.dat",
                                                 "geoip_url": "https://m.example/b.dat"}, "interval_hours": 12})
    assert view["source"]["geosite_url"] == "https://m.example/a.dat" and view["interval_hours"] == 12


def test_concurrent_updates_are_refused(tmp_path):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    assert instance._geodata_busy.acquire(blocking=False)
    try:
        with pytest.raises(ManagerConflict, match="already running"):
            instance.geodata_update(fetcher)
    finally:
        instance._geodata_busy.release()


TOKEN = "t" * 40


def test_unix_api_geodata_routes(tmp_path, monkeypatch):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    monkeypatch.setattr(instance.geodata, "stage", lambda fetcher_=None: GeodataStore.stage(instance.geodata, fetcher))
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, instance, TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {"X-Xray-Router-Token": TOKEN}
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(socket_path)), base_url="http://router") as client:
            assert client.get("/v1/geodata").status_code == 401
            view = client.get("/v1/geodata", headers=headers).json()
            assert view["source"]["kind"] == "loyalsoldier" and view["origin"] == "seed"
            bad = client.put("/v1/geodata/settings", json={"interval_hours": 0}, headers=headers)
            assert bad.status_code == 422 and bad.json()["code"] == "geodata_invalid"
            assert client.put("/v1/geodata/settings", json={"extra": 1}, headers=headers).status_code == 422
            ok = client.put("/v1/geodata/settings", json={"auto_update": True, "interval_hours": 12}, headers=headers)
            assert ok.status_code == 200 and ok.json()["auto_update"] is True
            updated = client.post("/v1/geodata/update", headers=headers)
            assert updated.status_code == 200 and updated.json()["changed"] is True
            codes = client.get("/v1/geodata/codes", headers=headers).json()["codes"]
            assert codes["geosite"] == ["category-ads-all", "cn"]
            restored = client.post("/v1/geodata/restore", headers=headers)
            assert restored.status_code == 200 and restored.json()["origin"] == "seed"
            status = client.get("/v1/status", headers=headers).json()
            assert status["geodata"]["source"]["kind"] == "xray" and "geodata" in status["capabilities"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_block_document_still_applies_after_an_update(tmp_path):
    instance, runner, fetcher, site, ip = _loyal(tmp_path)
    instance.geodata_update(fetcher)
    revision = instance.egress("naive")["revision"]
    result = instance.egress_apply("naive", revision, BLOCK_DOC, "op-1")
    assert result["applied"]["rules"][0]["action"] == "block"
    assert json.loads((instance.state_dir / "current.json").read_text())["generation"] == 2
