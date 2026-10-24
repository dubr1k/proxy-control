"""Static contract of the versions screen (v0.11): the upstream check bar, the source label
on every candidate, the upstream risk note, the Xray-router card and the Caddy build state."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "static"
JS = (STATIC / "js/management.js").read_text()
CSS = (STATIC / "style.css").read_text()


def test_versions_screen_checks_upstream_and_labels_the_source():
    assert '"/api/versions/check"' in JS and "data-version-check" in JS
    for text in (
        "Проверить обновления",
        "Проверено ",
        "каталог",
        "с GitHub",
        "Версия с GitHub: хэш из релиза подтверждает целостность скачивания, но проектом она не проверялась",
        "Xray-router / Xray-core",
        "Собираем…",
    ):
        assert text in JS, text
    assert "entry.version !== current" in (STATIC / "js/common.js").read_text()
    # An upstream release without a published digest is shown but not installable; the
    # agent already hides `xray` on a host without the router, so the UI has no such branch.
    assert 'reason === "no_published_digest"' in JS
    assert 'reason === "router_not_installed"' not in JS
    # v1.0.1: the Mieru manager takes any mita, so there is no «not supported yet» branch.
    assert "manager_unsupported" not in JS


def test_versions_screen_hides_the_check_when_upstream_polling_is_off():
    assert "upstream_enabled === false" in JS
    assert "Проверка не удалась: " in JS
    assert "Агент обновлений недоступен" in JS


def test_versions_screen_updates_the_panel_itself_and_waits_for_it_to_come_back():
    """The panel card (v0.11): the confirm text names the rollback copy, the request does not
    navigate but polls `GET /api/versions` every 3 s for up to 10 min, ignoring the fetch
    errors of the restart, and reloads the page once the panel answers with the new version."""
    assert 'panel: "Proxy Control / панель"' in JS
    assert "Панель пересоберётся и перезапустится; страница перезагрузится сама, когда панель ответит новой версией. База данных и код сохраняются в rollback-копии." in JS
    for text in ("Перезапускаем…", "Обновление идёт…", "Панель обновлена до ", "— ещё не пересобраны", "Пересобрать менеджеры", "Пересборка менеджеров…", "Панель не ответила за 10 минут"):
        assert text in JS, text
    assert "const PANEL_POLL_MS = 3000;" in JS and "const PANEL_POLL_LIMIT_MS = 10 * 60 * 1000;" in JS
    assert 'components?.panel?.status === "updating"' in JS and 'panel.status !== "updating"' in JS
    assert "window.location.reload()" in JS and "await pollPanelUpdate(context, version)" in JS
    # While the panel restarts, a failed fetch is expected, not an error.
    assert "continue; // the panel is restarting" in JS
    # Another tab may have started it: the card is disabled and the poll begins at render.
    assert 'item.status === "updating"' in JS and "void pollPanelUpdate(context, null)" in JS
    assert "item.pending_rebuild" in JS
    # The rebuild button is owner-only and calls the panel route; the screen polls while it runs.
    assert 'context.state.me?.role === "owner"' in JS and "/api/versions/panel/rebuild-managers" in JS
    assert "item.rebuilding_managers === true" in JS and 'data-managers-rebuild="1"' in JS


def test_versions_screen_puts_the_panel_first_and_names_the_protocol_managers():
    """3.2 (owner): the panel's card comes first; AmneziaWG and TrustTunnel get their own cards,
    and their confirm text says the manager image is rebuilt and the tunnels drop for seconds."""
    assert 'const names = { panel: "Proxy Control / панель", telemt:' in JS
    assert ".sort(([a], [b]) => rank(a) - rank(b))" in JS
    for text in ('amneziawg: "AmneziaWG / amneziawg-go"', 'trusttunnel: "TrustTunnel / endpoint"',
                 "Образ менеджера AmneziaWG будет пересобран", "Образ менеджера TrustTunnel будет пересобран"):
        assert text in JS, text
    assert ".version-card .panel-head h2{overflow-wrap:anywhere}" in CSS


def test_versions_screen_has_styles_for_the_check_bar_and_the_risk_note():
    assert ".version-check{" in CSS and ".version-risk{" in CSS
    assert "@media(max-width:560px){.version-check{flex-direction:column" in CSS


def test_versions_screen_explains_sources_once_in_plain_words():
    for jargon in ("owner-ролью", "allowlist", "immutable digest", "host-agent; произвольные"):
        assert jargon not in JS, jargon
    assert JS.count("«Каталог» — версии") == 1  # the legend sits above the cards, not in each one
    # a digest-identified build shows the human version or «сборка sha256:…»; older releases are «откат»
    common = (STATIC / "js/common.js").read_text()
    assert "offeredVersions(item)" in JS
    assert "installedVersion(raw, available)" in common and "versionIsNewer(entry.version, installed.version)" in common
    common = (STATIC / "js/common.js").read_text()
    assert "сборка ${current}" in common and '" · откат"' in common


NODE = shutil.which("node")


def _run_common(script: str):
    tmp = Path(tempfile.mkdtemp())
    (tmp / "common.mjs").write_text((STATIC / "js/common.js").read_text())
    (tmp / "run.mjs").write_text('import * as c from "./common.mjs";\n' + script)
    done = subprocess.run([NODE, str(tmp / "run.mjs")], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_installed_version_and_ordering_behave():
    digest = "7c843f370ec5"
    out = _run_common(f"""
const available = [{{ version: "3.5.14", image: "ghcr.io/x/telemt@sha256:{digest}aa" }}, {{ version: "3.5.9" }}];
console.log(JSON.stringify({{
  hit: c.installedVersion("sha256:{digest}", available).label,
  miss: c.installedVersion("sha256:{'0' * 12}", available).label,
  plain: c.installedVersion("3.38.1", available).label,
  a: c.versionIsNewer("3.5.14", "3.5.9"), b: c.versionIsNewer("3.5.9", "3.5.14"),
  c: c.versionIsNewer("3.1.20260828", "3.1.20260814"), d: c.versionIsNewer("3.1.20260814", "3.1.20260828"),
  v: c.versionIsNewer("v3.38.1", "3.38.0"), v2: c.versionIsNewer("v3.38.1", "3.38.1"),
  pre: c.versionIsNewer("26.10.17-beta", "26.10.17"), rel: c.versionIsNewer("26.10.17", "26.10.17-beta"),
}}));""")
    assert out["hit"] == "3.5.14" and out["miss"] == f"сборка sha256:{'0' * 12}" and out["plain"] == "3.38.1"
    assert out["a"] is True and out["b"] is False and out["c"] is True and out["d"] is False
    assert out["v"] is True and out["v2"] is False
    assert out["pre"] is False and out["rel"] is True


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_the_update_request_carries_the_raw_current_not_the_label():
    out = _run_common("""
console.log(JSON.stringify([c.updateRequestBody("3.5.14", "sha256:7c843f370ec5"), c.updateRequestBody("1.0", "не определена")]));""")
    assert out[0] == {"version": "3.5.14", "expected_current": "sha256:7c843f370ec5"}
    assert out[1]["expected_current"] is None
    # the button keeps the raw value, the label is for display only, and the POST uses the helper
    assert 'data-current="${esc(raw)}" data-current-label="${esc(current)}"' in JS
    assert "JSON.stringify(updateRequestBody(version, raw))" in JS
