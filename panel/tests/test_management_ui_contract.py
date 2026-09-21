"""Static contract of the versions screen (v0.11): the upstream check bar, the source label
on every candidate, the upstream risk note, the Xray-router card and the Caddy build state."""
from __future__ import annotations

from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
JS = (STATIC / "js/management.js").read_text()
CSS = (STATIC / "style.css").read_text()


def test_versions_screen_checks_upstream_and_labels_the_source():
    assert '"/api/versions/check"' in JS and "data-version-check" in JS
    for text in (
        "Проверить обновления",
        "Проверено ",
        "каталог",
        "upstream",
        "Версия из upstream: хэш из релиза подтверждает целостность скачивания, но проектом она не проверялась",
        "Xray-router / Xray-core",
        "Собираем…",
    ):
        assert text in JS, text
    assert "entry.version !== current" in JS
    # An upstream release without a published digest is shown but not installable; the
    # agent already hides `xray` on a host without the router, so the UI has no such branch.
    assert 'reason === "no_published_digest"' in JS
    assert 'reason === "router_not_installed"' not in JS
    # A mita newer than the Mieru manager supports is shown, not offered (found live).
    assert 'reason === "manager_unsupported"' in JS and "менеджер этой версии ещё не поддерживает" in JS


def test_versions_screen_hides_the_check_when_upstream_polling_is_off():
    assert "upstream_enabled === false" in JS
    assert "Проверка не удалась: " in JS
    assert "Агент обновлений недоступен" in JS


def test_versions_screen_has_styles_for_the_check_bar_and_the_risk_note():
    assert ".version-check{" in CSS and ".version-risk{" in CSS
    assert "@media(max-width:560px){.version-check{flex-direction:column" in CSS
