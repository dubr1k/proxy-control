"""Каждый раздел панели живёт по своему адресу.

До этого SPA держала все экраны на `/`: закладка вела на «Обзор», F5 уводил с текущего
экрана, кнопка «назад» закрывала панель целиком. Раздел адресуется хешем (`/#clients`) —
бекенд и Nginx при этом не меняются.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "static"


def main_js() -> str:
    return (STATIC / "js/main.js").read_text(encoding="utf-8")


def index_html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def test_navigation_writes_the_view_into_the_address():
    """Переход по меню меняет адрес, а не только заголовок: ссылку можно скопировать."""
    main = main_js()
    assert "history.pushState" in main
    assert re.search(r"#\$\{name\}|`#` \+ name|\"#\" \+ name", main), main


def test_boot_opens_the_view_the_address_names():
    """Открытый `/#routing` показывает «Маршрутизацию», а не «Обзор»."""
    main = main_js()
    assert "location.hash" in main
    assert "viewFromHash" in main


def test_back_and_forward_move_between_views():
    """Браузерная навигация — это `hashchange`/`popstate`, иначе «назад» закрывает панель."""
    assert re.search(r'addEventListener\("(hashchange|popstate)"', main_js())


def test_an_unknown_or_forbidden_view_falls_back_to_the_overview():
    """Чужой хеш из закладки (или раздел, закрытый ролью/выключенной фичей) не должен
    оставлять оператора на пустом экране."""
    main = main_js()
    assert "allowedView" in main
    assert '"dashboard"' in main


def test_every_menu_item_has_an_address():
    """Имена в адресе — те же `data-view`, что и в меню: никакого второго словаря."""
    views = set(re.findall(r'data-view="([a-z]+)"', index_html()))
    renderers = main_js().split("const RENDERERS = {", 1)[1].split("};", 1)[0]
    assert views
    assert views <= set(re.findall(r"^\s*([a-z]+):", renderers, re.M))
