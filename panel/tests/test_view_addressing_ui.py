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















