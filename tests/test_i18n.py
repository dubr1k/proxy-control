"""The English panel (v0.17, owner: «проверь, вся ли панель переведена на английский»).

The dictionary must cover every Russian fragment of the UI sources — a string added without a
translation fails here, not in front of an English-speaking operator — and translate into
English only.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "panel" / "static"
spec = importlib.util.spec_from_file_location("i18n_strings", ROOT / "scripts" / "dev" / "i18n-strings.py")
strings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(strings)
EN = json.loads((STATIC / "i18n" / "en.json").read_text(encoding="utf-8"))


def test_every_russian_ui_fragment_has_an_english_translation():
    missing = [item for item in strings.fragments() if item not in EN]
    assert missing == [], f"{len(missing)} untranslated (python3 scripts/dev/i18n-strings.py --missing): {missing[:15]}"


def test_translations_are_english_and_not_empty():
    cyrillic = {key: value for key, value in EN.items() if re.search(r"[А-Яа-яЁё]", value) or not value.strip()}
    assert cyrillic == {}, list(cyrillic.items())[:10]


def test_the_extractor_sees_template_parts_but_not_markup():
    found = set(strings.fragments())
    assert "Как это работает" in found and "Ключ не сохранён" in found and "Акцентный цвет" in found
    assert not any(re.search(r"[<>=${}]|\bclass\b", item) for item in found)


def test_the_runtime_switches_follows_renders_and_spares_typed_names():
    source = (STATIC / "js" / "i18n.js").read_text(encoding="utf-8")
    main = (STATIC / "js" / "main.js").read_text(encoding="utf-8")
    common = (STATIC / "js" / "common.js").read_text(encoding="utf-8")
    assert '"/static/i18n/en.json"' in source and "new MutationObserver" in source
    # whole words only: «из» must never bite into «изменить»
    assert "(?<![\\\\p{L}\\\\p{N}])" in source and '"gu"' in source
    for attribute in ("placeholder", "title", "aria-label", "alt"):
        assert f'"{attribute}"' in source
    assert ".client-identity b" in source and ".grant-account" in source and "[data-no-i18n]" in source
    assert "void applyLanguage();" in main and "bindLanguageSwitch(root);" in main
    assert 'document.documentElement.lang === "en" ? "en-GB" : "ru-RU"' in common
    for page in ("index.html", "login.html"):
        assert 'id="lang-button"' in (STATIC / page).read_text(encoding="utf-8"), page
