"""Dev extractor coverage and the actual shipped JavaScript translation consumer."""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "panel/static"
spec = importlib.util.spec_from_file_location("i18n_strings", ROOT / "scripts/dev/i18n-strings.py")
assert spec is not None and spec.loader is not None
strings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(strings)
EN = json.loads((STATIC / "i18n/en.json").read_text())


def test_every_russian_ui_fragment_has_an_english_translation():
    missing = [item for item in strings.fragments() if item not in EN]
    assert missing == [], f"Untranslated fragments: {missing[:15]}"


def test_translations_are_english_and_not_empty():
    assert {key: value for key, value in EN.items() if re.search(r"[А-Яа-яЁё]", value) or not value.strip()} == {}


def test_the_extractor_sees_template_parts_but_not_markup():
    found = set(strings.fragments())
    assert {"Как это работает", "Ключ не сохранён", "Акцентный цвет"} <= found
    assert not any(re.search(r"[<>=${}]|\bclass\b", item) for item in found)


def test_real_translation_runtime_handles_composed_strings_and_preserves_typed_names(tmp_path):
    # Node 18 defaults repository .js files to CommonJS; load the shipped bytes as an
    # ES module in a private package, just as the browser loads them.
    modules = tmp_path / "js"
    modules.mkdir()
    (modules / "package.json").write_text('{"type":"module"}')
    for name in ("i18n.js", "common.js"):
        shutil.copyfile(STATIC / "js" / name, modules / name)
    result = subprocess.run(
        ["node", "--input-type=module", "-e", r'''
import assert from "node:assert/strict";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
const dictionary = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const stored = new Map();
globalThis.window = {localStorage: {getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value)}};
globalThis.Node = {TEXT_NODE: 3, ELEMENT_NODE: 1};
globalThis.NodeFilter = {SHOW_TEXT: 4, SHOW_ELEMENT: 1};
let callback;
globalThis.MutationObserver = class {constructor(cb) {callback = cb;} observe() {}};
const normal = {closest: () => null};
const typed = {closest: selector => selector === "[data-translate]" ? null : {}};
const marked = {closest: () => ({})};
const text = (value, parent = normal) => ({nodeType: 3, nodeValue: value, parentElement: parent});
const nodes = [text("Как это работает"), text("Клиент: demo · профиль «demo-monitor»"), text("Как это работает", typed), text("Этот сервер", marked)];
globalThis.document = {documentElement: {}, title: "Как это работает", body: {nodeType: 1, closest: () => null}, querySelector: () => null,
  createTreeWalker: () => {let index = 0; return {nextNode: () => nodes[index++]};}};
globalThis.fetch = async () => ({ok: true, json: async () => dictionary});
const runtime = await import(pathToFileURL(process.argv[2]));
assert.equal(runtime.currentLang(), "ru");
stored.set("proxy-control.lang", "unsupported");
assert.equal(runtime.currentLang(), "ru");
await runtime.applyLanguage("en");
assert.equal(document.documentElement.lang, "en");
assert.equal(document.title, dictionary["Как это работает"]);
assert.equal(nodes[0].nodeValue, dictionary["Как это работает"]);
assert.match(nodes[1].nodeValue, /profile «demo-monitor»/);
assert.equal(nodes[2].nodeValue, "Как это работает");
assert.equal(nodes[3].nodeValue, dictionary["Этот сервер"]);
for (const [source, expected] of [
 ["Последнее обновление клиентом: 05.10.2026 12:00. Интервал автообновления: 12 ч.", "Auto-refresh interval: 12"],
 ["Попадёт: подписки. Не попадёт: ссылка mierus://.", "Not included"],
 ["Клиент: demo · профиль «demo-monitor»", "profile «demo-monitor»"],
]) assert.ok(runtime.translate(source).includes(expected), runtime.translate(source));
assert.equal(runtime.translate("изменить"), "изменить");
const added = text("Как это работает");
callback([{type: "childList", addedNodes: [added]}]);
assert.equal(added.nodeValue, dictionary["Как это работает"]);
''', str(STATIC / "i18n/en.json"), str(modules / "i18n.js")],
        text=True, capture_output=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
