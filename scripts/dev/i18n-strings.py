#!/usr/bin/env python3
"""The Russian strings of the panel UI — what `panel/static/i18n/en.json` must translate.

Every Cyrillic fragment of the UI sources: string literals and the static parts of template
literals (nested `${…}` scanned too) in `panel/static/js/*.js`, and the text and attribute values
of `index.html` and `login.html`. A literal is cut at interpolations, tags and quotes, then
whitespace-collapsed and trimmed of edge punctuation — exactly the pieces the runtime translator
(`panel/static/js/i18n.js`) meets whole in a text node or as a substring of one.

usage: i18n-strings.py [--missing]   list every fragment, or only those en.json lacks
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "panel" / "static"
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
# Tags, and the quotes of attribute values cut apart by an interpolation.
SPLIT = re.compile(r"<[^<>]*>|[<>\"]")
EDGE = " \t·,;:—–-()"


def _read_string(src: str, i: int, quote: str) -> tuple[str, int]:
    """A '…' or "…" literal starting at src[i] == quote; returns (body, index after it)."""
    j = i + 1
    out = []
    while j < len(src):
        ch = src[j]
        if ch == "\\" and j + 1 < len(src):
            out.append(src[j:j + 2])
            j += 2
            continue
        if ch == quote or ch == "\n":
            return "".join(out), j + 1
        out.append(ch)
        j += 1
    return "".join(out), j


def _skip_comment(src: str, i: int) -> int | None:
    if src.startswith("//", i):
        end = src.find("\n", i)
        return len(src) if end < 0 else end
    if src.startswith("/*", i):
        end = src.find("*/", i + 2)
        return len(src) if end < 0 else end + 2
    return None


def _read_template(src: str, i: int, pieces: list[str]) -> int:
    """A `…` literal at src[i]: static text goes to `pieces`, each ${…} is scanned as code."""
    j = i + 1
    static = []
    while j < len(src):
        ch = src[j]
        if ch == "\\" and j + 1 < len(src):
            static.append(src[j:j + 2])
            j += 2
            continue
        if ch == "`":
            pieces.append("".join(static))
            return j + 1
        if src.startswith("${", j):
            pieces.append("".join(static))
            static = []
            j = _scan_code(src, j + 2, pieces, until="}")
            continue
        static.append(ch)
        j += 1
    pieces.append("".join(static))
    return j


def _scan_code(src: str, i: int, pieces: list[str], until: str | None = None) -> int:
    """Walk code from src[i], collecting literal texts; stop after the brace that closes it."""
    depth = 0
    j = i
    while j < len(src):
        skipped = _skip_comment(src, j)
        if skipped is not None:
            j = skipped
            continue
        ch = src[j]
        if ch in "'\"":
            body, j = _read_string(src, j, ch)
            pieces.append(body)
            continue
        if ch == "`":
            j = _read_template(src, j, pieces)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            if until == "}" and depth == 0:
                return j + 1
            depth -= 1
        j += 1
    return j


def _clean(fragment: str) -> list[str]:
    fragment = fragment.replace("\\n", " ").replace('\\"', '"').replace("\\'", "'")
    out = []
    for part in SPLIT.split(fragment):
        part = re.sub(r"\s+", " ", part).strip(EDGE)
        if CYRILLIC.search(part) and not re.search(r"\b[\w-]+=$", part):
            out.append(part)
    return out


def fragments() -> list[str]:
    found: set[str] = set()
    for path in sorted((STATIC / "js").glob("*.js")):
        pieces: list[str] = []
        _scan_code(path.read_text(encoding="utf-8"), 0, pieces)
        for piece in pieces:
            found.update(_clean(piece))
    for name in ("index.html", "login.html"):
        html = (STATIC / name).read_text(encoding="utf-8")
        html = re.sub(r"<script.*?</script>|<style.*?</style>|<!--.*?-->", "", html, flags=re.S)
        for value in re.findall(r'="([^"]*)"', html):
            found.update(_clean(value))
        found.update(_clean(re.sub(r'="[^"]*"', "", html)))
    return sorted(found)


def main() -> int:
    items = fragments()
    if "--missing" in sys.argv:
        path = STATIC / "i18n" / "en.json"
        known = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        items = [item for item in items if item not in known]
    print(json.dumps(items, ensure_ascii=False, indent=0))
    print(f"# {len(items)} fragments", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
