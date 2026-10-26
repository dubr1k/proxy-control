"""Static contract of the «Маршрутизация» screen (spec §8.4): the endpoints it speaks,
the words it uses for the states and refusals, and the guard that data never reaches
the DOM unescaped."""

from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
ROUTING = (STATIC / "js/routing.js").read_text()





























def _interpolations(source: str) -> list[str]:
    """Every `${…}` of every template literal, nested ones included (brace-matched)."""
    found = []
    position = 0
    while (start := source.find("${", position)) != -1:
        depth, index = 0, start + 1
        while index < len(source):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        found.append(source[start + 2:index].strip())
        position = start + 2
    return found


# What may reach a template without `esc()`: literal-only ternaries, our own HTML-building
# helpers, URL-encoded path parts, counters and flags — never a bare API string.
_ALLOWED = (
    re.compile(r"^(esc|number|encodeURIComponent)\("),
    re.compile(r"^(cardActions|editor|previewPanel|nodeOptions|protocolTabs|targetCard|historyTable|routerLine|exitsLine|relayLine|laneTabs|explainPanel|exitSelect|geodataLine|codeOptions|whatChips|whereLabel|presetsLine|customExitsPanel|ruleRow|stepHead)\("),
    re.compile(r"^(policyPath|laneQuery)\("),  # URL builders: encoded path parts and a `?lane=` query
    re.compile(r"^(chips|tabs)\.join\(\"\"\)$"),  # our own escaped pieces
    re.compile(r"^[\w+\- ]+$"),  # a local composed of escaped pieces, or index arithmetic
    re.compile(r'^.+\?\s*("[^"]*"|\'[^\']*\'|`.*`)\s*:\s*("[^"]*"|\'[^\']*\'|`.*`|.+\?.+:.+)$', re.S),  # literal branches
    re.compile(r"^\w+\s*\|\|\s*('[^']*'|\"[^\"]*\")$"),  # a composed template, or a literal placeholder
    re.compile(r"^marker\[[01]\]$"),  # our own data-attribute values, into a selector
    re.compile(r"^reasonText\("),  # a bounded vocabulary, later passed through esc() by the caller
    re.compile(r"^item\.protocol$"),  # plain text for the node card, escaped there by facts()
)


















