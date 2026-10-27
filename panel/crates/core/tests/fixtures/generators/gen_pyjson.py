"""Golden vectors for `panel_core::pyjson`: what Python's `json.dumps` (and pydantic's JSON) writes.

Run with external Python 3.13 and panel/requirements-dev.txt installed, on ams-test:

    .venv/bin/python -I panel/crates/core/tests/fixtures/generators/gen_pyjson.py "$OUT"

Floats and strings are scalars, recorded with the writers that differ for them; structures carry
their input as `json.dumps(value)` text and the output of every variant below.
"""
from __future__ import annotations

import json
import math
import random
import struct
import sys
from pathlib import Path

import pydantic_core

VARIANTS = {
    "default": {},
    "compact": {"separators": (",", ":")},
    "canonical": {"sort_keys": True, "separators": (",", ":")},
    "sorted": {"sort_keys": True},
    "compact_utf8": {"ensure_ascii": False, "separators": (",", ":")},
    "indent1_sorted": {"indent": 1, "sort_keys": True},
    "indent2_utf8": {"ensure_ascii": False, "indent": 2},
    "indent2_utf8_sorted": {"ensure_ascii": False, "sort_keys": True, "indent": 2},
    "indent0": {"indent": 0},
    "indent2_custom_separators": {"indent": 2, "separators": (", ", ": ")},
    "compact_no_nan": {"separators": (",", ":"), "allow_nan": False},
}

TRICKY_STRINGS = [
    "", "a", "plain ascii", '"quoted"', "back\\slash", "slash/", "\b\f\n\r\t", "\x00\x01\x1f",
    "\x7f", "\x80\x9f\xa0\xff", "é", "Ж Этот сервер", "日本語", "\u2028\u2029", "\ufeff", "\uffff",
    "🙂", "𝄞 clef", "\U0010ffff", "a\u0301", "mixed \x00 🙂 é \\ \"", "<script>&'",
    "\u0085\u00a0\u1680\u3000", "😀😁😂🤣", "\U0001f1f7\U0001f1fa",
]

FLOATS = [
    0.0, -0.0, 1.0, -1.0, 0.1, 0.2, 0.30000000000000004, 1 / 3, 2 / 3, 1e-05, 0.0001, 0.001, 1e-07,
    1e16, 1e15, 9999999999999998.0, 1.5e16, 1e17, 1e21, 1e22, 1e23, 123456789.123, 1e308,
    1.7976931348623157e308, 5e-324, 2.2250738585072014e-308, 2.225073858507201e-308, 100.0,
    9007199254740993.0, 12345678901234567890.0, 0.5, 2.5, 1e-4, 1.0e-5, 4.35, 0.07, 1e100, 1.1e-100,
    12.5, 3.14159, 2.718281828459045, 6.02214076e23, 1.602176634e-19, 299792458.0, 0.000123,
    123e-20, 5e-310, 1.2345678901234567e-300,
]

INTS = [0, 1, -1, 42, 255, 256, 65535, 2**31 - 1, -(2**31), 2**32, 2**53, 2**53 + 1, 2**63 - 1, -(2**63),
        2**64 - 1, 1700000000, -1700000000]


def random_string(rng: random.Random) -> str:
    out = []
    for _ in range(rng.randint(0, 12)):
        pick = rng.random()
        if pick < 0.4:
            code = rng.randint(0x20, 0x7e)
        elif pick < 0.55:
            code = rng.randint(0, 0x1f)
        elif pick < 0.75:
            code = rng.randint(0x80, 0xffff)
        else:
            code = rng.randint(0x10000, 0x10ffff)
        if 0xd800 <= code <= 0xdfff:
            code = 0xfffd
        out.append(chr(code))
    return "".join(out)


def random_float(rng: random.Random) -> float:
    while True:
        pick = rng.random()
        if pick < 0.5:
            value = struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0]
        elif pick < 0.8:
            value = round(rng.uniform(-1e6, 1e6), rng.randint(0, 8))
        else:
            value = rng.uniform(-1, 1) * 10.0 ** rng.randint(-30, 30)
        if math.isfinite(value):
            return value


def tie_floats() -> list[float]:
    """Values exactly halfway between two shortest decimal candidates (x.5, x.25, … just below
    2**53): Python's dtoa breaks the tie to the even digit."""
    rng = random.Random(7)
    out = []
    for bits in range(44, 53):
        for fraction in (0.5, 0.25, 0.75, 0.125, 0.375):
            for _ in range(8):
                value = float(rng.randrange(2 ** bits, 2 ** (bits + 1))) + fraction
                out.append(value)
    out += [789296645419347.25, 1234567890123456.5, 0.5, 2.5, 9.5, 0.125, 0.375]
    return out


def random_value(rng: random.Random, depth: int = 0):
    pick = rng.random()
    if depth > 2 or pick < 0.45:
        scalar = rng.random()
        if scalar < 0.3:
            return random_string(rng)
        if scalar < 0.5:
            return random_float(rng)
        if scalar < 0.7:
            return rng.choice([rng.randint(-(2**63), 2**64 - 1), rng.randint(-1000, 1000)])
        return rng.choice([None, True, False])
    if pick < 0.7:
        return [random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys = [random_string(rng) or "k" for _ in range(rng.randint(0, 4))]
    return {key: random_value(rng, depth + 1) for key in keys}


def structures(rng: random.Random) -> list:
    values = [None, True, False, [], {}, [[]], [{}], {"a": []}, {"a": {}}, {"": ""}]
    values += INTS
    values += [{text: text} for text in TRICKY_STRINGS if text]
    values += [
        {"b": 1, "a": 2, "c": {"z": [1, 2.0, "3"], "y": None}},
        {"é": 1, "e": 2, "z": 3, "Z": 4, "🙂": 5, "\uffff": 6, "": 7, "10": 8, "9": 9},
        [1, [2, [3, [4, []]]], {"k": [{"x": {}}]}],
        {"detail": "Этот сервер", "code": "node_unreachable", "compiled": {"rules": [1.5, 1e-05]}},
        [0.1, 1e16, -0.0, 1e-07, 123456789012345680.0],
        {"nested": {"empty_list": [], "empty_obj": {}, "list": [[], {}], "s": "\u0000"}},
    ]
    values += [random_value(rng) for _ in range(150)]
    return values


def main(out: Path) -> None:
    rng = random.Random(20261025)
    floats = FLOATS + [-value for value in FLOATS if value] + [random_float(rng) for _ in range(1500)]
    floats += tie_floats()
    strings = TRICKY_STRINGS + [random_string(rng) for _ in range(400)]
    payload = {
        "python": sys.version,
        "variants": {name: {key: list(v) if isinstance(v, tuple) else v for key, v in options.items()}
                     for name, options in VARIANTS.items()},
        # [json.dumps(value) == repr(value), pydantic_core.to_json(value)]
        "floats": [[json.dumps(value), pydantic_core.to_json(value).decode()] for value in floats],
        # [value, json.dumps(value), json.dumps(value, ensure_ascii=False), pydantic_core.to_json(value)]
        "strings": [[text, json.dumps(text), json.dumps(text, ensure_ascii=False), pydantic_core.to_json(text).decode()]
                    for text in strings],
        # input: json.dumps(value) (parsed back by the Rust side into the same value and key order)
        "structures": [{"input": json.dumps(value),
                        "out": {name: json.dumps(value, **options) for name, options in VARIANTS.items()},
                        "pydantic": pydantic_core.to_json(value).decode()}
                       for value in structures(rng)],
    }
    (out / "pyjson.json").write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
