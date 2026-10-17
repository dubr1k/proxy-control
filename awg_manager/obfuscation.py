"""Per-version AmneziaWG obfuscation parameters: generation, validation, UAPI/client forms.

Values are dicts of STRINGS keyed with the client-config key names (Jc, Jmin, ..., H1..H4,
I1..I5, HeaderProtectionKey, ContentPaddingAddition). They are generated once at the first
bootstrap of a version, persisted, and never regenerated.
"""
from __future__ import annotations

import random
import re

from .keys import b64, hexkey, unb64

UINT32 = 2**32 - 1
MIN_HEADER_PROTECTION_PADDING = 12  # HeaderCipherNonceSize in amneziawg-go
_COMMON = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
_I_KEYS = ("I1", "I2", "I3", "I4", "I5")
_ALLOWED = {
    "1.5": set(_COMMON) | set(_I_KEYS),
    "2.0": set(_COMMON) | {"S3", "S4"} | set(_I_KEYS),
    "3.1": set(_COMMON)
    | {"S3", "S4", "HeaderProtectionKey", "ContentPaddingAddition", "RandomTrailers", "DisableCookies"}
    | set(_I_KEYS),
}
_REQUIRED = {
    "1.5": set(_COMMON),
    "2.0": set(_COMMON) | {"S3", "S4"},
    "3.1": set(_COMMON) | {"S3", "S4", "HeaderProtectionKey"},
}
_CPS = re.compile(r"(?:<(?:b 0x(?:[0-9a-fA-F]{2})+|r(?:c|d)? [0-9]{1,4}|t|c)>)+")
_RANGE = re.compile(r"([0-9]{1,10})(?:-([0-9]{1,10}))?")


class ObfuscationError(ValueError):
    """The parameters are invalid for the protocol version."""


def _int(params: dict, key: str, lo: int, hi: int) -> int:
    raw = params.get(key)
    if not isinstance(raw, str) or not raw.isdigit() or len(raw) > 10:
        raise ObfuscationError(f"{key} must be an integer string")
    value = int(raw)
    if not lo <= value <= hi:
        raise ObfuscationError(f"{key} must be {lo}-{hi}")
    return value


def parse_range(text: str, key: str) -> tuple[int, int]:
    match = _RANGE.fullmatch(text) if isinstance(text, str) else None
    if not match:
        raise ObfuscationError(f"{key} must be N or N-M")
    lo = int(match.group(1))
    hi = int(match.group(2)) if match.group(2) is not None else lo
    if lo > hi or hi > UINT32:
        raise ObfuscationError(f"{key} range is invalid")
    return lo, hi


def default_i1(rng: random.Random) -> str:
    """A QUIC-Initial-looking first packet: long header, v1, random DCID, timestamp, entropy."""
    first = 0xC0 | rng.randint(0, 3)
    dcid_len = rng.choice((8, 8, 8, 16, 18, 20))
    tail = rng.randint(32, 96)
    return f"<b 0x{first:02x}00000001{dcid_len:02x}><r {dcid_len}><b 0x0000><t><r {tail}>"


def generate(version: str, mtu: int, rng: random.Random | None = None) -> dict[str, str]:
    """Fresh random parameters valid for `version`. `rng` is injectable for tests."""
    if version not in _ALLOWED:
        raise ObfuscationError(f"unknown version {version}")
    rng = rng or random.SystemRandom()
    jmin = rng.randint(8, 24)
    jmax = min(jmin + rng.randint(40, 120), mtu)
    out: dict[str, str] = {"Jc": str(rng.randint(4, 8)), "Jmin": str(jmin), "Jmax": str(jmax)}
    if version == "3.1":
        s = [rng.randint(MIN_HEADER_PROTECTION_PADDING, 64) for _ in range(4)]
        while s[0] + 56 == s[1]:
            s[1] = rng.randint(MIN_HEADER_PROTECTION_PADDING, 64)
    else:
        s = [rng.randint(15, 150), rng.randint(15, 150), rng.randint(8, 64), rng.randint(8, 64)]
        while s[0] + 56 == s[1]:
            s[1] = rng.randint(15, 150)
    out["S1"], out["S2"] = str(s[0]), str(s[1])
    if version != "1.5":
        out["S3"], out["S4"] = str(s[2]), str(s[3])
    if version == "1.5":
        heads: set[int] = set()
        while len(heads) < 4:
            heads.add(rng.randint(5, UINT32))
        values = [str(h) for h in rng.sample(sorted(heads), 4)]
    elif version == "2.0":
        # Four non-overlapping ranges: cut [5, UINT32] into equal quarters, pick one per slot.
        span = (UINT32 - 5) // 4
        values = []
        for slot in range(4):
            base = 5 + slot * span
            lo = base + rng.randint(0, span // 2 - 1000)
            hi = lo + rng.randint(1000, span // 2 - 1)
            values.append(f"{lo}-{hi}")
        rng.shuffle(values)
    else:
        values = ["1", "2", "3", "4"]
    out.update({f"H{i + 1}": v for i, v in enumerate(values)})
    out["I1"] = default_i1(rng)
    if version == "3.1":
        out["HeaderProtectionKey"] = b64(rng.randbytes(32))
        out["ContentPaddingAddition"] = "0-32"
    validate(version, out, mtu)
    return out


def validate(version: str, params: dict, mtu: int) -> dict[str, str]:
    """Validate (and normalise empty I2..I5 away); returns the cleaned dict."""
    if version not in _ALLOWED:
        raise ObfuscationError(f"unknown version {version}")
    if not isinstance(params, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in params.items()
    ):
        raise ObfuscationError("parameters must be a string map")
    clean = {k: v for k, v in params.items() if not (k in _I_KEYS and v == "")}
    extra = set(clean) - _ALLOWED[version]
    if extra:
        raise ObfuscationError(f"{sorted(extra)[0]} is not valid for {version}")
    missing = _REQUIRED[version] - set(clean)
    if missing:
        raise ObfuscationError(f"{sorted(missing)[0]} is required for {version}")

    _int(clean, "Jc", 1, 128)
    jmin = _int(clean, "Jmin", 1, mtu)
    jmax = _int(clean, "Jmax", 1, mtu)
    if jmin >= jmax:
        raise ObfuscationError("Jmin must be below Jmax")
    s = {}
    for name in ("S1", "S2", "S3", "S4"):
        if name in clean:
            s[name] = _int(clean, name, 0, 1132)
    if s["S1"] + 56 == s["S2"]:
        raise ObfuscationError("S1 + 56 must differ from S2")

    heads = [parse_range(clean[f"H{i}"], f"H{i}") for i in range(1, 5)]
    floor = 1 if version == "3.1" else 5
    for i, (lo, hi) in enumerate(heads, 1):
        if lo < floor:
            raise ObfuscationError(f"H{i} must be at least {floor}")
        if version == "1.5" and lo != hi:
            raise ObfuscationError(f"H{i} must be a single value for 1.5")
    for i in range(4):
        for j in range(i + 1, 4):
            if heads[i][0] <= heads[j][1] and heads[j][0] <= heads[i][1]:
                raise ObfuscationError("H1..H4 must not overlap")

    for key in _I_KEYS:
        if key in clean and not _CPS.fullmatch(clean[key]):
            raise ObfuscationError(f"{key} is not a valid CPS string")

    if version == "3.1":
        for name in ("S1", "S2", "S3", "S4"):
            if s[name] < MIN_HEADER_PROTECTION_PADDING:
                raise ObfuscationError(f"{name} must be at least 12 with header protection")
        try:
            unb64(clean["HeaderProtectionKey"])
        except ValueError as exc:
            raise ObfuscationError("HeaderProtectionKey must be a base64 32-byte key") from exc
        if "ContentPaddingAddition" in clean:
            parse_range(clean["ContentPaddingAddition"], "ContentPaddingAddition")
        for flag in ("RandomTrailers", "DisableCookies"):
            if clean.get(flag, "false") not in {"true", "false"}:
                raise ObfuscationError(f"{flag} must be true or false")
    return clean


def client_view(params: dict[str, str]) -> dict[str, str]:
    """What the panel gets: client key names, strings only, nothing disabled."""
    return {
        k: v
        for k, v in params.items()
        if not (k in ("RandomTrailers", "DisableCookies") and v != "true")
    }


def uapi_lines(params: dict[str, str]) -> list[str]:
    """Device-level obfuscation lines in the order amneziawg-go's parser takes them.

    S1..S4, H1..H4 and the header-protection key are collected by the parser and applied
    together when the transaction ends, so they can sit anywhere inside one `set=1` block.
    """
    lines: list[str] = []
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
        if key in params:
            lines.append(f"{key.lower()}={params[key]}")
    for key in _I_KEYS:
        if params.get(key):
            lines.append(f"{key.lower()}={params[key]}")
    if "HeaderProtectionKey" in params:
        lines.append(f"header_protection_key={hexkey(params['HeaderProtectionKey'])}")
    if "ContentPaddingAddition" in params:
        lines.append(f"content_padding_addition={params['ContentPaddingAddition']}")
    if params.get("RandomTrailers") == "true":
        lines.append("random_trailers=true")
    if params.get("DisableCookies") == "true":
        lines.append("disable_cookies=true")
    return lines


def load_overrides(raw: object) -> dict[str, dict[str, str]]:
    """Normalise the optional AWG_OBFUSCATION_FILE document ({"2.0": {"I1": "...", "Jc": 6}})."""
    if not isinstance(raw, dict):
        raise ObfuscationError("obfuscation file must be a JSON object")
    out: dict[str, dict[str, str]] = {}
    for version, values in raw.items():
        if version not in _ALLOWED or not isinstance(values, dict):
            raise ObfuscationError(f"obfuscation file: bad section {version!r}")
        out[version] = {}
        for key, value in values.items():
            if isinstance(value, bool):
                value = "true" if value else "false"
            if not isinstance(value, (str, int)):
                raise ObfuscationError(f"obfuscation file: bad value for {key}")
            out[version][str(key)] = str(value)
    return out


def apply_overrides(version: str, base: dict[str, str], overrides: dict[str, str], mtu: int) -> dict[str, str]:
    merged = {**base, **overrides}
    return validate(version, merged, mtu)
