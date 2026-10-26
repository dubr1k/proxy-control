"""Client-side AmneziaWG helpers for the lab scripts (the manager itself is Rust since 4.0).

WireGuard keys (X25519, RFC 7748), the UAPI form of a client's obfuscation parameters and one
request on an amneziawg-go control socket — what a lab client needs to talk to the manager's
servers. `python3 scripts/lab/awg_lab.py genkey|genpsk|pubkey` prints keys (`pubkey` reads the
private key from stdin); the manager's binary offers the same as `awg-manager keys …`.
"""
from __future__ import annotations

import base64
import binascii
import secrets
import socket
import sys

_P = 2**255 - 19
_A24 = 121665
_I_KEYS = ("I1", "I2", "I3", "I4", "I5")


def _clamp(scalar: bytes) -> int:
    b = bytearray(scalar)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    """RFC 7748 section 5 scalar multiplication (Montgomery ladder, Python ints)."""
    if len(scalar) != 32 or len(u) != 32:
        raise ValueError("x25519 operands must be 32 bytes")
    k = _clamp(scalar)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def generate_private() -> bytes:
    b = bytearray(secrets.token_bytes(32))
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def public_key(private: bytes) -> bytes:
    return x25519(private, (9).to_bytes(32, "little"))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    """Strict 32-byte base64 key; raises ValueError otherwise."""
    if not isinstance(text, str) or len(text) != 44:
        raise ValueError("key must be 44 base64 characters")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("key is not valid base64") from exc
    if len(raw) != 32 or b64(raw) != text:
        raise ValueError("key must decode to 32 bytes")
    return raw


def hexkey(text: str) -> str:
    """The UAPI form of a base64 key."""
    return unb64(text).hex()


def uapi_lines(params: dict[str, str]) -> list[str]:
    """Device-level obfuscation lines in the order amneziawg-go's parser takes them."""
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


def uapi_exchange(path: str, request: bytes, timeout: float = 5.0) -> str:
    """One request on an amneziawg-go control socket; the reply minus its `errno=0` trailer."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        sock.sendall(request)
        data = b""
        while not (data.endswith(b"\n\n") and b"errno=" in data):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    text = data.decode("utf-8", "replace")
    tail = text.rstrip("\n").rsplit("\n", 1)[-1]
    if tail != "errno=0":
        raise RuntimeError(f"control socket replied {tail or 'nothing'}")
    return text[: text.rindex("errno=")]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["genkey"]:
        print(b64(generate_private()))
    elif args == ["genpsk"]:
        print(b64(secrets.token_bytes(32)))
    elif args == ["pubkey"]:
        print(b64(public_key(unb64(sys.stdin.read().strip()))))
    else:
        print("usage: python3 scripts/lab/awg_lab.py genkey|genpsk|pubkey", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
