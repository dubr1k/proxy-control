"""The TrustTunnel deep link: `tt://?` + base64url (no padding) of a TLV payload.

The format is the vendor's (TrustTunnel `DEEP_LINK.md`, version 2): every field is a tag, a
length and a value, tag and length as QUIC variable-length integers (RFC 9000 section 16). The
decoder reads up to version 2, ignores tags it does not know and rejects a higher version. The
encoder writes version 1: version 2 only adds `subscription_url`, which the panel never writes,
and the stable official client (TrustTunnelClient 1.1.11, the AdGuard apps' decoder) refuses a
version-2 link outright — «Unsupported deep link version: 2 (max supported: 1)». Only the fields the panel hands out are written (hostname, addresses,
username, password, certificate, upstream protocol, name, plus the optional flags); every field
of the specification is read back.
"""
from __future__ import annotations

import base64
import binascii

SCHEME = "tt://?"
VERSION = 2  # the highest version the decoder reads
WRITE_VERSION = 1  # what the encoder writes: every official client reads it
UPSTREAM_HTTP2, UPSTREAM_HTTP3 = 1, 2

TAG_VERSION, TAG_HOSTNAME, TAG_ADDRESSES, TAG_CUSTOM_SNI, TAG_HAS_IPV6 = 0x00, 0x01, 0x02, 0x03, 0x04
TAG_USERNAME, TAG_PASSWORD, TAG_SKIP_VERIFICATION, TAG_CERTIFICATE = 0x05, 0x06, 0x07, 0x08
TAG_UPSTREAM_PROTOCOL, TAG_ANTI_DPI, TAG_CLIENT_RANDOM_PREFIX, TAG_NAME = 0x09, 0x0A, 0x0B, 0x0C
TAG_DNS_UPSTREAMS, TAG_SUBSCRIPTION_URL, TAG_CLIENT_RANDOM_AUTH_KEY = 0x0D, 0x0E, 0x0F

MAX_LINK = 16384  # the vendor asks implementations to handle at least 8 KiB; no secret is this large


class DeepLinkError(ValueError):
    """A link that is not a valid TrustTunnel deep link. Messages never carry a value."""


def encode_varint(value: int) -> bytes:
    if value < 0 or value >= 1 << 62:
        raise DeepLinkError("varint out of range")
    if value < 1 << 6:
        return bytes([value])
    if value < 1 << 14:
        return (0x4000 | value).to_bytes(2, "big")
    if value < 1 << 30:
        return (0x80000000 | value).to_bytes(4, "big")
    return (0xC000000000000000 | value).to_bytes(8, "big")


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """The integer at `offset` and the offset after it."""
    if offset >= len(data):
        raise DeepLinkError("truncated payload")
    size = 1 << (data[offset] >> 6)
    if offset + size > len(data):
        raise DeepLinkError("truncated payload")
    value = data[offset] & 0x3F
    for byte in data[offset + 1:offset + size]:
        value = (value << 8) | byte
    return value, offset + size


def _field(tag: int, value: bytes) -> bytes:
    return encode_varint(tag) + encode_varint(len(value)) + value


def _text(tag: int, value: str) -> bytes:
    return _field(tag, value.encode("utf-8"))


def _flag(tag: int, value: bool) -> bytes:
    return _field(tag, b"\x01" if value else b"\x00")


def encode_deeplink(
    *, hostname: str, addresses: list[str], username: str, password: str,
    certificate_der: bytes | None = None, upstream_protocol: int = UPSTREAM_HTTP2, name: str | None = None,
    skip_verification: bool = False,
) -> str:
    """The `tt://?` link for one access. `certificate_der` is the concatenated DER chain, omitted
    when the endpoint's certificate is trusted by the system store. Fields at their default
    (`has_ipv6`, `anti_dpi`, `skip_verification` false) are left out, as the specification allows."""
    if not (hostname and addresses and username and password):
        raise DeepLinkError("hostname, addresses, username and password are required")
    if upstream_protocol not in (UPSTREAM_HTTP2, UPSTREAM_HTTP3):
        raise DeepLinkError("unknown upstream protocol")
    parts = [_field(TAG_VERSION, encode_varint(WRITE_VERSION)), _text(TAG_HOSTNAME, hostname)]
    parts += [_text(TAG_ADDRESSES, address) for address in addresses]
    parts += [_text(TAG_USERNAME, username), _text(TAG_PASSWORD, password)]
    if skip_verification:
        parts.append(_flag(TAG_SKIP_VERIFICATION, True))
    if certificate_der:
        parts.append(_field(TAG_CERTIFICATE, certificate_der))
    parts.append(_field(TAG_UPSTREAM_PROTOCOL, encode_varint(upstream_protocol)))
    if name:
        parts.append(_text(TAG_NAME, name))
    return SCHEME + base64.urlsafe_b64encode(b"".join(parts)).rstrip(b"=").decode("ascii")


def _string_list(value: bytes) -> list[str]:
    items, offset = [], 0
    while offset < len(value):
        length, offset = decode_varint(value, offset)
        if offset + length > len(value):
            raise DeepLinkError("truncated payload")
        items.append(value[offset:offset + length].decode("utf-8"))
        offset += length
    return items


def decode_deeplink(link: str) -> dict:
    """Every field of a link as a dict (absent fields at their specified default); unknown tags
    are skipped. Raises `DeepLinkError` for a malformed, too-new or incomplete link."""
    if not isinstance(link, str) or not link.startswith(SCHEME) or len(link) > MAX_LINK:
        raise DeepLinkError("not a tt:// deep link")
    body = link[len(SCHEME):]
    try:
        data = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DeepLinkError("the payload is not base64url") from exc
    fields = {"version": 0, "addresses": [], "has_ipv6": True, "skip_verification": False, "anti_dpi": False,
              "upstream_protocol": UPSTREAM_HTTP2, "dns_upstreams": []}
    offset = 0
    try:
        while offset < len(data):
            tag, offset = decode_varint(data, offset)
            length, offset = decode_varint(data, offset)
            if offset + length > len(data):
                raise DeepLinkError("truncated payload")
            value, offset = data[offset:offset + length], offset + length
            if tag == TAG_VERSION:
                fields["version"] = decode_varint(value, 0)[0]
            elif tag == TAG_ADDRESSES:
                fields["addresses"].append(value.decode("utf-8"))
            elif tag in (TAG_HAS_IPV6, TAG_SKIP_VERIFICATION, TAG_ANTI_DPI):
                fields[{TAG_HAS_IPV6: "has_ipv6", TAG_SKIP_VERIFICATION: "skip_verification",
                        TAG_ANTI_DPI: "anti_dpi"}[tag]] = value == b"\x01"
            elif tag == TAG_CERTIFICATE:
                fields["certificate"] = value
            elif tag == TAG_UPSTREAM_PROTOCOL:
                fields["upstream_protocol"] = decode_varint(value, 0)[0]
            elif tag == TAG_DNS_UPSTREAMS:
                fields["dns_upstreams"] = _string_list(value)
            elif tag in _TEXT_FIELDS:
                fields[_TEXT_FIELDS[tag]] = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeepLinkError("a text field is not UTF-8") from exc
    if fields["version"] > VERSION:
        raise DeepLinkError("the deep link is newer than this decoder")
    if "subscription_url" not in fields:
        for required in ("hostname", "username", "password"):
            if required not in fields:
                raise DeepLinkError(f"the deep link has no {required}")
        if not fields["addresses"]:
            raise DeepLinkError("the deep link has no addresses")
    return fields


_TEXT_FIELDS = {
    TAG_HOSTNAME: "hostname", TAG_CUSTOM_SNI: "custom_sni", TAG_USERNAME: "username", TAG_PASSWORD: "password",
    TAG_CLIENT_RANDOM_PREFIX: "client_random_prefix", TAG_NAME: "name", TAG_SUBSCRIPTION_URL: "subscription_url",
    TAG_CLIENT_RANDOM_AUTH_KEY: "client_random_auth_key",
}
