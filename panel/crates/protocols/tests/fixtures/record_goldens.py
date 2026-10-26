"""Records what the Python panel produces for every link, config and QR code (WP6 goldens).

Each case calls one pure function of `panel/protocols/*.py`, `panel/trusttunnel_link.py` or
`panel/reveals.py` and keeps its input and its output (or the error class and message). The Rust
tests (`tests/goldens.rs`) run the same inputs through the Rust functions and compare byte for byte.
Certificates and credentials are generated here for the purpose; nothing is a real secret.

Run on ams-test by `run.sh` (with the panel image's Python 3.13.5, the production interpreter).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from panel.clients.models import AccessGrant
from panel.protocols import amneziawg, mieru, naive, telemt, trusttunnel
from panel.protocols.base import AdapterError
from panel.protocols.telemt import TelemtAdapter
from panel.reveals import karing_client, qr_data
from panel.trusttunnel_link import decode_deeplink, decode_varint, encode_deeplink, encode_varint
from panel.telemt import MemoryTelemt


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def outcome(function, *args, **kwargs) -> dict:
    try:
        value = function(*args, **kwargs)
    except Exception as error:  # noqa: BLE001 — the class and message are the golden
        return {"error": type(error).__name__, "message": str(error),
                "adapter_error": isinstance(error, AdapterError)}
    return {"value": encode(value)}


def encode(value):
    if isinstance(value, bytes):
        return {"$bytes": b64(value)}
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    return value


def certificate(common_name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    built = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now)
             .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return built.public_bytes(serialization.Encoding.DER)


def grant(protocol: str, options: dict, username: str = "alice", **extra) -> dict:
    return AccessGrant(id="g1", client_id="c1", protocol=protocol, node_id="local", endpoint_id="default",
                       runtime_username=username, desired_state="enabled", options=options,
                       origin="provisioned", created_at=1, updated_at=1, **extra).model_dump(mode="json")


def artifacts(adapter, grant_dump, credential: bytes, public_host: str) -> dict:
    model = AccessGrant.model_validate(grant_dump)
    try:
        rendered = adapter.render_artifacts(model, credential, public_host=public_host)
    except Exception as error:  # noqa: BLE001
        return {"error": type(error).__name__, "message": str(error),
                "adapter_error": isinstance(error, AdapterError)}
    return {"value": [{"kind": item.kind, "label": item.label, "media_type": item.media_type,
                       "value": item.value, "auto_refresh": item.auto_refresh} for item in rendered]}


CERT_A, CERT_B = certificate("gate.example.com"), certificate("other.example")
BIG_CERT = certificate("x" * 60)


def deeplink_cases() -> dict:
    encode_cases = [
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p"},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "secret-1", "name": "n",
         "certificate_der": CERT_A, "skip_verification": True},
        {"hostname": "gate.example.com", "addresses": ["gate.example.com:443", "[2001:db8::1]:443"],
         "username": "alice-1.x_y", "password": "Zz9-_" * 8, "certificate_der": CERT_A + CERT_B,
         "name": "Алиса · телефон", "skip_verification": True},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p" * 300},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p" * 20000},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p", "upstream_protocol": 2},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p", "name": ""},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p", "certificate_der": b""},
        {"hostname": "", "addresses": ["a:1"], "username": "u", "password": "p"},
        {"hostname": "h", "addresses": [], "username": "u", "password": "p"},
        {"hostname": "h", "addresses": ["a:1"], "username": "", "password": "p"},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": ""},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p", "upstream_protocol": 9},
        {"hostname": "h", "addresses": ["a:1"], "username": "u", "password": "p", "upstream_protocol": 0},
    ]
    encoded = []
    for case in encode_cases:
        encoded.append({"input": encode(case), **outcome(encode_deeplink, **case)})

    def tlv(tag, value):
        return encode_varint(tag) + encode_varint(len(value)) + value

    def link(payload: bytes, pad: bool = False) -> str:
        body = base64.urlsafe_b64encode(payload)
        return "tt://?" + (body if pad else body.rstrip(b"=")).decode()

    good = encode_deeplink(hostname="h", addresses=["a:1"], username="u", password="p")
    body = good[len("tt://?"):]
    newer = base64.urlsafe_b64encode(bytes.fromhex("000103") + base64.urlsafe_b64decode(body + "=")[3:]).rstrip(b"=")
    dns = b"".join(encode_varint(len(item)) + item for item in (b"1.1.1.1", b"tls://dns.example.com"))
    every = (tlv(0, encode_varint(2)) + tlv(0x40, b"future") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(2, b"b:2")
             + tlv(3, b"sni.example") + tlv(4, b"\x00") + tlv(5, b"u") + tlv(6, b"p") + tlv(0x0A, b"\x01")
             + tlv(0x0B, b"aabb/ff00") + tlv(0x0D, dns) + tlv(0x0F, b"00ff") + tlv(7, b"\x02") + tlv(8, CERT_A)
             + tlv(9, encode_varint(2)) + tlv(0x0C, "имя".encode()))
    decode_cases = [
        good, link(every), link(tlv(0, encode_varint(2)) + tlv(0x0E, b"https://sub.example/x")),
        "", "https://x", "tt://", "tt://?!!!", good[:-3] + "A", "tt://?" + newer.decode(), "tt://?AAEC",
        "tt://?" + base64.urlsafe_b64encode(b"\x01\x01h").decode(), link(every, pad=True),
        link(tlv(1, b"\xff\xfe") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        link(tlv(1, b"h") + tlv(5, b"u") + tlv(6, b"p")), link(tlv(1, b"h") + tlv(2, b"a:1") + tlv(6, b"p")),
        link(tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u")), link(tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        link(tlv(0, b"") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        link(tlv(0, encode_varint(3)) + tlv(0x0E, b"x")),
        link(tlv(0x0D, b"\x05ab") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        link(tlv(0x0D, b"\x02\xff\xfe") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        link(tlv(9, b"") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        link(tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p") + b"\x01\x05ab"),
        link(tlv(0x3FFF, b"x") + tlv(1, b"h") + tlv(2, b"a:1") + tlv(5, b"u") + tlv(6, b"p")),
        "tt://?" + "A" * 16379, "tt://?" + "A" * 16378, "tt://?AAEBAQFoAgNhOjEFAXUGAXAJAQE===",
        "tt://?AAEBAQFoAgNhOjEFAXUGAXAJAQ", "tt://?AAEBAQFoAgNh+jEFAXUGAXAJAQE", "tt://?AAEBAQFoAgNh/jEFAXUGAXAJAQE",
        "tt://? AAEBAQFoAgNhOjEFAXUGAXAJAQE", "tt://?AAEBAQFo\nAgNhOjEFAXUGAXAJAQE", "tt://?é",
    ]
    decoded = [{"input": case, **outcome(decode_deeplink, case)} for case in decode_cases]
    values = [0, 1, 63, 64, 300, 16383, 16384, 2**30 - 1, 2**30, 2**62 - 1, 2**62, -1]
    varints = [{"input": value, **outcome(encode_varint, value)} for value in values]
    decodes = [{"input": encode(data), "offset": offset, **outcome(decode_varint, data, offset)}
               for data, offset in ((b"\x41", 0), (b"\x41\x2c", 0), (b"\x00\x41\x2c", 1), (b"", 0), (b"\xc0", 0),
                                    (b"\xff" * 8, 0), (b"\x80\x00\x40\x00", 0), (b"\x3f", 1))]
    return {"encode": encoded, "decode": decoded, "encode_varint": varints, "decode_varint": decodes}


def trusttunnel_cases() -> dict:
    credentials = [b"", b"\xff\xfe", b"line\nbreak", b"x" * 129, b"x" * 128, b"del\x7f1234", b"short",
                   b"has space1", "пароль-длинный".encode(), b"password-1234", b"pa\"ss\\word", b"12345678",
                   b"~!@#$%^&*()_+{}|:<>?"]
    parsed = [{"input": encode(item), **outcome(trusttunnel.parse_credential, item)} for item in credentials]
    der_cases = [CERT_A, CERT_A + CERT_B, BIG_CERT, b"", b"\x00\x01", b"\x30\x05\x01", b"\x30",
                 b"\x30\x80", b"\x30\x85\x00\x00\x00\x00\x01", b"\x30\x81\x01\x00", b"\x30\x82\x00\x01\x00",
                 b"\x30\x00", b"\x30\x00\x30\x01\x05", b"\x30\x84\x00\x00\x00\x02ab"]
    splits = [{"input": encode(item), **outcome(trusttunnel.split_der, item)} for item in der_cases]
    pems = [{"input": text, **outcome(trusttunnel.certificate_pem, text)}
            for text in (b64(CERT_A), b64(CERT_A + CERT_B), b64(BIG_CERT), "not base64!", "", "AAA", "MAA=",
                         b64(CERT_A)[:-4] + "====", " " + b64(CERT_A))]
    strings = ["", "plain", 'a\\b"c\td', "line\nbreak\r", "\x00\x01\x1f\x7f\x80 ", "Алиса · телефон 😀",
               "\x08\x0c\x0b"]
    toml_strings = [{"input": text, **outcome(trusttunnel._toml_string, text)} for text in strings]
    endpoints = [
        {"hostname": "gate.example.com", "public_port": 443, "certificate_der_b64": b64(CERT_A)},
        {"hostname": "gate.example.com", "public_port": 8443, "certificate_der_b64": b64(CERT_A),
         "certificate_trusted": True},
        {"hostname": "gate.example.com", "certificate_trusted": False, "certificate_der_b64": ""},
        {"hostname": None, "public_port": 0}, {}, {"certificate_trusted": 1, "certificate_der_b64": "x"},
    ]
    learned = [{"input": item, **outcome(trusttunnel.learned_options, item)} for item in endpoints]
    adapter = trusttunnel.TrusttunnelAdapter(None, public_host="fallback.example.com")
    options = [
        {"hostname": "gate.example.com", "port": 443, "certificate_der_b64": b64(CERT_A), "name": 'Carol "phone"'},
        {"hostname": "gate.example.com", "port": None, "certificate_der_b64": None, "name": None},
        {"hostname": "h.example", "port": 8443, "certificate_der_b64": b64(CERT_A + CERT_B), "name": "a\\b\"c\td"},
        {"hostname": None, "port": None, "certificate_der_b64": None, "name": "Алиса · телефон"},
        {"hostname": "gate.example.com", "port": 443, "certificate_der_b64": "MAA=", "name": None},
    ]
    rendered = []
    for option in options:
        for credential in (b"password-1234", b"pa\"ss\\word", b"bad"):
            for public_host in ("", "fallback.example.com"):
                dump = grant("trusttunnel", option, username="carol")
                rendered.append({"grant": dump, "credential": encode(credential), "public_host": public_host,
                                 **artifacts(adapter, dump, credential, public_host)})
    return {"parse_credential": parsed, "split_der": splits, "certificate_pem": pems, "toml_string": toml_strings,
            "learned_options": learned, "render": rendered}


def amneziawg_cases() -> dict:
    privates = [
        "d6ccTrRgemZRuxBqv66y1Jcf3s1Tqr9mfXTzjnGJw/Q=",  # an RFC 7748 test scalar, base64
        b64(bytes(32)), b64(bytes([255] * 32)), b64(bytes(range(32))), b64(bytes(range(32, 64))),
    ]
    publics = [{"input": key, **outcome(amneziawg.public_key_of, key)} for key in privates]
    credential = json.dumps({"private_key": privates[0], "preshared_key": b64(bytes(range(64, 96)))},
                            separators=(",", ":")).encode()
    credentials = [credential, b"not json", b'{"private_key":"x","preshared_key":"y"}', b"[]", b'{"private_key":1}',
                   json.dumps({"private_key": privates[0], "preshared_key": b64(bytes(31))}).encode(),
                   json.dumps({"private_key": privates[0] + "\n", "preshared_key": privates[1]}).encode(),
                   json.dumps({"private_key": privates[0], "preshared_key": privates[1], "x": 1}).encode(),
                   b'{"private_key":"' + privates[0].encode() + b'","preshared_key":null}', b"\xff",
                   json.dumps({"private_key": "AAAA" * 10 + "AAA=", "preshared_key": privates[1]}).encode()]
    parsed = [{"input": encode(item), **outcome(amneziawg.parse_credential, item)} for item in credentials]
    full_obfuscation = {"ContentPaddingAddition": "8", "HeaderProtectionKey": "k" * 44, "I5": "<b 0x5>",
                        "I4": "<b 0x4>", "I3": "<b 0x3>", "I2": "<b 0x2>", "I1": "<b 0x1>", "H4": "4", "H3": "3",
                        "H2": "2", "H1": "1", "S4": "16", "S3": "15", "S2": "14", "S1": "13", "Jmax": "50",
                        "Jmin": "10", "Jc": "4"}
    options = [
        {"version": "3.1", "address": "10.66.31.2", "port": 51822, "server_public_key": "S" * 43 + "=",
         "mtu": 1280, "dns": ["1.1.1.1", "1.0.0.1"], "obfuscation": full_obfuscation},
        {"version": "1.5", "address": "10.66.15.2", "port": 51820, "server_public_key": "S" * 43 + "=",
         "mtu": None, "dns": [], "obfuscation": {"Jc": "4", "S1": "1"}},
        {"version": "2.0", "address": None, "port": 51821, "server_public_key": "S" * 43 + "=", "mtu": None,
         "dns": [], "obfuscation": {}},
        {"version": "2.0", "address": "10.66.20.9", "port": 51821, "server_public_key": None, "mtu": None,
         "dns": [], "obfuscation": {}},
        {"version": "2.0", "address": "10.66.20.9", "port": 51821, "server_public_key": "S" * 43 + "=", "mtu": 1500,
         "dns": ["2001:db8::1"], "obfuscation": {"I1": "<b 0x" + "ab" * 1000 + ">"}},
        {"version": "2.0", "address": "10.66.20.9", "port": 51821, "server_public_key": "S" * 43 + "=", "mtu": 1500,
         "dns": ["2001:db8::1"], "obfuscation": {"I1": "<b 0x" + "ab" * 1000 + ">", "I2": "<b 0x" + "cd" * 1000 + ">"}},
    ]
    rendered = []
    for option in options:
        for public_host in ("vpn.example.com", ""):
            for item in (credential, b"not json"):
                dump = grant("amneziawg", option, username="carol-awg")
                rendered.append({"grant": dump, "credential": encode(item), "public_host": public_host,
                                 **artifacts(amneziawg.AmneziawgAdapter(None), dump, item, public_host)})
    learned = [
        {"peer": {"address": "10.66.20.2", "username": "a"},
         "instance": {"version": "2.0", "port": 51821, "server_public_key": "k", "mtu": 1280, "dns": ["1.1.1.1"],
                      "obfuscation": {"Jc": "4"}}},
        {"peer": {"address": "10.66.20.2"}, "instance": {"version": "2.0", "port": 51821, "server_public_key": "k"}},
        {"peer": {"address": "10.66.20.2"}, "instance": {"version": "2.0", "port": 51821, "server_public_key": "k",
                                                         "dns": None, "obfuscation": None, "mtu": 0}},
        {"peer": {}, "instance": {"version": "2.0", "port": 1, "server_public_key": "k"}},
    ]
    learned_cases = [{"input": item, **outcome(amneziawg.learned_options, item["peer"], item["instance"])}
                     for item in learned]
    return {"public_key_of": publics, "parse_credential": parsed, "render": rendered, "learned_options": learned_cases}


def naive_cases() -> list:
    rows = [("alice", "password", "naive.example.com"), ("a b", "p@ss:w/rd?#%", "h"), ("ünï", "пароль~._-", "[::1]:8443"),
            ("", "", "")]
    out = [{"input": list(row), **outcome(naive.proxy_url, *row)} for row in rows]
    adapter = naive.NaiveAdapter(None, public_host="naive.example.com")
    for username, password, host in rows[:3]:
        dump = grant("naive", {"quota_bytes": None}, username="u-1" if " " in username else "alice")
        out.append({"grant": dump, "credential": encode(password.encode()), "public_host": host,
                    **artifacts(adapter, dump, password.encode(), host)})
    return out


def mieru_cases() -> dict:
    shares = [("alice", "pass word/1", "mieru.example.com", 8443), ("a/b", "p%", "h", 1), ("ü", "ä", "", 65535)]
    share_urls = [{"input": list(row), **outcome(mieru.share_url, *row[:3], port=row[3])} for row in shares]
    links = [
        "mierus://alice:pa%20ss@mieru.example.com?profile=alice&port=8443&protocol=TCP",
        "mierus://alice:pass@[2001:DB8::1]?profile=p&port=8443&protocol=TCP&port=9000-9010&protocol=UDP&mtu=1400",
        "mierus://alice:pass@192.168.001.1?profile=p&port=1&protocol=TCP",
        "mierus://alice:pass@10.0.0.1?profile=p&port=8443&protocol=TCP&mtu=1280",
        "mierus://alice:pass@h/?profile=p&port=8443&protocol=UDP",
        "mierus://alice:pass@h?profile=p+q&port=8443&protocol=TCP",
        "mierus://alice:pass@h?profile=&port=8443&protocol=TCP",
        "mierus://alice:pass@h?profile=p&profile=q&port=8443&protocol=TCP",
        "mierus://alice:pass@h:8443?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@h:x?profile=p&port=8443&protocol=TCP",
        "mierus://alice@h?profile=p&port=8443&protocol=TCP",
        "mierus://:pass@h?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP#frag",
        "mierus://alice:pass@h/path?profile=p&port=8443&protocol=TCP",
        "mieru://alice:pass@h?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=8443",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=SCTP",
        "mierus://alice:pass@h?profile=p&port=0&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=65536&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=9-1&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=1-65535&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP&mtu=1279",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP&mtu=1501",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP&mtu=01400",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP&mtu=1400&mtu=1400",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP&mtu=abc",
        "mierus://alice:pass@h?profile=p&port=%38443&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP&extra",
        "mierus://alice:pass@h?profile=p&&port=8443&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=8443&protocol=TCP;x=1",
        "mierus://alice:pass@H.Example.COM?profile=p&port=8443&protocol=TCP",
        "mierus://al%C3%BCce:p%E2%82%ACss@h?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@[::ffff:1.2.3.4]?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pa:ss@h?profile=p&port=8443&protocol=TCP",
        "MIERUS://alice:pass@h?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@h?profile=p&port=٨٤٤٣&protocol=TCP",
        "mierus://a@b:pass@h?profile=p&port=8443&protocol=TCP",
        "mierus://alice:pass@[1.2.3.4]?profile=p&port=8443&protocol=TCP",
        "x" * 4097, 5, None,
    ]
    parsed = []
    for link in links:
        result = outcome(mieru.parse_share_url, link)
        if "value" not in result:
            parsed.append({"input": link, **result})
            continue
        share = mieru.parse_share_url(link)
        parsed.append({"input": link, "value": {
            "username": share.username, "password": share.password, "host": share.host, "is_ip": share.is_ip,
            "profile": share.profile, "bindings": list(share.bindings), "mtu": share.mtu,
            "exact_ports": share.exact_ports,
            "singbox": mieru.singbox_outbounds(share, tag=lambda port, protocol: f"mieru-{protocol}-{port}")}})
    templates = [("mierus://alice:pa%20ss@h?profile=alice&port=1&protocol=TCP", "alice", "pa ss"),
                 ("mierus://alice:pass@h?x=alice:pass@", "alice", "pass"), ("mierus://bob:x@h", "alice", "pass"),
                 (None, "alice", "pass"), (5, "a", "b"), ("", "a", "b")]
    template_cases = [{"input": encode(list(row)), **outcome(mieru.template_from, *row)} for row in templates]
    adapter = mieru.MieruAdapter(None, public_host="mieru.example.com", port=8443)
    rendered = []
    for template in (None, "mierus://{username}:{password}@mita.example?profile={profile}&port=9000&protocol=TCP",
                     "mierus://{username}:{password}@{host}:{port}?x={{y}}", "mierus://{username}:{password}@{oops}",
                     "mierus://{username}:{password}@}", "mierus://{username}:{password}@{"):
        for username, password in (("alice", "pass word/1"), ("a.b-c_d", "p%&=")):
            dump = grant("mieru", {"quotas": [], "share_template": template}, username=username)
            rendered.append({"grant": dump, "credential": encode(password.encode()), "public_host": "x.example.com",
                             **artifacts(adapter, dump, password.encode(), "x.example.com")})
    shares = [{"input": ["alice", "pass word/1"], **outcome(adapter.share, "alice", "pass word/1")}]
    return {"share_url": share_urls, "parse_share_url": parsed, "template_from": template_cases, "render": rendered,
            "share": shares}


def telemt_cases() -> dict:
    links = [{"input": [host, port, secret], **outcome(telemt._link, host, port, secret)}
             for host, port, secret in (("proxy.example.com", 443, "ee" + "ab" * 16), ("a b/c", 8443, "x/y z"),
                                        ("пример.рф", 1, ""))]
    adapter = TelemtAdapter(MemoryTelemt(), public_host="fallback.example.com", public_port=8443)
    rendered = []
    for options in ({}, {"host": "proxy.example.com", "port": 443}, {"host": "proxy.example.com"},
                    {"port": 9443, "data_quota_bytes": 5}):
        for public_host in ("", "fallback.example.com"):
            dump = grant("mtproxy", options)
            secret = ("ee" + "cd" * 16).encode()
            rendered.append({"grant": dump, "credential": encode(secret), "public_host": public_host,
                             **artifacts(adapter, dump, secret, public_host)})
    upstreams = [
        [{"type": "direct", "ipv4": True, "ipv6": False}],
        [{"type": "direct", "interface": "eth0"}],
        [{"type": "direct", "bind_addresses": []}, {"type": "socks5", "enabled": False}],
        [{"type": "direct", "scopes": ["x"]}],
        [{"type": "socks5", "address": "xray-router-ingress:45103", "username": "telemt", "password": "m" * 43,
          "weight": 1, "enabled": True}],
        [{"type": "socks5", "address": "xray-router-ingress:45103", "scopes": "s"}],
        [{"type": "socks5", "address": "203.0.113.5:1080"}],
        [{"type": "direct"}, {"type": "direct"}],
        [{"type": "direct", "enabled": None}],
        [{"type": "direct", "enabled": 0}],
        [],
        [{"type": "direct", "ipv4": True, "ipv6": True, "weight": 3, "nested": {"b": 1, "a": "é"}}],
    ]
    documents = [{"input": item, "document": TelemtAdapter._document_of(item),
                  "revision": TelemtAdapter._revision(item)} for item in upstreams]
    probes = [{"input": item, "value": telemt.probe_bridge(item, timeout=0.01)}
              for item in ({}, {"address": "h:x", "username": "u", "password": "p"},
                           {"address": ":1", "username": "u", "password": "p"},
                           {"address": "h:1", "username": "", "password": "p"},
                           {"address": "h:1", "username": "u" * 256, "password": "p"},
                           {"address": "h:1", "username": "u", "password": ""},
                           {"address": "h:1", "username": "ü" * 128, "password": "p"})]
    return {"link": links, "render": rendered, "document_of": documents, "probe_invalid": probes}


QR_PAYLOADS = [
    "https://sub.example.com/s/" + "A1b2C3d4" * 5,
    "tg://proxy?server=proxy.example.com&port=443&secret=ee" + "0123456789abcdef" * 2,
    "0123456789" * 3,
    "HELLO WORLD 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:",
    "a", "12345", "ABCDE", "Привет, мир! 😀",
    "naive+https://alice:p%40ss@naive.example.com:443#Naive%20%C2%B7%20alice",
    "mierus://alice:pass@mieru.example.com?profile=alice&port=8443&protocol=TCP",
    "x" * 300, "9" * 1500, "Z" * 1800, "y" * 2331, "y" * 2332, "q" * 3000,
    "mixed 123456789012345678901234567890 TEXT ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 tail" * 4,
]


def qr_cases(amneziawg_rendered: list) -> list:
    """Every payload, plus each AmneziaWG config rendered above (the last ones overflow version 40-M:
    python-qrcode raises `ValueError` from its version setter). A data URI over 32 KiB is kept as its
    SHA-256 and length to keep the fixture small."""
    configs = [item["value"][0]["value"] for item in amneziawg_rendered if "value" in item]
    cases = []
    for payload in QR_PAYLOADS + configs:
        case = {"input": payload, **outcome(qr_data, payload)}
        if len(case.get("value") or "") > 32768:
            uri = case.pop("value")
            case["sha256"], case["length"] = hashlib.sha256(uri.encode()).hexdigest(), len(uri)
        cases.append(case)
    return cases


def karing_cases() -> list:
    configs = [({"outbounds": [{"type": "mieru", "tag": "mieru-TCP-8443", "server": "mieru.example.com",
                                "server_port": 8443, "transport": "TCP", "username": "alice",
                                "password": "pa ss/+&="}]}, "Mieru · alice · 1a2b3c4d", "karing-mieru-alice.json"),
               ({"x": "Привет", "y": [1, 2.5, None, True]}, "Naive · ü", "f.json")]
    return [{"input": {"config": config, "name": name, "filename": filename},
             **outcome(karing_client, config, name=name, filename=filename)} for config, name, filename in configs]


def main() -> None:
    awg = amneziawg_cases()
    goldens = {"deeplink": deeplink_cases(), "trusttunnel": trusttunnel_cases(), "amneziawg": awg,
               "naive": naive_cases(), "mieru": mieru_cases(), "telemt": telemt_cases(),
               "qr": qr_cases(awg["render"]), "karing": karing_cases()}
    json.dump(goldens, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
