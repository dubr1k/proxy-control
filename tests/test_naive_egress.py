"""`naive_manager/egress.py`: the managed egress block, parsed and rendered byte-carefully."""
from __future__ import annotations

import asyncio
import socket
import threading

import pytest

from naive_manager import egress
from naive_manager.egress import (
    EGRESS_BEGIN,
    EGRESS_END,
    EgressInvalid,
    check_reachable,
    document_digest,
    parse,
    render,
    render_raw,
    revision_of,
    validate_document,
)

WARP = "socks5://127.0.0.1:45000"
LEGACY = """{
    admin 127.0.0.1:2019
}
:4443 {
    bind 127.0.0.1
    route {
        forward_proxy {
            # BEGIN NAIVE-MANAGER USERS
            basic_auth alice pw-alice
            # END NAIVE-MANAGER USERS
            hide_ip
            hide_via
            probe_resistance
            upstream http://127.0.0.1:8118
        }
        file_server { root /var/www/naive }
    }
}
"""
DIRECT = LEGACY.replace("            upstream http://127.0.0.1:8118\n", "")


def _block(text: str) -> list[str]:
    lines = text.splitlines()
    begin = next(i for i, line in enumerate(lines) if line.strip() == EGRESS_BEGIN)
    end = next(i for i, line in enumerate(lines) if line.strip() == EGRESS_END)
    return lines[begin:end + 1]


# --- documents ---

def test_validate_document_rejects_unknown_fields_and_schema():
    with pytest.raises(EgressInvalid, match="unknown field"):
        validate_document({"schema": 1, "upstream": None, "acl": [], "path": "/etc"})
    with pytest.raises(EgressInvalid, match="schema"):
        validate_document({"schema": 2, "upstream": None, "acl": []})
    with pytest.raises(EgressInvalid, match="provider"):
        validate_document({"schema": 1, "upstream": {"provider": "socks5://evil"}, "acl": []})
    with pytest.raises(EgressInvalid, match="provider"):
        validate_document({"schema": 1, "upstream": {"provider": "warp", "url": "x"}, "acl": []})
    with pytest.raises(EgressInvalid, match="not enforced"):
        validate_document({"schema": 1, "upstream": {"provider": "warp"}, "acl": [{"deny": ["example.com"]}]})


def test_validate_document_normalises_subjects_and_bounds():
    normalised = validate_document({"schema": 1, "upstream": None,
                                    "acl": [{"deny": ["Example.COM", "*.Example.com", "10.1.2.3/8", "2001:db8::1"]}]})
    assert normalised["acl"] == [{"deny": ["example.com", "*.example.com", "10.0.0.0/8", "2001:db8::1/128"]}]
    for bad in ("not a host", "example.com/24", "*.", "-bad.example", "a" * 260, ""):
        with pytest.raises(EgressInvalid):
            validate_document({"schema": 1, "upstream": None, "acl": [{"deny": [bad]}]})
    with pytest.raises(EgressInvalid, match="invalid acl list"):
        validate_document({"schema": 1, "upstream": None, "acl": [{"deny": ["a.example"]}] * (egress.MAX_RULES + 1)})
    with pytest.raises(EgressInvalid, match="too many"):
        validate_document({"schema": 1, "upstream": None,
                           "acl": [{"deny": [f"h{i}.example" for i in range(egress.MAX_SUBJECTS + 1)]}]})
    with pytest.raises(EgressInvalid, match="invalid acl rule"):
        validate_document({"schema": 1, "upstream": None, "acl": [{"allow": ["example.com"]}]})
    assert document_digest(validate_document({"schema": 1, "upstream": None, "acl": []})) == document_digest(
        {"acl": [], "schema": 1, "upstream": None})


# --- parsing ---

def test_parse_reports_an_unmanaged_upstream_as_custom_and_a_bare_handler_as_direct():
    parsed = parse(LEGACY)
    assert (parsed.mode, parsed.upstream, parsed.managed) == ("custom", "http://127.0.0.1:8118", False)
    assert parsed.raw_lines == ("            upstream http://127.0.0.1:8118",)
    bare = parse(DIRECT)
    assert (bare.mode, bare.upstream, bare.managed, bare.raw_lines) == ("direct", None, False, ())
    assert bare.revision != parsed.revision and revision_of(DIRECT) == bare.revision


def test_render_adopts_the_unmanaged_upstream_into_a_block_and_keeps_the_rest():
    document = validate_document({"schema": 1, "upstream": {"provider": "warp"}, "acl": []})
    rendered = render(LEGACY, document, WARP)
    assert "upstream http://127.0.0.1:8118" not in rendered
    assert _block(rendered) == [f"            {EGRESS_BEGIN}", f"            upstream {WARP}", f"            {EGRESS_END}"]
    # The block lands right after probe_resistance; every other line is untouched.
    assert rendered.replace("\n".join(_block(rendered)) + "\n", "") == DIRECT
    parsed = parse(rendered)
    assert (parsed.mode, parsed.upstream, parsed.managed) == ("proxy", WARP, True)
    # Rolling back to the adopted lines restores the original bytes.
    assert render_raw(rendered, parse(LEGACY).raw_lines) == LEGACY


def test_render_replaces_an_existing_block_and_direct_has_no_upstream_line():
    warp = render(DIRECT, validate_document({"schema": 1, "upstream": {"provider": "warp"}, "acl": []}), WARP)
    direct = render(warp, validate_document({"schema": 1, "upstream": None, "acl": []}), WARP)
    assert _block(direct) == [f"            {EGRESS_BEGIN}", f"            {EGRESS_END}"]
    assert "upstream" not in direct
    assert parse(direct).mode == "direct" and parse(direct).managed is True
    assert direct.replace("\n".join(_block(direct)) + "\n", "") == DIRECT
    assert revision_of(direct) != revision_of(warp) and revision_of(direct) != revision_of(DIRECT)


def test_render_acl_deny_lines_and_parse_reads_them_back():
    document = validate_document({"schema": 1, "upstream": None,
                                  "acl": [{"deny": ["example.com", "*.example.com"]}, {"deny": ["10.0.0.0/8"]}]})
    rendered = render(DIRECT, document, None)
    assert _block(rendered) == [
        f"            {EGRESS_BEGIN}",
        "            acl {",
        "                deny example.com *.example.com",
        "            }",
        "            acl {",
        "                deny 10.0.0.0/8",
        "            }",
        f"            {EGRESS_END}",
    ]
    parsed = parse(rendered)
    assert parsed.acl_deny == ("example.com", "*.example.com", "10.0.0.0/8") and parsed.mode == "direct"


def test_render_refuses_a_provider_this_host_does_not_have():
    with pytest.raises(EgressInvalid, match="not configured"):
        render(DIRECT, validate_document({"schema": 1, "upstream": {"provider": "warp"}, "acl": []}), None)


def test_parse_refuses_directives_outside_the_managed_block_or_broken_markers():
    managed = render(DIRECT, validate_document({"schema": 1, "upstream": None, "acl": []}), None)
    with pytest.raises(EgressInvalid, match="outside the managed"):
        parse(managed.replace("            hide_via\n", "            hide_via\n            upstream socks5://127.0.0.1:1\n"))
    with pytest.raises(EgressInvalid, match="marker pair"):
        parse(managed.replace(f"            {EGRESS_END}\n", ""))
    with pytest.raises(EgressInvalid, match="forward_proxy"):
        parse("{\n}\n:4443 {\n}\n")


# --- reachability ---

def test_check_reachable_socks5_greeting_and_refused():
    async def stub(reader, writer):
        if await reader.readexactly(3) == b"\x05\x01\x00":
            writer.write(b"\x05\x00")
            await writer.drain()
        writer.close()

    async def run():
        server = await asyncio.start_server(stub, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await asyncio.to_thread(check_reachable, f"socks5://127.0.0.1:{port}", 2.0)
        finally:
            server.close()

    assert asyncio.run(run()) is True
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
    assert check_reachable(f"socks5://127.0.0.1:{port}", 1.0) is False
    assert check_reachable("socks5://127.0.0.1", 1.0) is False


def test_check_reachable_http_is_a_tcp_connect():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted = threading.Thread(target=lambda: listener.accept()[0].close())
    accepted.start()
    try:
        assert check_reachable(f"http://127.0.0.1:{port}", 2.0) is True
    finally:
        accepted.join(timeout=2)
        listener.close()
