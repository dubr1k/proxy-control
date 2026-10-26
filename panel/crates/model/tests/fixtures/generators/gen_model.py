"""Golden vectors for `panel-model`: what the Python panel's model modules produce.

Run on ams-test with the panel venv against a copy of this tree, e.g.:

    cd /root/dev/rust-panel-wp2 && /root/dev/proxy-control/.venv/bin/python \
        panel/crates/model/tests/fixtures/generators/gen_model.py panel/crates/model/tests/fixtures

It writes `model.json`:
- `fleet_documents`: generation documents with their `wire()` (key order kept), pydantic's stored
  form (`model_dump_json`), `canonical_digest`, `content_digest` and the push request's wire form;
- `validation`: inputs for every validated model with FastAPI's 422 body (the model as a request
  body) and `model_validate`'s outcome (the dump, or `str(ValidationError)`);
- `functions`: the routing normalisers, the egress-document helpers, the adapter-view parsers,
  `within_validity`, the metrics names and Python `repr`/`str` of JSON values.
No secrets: every credential-looking value is made up.
"""
import hashlib
import json
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from panel.clients import models as clients
from panel.fleet_v2 import protocol as fleet
from panel.fleet_v2.generations import content_digest
from panel.metrics import model as metrics
from panel.protocols import base as protocols
from panel.routing import document as rdoc
from panel.routing import models as routing


def text(value):
    return json.dumps(value, ensure_ascii=False)


def digest(document):
    return rdoc.document_digest(document)


NAIVE_WARP = {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
NAIVE_BLOCK = {"schema": 1, "upstream": None, "acl": [{"deny": ["example.com", "*.пример.рф"]}]}
WARP_INTENT = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": [],
               "note": "Узел ✓ 🙂", "ratio": 0.5, "big": 1e16, "small": 1e-05}
MIERU_DOC = {"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
             "rules": [{"domains": ["a.example"], "cidrs": [], "action": "PROXY", "proxy": "warp"}]}


def egress(document, *, backend="naive_native", companion=None, passthrough=False, policy="p-1", revision=1):
    section = {"backend": backend, "policy_id": policy, "policy_revision": revision, "document": document,
               "digest": digest(document)}
    if companion is not None:
        section["companion"] = companion
    if passthrough:
        section["passthrough"] = True
    return section


def resource(ref, protocol="naive", user="alice", **extra):
    item = {"ref": ref, "protocol": protocol, "runtime_username": user, "desired_state": "enabled",
            "credential_ref": f"{ref}:1", "credential_origin": "caller"}
    item.update(extra)
    return item


def document(**overrides):
    base = {"node_guid": "n" * 36, "master_guid": "m" * 36, "generation": 3, "previous_generation": 2,
            "created_at": 1761400000, "created_by": "owner",
            "resources": [resource("grant:a", options={"quota_bytes": 5})]}
    base.update(overrides)
    return base


FLEET_DOCUMENTS = {
    "plain": document(),
    "empty": document(resources=[], created_by=""),
    "unicode_and_numbers": document(created_by="Сергей 🙂 \"q\" \\  ", resources=[
        resource("grant:z", "mieru", "zed", options={"quotas": [{"days": 30, "megabytes": 1024}],
                                                     "share_template": "mierus://{username}:{password}@h?n=Ж",
                                                     "float": 1.5, "tiny": 1e-07, "huge": 1e22, "neg": -0.0}),
        resource("grant:a", "naive", "alice", options={}, valid_from=10, valid_until=20),
        resource("grant:m", "mtproxy", "mt", options={"host": "proxy.example", "port": 443},
                 credential_origin="manager", origin="imported", desired_state="disabled"),
    ]),
    "every_protocol": document(resources=[
        resource("grant:1", "mtproxy", "u1"), resource("grant:2", "naive", "u2"), resource("grant:3", "mieru", "u3"),
        resource("grant:4", "amneziawg", "u4", options={"version": "3.1", "dns": ["1.1.1.1"],
                                                         "obfuscation": {"Jc": "4", "H1": "1-2"}}),
        resource("grant:5", "trusttunnel", "u5", options={"hostname": "tt.example", "port": 443}),
        resource("grant:6", "naive", "u6", desired_state="deleted"),
    ]),
    "egress": document(egress={"naive": egress(NAIVE_WARP), "mieru": egress(MIERU_DOC, backend="mieru_native")}),
    "egress_router": document(egress={
        "naive": egress(WARP_INTENT, backend="xray_router", companion=rdoc.attach_document("naive")),
        "mtproxy": egress(rdoc.TELEMT_DIRECT_DOCUMENT, backend="mtproxy_native", passthrough=True),
        "trusttunnel": egress(rdoc.ATTACH_DOCUMENTS["trusttunnel"], backend="trusttunnel_native"),
        "amneziawg": egress({"schema": 1, "upstream": None}, backend="amneziawg_native", companion=None),
    }),
    "lanes_and_relay": document(resources=[resource("grant:b", user="bob", lane="own"), resource("grant:a")],
                                relay={"enabled": True, "port": 45443, "server_name": "node.example",
                                       "accounts": [{"email": "relay:" + "b" * 32 + ":warp",
                                                     "credential_ref": "relay:abc:1"},
                                                    {"email": "relay:src-1:direct", "credential_ref": "relay:def:2"}]}),
    "relay_off": document(relay={"enabled": False, "port": 1, "server_name": "x"}),
    "lax_coercions": document(generation="7", previous_generation=6.0, created_at="1761400000",
                              resources=[resource("grant:c", options={"nested": {"b": [1, 2, {"z": None}], "a": True}})]),
    "explicit_defaults": document(schema_version=1, egress=None, relay=None,
                                  resources=[resource("grant:d", origin="provisioned", options={}, valid_from=None,
                                                      valid_until=None, lane=None)]),
    "unsorted_refs": document(resources=[resource("grant:9"), resource("grant:10", user="b"),
                                         resource("Grant:0", user="c"), resource("grant:ä", user="d")]),
}


# -- validation corpus ---------------------------------------------------------------

def push(**overrides):
    base = {"expected_guid": "n" * 36, "generation": document(), "secrets": {"grant:a:1": "pw"}}
    base.update(overrides)
    return base


VALIDATION = {
    "Resource": [
        resource("x"), resource("x", protocol="xray"), resource("x", desired_state="paused"),
        resource("x", user="has space"), resource("x", user="a" * 65), resource("x", user="ok\n"),
        {**resource("x"), "ref": ""}, {**resource("x"), "ref": "r" * 129}, {**resource("x"), "credential_ref": ""},
        resource("x", lane="theirs"), resource("x", lane="own"), resource("x", future=1),
        resource("x", options=[1]), resource("x", valid_from="12"), resource("x", valid_from=1.5),
        resource("x", valid_from=True), resource("x", valid_until="soon"), resource("x", origin="adopted"),
        {"ref": "x"}, {}, [], "text", None, 5,
        resource("x", user=5), {**resource("x"), "ref": 5}, resource("x", credential_origin=None),
        resource("x", valid_from=12.0), resource("x", valid_from=" 12 "), resource("x", valid_from="1_000"),
        resource("x", valid_from="1e3"), resource("x", valid_from="12.0"), resource("x", valid_from=False),
        resource("x", valid_from=2 ** 63), resource("x", valid_from=-5), resource("x", protocol=1),
        resource("Ж" * 128), resource("Ж" * 129), resource("x", user="Ж"),
    ],
    "RelayAccount": [
        {"email": "relay:abc:warp", "credential_ref": "a:1"}, {"email": "bogus", "credential_ref": "a:1"},
        {"email": "relay:abc:warp", "credential_ref": "a:"}, {"email": "relay:abc:direct\n", "credential_ref": "abc"},
        {"email": "relay:" + "a" * 65 + ":warp", "credential_ref": "abc"}, {"email": "relay:a_b:warp", "credential_ref": "abc"},
    ],
    "RelaySection": [
        {"enabled": True, "port": 45443, "server_name": "node.example"},
        {"enabled": "yes", "port": "443", "server_name": "n"}, {"enabled": "maybe", "port": 0, "server_name": ""},
        {"enabled": 2, "port": 65536, "server_name": "x" * 254}, {"enabled": 1.0, "port": 1, "server_name": "x"},
        {"enabled": "OFF", "port": 1, "server_name": "x"}, {"enabled": None, "port": None, "server_name": None},
        {"enabled": True, "port": 1, "server_name": "x", "accounts": [{"email": "bogus", "credential_ref": "a"}] * 2},
        {"enabled": True, "port": 1, "server_name": "x",
         "accounts": [{"email": "relay:a:warp", "credential_ref": "a:1"}] * 65},
        {"enabled": True, "port": 1, "server_name": "x", "accounts": [1, "x"]},
        {"enabled": True, "port": 1, "server_name": "x", "accounts": {"a": 1}},
        {"enabled": "t", "port": 1, "server_name": "x"}, {"enabled": "Yes", "port": 1, "server_name": "x"},
        {"enabled": " true", "port": 1, "server_name": "x"}, {"enabled": 0, "port": 1, "server_name": "x"},
        {"enabled": 0.5, "port": 1, "server_name": "x"},
    ],
    "EgressDocument": [
        egress(NAIVE_WARP), {**egress(NAIVE_WARP), "digest": "0" * 64}, {**egress(NAIVE_WARP), "digest": "X" * 64},
        {**egress(NAIVE_WARP), "backend": "xray"}, {**egress(NAIVE_WARP), "policy_revision": 0},
        {**egress(NAIVE_WARP), "document": [1]}, {**egress(NAIVE_WARP), "companion": "no"},
        egress({"schema": 1, "upstream": None, "acl": [{"deny": [f"{'x' * 60}{i:04d}.example" for i in range(300)]}]}),
        egress(WARP_INTENT, backend="xray_router",
               companion={"schema": 1, "upstream": None, "acl": [{"deny": [f"{'x' * 60}{i:04d}.example" for i in range(300)]}]}),
        egress(WARP_INTENT, backend="xray_router", companion=rdoc.attach_document("naive"), passthrough=True),
        {**egress(NAIVE_WARP), "passthrough": "yes"}, {**egress(NAIVE_WARP), "policy_id": ""},
        {**egress(NAIVE_WARP), "unknown": 1},
    ],
    "GenerationDocument": [
        document(), document(generation=0, previous_generation=0), document(schema_version=2),
        document(schema_version="1"), document(schema_version=True), document(schema_version=1.0),
        document(node_guid="", master_guid="m" * 65, created_by="c" * 129),
        document(resources=[resource("grant:a"), resource("grant:a2", desired_state="disabled")]),
        document(resources=[resource("grant:a"), resource("grant:b", "mieru"), resource("grant:c", "naive", user="alice")]),
        document(resources=[resource(f"grant:{i}", user=f"u{i}") for i in range(501)]),
        document(resources=[resource("x", protocol="xray")] * 2 + [resource(f"g{i}", user=f"u{i}") for i in range(500)]),
        document(egress={"socks": egress(NAIVE_WARP)}),
        document(egress={"naive": {**egress(NAIVE_WARP), "x": 1}}),
        document(egress={"naive": {**egress(NAIVE_WARP), "digest": "0" * 64}, "mieru": egress(MIERU_DOC)}),
        document(egress=[]), document(relay={"enabled": True}), document(resources=None),
        document(resources={"a": 1}), document(future_field=1), document(created_at=None),
        {}, document(egress={"naive": egress(NAIVE_WARP), "socks": 1}),
    ],
    "PushRequest": [
        push(), push(secrets={"grant:zzz:1": "pw", "grant:aaa:1": "x"}), push(shell="rm -rf /"),
        push(secrets={"grant:a:1": 5}), push(secrets=[]), push(expected_guid=None),
        push(generation=document(generation=0)), push(generation="doc"),
        push(generation=document(relay={"enabled": True, "port": 1, "server_name": "x",
                                         "accounts": [{"email": "relay:a:warp", "credential_ref": "relay:1"}]}),
             secrets={"relay:1": "uuid", "grant:a:1": "pw"}),
        push(generation=document(resources=[resource("grant:a"), resource("grant:b", user="alice")]),
             secrets={"zz": "1"}),
        {"generation": document()},
    ],
    "ObservedResource": [
        {"ref": "grant:1", "protocol": "mtproxy", "runtime_username": "a", "state": "enabled",
         "learned": {"host": "proxy.example", "port": 443, "dns": ["1.1.1.1"], "obf": {"Jc": "4"}}},
        {"ref": "grant:1", "protocol": "naive", "runtime_username": "a", "state": "missing", "future": {"x": 1}},
        {"ref": "grant:1", "protocol": "naive", "runtime_username": "a", "state": "gone"},
        {"ref": "grant:1", "protocol": "naive", "runtime_username": "a", "state": "enabled",
         "learned": {f"k{i}": i for i in range(9)}},
        {"ref": "grant:1", "protocol": "naive", "runtime_username": "a", "state": "enabled",
         "learned": {"a": 1.5, "b": True, "c": None, "d": [1], "e": {"x": 1}, "f": "5", "g": 2.0}},
        {"ref": 1, "protocol": None, "runtime_username": [], "state": "enabled", "error": 5, "revision": 1.5},
        {"ref": "grant:1", "protocol": "awg", "runtime_username": "a", "state": "drifted", "error": "e", "revision": "r",
         "learned": {"b": True, "g": 2.0, "f": "5", "x": ["a", "b"], "y": {"k": "v"}, "z": False, "n": -3, "e": []}},
        {"ref": "grant:1", "protocol": "awg", "runtime_username": "a", "state": "enabled", "learned": []},
    ],
    "ObservedEgress": [
        {"state": "converged", "revision": "r1", "digest": "d", "router": {"revision": "x"}, "lanes": ["grant:a"]},
        {"state": "unsupported"}, {"state": "odd"}, {"state": "failed", "error": "egress_invalid", "lanes": "x"},
        {"state": "converged", "router": "no", "future": 1},
    ],
    "ObservedRelay": [
        {"state": "converged", "enabled": True, "port": 443, "server_name": "n", "public_key": "pk", "short_id": "ab",
         "accounts": ["relay:a:warp"], "error": None, "extra": 1},
        {"state": "failed", "error": "relay_disabled"}, {"state": "x", "port": "p", "accounts": [1]},
    ],
    "ObservedGeneration": [
        {"applied_generation": 0, "digest": "", "reconcile_state": "idle", "resources": [], "reported_at": 0,
         "egress": {}, "relay": None},
        {"applied_generation": 1, "digest": "d", "reconcile_state": "converged", "reported_at": 1,
         "resources": [{"ref": "grant:1", "protocol": "naive", "runtime_username": "a", "state": "enabled",
                        "future_field": {"x": 1}}], "another_future_field": True},
        {"applied_generation": "2", "digest": "d", "reconcile_state": "applying", "reported_at": 5, "resources": [],
         "egress": {"naive": {"state": "converged", "revision": "r", "digest": "x"}, "mieru": {"state": "bad"}},
         "relay": {"state": "converged", "enabled": True}},
        {"digest": 1, "reconcile_state": "done", "resources": {}},
    ],
    "PushResponse": [
        {"observed": {"applied_generation": 1, "digest": "d", "reconcile_state": "converged", "reported_at": 1,
                      "resources": []}, "credentials": {"naive:a": "pw"}, "future": 1},
        {"observed": None}, {"credentials": {"a": 1}},
    ],
    "RuleMatch": [
        {"domains": ["Example.COM.", "*.CDN.example", "пример.рф", "example.com"],
         "cidrs": ["10.1.2.3", "192.168.1.0/24", "2001:db8::1", "10.0.0.5/8"], "ports": [443, "80", "1000-2000"]},
        {"domains": ["exa mple.com"]}, {"domains": ["*"]}, {"domains": ["a.*.com"]}, {"domains": ["-bad.com"]},
        {"cidrs": ["300.1.1.1"]}, {"cidrs": ["10.0.0.0/33"]}, {"domains": ["ok.com"], "ports": [0]},
        {"domains": ["ok.com"], "ports": ["9-1"]}, {"domains": ["ok.com"], "ports": [True]},
        {"domains": ["ok.com"], "extra": 1}, {}, {"ports": [443]}, {"ports": [25, "80-90"]},
        {"domains": [f"h{i}.com" for i in range(65)]}, {"cidrs": [f"10.0.{i}.0/24" for i in range(65)]},
        {"domains": ["a.com"], "ports": list(range(1, 34))}, {"domains": ["a.com"], "ports": [443] * 40},
        {"domains": ["a.com"], "ports": "443"}, {"domains": ["a.com"], "ports": None},
        {"domains": ["a.com"], "ports": [1.5]}, {"domains": ["a.com"], "ports": ["²"]},
        {"domains": ["a.com"], "ports": ["٨٠"]}, {"domains": ["a.com"], "ports": [" 80 ", "080", "1-65535", "0-5"]},
        {"domains": ["a.com"], "ports": [{"a": 1}]}, {"domains": ["a.com"], "ports": [None]},
        {"geosites": ["geosite:Category-Ads-All", "category-ads-all", "cn"], "geoips": ["GeoIP:CN", "cloudflare"]},
        {"geoips": ["private"]}, {"geosites": ["not a code"]}, {"geosites": [5]}, {"geoips": ["geoip:"]},
        {"protocols": [" TLS ", "http", "tls"]}, {"protocols": ["ssh"]}, {"protocols": [1]},
        {"protocols": ["tls", "http", "quic", "bittorrent", "tls"]}, {"domains": [5, "a.com", None]},
        {"domains": "a.com"}, {"cidrs": [" 10.0.0.1 ", "::ffff:1.2.3.4/120", "fe80::1%eth0/64", "fe80::%eth0/64",
                                         "10.0.0.0/255.0.0.0", "10.0.0.0/0.0.0.255", "1.2.3.4/32", "0.0.0.0/0", "::/0"]},
        {"cidrs": ["10.0.0.0/8/9"]}, {"cidrs": ["10.0.0.0/255.0.255.0"]}, {"cidrs": ["1.2.3.4/64"]}, {"cidrs": [""]},
        {"cidrs": ["010.0.0.1"]}, {"cidrs": [None]}, {"cidrs": ["10.0.0.0/ 8"]}, {"cidrs": ["10.0.0.0/+8"]},
        {"domains": ["straße.de", "ÉCOLE.fr", "xn--e1afmkfd.xn--p1ai", "a..b", "a" * 64 + ".com", "日本。jp"]},
        {"domains": ["xn--e1afmkfd.рф"]}, {"domains": ["ex­ample.com"]}, {"domains": ["الa.com"]},
        {"domains": ["ال.com"]}, {"domains": ["*.*.a.com"]}, {"domains": ["a/b.com"]}, {"domains": [""]},
        {"domains": ["."]}, {"domains": ["*."]}, {"domains": ["xn--abc.com"]}, {"domains": ["a.com\n"]},
        {"domains": ["Ⅳ.com"]}, {"domains": ["ﬁ.com"]}, {"domains": ["​zero.com"]},
        {"domains": ["xn--d1acufc.xn--p1ai", "XN--zz.Com"]}, {"domains": ["эх.com", "ЭХ.COM"]},
    ],
    "RoutingRule": [
        {"match": {"domains": ["a.com"]}, "action": "block"},
        {"match": {"domains": ["a.com"]}, "action": "egress"},
        {"match": {"domains": ["a.com"]}, "action": "block", "egress": "warp"},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": " WARP "},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "tor"},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "node:" + "b" * 32 + ":WARP"},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "exit:My-Exit_1"},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "node:nope!"},
        {"match": {"domains": ["a.com"]}, "action": "block", "note": "x" * 121},
        {"match": {"domains": ["a.com"]}, "action": "block", "preset": "Bad Name"},
        {"match": {"domains": ["a.com"]}, "action": "block", "preset": ""},
        {"match": {"domains": ["a.com"]}, "action": "block", "preset": "torrent", "id": "0" * 8 + "-0000-4000-8000-" + "0" * 12,
         "position": 3, "enabled": "false", "note": "Заметка"},
        {"match": {"domains": ["a.com"]}, "action": "block", "id": "not-a-uuid"},
        {"match": {"domains": ["a.com"]}, "action": "block", "position": -1},
        {"match": {}, "action": "redirect"}, {"action": "block"}, {"match": "x", "action": "block"},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": 5},
        {"match": {"domains": ["a.com"]}, "action": "block", "preset": "x" * 33},
        {"match": {"domains": ["a.com"]}, "action": "block", "preset": 5},
        {"match": {"protocols": ["bittorrent"]}, "action": "block", "preset": "torrent"},
    ],
    "PolicyInput": [
        {}, {"default_action": "egress"}, {"default_action": "direct", "default_egress": "warp"},
        {"default_action": "egress", "default_egress": "tor"}, {"default_action": "egress", "default_egress": "WARP"},
        {"revision": 3}, {"state": "applied"}, {"backend": "xray_router"}, {"backend": "sing_box"},
        {"default_action": "egress", "default_egress": "node:" + "b" * 32 + "," + "c" * 32,
         "rules": [{"match": {"domains": ["a.example"]}, "action": "egress", "egress": "node:" + "b" * 32 + ":warp"},
                   {"match": {"domains": ["a.example"]}, "action": "egress", "egress": "warp"}]},
        {"rules": [{"match": {"domains": ["a.com"]}, "action": "block"}] * 129},
        {"rules": [{"match": {"domains": ["a.com"]}, "action": "block"}] * 128},
        {"fallback": "open", "rules": [{"match": {}, "action": "block"}, {"match": {"domains": ["b.com"]}, "action": "x"}]},
        {"default_action": "egress", "default_egress": "node:" + "b" * 32 + "," + "b" * 32},
        {"rules": None}, {"default_egress": "warp"},
    ],
    "RoutingPolicy": [
        {"id": "p1", "node_id": "local", "protocol": "naive", "backend": "naive_native", "revision": 1},
        {"id": "p1", "node_id": "local", "protocol": "naive", "backend": "naive_native", "revision": 0, "state": "x"},
        {"id": "p1", "node_id": "n1", "protocol": "trusttunnel", "lane": "grant:g1", "backend": "xray_router",
         "revision": 7, "state": "applied", "applied_revision": 7, "applied_digest": "d", "applied_at": 5,
         "last_error": None, "created_at": 1, "updated_at": 2, "default_action": "egress", "default_egress": "warp",
         "rules": [{"id": "1" * 8 + "-0000-4000-8000-" + "1" * 12, "position": 0, "match": {"domains": ["a.com"]},
                    "action": "block"}]},
    ],
    "Reason": [{"code": "x"}, {"code": "x", "rule_id": "r", "message": "m"}, {"code": 1}, {"message": "m", "y": 1}],
    "MieruQuota": [{"days": 30, "megabytes": 10}, {"days": "30", "megabytes": 10}, {"days": 0, "megabytes": 2 ** 31},
                   {"days": 30.0, "megabytes": True}, {"days": 3651}],
    "MtproxyOptions": [
        {}, {"max_tcp_conns": 0}, {"max_tcp_conns": "5"}, {"data_quota_bytes": 2 ** 63 - 1}, {"data_quota_bytes": 2 ** 63},
        {"rate_limit_up_bps": 10 ** 12 + 1}, {"max_unique_ips": 100001}, {"expiration": -1}, {"expiration": 0},
        {"host": ""}, {"host": "h" * 254}, {"port": 0}, {"port": 443.0}, {"port": True}, {"x": 1},
        {"host": "proxy.example", "port": 443, "max_tcp_conns": 10, "rate_limit_down_bps": 10 ** 12},
    ],
    "NaiveOptions": [{}, {"quota_bytes": 5}, {"quota_bytes": "5"}, {"quota_bytes": 0}, {"quota_bytes": None},
                     {"quota_bytes": 5, "x": None}],
    "MieruOptions": [
        {}, {"quotas": []}, {"quotas": [{"days": 30, "megabytes": 10}]},
        {"quotas": [], "share_template": "mierus://u:realpassword@h?port=1"},
        {"quotas": [], "share_template": "mierus://{username}:{password}@h?port=1"},
        {"share_template": "no placeholders"}, {"share_template": "{username}{password}"},
        {"share_template": "x" * 513}, {"share_template": "Mierus://real@h {username}{password}"},
        {"share_template": "mierus://{username}:{password}/@h"},
        {"share_template": "m+x.-://{username}:{password}@h"}, {"share_template": "mierus://a/{username}:{password}@h"},
        {"quotas": [{"days": 30, "megabytes": 10}] * 17}, {"quotas": [{"days": 0}]}, {"quotas": "x"},
        {"share_template": None}, {"share_template": 5},
    ],
    "AmneziawgOptions": [
        {}, {"version": "1.0"}, {"version": "4.0"}, {"version": 2.0}, {"address": "999.1.1.1"}, {"address": "10.8.0.2"},
        {"address": "1.2.3"}, {"address": "01.2.3.4"}, {"address": "a.b.c.d"}, {"address": "1.2.3.1234"},
        {"address": ""}, {"address": "1.2.3.4/32"}, {"address": "1..2.3"}, {"address": "1.2.3.٤"},
        {"address": "1234567890123456"}, {"port": 0}, {"obfuscation": {"Evil": "1"}},
        {"obfuscation": {"Jc": "1\nPostUp = rm -rf /"}}, {"obfuscation": {"Jc": 5}}, {"obfuscation": {"Jc": "x" * 2049}},
        {"dns": ["not-an-ip"]}, {"dns": ["1.1.1.1", "2606:4700::1111"]}, {"dns": ["1.1.1.1"] * 5}, {"dns": [5]},
        {"unknown": 1}, {"server_public_key": "k" * 43}, {"server_public_key": "k" * 44}, {"mtu": 575},
        {"mtu": 1280, "version": "3.1", "address": "10.8.0.2", "port": 51820, "dns": ["1.1.1.1"],
         "obfuscation": {"Jc": "4", "Jmin": "10", "I1": "<b 0x01>"}},
    ],
    "TrusttunnelOptions": [
        {}, {"hostname": "bad host"}, {"hostname": "-x.example"}, {"hostname": "tt.example"}, {"hostname": "tt.example\n"},
        {"hostname": "a"}, {"hostname": "a-"}, {"hostname": "x" * 254}, {"port": 0}, {"port": 70000},
        {"certificate_der_b64": "not base64!"}, {"certificate_der_b64": "QUJD"}, {"certificate_der_b64": "QUJD=="},
        {"certificate_der_b64": "QQ=="}, {"certificate_der_b64": "QQ="}, {"certificate_der_b64": "QQ"},
        {"certificate_der_b64": "QUJDRA="}, {"certificate_der_b64": "Q"}, {"certificate_der_b64": ""},
        {"certificate_der_b64": "=="}, {"certificate_der_b64": "QU JD"}, {"certificate_der_b64": "Ж"},
        {"certificate_der_b64": "QUJ="}, {"name": ""}, {"name": "x" * 65}, {"name": "Мой профиль"}, {"unknown": 1},
    ],
    "Client": [
        {"id": "c1", "display_name": "Sergey", "state": "active", "created_at": 1, "updated_at": 2},
        {"id": "c1", "display_name": "", "state": "deleted", "created_at": 1, "updated_at": 2, "metadata": {"a": 1}},
        {"id": "c1", "display_name": "x" * 129, "state": "active\n", "created_at": "1", "updated_at": 2.5},
    ],
}

# -- functions -----------------------------------------------------------------------------


def outcome(function, *args):
    try:
        return {"ok": True, "value": function(*args)}
    except (ValueError, UnicodeError) as exc:
        return {"ok": False, "error": str(exc), "class": type(exc).__name__}


EXITS = ["warp", " WARP ", "Warp", "exit:My-Exit_1", "EXIT:a", "exit:", "exit:a b", "exit:" + "x" * 65,
         "node:" + "b" * 32, "NODE:" + "b" * 32 + ":WARP", "node:" + "b" * 32 + "," + "c" * 32 + ":warp",
         "direct", "node:", "node:has space", "node:" + "b" * 32 + ":direct", "node:" + "b" * 32 + "," + "b" * 32,
         "node:a,b,c,d", "node:a,b,c", "socks5://x", "", None, 5, "node:a:warp:x", "node:a,,b", "node:İ",
         "ｗarp", "node:a:WARP ", "\twarp\n", "exit:a:b", "node:a:", "warp:", True]
LANES = [None, "", "svc", "grant:g1", "grant:" + "x" * 64, "grant:" + "x" * 65, "grant:", "lane", 5, "grant:a b", "SVC"]
DOMAINS = [
    "Example.COM.", "*.CDN.example", "пример.рф", "example.com", "exa mple.com", "*", "a.*.com", "-bad.com",
    "straße.de", "ÉCOLE.fr", "xn--e1afmkfd.xn--p1ai", "a..b", "a" * 63 + ".com", "a" * 64 + ".com", "日本。jp",
    "xn--e1afmkfd.рф", "ex­ample.com", "الa.com", "ال.com", "אב.com", "*.*.a.com",
    "a/b.com", "", ".", "*.", "xn--abc.com", "a.com\n", "Ⅳ.com", "ﬁ.com", "​zero.com", "XN--zz.Com",
    "эх.com", "ЭХ.COM", "Ǆ.com", "ß", "ς.gr", "Σ.gr", "İstanbul.tr", "ﾟ.jp", "①.com", "㎏.com", "á.com",
    "á.com", "ẞ.de", "ϐ.gr", "localhost", "a.b.c.d.e", "1.2.3.4", "a_b.com", "a-.com", "a--b.com",
    "x" * 300, ("a" * 60 + ".") * 4 + "com", ("a" * 61 + ".") * 4 + "co", "\U0001f600.com", "﻿a.com",
    "a。b．c｡d", "ـ.com", "אa.com", "aא.com", "א١א.com", "‍.com",
    ".com", "\x80.com", "ȡ.com", "͸.com", 5, None, "*.пример.рф", " Пример.РФ ", "a　b.com",
]
CIDRS = ["10.1.2.3", "192.168.1.0/24", "2001:db8::1", "10.0.0.5/8", "300.1.1.1", "10.0.0.0/33", " 10.0.0.1 ",
         "::ffff:1.2.3.4/120", "fe80::1%eth0/64", "fe80::%eth0/64", "fe80::1%eth0", "10.0.0.0/255.0.0.0",
         "10.0.0.0/0.0.0.255", "1.2.3.4/32", "0.0.0.0/0", "::/0", "10.0.0.0/8/9", "10.0.0.0/255.0.255.0",
         "1.2.3.4/64", "", "010.0.0.1", "10.0.0.0/ 8", "10.0.0.0/+8", "10.0.0.0/08", "10.0.0.0/", "::1/129",
         "2001:DB8::/32", "2001:db8:0:0:0:0:0:1/64", "::ffff:0:0/96", "1.2.3.4/0.0.0.0", "1.2.3.4/255.255.255.255",
         "10.0.0.0/٨", "fd00::/8", "a.b.c.d/8", 5, None, "1.2.3.4%x/32", "::/128", "1:2:3:4:5:6:7:8/127"]
GEO = [("geosite", "geosite:Category-Ads-All"), ("geosite", "cn"), ("geosite", "not a code"), ("geoip", "private"),
       ("geoip", "GeoIP:Private"), ("geoip", "geoip:"), ("geoip", "CN"), ("geosite", "a@b!c_d-e"), ("geosite", "x" * 64),
       ("geosite", "x" * 65), ("geosite", "-a"), ("geosite", "geoip:cn"), ("geoip", " cn "), ("geosite", 5),
       ("geosite", "İ"), ("geosite", "ab\n")]
PORTS = [443, 0, 65535, 65536, -1, True, False, "80", " 80 ", "080", "1000-2000", "9-1", "0-5", "1-65535", "1-65536",
         "²", "٨٠", "80-", "-80", "1 - 2", "00080-00090", "123456", "", 1.5, 80.0, None, [80], {"a": 1}, "８０",
         "1-٨٠", "80\n"]
HOPS = ["warp", None, "", "node:a", "node:a,b:warp", "node:a:warp", "exit:x", "node:"]
BACKENDS = ["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg", "xray", ""]

ATTACH_CASES = [
    ("naive", {"schema": 1, "upstream": {"provider": "router"}, "acl": []}), ("naive", NAIVE_WARP),
    ("mtproxy", {"upstream": {"provider": "router"}}), ("amneziawg", {"schema": 1, "upstream": {"provider": "router"}}),
    ("amneziawg", {"upstream": {"provider": "warp"}}), ("trusttunnel", {"mode": "socks5", "address": "127.0.0.1:45104"}),
    ("trusttunnel", {"address": "127.0.0.1:45104", "mode": "socks5"}), ("trusttunnel", {"mode": "direct"}),
    ("trusttunnel", {"mode": "socks5", "address": "127.0.0.1:45104", "x": 1}),
    ("mieru", rdoc.attach_document("mieru")),
    ("mieru", {"proxies": [{"name": "router"}], "rules": [{"x": 1}, {"domains": ["*"], "cidrs": ["*"], "action": "PROXY",
                                                                     "proxy": "router"}]}),
    ("mieru", {"proxies": [{"name": "router"}], "rules": []}), ("mieru", {"proxies": [], "rules": [
        {"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]}),
    ("mieru", {"proxies": ["router", {"name": "router"}], "rules": [{"proxy": "router", "action": "PROXY", "cidrs": ["*"],
                                                                     "domains": ["*"]}]}),
    ("mieru", {"proxies": None, "rules": None}), ("naive", None), ("naive", [1]), ("naive", {"upstream": {"provider": "router", "x": 1}}),
    ("xray", {"upstream": {"provider": "router"}}), ("mtproxy", {"schema": 1, "upstream": None}),
]
REDACT_CASES = [
    {"schema": 2, "chains": {"c1": {"hops": [{"node": "a", "uuid": "11111111-2222"}, {"node": "b"}, "x"]},
                             "c2": "bad", "c3": {"hops": [{"uuid": None}]}},
     "exits": {"e1": {"protocol": "vless", "credential": {"uuid": "u", "password": "p"}}, "e2": {"credential": "x"},
               "e3": "y"}, "lanes": {}},
    {"schema": 1, "rules": []}, {"chains": []}, {"chains": {"c": {"hops": "abc"}}, "exits": None}, [1, 2], "text", None,
    {"chains": {"c": {"hops": [{"uuid": "x"}]}}, "exits": {}},
]
DIFF_LINES = ['+  "uuid": "abc-123",', '-    "password":"secret"', '   "uuid" : "x"', '"uuid":"a","password": "b" x',
              '"uuid":\t\n"multi', '"uuid": "unterminated', 'plain line', '"UUID": "x"', '"uuid": ""',
              '"uuid":　"wide space"', '{"uuid": "a"}{"password": "b"}', '"password":   "p\\"q"']
LANE_DOC = {
    "schema": 2,
    "lanes": {"svc": {"default": {"action": "egress", "egress": "chain:c1"}, "rules": [{"egress": "exit:e1"}]},
              "grant:a": {"default": {"action": "direct", "egress": None}, "rules": [{"egress": "chain:c2"}]},
              "grant:b": {"default": {"egress": "exit:e2"}, "rules": []}},
    "chains": {"c1": {"hops": []}, "c2": {"hops": []}},
    "exits": {"e1": {"protocol": "socks"}, "e2": {"protocol": "http"}},
    "note": "kept",
}
WITHOUT_LANE = [(LANE_DOC, "grant:a"), (LANE_DOC, "grant:b"), (LANE_DOC, "svc"), (LANE_DOC, "grant:none"),
                ({**LANE_DOC, "schema": 1}, "grant:a"), ({"schema": 2, "lanes": {"grant:a": {}}}, "grant:a"),
                ({"schema": 2, "lanes": {"svc": {"rules": []}, "grant:a": {}}, "exits": {"e": {}}}, "grant:a"),
                ({"schema": 2, "lanes": {"svc": {"default": {"egress": "chain:c"}}, "grant:a": {}}, "chains": {"c": 1}},
                 "grant:a"), ("not a dict", "grant:a")]

EGRESS_VIEWS = [
    ("naive", "naive_native", {}),
    ("naive", "naive_native", {"revision": "r1", "document": NAIVE_WARP, "capabilities": ["whole_warp", 5, "block_cidr"],
                               "providers": {"warp": {"reachable": True, "endpoint": "x"}, "bad": 1, "z": {}},
                               "mode": "proxy", "restart_required": True, "warnings": ["w1", 2]}),
    ("naive", "naive_native", {"revision": 7, "document": None, "mode": "other", "restart_required": 1}),
    ("trusttunnel", "trusttunnel_native", {"revision": None, "document": rdoc.ATTACH_DOCUMENTS["trusttunnel"],
                                           "mode": "custom", "restart_required": "yes"}),
    ("mieru", "mieru_native", {"revision": 1.5, "document": rdoc.attach_document("mieru"), "providers": None}),
    ("mtproxy", "mtproxy_native", {"revision": True, "document": {"schema": 1, "upstream": {"provider": "router"}}}),
    ("amneziawg", "amneziawg_native", {"revision": {"a": 1}, "document": {}, "mode": "direct"}),
]
ROUTER_VIEWS = [
    ("naive", {}),
    ("naive", {"revision": "r2", "document": WARP_INTENT, "capabilities": ["lanes"], "providers": {"warp": {"reachable": False}},
               "runtime_version": "26.10.17", "restart_required": False}),
    ("mieru", {"revision": 0, "runtime_version": 5, "restart_required": None, "document": None}),
]
APPLIED_VIEWS = [{}, {"revision": "r3", "applied": NAIVE_WARP, "readback_sha256": "ab", "replayed": True},
                 {"revision": 4, "applied": None, "readback_sha256": 5, "replayed": "yes"}]
EGRESS_ERRORS = [("naive-manager", 409, None), ("naive-manager", 422, "nope"), ("mieru-manager", 500, None),
                 ("x", 409, "manual_intervention_required"), ("x", 503, "egress_unreachable"), ("x", 400, "lanes_invalid"),
                 ("x", 422, "egress_unsupported"), ("x", 409, "relay_disabled")]
VALIDITY = [(None, None, 5), (5, None, 5), (6, None, 5), (None, 5, 5), (None, 6, 5), (1, 10, 10), (1, 10, 1), (10, 1, 5)]
REPR_VALUES = [None, True, False, 0, -5, 2 ** 63 - 1, 1.5, 1e16, 1e-05, -0.0, "", "a'b", 'a"b', "a'b\"c", "\n\t\\",
               "Ж🙂", "\x00\x7f\x80\xa0 ", "퟿", [], [1, "a", None], {}, {"a": 1, "b": [True, {"c": "d"}]},
               {"k'": "v\""}, [[], {}], "\U0001f600" * 3]
PROTECTED_REPR = ["\u0085", "­", "͸", "", "\U000e0001", "　", "​"]


def protocols_target(target):
    return {"protocol": target.protocol, "backend": target.backend, "capabilities": sorted(target.capabilities),
            "providers": target.providers, "revision": target.revision, "applied": target.applied, "mode": target.mode,
            "restart_required": target.restart_required, "warnings": list(target.warnings),
            "runtime_version": target.runtime_version, "router_attached": target.router_attached}


def router_target(target):
    return {"available": target.available, "service": target.service, "capabilities": sorted(target.capabilities),
            "providers": target.providers, "revision": target.revision, "applied": target.applied,
            "xray_version": target.xray_version, "restart_required": target.restart_required, "reason": target.reason}


def functions():
    out = {}
    out["normalise_exit"] = [{"input": value, **outcome(routing.normalise_exit, value)} for value in EXITS]
    out["normalise_lane"] = [{"input": value, **outcome(routing.normalise_lane, value)} for value in LANES]
    out["normalise_domain"] = [{"input": value, **outcome(routing.normalise_domain, value)} for value in DOMAINS]
    out["normalise_cidr"] = [{"input": value, **outcome(routing.normalise_cidr, value)} for value in CIDRS]
    out["normalise_geo_code"] = [{"input": value, "kind": kind, **outcome(routing.normalise_geo_code, value, kind)}
                                 for kind, value in GEO]
    out["normalise_port"] = [{"input": value, **outcome(routing.normalise_port, value)} for value in PORTS]
    out["exit_hops"] = [{"input": value, "value": list(routing.exit_hops(value))} for value in HOPS]
    out["backends_for"] = [{"input": value, "value": list(routing.backends_for(value))} for value in BACKENDS]
    out["constants"] = {
        "BACKEND_FOR": routing.BACKEND_FOR, "LANE_PROTOCOLS": list(routing.LANE_PROTOCOLS),
        "COMPILER_VERSION": routing.COMPILER_VERSION, "SNIFFED_PROTOCOLS": list(routing.SNIFFED_PROTOCOLS),
        "AMNEZIAWG_WHOLE_ONLY": routing.AMNEZIAWG_WHOLE_ONLY,
        "LANES_UNSUPPORTED_AMNEZIAWG": routing.LANES_UNSUPPORTED_AMNEZIAWG,
        "LANES_UNSUPPORTED_TRUSTTUNNEL": routing.LANES_UNSUPPORTED_TRUSTTUNNEL,
        "EGRESS_REASON_CODES": sorted(rdoc.EGRESS_REASON_CODES), "EGRESS_ERROR_CODES": sorted(protocols.EGRESS_ERROR_CODES),
        "ATTACH_DOCUMENTS": rdoc.ATTACH_DOCUMENTS, "TRUSTTUNNEL_DIRECT_DOCUMENT": rdoc.TRUSTTUNNEL_DIRECT_DOCUMENT,
        "TELEMT_DIRECT_DOCUMENT": rdoc.TELEMT_DIRECT_DOCUMENT, "MTPROXY_BRIDGE_ADDRESS": rdoc.MTPROXY_BRIDGE_ADDRESS,
        "ROUTER_DIRECT_INTENT": rdoc.ROUTER_DIRECT_INTENT, "CONFLICT_CODES": list(fleet.CONFLICT_CODES),
        "PROTOCOLS": list(clients.PROTOCOLS), "AWG_VERSIONS": list(clients.AWG_VERSIONS),
        "AWG_OBFUSCATION_KEYS": sorted(clients.AWG_OBFUSCATION_KEYS),
    }
    out["attach_document"] = {protocol: text(rdoc.attach_document(protocol)) for protocol in rdoc.ATTACH_DOCUMENTS}
    out["attached_to_router"] = [{"protocol": p, "document": d, "value": rdoc.attached_to_router(p, d)}
                                 for p, d in ATTACH_CASES]
    out["canonical"] = [{"document": d, "canonical": rdoc.canonical(d).decode(), "digest": digest(d)}
                        for d in [NAIVE_WARP, NAIVE_BLOCK, WARP_INTENT, MIERU_DOC, LANE_DOC, {}, {"é": [1.0, -0.0, 1e16]}]]
    out["redact_document"] = [{"document": d, "value": text(rdoc.redact_document(d))} for d in REDACT_CASES]
    out["redact_diff"] = {"lines": DIFF_LINES, "value": rdoc.redact_diff(DIFF_LINES)}
    out["without_lane"] = [{"document": d, "lane": lane, "value": text(rdoc.without_lane(d, lane))} for d, lane in WITHOUT_LANE]
    out["egress_target_from_view"] = [{"protocol": p, "backend": b, "view": v,
                                       "value": protocols_target(protocols.egress_target_from_view(p, b, v))}
                                      for p, b, v in EGRESS_VIEWS]
    out["router_target_from_view"] = [{"service": s, "view": v, "value": router_target(protocols.router_target_from_view(s, v))}
                                      for s, v in ROUTER_VIEWS]
    out["applied_egress_from_view"] = [{"view": v, "value": vars(protocols.applied_egress_from_view(v))}
                                       for v in APPLIED_VIEWS]
    errors = []
    for runtime, status, code in EGRESS_ERRORS:
        error = protocols.egress_error(runtime, status, code)
        errors.append({"runtime": runtime, "status": status, "code": code, "class": type(error).__name__,
                       "message": str(error), "value_code": error.code, "already_gone": error.already_gone})
    out["egress_error"] = errors
    out["within_validity"] = [{"args": list(args), "value": clients.within_validity(*args)} for args in VALIDITY]
    out["metrics"] = {"ALL_SERIES": list(metrics.ALL_SERIES), "RANGES": metrics.RANGES,
                      "RETENTION": {str(k): v for k, v in metrics.RETENTION.items()},
                      "POINTS": [metrics.POINTS_MIN, metrics.POINTS_MAX, metrics.POINTS_DEFAULT],
                      "resolution_for": [[seconds, metrics.resolution_for(seconds)]
                                         for seconds in (0, 900, 259200, 259201, 3024000, 3024001, 7776000)],
                      "is_bytes_series": [[name, metrics.is_bytes_series(name)]
                                          for name in ("naive.up_bytes", "naive.up_bps", "host.cpu", "_bytes")]}
    out["repr"] = [{"value": v, "repr": repr(v), "str": str(v)} for v in REPR_VALUES + PROTECTED_REPR]
    compiled = [
        routing.Compiled(status="supported", document=REDACT_CASES[0], digest=digest(REDACT_CASES[0]),
                         diff=DIFF_LINES[:3], warnings=["w"], backend="xray_router", attach=rdoc.attach_document("naive"),
                         rollback={"to_revision": "r", "to_digest": "d"}),
        routing.Compiled(status="unsupported", reasons=[routing.Reason(code="backend_capability_missing", rule_id="r1",
                                                                       message="naive_native lacks block_cidr")]),
    ]
    out["compiled_redacted"] = [{"dump": text(item.model_dump()), "redacted": text(item.redacted())} for item in compiled]
    policy = routing.RoutingPolicy.model_validate(VALIDATION["RoutingPolicy"][2])
    out["policy_input_from_policy"] = text(routing.PolicyInput.from_policy(policy).model_dump())
    intent = routing.PolicyInput.model_validate(VALIDATION["PolicyInput"][9])
    out["intent_exits"] = {"exits": intent.exits(), "node_exits": intent.node_exits(),
                           "custom_exits": routing.PolicyInput(default_action="egress", default_egress="exit:e1", rules=[
                               {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "exit:e2", "enabled": False},
                               {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "EXIT:e3"}]).custom_exits()}
    return out


# -- validation through FastAPI and model_validate ------------------------------------------

MODELS = {
    "Resource": fleet.Resource, "RelayAccount": fleet.RelayAccount, "RelaySection": fleet.RelaySection,
    "EgressDocument": fleet.EgressDocument, "GenerationDocument": fleet.GenerationDocument,
    "PushRequest": fleet.PushRequest, "ObservedResource": fleet.ObservedResource,
    "ObservedEgress": fleet.ObservedEgress, "ObservedRelay": fleet.ObservedRelay,
    "ObservedGeneration": fleet.ObservedGeneration, "PushResponse": fleet.PushResponse,
    "RuleMatch": routing.RuleMatch, "RoutingRule": routing.RoutingRule, "PolicyInput": routing.PolicyInput,
    "RoutingPolicy": routing.RoutingPolicy, "Reason": routing.Reason, "MieruQuota": clients.MieruQuota,
    "MtproxyOptions": clients.MtproxyOptions, "NaiveOptions": clients.NaiveOptions, "MieruOptions": clients.MieruOptions,
    "AmneziawgOptions": clients.AmneziawgOptions, "TrusttunnelOptions": clients.TrusttunnelOptions,
    "Client": clients.Client,
}


def app():
    application = FastAPI()

    def route(model):
        async def endpoint(body: model):
            return {"ok": True}
        return endpoint

    for name, model in MODELS.items():
        application.post(f"/{name}")(route(model))
    return application


def validation():
    client = TestClient(app())
    cases = []
    for name, inputs in VALIDATION.items():
        model = MODELS[name]
        for value in inputs:
            response = client.post(f"/{name}", content=json.dumps(value).encode(),
                                   headers={"content-type": "application/json"})
            case = {"model": name, "input": value, "status": response.status_code}
            if response.status_code == 422:
                case["body"] = response.text
            try:
                instance = model.model_validate(value)
            except ValidationError as exc:
                case["python"] = {"ok": False, "str": str(exc)}
            else:
                case["python"] = {"ok": True, "dump": text(instance.model_dump()), "json": instance.model_dump_json()}
            cases.append(case)
    return cases


def fleet_documents():
    out = []
    for name, value in FLEET_DOCUMENTS.items():
        doc = fleet.GenerationDocument.model_validate(value)
        secrets = {item.credential_ref: "pw-" + item.ref for item in doc.resources}
        if doc.relay is not None:
            secrets.update({account.credential_ref: "uuid" for account in doc.relay.accounts})
        request = fleet.PushRequest(expected_guid=doc.node_guid, generation=doc, secrets=secrets)
        stored = doc.model_dump_json()
        again = fleet.GenerationDocument.model_validate_json(stored)
        rewired = fleet.GenerationDocument.model_validate(doc.wire())
        assert fleet.canonical_digest(again) == fleet.canonical_digest(doc) == fleet.canonical_digest(rewired)
        out.append({"name": name, "input": value, "wire": text(doc.wire()), "stored": stored,
                    "canonical_digest": fleet.canonical_digest(doc), "content_digest": content_digest(doc),
                    "push_wire": text(request.wire()), "push_stored": request.model_dump_json()})
    return out


def main():
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    payload = {"fleet_documents": fleet_documents(), "validation": validation(), "functions": functions()}
    data = json.dumps(payload, ensure_ascii=False, indent=1) + "\n"
    (target / "model.json").write_text(data, encoding="utf-8")
    print("model.json", hashlib.sha256(data.encode()).hexdigest()[:16], len(payload["validation"]), "validation cases")


if __name__ == "__main__":
    main()
