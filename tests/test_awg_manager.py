from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import random
import socket
import stat
import tempfile
import threading

import pytest

from awg_manager import healthcheck, keys, obfuscation
from awg_manager.config import ConfigError, from_env
from awg_manager.host import UapiError
from awg_manager.server import ManagerHTTPServer
from awg_manager.service import AwgManager, parse_uapi
from awg_manager.state import StateError, StateStore

TOKEN = "t" * 40
ZERO = "0" * 64
FIXED_PRIVATE = bytes(range(1, 33))


# ---------------------------------------------------------------- fakes


class FakeProc:
    def __init__(self):
        self.returncode = None
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        return self.returncode


class FakeHost:
    """Models the control socket of amneziawg-go closely enough to test reconciliation."""

    def __init__(self):
        self.procs: dict[str, FakeProc] = {}
        self.devices: dict[str, dict] = {}
        self.sets: list[tuple[str, str]] = []
        self.ip_calls: list[tuple[str, ...]] = []
        self.nft_scripts: list[str] = []
        self.nft_deleted = 0
        self.forward = True
        self.ready = True
        self.stats: dict[str, dict] = {}
        self.starts: list[tuple[str, str]] = []

    def start_process(self, iface, log_level):
        self.starts.append((iface, log_level))
        self.procs[iface] = FakeProc()
        self.devices[iface] = {"device": {}, "peers": {}}
        return self.procs[iface]

    def crash(self, iface):
        self.procs[iface].returncode = 2
        self.devices[iface] = {"device": {}, "peers": {}}

    def _alive(self, iface):
        proc = self.procs.get(iface)
        if proc is None or proc.returncode is not None or not self.ready:
            raise UapiError("no control socket")

    def ip(self, *args):
        self.ip_calls.append(args)

    def nft_apply(self, script):
        self.nft_scripts.append(script)

    def nft_delete(self):
        self.nft_deleted += 1

    def uapi_set(self, iface, body):
        self._alive(iface)
        self.sets.append((iface, body))
        dev = self.devices[iface]
        current = None
        for line in body.splitlines():
            key, _, value = line.partition("=")
            if key == "public_key":
                current = value
                dev["peers"].setdefault(value, {"psk": ZERO, "allowed": []})
            elif current is None:
                dev["device"][key] = value
            elif key == "remove":
                dev["peers"].pop(current, None)
                current = "gone"
                dev["peers"].setdefault("gone", {"psk": ZERO, "allowed": []})
            elif key == "preshared_key":
                dev["peers"][current]["psk"] = value
            elif key == "replace_allowed_ips":
                dev["peers"][current]["allowed"] = []
            elif key == "allowed_ip":
                dev["peers"][current]["allowed"].append(value)
        dev["peers"].pop("gone", None)

    def uapi_get(self, iface):
        self._alive(iface)
        dev = self.devices[iface]
        lines = [f"{k}={v}" for k, v in dev["device"].items()]
        for pub, peer in dev["peers"].items():
            st = self.stats.get(pub, {})
            lines += [
                f"public_key={pub}",
                f"preshared_key={peer['psk']}",
                "protocol_version=1",
                f"last_handshake_time_sec={st.get('hs', 0)}",
                "last_handshake_time_nsec=0",
                f"tx_bytes={st.get('tx', 0)}",
                f"rx_bytes={st.get('rx', 0)}",
            ] + [f"allowed_ip={a}" for a in peer["allowed"]]
        return "\n".join(lines) + "\n"

    def ip_forward_enabled(self):
        return self.forward


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_env(tmp_path, **extra):
    env = {
        "AWG_MANAGER_TOKEN_FILE": str(tmp_path / "token"),
        "AWG_MANAGER_SOCKET": str(tmp_path / "run" / "m.sock"),
        "AWG_STATE_DIR": str(tmp_path / "state"),
    }
    env.update(extra)
    return env


def make_manager(tmp_path, *, overrides=None, seed=7, **env_extra):
    host, clock = FakeHost(), Clock()
    manager = AwgManager(
        from_env(make_env(tmp_path, **env_extra)),
        host,
        overrides=overrides,
        clock=clock,
        wall=lambda: 1_700_000_000,
        rng=random.Random(seed),
    )
    manager.bootstrap()
    return manager, host, clock


def keypair():
    private = keys.generate_private()
    return keys.b64(keys.public_key(private)), keys.b64(os.urandom(32))


def create_body(name="alice", version="2.0", op="op-1"):
    public, psk = keypair()
    return {
        "operation_id": op, "username": name, "version": version,
        "public_key": public, "preshared_key": psk,
    }


# ---------------------------------------------------------------- X25519 / keys


@pytest.mark.parametrize(
    ("scalar", "u", "expected"),
    [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    ],
)
def test_x25519_rfc7748_section_5_2_vectors(scalar, u, expected):
    assert keys.x25519(bytes.fromhex(scalar), bytes.fromhex(u)).hex() == expected


def test_x25519_rfc7748_one_iteration_and_diffie_hellman():
    nine = (9).to_bytes(32, "little")
    assert keys.x25519(nine, nine).hex() == (
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    )
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    assert keys.public_key(alice).hex() == (
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    assert keys.public_key(bob).hex() == (
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert keys.x25519(alice, keys.public_key(bob)).hex() == shared
    assert keys.x25519(bob, keys.public_key(alice)).hex() == shared


def test_generated_private_key_is_clamped_and_base64_is_strict():
    private = keys.generate_private()
    assert private[0] & 7 == 0 and private[31] & 0x80 == 0 and private[31] & 0x40
    assert keys.unb64(keys.b64(private)) == private
    for bad in ["", "abc", "A" * 44, keys.b64(b"\x01" * 31) + "=", 5]:
        with pytest.raises(ValueError):
            keys.unb64(bad)


# ---------------------------------------------------------------- obfuscation


@pytest.mark.parametrize("version", ["1.5", "2.0", "3.1"])
def test_generated_parameters_are_valid_and_deterministic_for_a_seed(version):
    first = obfuscation.generate(version, 1280, random.Random(1))
    assert first == obfuscation.generate(version, 1280, random.Random(1))
    assert first != obfuscation.generate(version, 1280, random.Random(2))
    assert obfuscation.validate(version, first, 1280) == first
    for seed in range(60):
        params = obfuscation.generate(version, 1280, random.Random(seed))
        assert int(params["Jmax"]) <= 1280 and int(params["Jmin"]) < int(params["Jmax"])
        assert int(params["S1"]) + 56 != int(params["S2"])
        assert 4 <= int(params["Jc"]) <= 8
        assert params["I1"].startswith("<b 0xc") and "<t>" in params["I1"]


def test_version_1_5_has_distinct_single_values_and_no_s3_s4():
    params = obfuscation.generate("1.5", 1280, random.Random(3))
    heads = [params[f"H{i}"] for i in range(1, 5)]
    assert len(set(heads)) == 4 and all(h.isdigit() and int(h) > 4 for h in heads)
    assert "S3" not in params and "HeaderProtectionKey" not in params


def test_version_2_0_headers_are_wide_non_overlapping_ranges():
    for seed in range(40):
        params = obfuscation.generate("2.0", 1280, random.Random(seed))
        ranges = sorted(tuple(map(int, params[f"H{i}"].split("-"))) for i in range(1, 5))
        assert all(hi - lo >= 1000 and lo > 4 for lo, hi in ranges)
        assert all(ranges[i][1] < ranges[i + 1][0] for i in range(3))
        assert "S3" in params and "S4" in params


def test_version_3_1_header_protection_constraints():
    params = obfuscation.generate("3.1", 1280, random.Random(5))
    assert [params[f"H{i}"] for i in range(1, 5)] == ["1", "2", "3", "4"]
    assert all(int(params[f"S{i}"]) >= 12 for i in range(1, 5))
    assert len(keys.unb64(params["HeaderProtectionKey"])) == 32
    assert params["ContentPaddingAddition"] == "0-32"
    assert "RandomTrailers" not in obfuscation.client_view(params)
    assert "DisableCookies" not in obfuscation.client_view(params)


@pytest.mark.parametrize(
    ("version", "change", "message"),
    [
        ("1.5", {"S1": "100", "S2": "156"}, "S1 \\+ 56"),
        ("1.5", {"H1": "10", "H2": "10"}, "overlap"),
        ("1.5", {"H1": "1"}, "at least 5"),
        ("1.5", {"H1": "10-20"}, "single value"),
        ("1.5", {"S3": "20"}, "not valid"),
        ("1.5", {"Jmax": "2000"}, "Jmax"),
        ("1.5", {"Jmin": "90", "Jmax": "50"}, "Jmin"),
        ("1.5", {"I1": "<x 1>"}, "CPS"),
        ("2.0", {"H1": "10-5000", "H2": "4000-9000"}, "overlap"),
        ("3.1", {"S3": "11"}, "at least 12"),
        ("3.1", {"HeaderProtectionKey": "short"}, "HeaderProtectionKey"),
        ("3.1", {"RandomTrailers": "yes"}, "RandomTrailers"),
    ],
)
def test_invalid_parameters_are_rejected(version, change, message):
    params = {**obfuscation.generate(version, 1280, random.Random(9)), **change}
    with pytest.raises(obfuscation.ObfuscationError, match=message):
        obfuscation.validate(version, params, 1280)


def test_uapi_lines_per_version_are_exact():
    v15 = {"Jc": "5", "Jmin": "10", "Jmax": "70", "S1": "20", "S2": "30",
           "H1": "11", "H2": "12", "H3": "13", "H4": "14", "I1": "<r 8>"}
    assert obfuscation.uapi_lines(v15) == [
        "jc=5", "jmin=10", "jmax=70", "s1=20", "s2=30", "h1=11", "h2=12", "h3=13", "h4=14",
        "i1=<r 8>",
    ]
    v31 = {**v15, "S3": "13", "S4": "14", "H1": "1", "H2": "2", "H3": "3", "H4": "4",
           "HeaderProtectionKey": keys.b64(bytes(range(32))), "ContentPaddingAddition": "0-32",
           "RandomTrailers": "true"}
    del v31["I1"]
    assert obfuscation.uapi_lines(v31) == [
        "jc=5", "jmin=10", "jmax=70", "s1=20", "s2=30", "s3=13", "s4=14",
        "h1=1", "h2=2", "h3=3", "h4=4",
        f"header_protection_key={bytes(range(32)).hex()}",
        "content_padding_addition=0-32", "random_trailers=true",
    ]


def test_overrides_are_validated_and_applied_once(tmp_path):
    manager, _, _ = make_manager(tmp_path, overrides={"2.0": {"Jc": "6", "I1": "<r 20>"}})
    obf = manager.list_instances()["instances"][1]["obfuscation"]
    assert obf["Jc"] == "6" and obf["I1"] == "<r 20>"
    with pytest.raises(obfuscation.ObfuscationError):
        make_manager(tmp_path / "x", overrides={"2.0": {"Jc": "0"}})
    with pytest.raises(obfuscation.ObfuscationError):
        obfuscation.load_overrides({"9.9": {}})
    assert obfuscation.load_overrides({"2.0": {"Jc": 6, "RandomTrailers": True}}) == {
        "2.0": {"Jc": "6", "RandomTrailers": "true"}
    }


# ---------------------------------------------------------------- config


def test_config_defaults(tmp_path):
    cfg = from_env(make_env(tmp_path))
    assert cfg.versions == ("1.5", "2.0", "3.1")
    assert cfg.ports == {"1.5": 51820, "2.0": 51821, "3.1": 51822}
    assert [str(n) for n in cfg.subnets.values()] == ["10.66.15.0/24", "10.66.20.0/24", "10.66.31.0/24"]
    assert cfg.mtu == 1280 and cfg.dns == ("1.1.1.1", "1.0.0.1") and cfg.nat
    assert cfg.socket_mode == 0o660 and cfg.log_level == "error"


def test_config_partial_override_and_subset(tmp_path):
    cfg = from_env(make_env(tmp_path, AWG_VERSIONS="3.1", AWG_PORTS="3.1=60000",
                            AWG_SUBNETS="3.1=192.168.50.0/28", AWG_NAT="false"))
    assert cfg.versions == ("3.1",) and cfg.ports == {"3.1": 60000} and not cfg.nat


@pytest.mark.parametrize(
    "extra",
    [
        {"AWG_VERSIONS": ""},
        {"AWG_VERSIONS": "2.0,2.0"},
        {"AWG_VERSIONS": "4.0"},
        {"AWG_PORTS": "1.5=51821"},
        {"AWG_PORTS": "1.5=80"},
        {"AWG_PORTS": "1.5=99999"},
        {"AWG_PORTS": "9.9=51820"},
        {"AWG_PORTS": "garbage"},
        {"AWG_SUBNETS": "1.5=8.8.8.0/24"},
        {"AWG_SUBNETS": "1.5=10.66.15.0/23"},
        {"AWG_SUBNETS": "1.5=10.66.15.0/29"},
        {"AWG_SUBNETS": "1.5=10.66.15.5/24"},
        {"AWG_SUBNETS": "2.0=10.66.15.0/24"},
        {"AWG_MTU": "1000"},
        {"AWG_MTU": "x"},
        {"AWG_DNS": "not-an-ip"},
        {"AWG_DNS": ""},
        {"AWG_NAT": "maybe"},
        {"AWG_LOG_LEVEL": "debug"},
        {"AWG_MANAGER_SOCKET_MODE": "666"},
        {"AWG_MANAGER_SOCKET": "relative.sock"},
    ],
)
def test_config_fails_closed(tmp_path, extra):
    with pytest.raises(ConfigError):
        from_env(make_env(tmp_path, **extra))


def test_config_requires_token_file():
    with pytest.raises(ConfigError):
        from_env({})


# ---------------------------------------------------------------- state


def test_state_is_atomic_private_and_schema_checked(tmp_path):
    store = StateStore(tmp_path / "s")
    store.load()
    store.peers["a"] = {"x": 1}
    store.save()
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert [p.name for p in store.directory.iterdir()] == ["state.json"]
    again = StateStore(tmp_path / "s")
    again.load()
    assert again.peers == {"a": {"x": 1}}
    store.path.write_text("{not json")
    with pytest.raises(StateError):
        StateStore(tmp_path / "s").load()
    store.path.write_text(json.dumps({"schema": 99, "instances": {}, "peers": {}, "operations": {}}))
    with pytest.raises(StateError):
        StateStore(tmp_path / "s").load()


def test_failed_save_rolls_the_document_back(tmp_path, monkeypatch):
    manager, _, _ = make_manager(tmp_path)
    monkeypatch.setattr(manager.store, "save", lambda: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        manager.create_peer(create_body())
    assert manager.store.peers == {}


def test_bootstrap_persists_keys_once_and_never_regenerates(tmp_path):
    first, _, _ = make_manager(tmp_path, seed=1)
    snapshot = first.list_instances()
    second, _, _ = make_manager(tmp_path, seed=2)
    assert second.list_instances() == snapshot
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["schema"] == 1 and set(state["instances"]) == {"1.5", "2.0", "3.1"}
    assert "private_key" not in json.dumps(snapshot)


def test_corrupt_stored_instance_is_refused(tmp_path):
    make_manager(tmp_path)
    path = tmp_path / "state" / "state.json"
    doc = json.loads(path.read_text())
    doc["instances"]["2.0"]["obfuscation"]["S1"] = "999999"
    path.write_text(json.dumps(doc))
    with pytest.raises(StateError):
        make_manager(tmp_path)


# ---------------------------------------------------------------- UAPI text and host plumbing


def test_exact_device_and_peer_uapi_for_each_version(tmp_path, monkeypatch):
    monkeypatch.setattr("awg_manager.service.generate_private", lambda: FIXED_PRIVATE)
    pins = {
        "1.5": {"Jc": "5", "Jmin": "10", "Jmax": "70", "S1": "20", "S2": "30",
                "H1": "11", "H2": "12", "H3": "13", "H4": "14", "I1": "<r 8>"},
        "2.0": {"Jc": "6", "Jmin": "11", "Jmax": "71", "S1": "21", "S2": "31", "S3": "41", "S4": "51",
                "H1": "100-2000", "H2": "3000-5000", "H3": "6000-8000", "H4": "9000-11000",
                "I1": "<r 9>"},
        "3.1": {"Jc": "7", "Jmin": "12", "Jmax": "72", "S1": "22", "S2": "32", "S3": "42", "S4": "52",
                "H1": "1", "H2": "2", "H3": "3", "H4": "4",
                "HeaderProtectionKey": keys.b64(bytes(range(32))), "ContentPaddingAddition": "0-32",
                "I1": "<r 10>"},
    }
    manager, host, _ = make_manager(tmp_path, overrides=pins)
    priv = FIXED_PRIVATE.hex()
    by_iface = {}
    for iface, body in host.sets:
        by_iface.setdefault(iface, []).append(body)
    assert by_iface["awg15"][0] == (
        f"private_key={priv}\nlisten_port=51820\njc=5\njmin=10\njmax=70\ns1=20\ns2=30\n"
        "h1=11\nh2=12\nh3=13\nh4=14\ni1=<r 8>\n"
    )
    assert by_iface["awg20"][0] == (
        f"private_key={priv}\nlisten_port=51821\njc=6\njmin=11\njmax=71\ns1=21\ns2=31\ns3=41\ns4=51\n"
        "h1=100-2000\nh2=3000-5000\nh3=6000-8000\nh4=9000-11000\ni1=<r 9>\n"
    )
    assert by_iface["awg31"][0] == (
        f"private_key={priv}\nlisten_port=51822\njc=7\njmin=12\njmax=72\ns1=22\ns2=32\ns3=42\ns4=52\n"
        f"h1=1\nh2=2\nh3=3\nh4=4\ni1=<r 10>\nheader_protection_key={bytes(range(32)).hex()}\n"
        "content_padding_addition=0-32\n"
    )
    body = create_body("alice", "2.0")
    manager.create_peer(body)
    pub, psk = keys.hexkey(body["public_key"]), keys.hexkey(body["preshared_key"])
    assert host.sets[-1] == (
        "awg20",
        f"public_key={pub}\npreshared_key={psk}\nreplace_allowed_ips=true\nallowed_ip=10.66.20.2/32\n",
    )


def test_interfaces_addresses_and_nft_table(tmp_path):
    _, host, _ = make_manager(tmp_path)
    assert ("addr", "replace", "10.66.20.1/24", "dev", "awg20") in host.ip_calls
    assert ("link", "set", "awg31", "mtu", "1280", "up") in host.ip_calls
    assert host.starts == [("awg15", "error"), ("awg20", "error"), ("awg31", "error")]
    script = host.nft_scripts[0]
    assert script.startswith("table inet awg_manager\ndelete table inet awg_manager\n")
    assert 'iifname { "awg15", "awg20", "awg31" } accept' in script
    assert 'ip saddr 10.66.20.0/24 oifname != "awg20" masquerade' in script


def test_nat_can_be_disabled(tmp_path):
    _, host, _ = make_manager(tmp_path, AWG_NAT="false")
    assert "masquerade" not in host.nft_scripts[0]


def test_shutdown_stops_processes_and_removes_nft_but_keeps_state(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    manager.create_peer(create_body())
    manager.shutdown()
    assert all(p.returncode == -15 for p in host.procs.values())
    assert host.nft_deleted == 1
    assert (tmp_path / "state" / "state.json").exists()


def test_parse_uapi():
    text = "private_key=aa\nlisten_port=1\npublic_key=bb\npreshared_key=cc\nrx_bytes=5\ntx_bytes=6\n" \
           "last_handshake_time_sec=9\nallowed_ip=10.0.0.2/32\n"
    device, peers = parse_uapi(text)
    assert device == {"private_key": "aa", "listen_port": "1"}
    assert peers["bb"] == {"allowed_ips": ["10.0.0.2/32"], "preshared_key": "cc", "rx": 5, "tx": 6, "handshake": 9}


# ---------------------------------------------------------------- peers (service level)


def test_create_allocates_lowest_free_address_and_reuses_freed_ones(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    addresses = []
    for i, name in enumerate(["a", "b", "c"]):
        status, out = manager.create_peer(create_body(name, "2.0", f"op-{i}"))
        assert status == 201
        addresses.append(out["peer"]["address"])
    assert addresses == ["10.66.20.2", "10.66.20.3", "10.66.20.4"]
    manager.delete_peer("b")
    assert manager.create_peer(create_body("d", "2.0", "op-d"))[1]["peer"]["address"] == "10.66.20.3"
    # Another version has its own pool.
    assert manager.create_peer(create_body("e", "3.1", "op-e"))[1]["peer"]["address"] == "10.66.31.2"


def test_disabled_peer_keeps_its_address_reserved(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.create_peer(create_body("a", "2.0", "op-a"))
    manager.set_enabled("a", False)
    assert manager.create_peer(create_body("b", "2.0", "op-b"))[1]["peer"]["address"] == "10.66.20.3"


def test_pool_exhaustion(tmp_path):
    manager, _, _ = make_manager(tmp_path, AWG_VERSIONS="2.0", AWG_SUBNETS="2.0=10.66.20.0/28")
    for i in range(13):
        manager.create_peer(create_body(f"u{i}", "2.0", f"op{i}"))
    with pytest.raises(Exception, match="no free address"):
        manager.create_peer(create_body("overflow", "2.0", "opx"))


def test_idempotent_create_conflicts_and_uniqueness(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    body = create_body("alice", "2.0", "op-1")
    status, first = manager.create_peer(body)
    sets = len(host.sets)
    status2, second = manager.create_peer(dict(body))
    assert (status, status2) == (201, 200) and first["peer"] == second["peer"]
    assert len(host.sets) == sets  # replay does not touch the device
    assert manager.store.peers["alice"]["revision"] == 1
    other = dict(body, version="3.1")
    with pytest.raises(Exception) as err:
        manager.create_peer(other)
    assert err.value.code == "operation_conflict"
    with pytest.raises(Exception) as err:  # same name, another version, new operation
        manager.create_peer(create_body("alice", "3.1", "op-2"))
    assert err.value.code == "username_taken"
    clash = create_body("bob", "2.0", "op-3")
    clash["public_key"] = body["public_key"]
    with pytest.raises(Exception) as err:
        manager.create_peer(clash)
    assert err.value.code == "public_key_in_use"


@pytest.mark.parametrize(
    "mutate",
    [
        {"username": "Bad Name"}, {"username": "-lead"}, {"username": "x" * 65}, {"username": ""},
        {"public_key": "nope"}, {"preshared_key": "A" * 44},
        {"public_key": keys.b64(bytes(32))}, {"operation_id": "has space"}, {"operation_id": 1},
    ],
)
def test_create_validation(tmp_path, mutate):
    manager, _, _ = make_manager(tmp_path)
    with pytest.raises(Exception) as err:
        manager.create_peer({**create_body(), **mutate})
    assert err.value.status == 422 and err.value.code == "invalid_request"


def test_create_rejects_missing_and_extra_fields(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    body = create_body()
    for bad in ({k: v for k, v in body.items() if k != "version"}, {**body, "extra": 1}):
        with pytest.raises(Exception) as err:
            manager.create_peer(bad)
        assert err.value.status == 422


def test_unknown_and_disabled_versions(tmp_path):
    manager, _, _ = make_manager(tmp_path, AWG_VERSIONS="2.0")
    with pytest.raises(Exception) as err:
        manager.create_peer(create_body(version="9.9"))
    assert (err.value.status, err.value.code) == (422, "unknown_version")
    with pytest.raises(Exception) as err:
        manager.create_peer(create_body(version="3.1"))
    assert (err.value.status, err.value.code) == (409, "version_disabled")
    assert [i["version"] for i in manager.list_instances()["instances"]] == ["2.0"]


def test_enable_disable_are_idempotent_and_apply_live(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    body = create_body("alice", "2.0")
    manager.create_peer(body)
    pub = keys.hexkey(body["public_key"])
    assert pub in host.devices["awg20"]["peers"]
    first = manager.set_enabled("alice", False)["peer"]
    assert first["enabled"] is False and first["revision"] == 2
    assert pub not in host.devices["awg20"]["peers"]
    assert manager.set_enabled("alice", False)["peer"]["revision"] == 2
    again = manager.set_enabled("alice", True)["peer"]
    assert again["enabled"] and again["revision"] == 3 and again["address"] == "10.66.20.2"
    assert pub in host.devices["awg20"]["peers"]
    assert manager.set_enabled("alice", True)["peer"]["revision"] == 3
    with pytest.raises(Exception) as err:
        manager.set_enabled("ghost", True)
    assert err.value.code == "not_found"


def test_rotate_replaces_keys_keeps_address_and_is_idempotent(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    body = create_body("alice", "3.1")
    manager.create_peer(body)
    old = keys.hexkey(body["public_key"])
    public, psk = keypair()
    rot = {"operation_id": "rot-1", "public_key": public, "preshared_key": psk}
    peer = manager.rotate("alice", rot)["peer"]
    assert peer["public_key"] == public and peer["revision"] == 2 and peer["address"] == "10.66.31.2"
    live = host.devices["awg31"]["peers"]
    assert old not in live and live[keys.hexkey(public)]["psk"] == keys.hexkey(psk)
    assert manager.rotate("alice", dict(rot))["peer"]["revision"] == 2
    with pytest.raises(Exception) as err:
        manager.rotate("alice", {**rot, "public_key": keypair()[0]})
    assert err.value.code == "operation_conflict"
    with pytest.raises(Exception) as err:
        manager.rotate("ghost", rot)
    assert err.value.code == "not_found"


def test_rotate_of_a_disabled_peer_stays_off_the_device(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    manager.create_peer(create_body("alice", "2.0"))
    manager.set_enabled("alice", False)
    public, psk = keypair()
    manager.rotate("alice", {"operation_id": "r", "public_key": public, "preshared_key": psk})
    assert host.devices["awg20"]["peers"] == {}


def test_delete_removes_from_state_and_device(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    body = create_body("alice", "1.5")
    manager.create_peer(body)
    manager.delete_peer("alice")
    assert "alice" not in manager.store.peers and host.devices["awg15"]["peers"] == {}
    with pytest.raises(Exception) as err:
        manager.delete_peer("alice")
    assert err.value.code == "not_found"


def test_peers_list_reports_live_counters_and_handshake(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    body = create_body("alice", "2.0")
    manager.create_peer(body)
    assert manager.list_peers()["peers"][0]["latest_handshake"] is None
    host.stats[keys.hexkey(body["public_key"])] = {"rx": 10, "tx": 20, "hs": 1_700_000_001}
    peer = manager.list_peers()["peers"][0]
    assert (peer["rx"], peer["tx"], peer["latest_handshake"]) == (10, 20, 1_700_000_001)
    assert set(peer) == {"username", "version", "enabled", "address", "public_key", "revision",
                         "rx", "tx", "latest_handshake"}


def test_create_response_carries_instance_with_client_obfuscation(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    _, out = manager.create_peer(create_body("alice", "3.1"))
    inst = out["instance"]
    assert inst["interface"] == "awg31" and inst["gateway"] == "10.66.31.1"
    assert inst["subnet"] == "10.66.31.0/24" and inst["port"] == 51822 and inst["mtu"] == 1280
    assert inst["dns"] == ["1.1.1.1", "1.0.0.1"]
    assert inst["server_public_key"] == manager.store.instances["3.1"]["public_key"]
    assert "HeaderProtectionKey" in inst["obfuscation"] and "I2" not in inst["obfuscation"]
    assert all(isinstance(v, str) for v in inst["obfuscation"].values())


# ---------------------------------------------------------------- supervision / reconcile


def test_health_degrades_without_ip_forward_or_with_a_dead_instance(tmp_path):
    manager, host, clock = make_manager(tmp_path)
    health = manager.health()
    assert health["status"] == "ok" and health["ip_forward"] is True
    assert health["instances"]["2.0"] == {"interface": "awg20", "running": True, "port": 51821, "peers": 0}
    host.forward = False
    assert manager.health()["status"] == "degraded"
    host.forward = True
    host.ready = False
    host.crash("awg20")
    manager.tick()
    assert manager.health()["instances"]["2.0"]["running"] is False
    assert manager.health()["status"] == "degraded"


def test_reconcile_restores_peers_after_the_process_crashes(tmp_path):
    manager, host, clock = make_manager(tmp_path)
    a, b = create_body("alice", "2.0", "o1"), create_body("bob", "2.0", "o2")
    manager.create_peer(a)
    manager.create_peer(b)
    manager.set_enabled("bob", False)
    host.crash("awg20")
    manager.tick()  # notices the crash, backoff 1 s before the restart
    assert manager.health()["instances"]["2.0"]["running"] is False
    assert host.devices["awg20"]["peers"] == {}
    clock.now += 1.5
    manager.tick()
    live = host.devices["awg20"]["peers"]
    assert list(live) == [keys.hexkey(a["public_key"])]  # disabled bob stays off
    assert live[keys.hexkey(a["public_key"])]["allowed"] == ["10.66.20.2/32"]
    assert host.devices["awg20"]["device"]["listen_port"] == "51821"
    assert manager.health()["status"] == "ok"
    assert len([s for s in host.starts if s[0] == "awg20"]) == 2


def test_restart_backoff_grows_and_resets_after_a_stable_run(tmp_path):
    manager, host, clock = make_manager(tmp_path)
    for expected in (1, 2, 4):
        host.crash("awg20")
        manager.tick()
        clock.now += expected - 0.1
        manager.tick()
        assert host.procs["awg20"].returncode == 2  # still down inside the window
        clock.now += 0.2
        manager.tick()
        assert host.procs["awg20"].returncode is None
    clock.now += 120
    host.crash("awg20")
    manager.tick()
    assert manager.instances["2.0"].failures == 1


def test_periodic_reconcile_repairs_drift_and_removes_strays(tmp_path):
    manager, host, clock = make_manager(tmp_path)
    body = create_body("alice", "2.0")
    manager.create_peer(body)
    pub = keys.hexkey(body["public_key"])
    host.devices["awg20"]["peers"].pop(pub)
    stray = keys.hexkey(keypair()[0])
    host.devices["awg20"]["peers"][stray] = {"psk": ZERO, "allowed": ["10.66.20.99/32"]}
    manager.tick()  # inside the interval: nothing changes
    assert pub not in host.devices["awg20"]["peers"]
    clock.now += 31
    manager.tick()
    assert pub in host.devices["awg20"]["peers"] and stray not in host.devices["awg20"]["peers"]


def test_failed_live_update_marks_dirty_and_next_tick_converges(tmp_path):
    manager, host, _ = make_manager(tmp_path)
    host.ready = False
    body = create_body("alice", "2.0")
    status, _ = manager.create_peer(body)  # device unreachable: state still wins
    assert status == 201 and manager.instances["2.0"].dirty
    host.ready = True
    manager.tick()
    assert keys.hexkey(body["public_key"]) in host.devices["awg20"]["peers"]


def test_unready_control_socket_is_retried_then_process_is_killed(tmp_path):
    host, clock = FakeHost(), Clock()
    host.ready = False
    manager = AwgManager(from_env(make_env(tmp_path, AWG_VERSIONS="2.0")), host, clock=clock,
                         wall=lambda: 1, rng=random.Random(1))
    manager.bootstrap()
    assert manager.health()["instances"]["2.0"]["running"] is False
    clock.now += 11
    manager.tick()
    assert host.procs["awg20"].killed
    host.ready = True
    manager.tick()  # sees the exit, schedules the restart
    clock.now += 2
    manager.tick()
    assert manager.health()["instances"]["2.0"]["running"] is True


# ---------------------------------------------------------------- HTTP API


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("awg-manager")
        self.path_ = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path_)


@pytest.fixture
def api(tmp_path):
    short = Path(tempfile.mkdtemp(prefix="awg"))
    manager, host, _ = make_manager(tmp_path)
    server = ManagerHTTPServer(short / "m.sock", manager, TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def call(method, path, body=None, token=TOKEN):
        conn = UnixConnection(str(short / "m.sock"))
        headers = {"X-Awg-Token": token} if token is not None else {}
        data = None
        if body is not None:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, (json.loads(raw) if raw else None)

    call.socket = short / "m.sock"
    call.manager, call.host = manager, host
    yield call
    server.shutdown()
    server.server_close()


def test_api_requires_the_token(api):
    for token in (None, "", "wrong" * 10):
        status, body = api("GET", "/v1/health", token=token)
        assert status == 401 and body["code"] == "unauthorized"
    assert api("GET", "/v1/health")[0] == 200


def test_api_health_and_instances(api):
    status, health = api("GET", "/v1/health")
    assert status == 200 and health["status"] == "ok"
    assert set(health["instances"]) == {"1.5", "2.0", "3.1"}
    status, body = api("GET", "/v1/instances")
    assert [i["interface"] for i in body["instances"]] == ["awg15", "awg20", "awg31"]
    api.host.forward = False
    assert api("GET", "/v1/health") [1]["status"] == "degraded"


def test_api_peer_lifecycle(api):
    body = create_body("alice", "2.0")
    status, created = api("POST", "/v1/peers", body)
    assert status == 201 and created["peer"]["address"] == "10.66.20.2"
    assert api("POST", "/v1/peers", body)[0] == 200
    assert api("POST", "/v1/peers", {**body, "version": "3.1"})[0] == 409
    status, listing = api("GET", "/v1/peers")
    assert [p["username"] for p in listing["peers"]] == ["alice"]
    assert api("POST", "/v1/peers/alice/disable", {})[1]["peer"]["enabled"] is False
    assert api("POST", "/v1/peers/alice/disable")[0] == 200
    assert api("POST", "/v1/peers/alice/enable", {})[1]["peer"]["enabled"] is True
    public, psk = keypair()
    status, rotated = api("POST", "/v1/peers/alice/rotate",
                          {"operation_id": "r1", "public_key": public, "preshared_key": psk})
    assert status == 200 and rotated["peer"]["public_key"] == public
    assert api("DELETE", "/v1/peers/alice") == (204, None)
    status, err = api("DELETE", "/v1/peers/alice")
    assert status == 404 and err["code"] == "not_found"


def test_api_error_shapes(api):
    status, err = api("POST", "/v1/peers", create_body(version="9.9"))
    assert (status, err["code"]) == (422, "unknown_version") and "detail" in err
    api.manager.instances.pop("3.1")
    status, err = api("POST", "/v1/peers", create_body(version="3.1"))
    assert (status, err["code"]) == (409, "version_disabled")
    assert api("POST", "/v1/peers", {"junk": 1})[1]["code"] == "invalid_request"
    assert api("GET", "/v1/nothing")[0] == 404
    assert api("POST", "/v1/peers/alice/explode", {})[0] == 404
    assert api("POST", "/v1/peers/alice/enable", {"x": 1})[0] == 422


def test_api_socket_mode_and_healthcheck_probe(api, tmp_path):
    token_file = tmp_path / "tok"
    token_file.write_text(TOKEN)
    assert healthcheck.check(api.socket, token_file) is True
    token_file.write_text("x" * 40)
    assert healthcheck.check(api.socket, token_file) is False
    token_file.write_text(TOKEN)
    api.host.forward = False
    assert healthcheck.check(api.socket, token_file) is False  # degraded
    api.host.forward = True
    host_crash = api.host
    host_crash.ready = False
    host_crash.crash("awg15")
    api.manager.tick()
    assert healthcheck.check(api.socket, token_file) is False  # an instance is down
    assert healthcheck.check(tmp_path / "missing.sock", token_file) is False


def test_server_socket_permissions_and_short_token(tmp_path):
    short = Path(tempfile.mkdtemp(prefix="awg"))
    manager, _, _ = make_manager(tmp_path)
    server = ManagerHTTPServer(short / "s.sock", manager, TOKEN, socket_mode=0o660)
    try:
        assert stat.S_IMODE((short / "s.sock").stat().st_mode) == 0o660
    finally:
        server.server_close()
    with pytest.raises(ValueError):
        ManagerHTTPServer(short / "t.sock", manager, "short")
