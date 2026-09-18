"""scripts/lab/fleet-acceptance.py off the stand: argument parsing, the credential file
formats, the secret-free report, and the eleven-step scenario assembled on fakes — no
network, no Docker, no subprocess. The live run is `scripts/dev/remote-gate.sh fleet`."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab" / "fleet-acceptance.py"


def _load():
    spec = importlib.util.spec_from_file_location("fleet_acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("fleet_acceptance", module)
    spec.loader.exec_module(module)
    return module


fa = _load()
REQUIRED = ["--node-url", "https://panel.lab.test", "--node-password-file", "/root/pw",
            "--central-dir", "/root/lab-central", "--output", "out"]


# --- arguments -------------------------------------------------------------------------

def test_defaults_follow_the_brief_and_the_controller_rulings():
    args = fa.parse_args(REQUIRED)
    assert args.central_port == 8791 and args.central_host == "127.0.0.1"
    # Ruling 3: the interpreter that starts the central and the tree it imports `panel` from.
    assert args.python == sys.executable
    assert args.source == ROOT
    assert args.node_username == "owner" and args.node_container == "proxy-control-panel"
    assert args.heartbeat_seconds == 3 and args.bulk_grants == 20
    assert args.cleanup is False and args.allow_private_address is False
    # The pinned cores are the defaults; an empty value skips a core.
    assert args.singbox_image.startswith("ghcr.io/sagernet/sing-box@sha256:")
    assert args.mihomo_image.startswith("metacubex/mihomo@sha256:")
    assert args.mtproxy_probe == "/usr/local/libexec/mtproxy-respq-probe"
    assert args.mtproxy_domain == "proxy.lab.test"
    assert args.client_ca_file is None  # WebPKI unless the lab hands over its own CA


def test_interpreter_and_source_are_independent_and_cores_can_be_skipped(tmp_path):
    args = fa.parse_args(REQUIRED + ["--python", "/root/dev/.venv/bin/python", "--source", str(tmp_path),
                                     "--singbox-image", "", "--mihomo-image", "", "--mtproxy-probe", "",
                                     "--cleanup", "--bulk-grants", "5"])
    assert args.python == "/root/dev/.venv/bin/python" and args.source == tmp_path
    assert args.singbox_image == "" and args.mihomo_image == "" and args.mtproxy_probe == ""
    assert args.cleanup is True and args.bulk_grants == 5


def test_routing_scenarios_are_opt_in_and_sit_after_the_grants(tmp_path):
    """[v0.4] `--routing` inserts the routing step right after the grants (it needs the probe
    user's credentials); the defaults name the stub, the Caddyfile and the probe targets."""
    plain = fa.parse_args(REQUIRED)
    assert plain.routing is False and plain.stub_listen == "127.0.0.1:45000"
    assert plain.caddyfile == Path("/var/lib/naive-manager/Caddyfile")
    assert plain.routing_allowed == "https://api.ipify.org" and plain.routing_blocked_host == "example.com"
    assert plain.routing_cidr == "1.1.1.0/24" and plain.routing_cidr_target.startswith("https://1.1.1.1/")
    scenario = fa.Scenario(plain, node=None, central=None, process=None, docker=None, probes=None)
    assert "step_05r_routing" not in scenario.steps() and scenario.steps() == fa.Scenario.STEPS
    routing = fa.parse_args(REQUIRED + ["--routing", "--stub-listen", "127.0.0.1:45001"])
    scenario = fa.Scenario(routing, node=None, central=None, process=None, docker=None, probes=None,
                           stub=fa.Stub("127.0.0.1:45001", tmp_path / "stub.log"), host=fa.Host(tmp_path / "Caddyfile"),
                           routing_probes=None)
    steps = scenario.steps()
    assert steps.index("step_05r_routing") == steps.index("step_05_grants") + 1
    assert steps.index("step_05r_routing") < steps.index("step_06_disable_rotate_delete")
    assert scenario.stub.listen == "127.0.0.1:45001" and scenario.stub.lines() == []


def test_stub_log_lines_name_the_connect_targets(tmp_path):
    log = tmp_path / "stub.log"
    log.write_text("1\tapi.ipify.org\t443\n2\t1.1.1.1\t443\nnoise\n")
    stub = fa.Stub("127.0.0.1:45000", log)
    assert stub.hosts_since(0) == ["api.ipify.org", "1.1.1.1"] and stub.hosts_since(1) == ["1.1.1.1"]


def test_required_arguments_are_enforced():
    with pytest.raises(SystemExit):
        fa.parse_args(["--node-url", "https://panel.lab.test"])


def test_naive_probe_retries_a_cut_connection_but_not_a_refusal(tmp_path, monkeypatch):
    """[v0.7] A probe through Caddy right after a lane withdrawal or a policy apply can land
    on the router's generation swap (the process restarts) or on Caddy's reload: curl 55
    («send failure») / 35 (TLS cut mid-way) — the Internet or the swap blinked, not the
    thing under test. Those get another try, like `_socks_probe`; a refusal (the proxy
    answered) is final and is never retried."""
    calls: list[tuple[int, str]] = []
    outcomes = iter([(55, "curl: (55) Send failure: Broken pipe"), (0, "200")])
    monkeypatch.setattr(fa.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fa.RoutingProbes, "_run", staticmethod(lambda *argv, timeout=40: calls.append(next(outcomes)) or calls[-1]))
    probes = fa.RoutingProbes(fa.parse_args(REQUIRED), tmp_path)
    probes.naive_artifact = "naive+https://user:pass@naive.lab.test"
    ok, detail = probes.naive("https://www.wikipedia.org/")
    assert ok and len(calls) == 2 and "pass" not in detail
    assert 55 in fa._TRANSIENT_CURL and 35 in fa._TRANSIENT_CURL
    # a refusal (curl 7 / the proxy's 403): no retry — the check reads it as-is
    calls.clear()
    outcomes = iter([(7, "curl: (7) Failed to connect")])
    ok, _ = probes.naive("https://www.wikipedia.org/")
    assert not ok and len(calls) == 1


# --- the node's credential file, in every shape the installer produces -----------------

def test_plain_bootstrap_password_file(tmp_path):
    path = tmp_path / "panel-bootstrap-password"
    path.write_text("s3cret-value\n")
    assert fa.read_node_credentials(path, "owner") == ("owner", "s3cret-value")


def test_wizard_credentials_toml_carries_username_and_password(tmp_path):
    path = tmp_path / "install.credentials"
    path.write_text('# comment\npanel_username = "admin2"\npanel_password = "pa\\"ss word"\nthree_xui_password = "x"\n')
    assert fa.read_node_credentials(path, "owner") == ("admin2", 'pa"ss word')


def test_handoff_json_is_accepted(tmp_path):
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps({"credentials": {"panel-bootstrap-password": "abc123", "other": "x"}, "schema": 1}))
    assert fa.read_node_credentials(path, "owner") == ("owner", "abc123")


def test_empty_credential_file_is_refused(tmp_path):
    path = tmp_path / "empty"
    path.write_text("\n")
    with pytest.raises(fa.Check):
        fa.read_node_credentials(path, "owner")


# --- pure helpers ----------------------------------------------------------------------

def test_mtproxy_secret_is_taken_out_of_the_fake_tls_link():
    secret = "0123456789abcdef0123456789abcdef"
    link = f"tg://proxy?server=proxy.lab.test&port=443&secret=ee{secret}{'proxy.lab.test'.encode().hex()}"
    assert fa.mtproxy_secret(link) == secret
    with pytest.raises(fa.Check):
        fa.mtproxy_secret("tg://proxy?server=x&port=443&secret=dd00")


def test_central_environment_points_at_the_source_tree_and_disables_every_runtime(tmp_path):
    args = fa.parse_args(REQUIRED + ["--source", str(tmp_path), "--central-dir", str(tmp_path / "central")])
    env = fa.central_environment(args)
    assert env["PANEL_DATABASE"] == str(tmp_path / "central" / "panel.sqlite3")
    assert env["PANEL_MASTER_KEY_FILE"] == str(tmp_path / "central" / "master-key")
    assert env["PANEL_ALLOWED_HOSTS"] == "127.0.0.1,localhost"
    assert env["PANEL_COOKIE_SECURE"] == "false"
    assert env["NAIVE_ENABLED"] == "false" and env["MIERU_ENABLED"] == "false"
    assert env["PANEL_FLEET_HEARTBEAT_SECONDS"] == "3"
    assert env["PANEL_SUBSCRIPTION_URL"] == "http://127.0.0.1:8791"
    assert env["PANEL_VERSION_FILE"] == str(tmp_path / "VERSION")
    assert env["PYTHONPATH"] == str(tmp_path)
    # The central's own runtimes are unreachable on purpose: it manages the node's.
    assert env["TELEMT_API_URL"].startswith("http://127.0.0.1:")


def test_report_never_carries_a_secret_shaped_value():
    report = {"node_key_length": 60, "checks": {"link_created": True}, "detail": "prefix pc_1234"}
    fa.assert_secret_free(report)
    with pytest.raises(fa.Check):
        fa.assert_secret_free({"x": "tg://proxy?server=a&port=443&secret=ee00"})
    with pytest.raises(fa.Check):
        fa.assert_secret_free({"x": "pc_0123abcd_" + "A" * 43})


# --- the scenario on fakes -------------------------------------------------------------

def test_scenario_runs_all_eleven_steps_on_fakes(tmp_path):
    fleet = FakeFleet()
    report = _run(tmp_path, fleet)
    checks = report["checks"]
    failed = sorted(name for name, value in checks.items() if value is False)
    assert failed == [], {name: report["details"].get(name) for name in failed}
    # Every step of the brief left at least one check with a meaningful condition.
    for step in range(1, 12):
        assert any(name.startswith(f"s{step:02d}_") for name in checks), f"step {step} has no check"
    assert report["ok"] is True
    # The node ends exactly as found (ruling 6).
    assert fleet.node_users() == fleet.initial_users
    assert fleet.master_guid is None and fleet.keys == {} and fleet.managed == {}
    assert fleet.central_nodes == {}
    # The clients the import created stay on the central without grants; the test client is archived.
    assert "fleet-probe" not in [c["display_name"] for c in fleet.clients.values()]
    assert fleet.process_started and fleet.process_stopped
    # Bulk grants converged once, no duplicates on either side (step 8).
    assert checks["s08_no_duplicates_on_node"] and checks["s08_no_duplicates_on_central"]


def test_scenario_report_is_secret_free_and_stops_the_central_on_failure(tmp_path):
    fleet = FakeFleet(break_link=True)
    report = _run(tmp_path, fleet)
    assert report["ok"] is False
    assert report["checks"]["s03_link_online"] is False
    # try/finally: the central is stopped and the node restored even when a step fails.
    assert fleet.process_stopped
    assert fleet.keys == {} and fleet.master_guid is None
    fa.assert_secret_free(report)
    text = json.dumps(report)
    for secret in fleet.secrets_issued:
        assert secret not in text


def _run(tmp_path, fleet):
    output = tmp_path / "out"
    args = fa.parse_args(["--node-url", "https://node.lab.test", "--node-password-file", str(tmp_path / "pw"),
                          "--central-dir", str(tmp_path / "central"), "--output", str(output),
                          "--source", str(tmp_path), "--cleanup"])
    (tmp_path / "pw").write_text("node-owner-password\n")
    scenario = fa.Scenario(
        args,
        node=fleet.node_panel(),
        central=fleet.central_panel(),
        process=fleet.process(),
        docker=fleet.docker(),
        probes=fleet.probes(),
        clock=fleet.clock(),
        fingerprint=lambda host, port: fleet.leaf_sha256,
        fetch=fleet.fetch,
    )
    scenario.run()
    return json.loads((output / "report.json").read_text())


# --- fakes: one in-memory node panel, one in-memory central panel, one pusher ----------

HEX32 = "0123456789abcdef0123456789abcdef"


class FakeClock:
    def __init__(self, fleet):
        self.fleet, self.now = fleet, 1_700_000_000.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        self.fleet.tick()


class FakePanel:
    """`fa.Panel`'s surface — request/json/login/with_bearer — over a dispatcher."""

    def __init__(self, fleet, side, bearer=None):
        self.fleet, self.side, self.bearer, self.base_url = fleet, side, bearer, f"http://{side}"
        self.logged_in = None

    def login(self, username, password):
        self.fleet.logins.append((self.side, username, password))
        self.logged_in = username

    def with_bearer(self, token):
        return FakePanel(self.fleet, self.side, bearer=token)

    def request(self, path, *, method="GET", payload=None, headers=None):
        status, body = self.fleet.dispatch(self.side, method, path, payload, self.bearer)
        reason = {"X-Reason": body.pop("code")} if isinstance(body, dict) and "code" in body else {}
        return status, reason, json.dumps(body).encode()

    def json(self, path, *, method="GET", payload=None, expect=(200, 201)):
        status, body = self.fleet.dispatch(self.side, method, path, payload, self.bearer)
        if status not in expect:
            raise fa.Check(f"{method} {path} -> {status}")
        return body


class FakeFleet:
    def __init__(self, *, break_link=False):
        self.break_link = break_link
        self.node_guid, self.central_guid, self.leaf_sha256 = "node-guid-1", "central-guid-1", "ab" * 32
        self.initial_users = {"mtproxy": ["owner"], "naive": ["alice"], "mieru": ["bob"]}
        self.runtime = {p: {u: {"enabled": True, "secret": f"{p}-{u}-v1"} for u in users}
                        for p, users in self.initial_users.items()}
        self.managed: dict[tuple[str, str], str] = {}  # (protocol, user) -> grant ref
        self.master_guid = None
        self.keys: dict[int, dict] = {}
        self.next_key = 1
        self.container_up = True
        self.logins: list = []
        self.secrets_issued: list[str] = []
        # central
        self.central_nodes: dict[str, dict] = {}
        self.clients: dict[str, dict] = {}
        self.grants: dict[str, dict] = {}
        self.operations: dict[str, dict] = {}
        self.reveals: dict[str, dict] = {}
        self.events: list[dict] = []
        self.generation = 0
        self.counter = 0
        self.process_started = self.process_stopped = False
        self.subscription_token = None

    # --- wiring for the scenario ---
    def node_panel(self):
        return FakePanel(self, "node")

    def central_panel(self):
        return FakePanel(self, "central")

    def clock(self):
        return FakeClock(self)

    def process(self):
        fleet = self

        class Process:
            def start(self, owner_password):
                fleet.process_started = True
                fleet.owner_password = owner_password

            def stop(self):
                fleet.process_stopped = True

            def is_running(self):
                return not fleet.process_stopped

            def collect_log(self, destination):
                return "INFO: Application startup complete.\n"

        return Process()

    def docker(self):
        fleet = self

        class Docker:
            def stop(self, name):
                fleet.container_up = False

            def start(self, name):
                fleet.container_up = True

            def restart(self, name):
                fleet.container_up = True

        return Docker()

    def probes(self):
        fleet = self

        class Probes:
            enabled = True

            def cores(self, feeds_dir):
                # The feed files were rendered from the runtime the fake believes in.
                naive = (feeds_dir / "subscription.singbox-official").read_text()
                clash = (feeds_dir / "subscription.clash").read_text()
                return {"singbox_check": True, "mihomo_check": True,
                        "singbox_naive_traffic": fleet.credential_live("naive", naive),
                        "mihomo_mieru_tcp": fleet.credential_live("mieru", clash),
                        "mihomo_mieru_udp": fleet.credential_live("mieru", clash)}

            def mtproxy(self, secret):
                return fleet.credential_live("mtproxy", secret), "probe"

        return Probes()

    def credential_live(self, protocol, text):
        return any(row["enabled"] and row["secret"] in text for row in self.runtime[protocol].values())

    def node_users(self):
        return {p: sorted(self.runtime[p]) for p in self.runtime}

    # --- the pusher: one heartbeat + delivery per tick ---
    def tick(self):
        for node_id, link in self.central_nodes.items():
            key = self.keys.get(link["key_id"])
            online = self.container_up and key is not None and key["enabled"]
            if link["status"] != ("online" if online else "offline"):
                self.events.append({"name": "node.up" if online else "node.down", "node_id": node_id})
            link["status"] = "online" if online else "offline"
            if not online:
                continue
            if link["desired"] > link["acknowledged"]:
                self.apply(node_id)
                link["acknowledged"] = link["desired"]

    def apply(self, node_id):
        if self.master_guid is None:
            self.master_guid = self.central_guid
        wanted = set()
        for gid, grant in list(self.grants.items()):
            if grant["node_id"] != node_id:
                continue
            key = (grant["protocol"], grant["runtime_username"])
            users = self.runtime[grant["protocol"]]
            if grant["desired_state"] == "deleted":
                if key in self.managed:
                    users.pop(key[1], None)
                    del self.managed[key]
                grant["observed_state"] = "missing"
                del self.grants[gid]
                continue
            wanted.add(key)
            if key not in self.managed:
                if key[1] in users and grant["origin"] != "imported":
                    grant["observed_state"] = "failed"
                    continue
                self.managed[key] = f"grant:{gid}"
                users.setdefault(key[1], {"enabled": True, "secret": grant["secret"]})
            row = users[key[1]]
            if grant["origin"] != "imported" or grant["version"] > 1:
                row["secret"] = grant["secret"]
            row["enabled"] = grant["desired_state"] == "enabled"
            grant["observed_state"] = grant["desired_state"]
            for op in self.operations.values():
                if gid in op["grants"]:
                    op["status"] = "succeeded"
        for key in [k for k in self.managed if k not in wanted]:
            self.runtime[key[0]].pop(key[1], None)
            del self.managed[key]

    def publish(self, node_id):
        self.generation += 1
        self.central_nodes[node_id]["desired"] = self.generation

    # --- dispatch ---
    def dispatch(self, side, method, path, payload, bearer):
        path, _, query = path.partition("?")
        if path == "/api/auth/me":
            return 200, {"username": "owner", "role": "owner"}
        try:
            return (self.node_route if side == "node" else self.central_route)(method, path, payload, bearer, query)
        except KeyError:
            return 404, {"detail": "not found"}

    def _key_for(self, bearer):
        for key_id, key in self.keys.items():
            if key["plaintext"] == bearer and key["enabled"]:
                return key_id
        return None

    def node_route(self, method, path, payload, bearer, query):
        if path.startswith("/api/fleet/v2/"):
            if self._key_for(bearer) is None or not self.container_up:
                return 401, {"detail": "unauthorized"}
            if path.endswith("/identity"):
                return 200, {"guid": self.node_guid, "api_version": 2, "master_guid": self.master_guid,
                             "panel_version": "0.3.0", "protocols": {}}
            if path.endswith("/inventory"):
                return 200, {"protocols": self.inventory()}
        if method == "GET" and path == "/healthz":
            return 200, {"status": "ok"}
        if method == "GET" and path in ("/api/users", "/api/naive/users", "/api/mieru/users"):
            protocol = {"/api/users": "mtproxy", "/api/naive/users": "naive", "/api/mieru/users": "mieru"}[path]
            return 200, {"items": [{"username": u, "enabled": r["enabled"]} for u, r in self.runtime[protocol].items()],
                         "service": {"revision": "r1"}}
        match = re.fullmatch(r"/api/(naive/|mieru/)?users/([^/]+)/(enable|disable)", path)
        if match and method == "POST":
            protocol = {None: "mtproxy", "naive/": "naive", "mieru/": "mieru"}[match.group(1)]
            if (protocol, match.group(2)) in self.managed:
                return 409, {"detail": "managed by the central panel", "code": "managed_by_central"}
            self.runtime[protocol][match.group(2)]["enabled"] = match.group(3) == "enable"
            return 200, {}
        match = re.fullmatch(r"/api/(naive/|mieru/)?users/([^/]+)", path)
        if match and method == "DELETE":
            protocol = {None: "mtproxy", "naive/": "naive", "mieru/": "mieru"}[match.group(1)]
            if protocol == "mieru" and (payload or {}).get("expected_revision") != "r1":
                return 422, {"detail": "expected_revision is required"}
            self.runtime[protocol].pop(match.group(2), None)
            return 204, {}
        if path == "/api/keys" and method == "GET":
            return 200, {"items": [self._key_row(i) for i in self.keys]}
        if path == "/api/keys" and method == "POST":
            key_id, self.next_key = self.next_key, self.next_key + 1
            plaintext = f"pc_{key_id:08x}_" + "k" * 43
            self.secrets_issued.append(plaintext)
            self.keys[key_id] = {"name": payload["name"], "scope": payload["scope"], "enabled": True, "plaintext": plaintext}
            return 201, {"key": self._key_row(key_id), "plaintext": plaintext}
        match = re.fullmatch(r"/api/keys/(\d+)/enabled", path)
        if match and method == "POST":
            self.keys[int(match.group(1))]["enabled"] = payload["enabled"]
            return 200, {"ok": True}
        match = re.fullmatch(r"/api/keys/(\d+)", path)
        if match and method == "DELETE":
            del self.keys[int(match.group(1))]
            return 200, {"ok": True}
        if path == "/api/nodes/local/unlink" and method == "POST":
            self.master_guid, released = None, len(self.managed)
            self.managed.clear()
            return 200, {"released": released}
        raise KeyError(path)

    def _key_row(self, key_id):
        key = self.keys[key_id]
        return {"id": key_id, "name": key["name"], "scope": key["scope"], "enabled": key["enabled"],
                "prefix": key["plaintext"].split("_")[1]}

    def inventory(self):
        return {p: [{"runtime_username": u, "enabled": r["enabled"], "options": {},
                     "ownership": "central" if (p, u) in self.managed else "local",
                     "ref": self.managed.get((p, u))} for u, r in rows.items()]
                for p, rows in self.runtime.items()}

    def _grant_view(self, gid):
        grant = self.grants[gid]
        return {"id": gid, "client_id": grant["client_id"], "protocol": grant["protocol"], "node_id": grant["node_id"],
                "runtime_username": grant["runtime_username"], "desired_state": grant["desired_state"],
                "observed_state": grant["observed_state"], "origin": grant["origin"],
                "secret_ref": {"secret_id": f"grant:{gid}", "version": grant["version"]}}

    def _node_view(self, node_id):
        link = self.central_nodes[node_id]
        return {"node_id": node_id, "transport": "panel",
                "link": {"status": link["status"], "desired_generation": link["desired"],
                         "acknowledged_generation": link["acknowledged"], "config_dirty": link["desired"] > link["acknowledged"],
                         "last_error": None if link["status"] == "online" else "NodeUnreachable: ConnectError"}}

    def _client_view(self, cid):
        return {"client": {"id": cid, "display_name": self.clients[cid]["display_name"], "state": "active"},
                "grants": [self._grant_view(g) for g, grant in self.grants.items() if grant["client_id"] == cid]}

    def _new_id(self, prefix):
        self.counter += 1
        return f"{prefix}-{self.counter}"

    def central_route(self, method, path, payload, bearer, query):
        if method == "GET" and path == "/healthz":
            return 200, {"status": "ok"}
        if path == "/api/nodes/fingerprint":
            return 200, {"sha256": self.leaf_sha256}
        if path == "/api/nodes/test":
            if self._key_for(payload["api_key"]) is None:
                return 409, {"detail": "the node refused the API key", "code": "node_auth_failed"}
            if payload.get("tls_verify") == "pin" and payload.get("pinned_sha256") != self.leaf_sha256:
                return 409, {"detail": "the node is unreachable: SSLCertVerificationError"}
            return 200, {"identity": {"guid": self.node_guid, "api_version": 2, "master_guid": self.master_guid},
                         "status": {}, "inventory": {"protocols": self.inventory()}, "latency_ms": 3, "url": payload["url"]}
        if path == "/api/nodes/link" and method == "POST":
            key_id = self._key_for(payload["api_key"])
            if key_id is None:
                return 409, {"detail": "the node refused the API key"}
            if self.break_link:
                self.keys[key_id]["enabled"] = False  # the heartbeat will never see the node online
            self.central_nodes[self.node_guid] = {"key_id": key_id, "status": "unknown", "desired": 0, "acknowledged": 0}
            return 201, {"node_id": self.node_guid}
        if path == "/api/nodes" and method == "GET":
            return 200, {"items": [self._node_view(n) for n in self.central_nodes]}
        match = re.fullmatch(r"/api/nodes/([^/]+)(/.*)?", path)
        if match:
            node_id, rest = match.group(1), match.group(2) or ""
            if node_id not in self.central_nodes:
                return 404, {"detail": "node not found"}
            link = self.central_nodes[node_id]
            if rest == "" and method == "GET":
                return 200, self._node_view(node_id)
            if rest == "" and method == "DELETE":
                # Provisioned grants block; imported ones are released (their rows go, the
                # node keeps the users as local ones) — panel.fleet_v2.links.delete.
                if any(g["node_id"] == node_id and g["origin"] != "imported" for g in self.grants.values()):
                    return 409, {"detail": "the node still carries provisioned grants that are not deleted"}
                for gid in [g for g, grant in self.grants.items() if grant["node_id"] == node_id]:
                    del self.grants[gid]
                self.master_guid, self.managed = None, {}
                del self.central_nodes[node_id]
                return 200, {"ok": True}
            if rest == "/inventory":
                table = self.inventory()
                for protocol, rows in table.items():
                    for row in rows:
                        row["linked_grant_id"] = next((g for g, grant in self.grants.items()
                                                       if (grant["protocol"], grant["runtime_username"]) == (protocol, row["runtime_username"])), None)
                return 200, {"protocols": table}
            if rest == "/import":
                imported, without = [], []
                for item in payload["resources"]:
                    cid = self._new_id("client")
                    self.clients[cid] = {"display_name": item["runtime_username"]}
                    gid = self._new_id("grant")
                    row = self.runtime[item["protocol"]][item["runtime_username"]]
                    self.grants[gid] = {"client_id": cid, "protocol": item["protocol"], "node_id": node_id,
                                        "runtime_username": item["runtime_username"], "desired_state": "enabled" if row["enabled"] else "disabled",
                                        "observed_state": "enabled", "origin": "imported", "version": 1, "secret": row["secret"]}
                    imported.append({"grant_id": gid, "client_id": cid, "protocol": item["protocol"],
                                     "runtime_username": item["runtime_username"], "has_credential": item["protocol"] != "mieru"})
                    if item["protocol"] == "mieru":
                        without.append(f"mieru:{item['runtime_username']}")
                self.publish(node_id)
                return 200, {"imported": imported, "without_credential": without, "already_linked": []}
            if rest == "/generations":
                return 200, {"desired": {"generation": link["desired"]},
                             "observed": {"applied_generation": link["acknowledged"],
                                          "reconcile_state": "converged" if link["acknowledged"] == link["desired"] else "applying",
                                          "resources": [{"ref": ref, "state": "enabled"} for ref in self.managed.values()]}}
            if rest == "/link" and method == "POST":
                key_id = self._key_for(payload["api_key"])
                if key_id is None:
                    return 409, {"detail": "the node refused the API key"}
                link["key_id"] = key_id
                return 200, self._node_view(node_id)
        if path == "/api/clients" and method == "POST":
            cid = self._new_id("client")
            self.clients[cid] = {"display_name": payload["display_name"]}
            return 201, {"id": cid, "display_name": payload["display_name"], "state": "active"}
        match = re.fullmatch(r"/api/clients/([^/]+)", path)
        if match and method == "GET":
            return 200, self._client_view(match.group(1))
        match = re.fullmatch(r"/api/clients/([^/]+)/grants", path)
        if match and method == "POST":
            cid, op_id, gids = match.group(1), self._new_id("op"), []
            for item in payload["grants"]:
                gid = self._new_id("grant")
                secret = HEX32 if item["protocol"] == "mtproxy" else f"{item['protocol']}-{gid}-secret"
                self.secrets_issued.append(secret)
                self.grants[gid] = {"client_id": cid, "protocol": item["protocol"], "node_id": item["node_id"],
                                    "runtime_username": item["runtime_username"], "desired_state": "enabled",
                                    "observed_state": "pending", "origin": "provisioned", "version": 1, "secret": secret}
                gids.append(gid)
            self.operations[op_id] = {"status": "pending_remote", "grants": gids, "client_id": cid}
            self.publish(item["node_id"])
            return 200, {"operation_id": op_id, "status": "pending_remote"}
        match = re.fullmatch(r"/api/operations/([^/]+)", path)
        if match and method == "GET":
            op = self.operations[match.group(1)]
            return 200, {"operation_id": match.group(1), "status": op["status"], "client_id": op["client_id"]}
        match = re.fullmatch(r"/api/operations/([^/]+)/bundle", path)
        if match and method == "POST":
            op = self.operations[match.group(1)]
            if op["status"] != "succeeded":
                return 409, {"detail": "only a succeeded operation has a bundle"}
            grants = []
            for gid in op["grants"]:
                grant = self.grants.get(gid)
                if grant is None:
                    continue
                value = {"mtproxy": f"tg://proxy?server=proxy.lab.test&port=443&secret=ee{grant['secret']}{'proxy.lab.test'.encode().hex()}",
                         "naive": f"naive+https://{grant['runtime_username']}:{grant['secret']}@naive.lab.test",
                         "mieru": f"mierus://{grant['runtime_username']}:{grant['secret']}@mieru.lab.test?port=46001"}[grant["protocol"]]
                grants.append({"protocol": grant["protocol"], "runtime_username": grant["runtime_username"],
                               "artifacts": [{"kind": "link", "value": value}]})
            token = self._new_id("reveal")
            self.reveals[token] = {"operation_id": match.group(1), "grants": grants}
            return 200, {"reveal_token": token}
        match = re.fullmatch(r"/api/reveal/([^/]+)", path)
        if match and method == "GET":
            payload = self.reveals.pop(match.group(1), None)
            return (200, payload) if payload else (410, {"detail": "gone"})
        match = re.fullmatch(r"/api/clients/grants/([^/]+)/(enable|disable|rotate|delete)", path)
        if match and method == "POST":
            gid, action = match.groups()
            grant = self.grants.get(gid)
            if grant is None:
                return 404, {"detail": "grant not found"}
            if action == "delete":
                grant["desired_state"] = "deleted"
            elif action == "rotate":
                grant["version"] += 1
                grant["secret"] = HEX32[::-1] if grant["protocol"] == "mtproxy" else f"{grant['protocol']}-{gid}-v{grant['version']}"
                self.secrets_issued.append(grant["secret"])
            else:
                grant["desired_state"] = "enabled" if action == "enable" else "disabled"
            grant["observed_state"] = "pending"
            self.publish(grant["node_id"])
            return (200, {"ok": True}) if action == "delete" else (200, self._grant_view(gid))
        match = re.fullmatch(r"/api/clients/([^/]+)/subscription", path)
        if match and method == "GET":
            current = None if self.subscription_token is None else {"id": "s1", "generation": 1}
            return 200, {"configured": True, "subscription": current, "grants": []}
        if match and method == "POST":
            self.subscription_token = self._new_id("sub") + "-" + "t" * 40
            token = self._new_id("reveal")
            self.reveals[token] = {"url": f"http://127.0.0.1:8791/s/{self.subscription_token}"}
            return 201, {"reveal_token": token}
        match = re.fullmatch(r"/api/clients/([^/]+)/subscription/revoke", path)
        if match and method == "POST":
            self.subscription_token = None
            return 200, {"revoked": True}
        match = re.fullmatch(r"/api/clients/([^/]+)/state", path)
        if match and method == "POST":
            if payload["state"] == "archived" and any(g["client_id"] == match.group(1) for g in self.grants.values()):
                return 409, {"detail": "client still has grants that are not deleted"}
            if payload["state"] == "archived":
                del self.clients[match.group(1)]
            return 200, {"id": match.group(1), "state": payload["state"]}
        if path == "/api/events" and method == "GET":
            return 200, {"items": [{"id": i + 1, "name": e["name"], "detail": {"node_id": e["node_id"]}}
                                   for i, e in enumerate(self.events)]}
        raise KeyError(path)

    # --- the subscription the scenario fetches over plain HTTP ---
    def fetch(self, url, headers=None):
        if self.subscription_token is None or self.subscription_token not in url:
            return 404, {}, b"not found"
        client_id = next(iter(c for c in self.clients if self.clients[c]["display_name"] == "fleet-probe"), None)
        live = [g for g in self.grants.values() if g["client_id"] == client_id and g["desired_state"] == "enabled"]
        if "format=clash" in url:
            body = "proxies:\n" + "".join(f"  - name: {g['runtime_username']}\n    password: {g['secret']}\n" for g in live if g["protocol"] == "mieru")
        elif "format=singbox" in url:
            body = json.dumps({"outbounds": [{"type": "naive", "tag": g["runtime_username"], "password": g["secret"]}
                                             for g in live if g["protocol"] == "naive"]})
        else:
            body = "\n".join({"mtproxy": "tg://proxy?x", "naive": "naive+https://x", "mieru": "mierus://x"}[g["protocol"]] for g in live)
        return 200, {"ETag": '"e"'}, body.encode()
