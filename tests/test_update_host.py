"""`install-release.sh --update` → `scripts/update-host.sh` (v1.1): the host's version-agent updates
the panel only to the digest the script verified, then the managers it names are rebuilt with the
agent's own Compose call and the router's MTProxy bridge is started — against a fake agent on a
Unix socket and a fake `docker` that records what it was asked."""
from __future__ import annotations

import json
import os
import socketserver
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "update-host.sh"
DIGEST = "a" * 64
RUNNING_IMAGE = "sha256:" + "b" * 64
CACHED_IMAGE = "sha256:" + "c" * 64
CONTAINER = "d" * 64
pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="update-host.sh runs as root (the lab suite does)")


class Agent:
    def __init__(self, *, current="1.0.3", offered_digest=DIGEST, pending=("xray_router_manager",)):
        self.current, self.offered_digest, self.pending = current, offered_digest, list(pending)
        self.updates: list[dict] = []
        self.acks: list[dict] = []
        self.ack_status = 200
        self.rebuilding_polls = 0

    def _count(self) -> bool:
        self.rebuilding_polls -= 1
        return self.rebuilding_polls <= 0

    def versions(self) -> dict:
        panel = {"current": self.current, "status": "ready", "pending_rebuild": self.pending if self.updates else [],
                 **({"rebuilding_managers": True} if self.rebuilding_polls > 0 and not self._count() else {}),
                 "available": [{"version": "1.1.0", "sha256": self.offered_digest}]}
        return {"components": {"panel": panel}}


def _serve(path: Path, agent: Agent):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _answer(self, value, status=200):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._answer(agent.versions() if self.path == "/v1/versions" else {"ok": True})

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.path == "/v1/update":
                request = json.loads(body)
                agent.updates.append(request)
                agent.current = request["version"]
            if self.path == "/v1/panel/managers/ack":
                agent.acks.append(json.loads(body))
                self._answer({"detail": "x"} if agent.ack_status != 200 else {"pending_rebuild": []}, agent.ack_status)
                return
            self._answer(agent.versions() if self.path == "/v1/upstream/check" else {"changed": True})

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

        def get_request(self):
            request, _ = super().get_request()
            return request, ("local", 0)

    server = Server(str(path), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def host(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text("X=1\n")
    (project / ".env.xray-router").write_text("Y=1\n")
    (project / "compose.xray-router.yaml").write_text("services:\n  xray-router:\n    image: x\n  xray-router-ingress:\n    image: x\n")
    # A 4.0 host: the agent already syncs the shared Rust crate.
    shutil.copytree(ROOT / "pc_common", project / "pc_common", ignore=shutil.ignore_patterns("target"))
    env_file = tmp_path / "version-agent.env"
    env_file.write_text(f"PROXY_CONTROL_COMPOSE_DIR={project}\n"
                        "PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.naive.yaml:compose.xray-router.yaml\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.log"
    running_services = tmp_path / "running-services"
    running_services.write_text("")
    (bin_dir / "docker").write_text(f"""#!/bin/sh
echo "$*" >> {log}
case "$*" in
  "ps -a -q --filter label=com.docker.compose.project=mtproxy") exit 0 ;;  # 3.0: nothing left to move
  *"ps --filter label=com.docker.compose.project=proxy_panel_by_dubr1k --format "*) cat {running_services}; exit 0 ;;
  *" ps -a -q "*) echo {CONTAINER}; exit 0 ;;
esac
case "$1 $2" in
  "exec proxy-control-panel") echo 1.1.0 ;;
  "inspect -f") echo healthy ;;
  "inspect --format") echo {RUNNING_IMAGE} ;;
  "image inspect") echo {CACHED_IMAGE} ;;
  "ps -a") echo proxy-control-panel; echo proxy-control-xray-router-ingress ;;
esac
exit 0
""")
    (bin_dir / "docker").chmod(0o755)
    return {"tmp": tmp_path, "env_file": env_file, "bin": bin_dir, "log": log, "project": project,
            "running_services": running_services}


def _run(host, agent: Agent, digest=DIGEST):
    socket_path = host["tmp"] / "agent.sock"
    server = _serve(socket_path, agent)
    try:
        environment = {"PATH": f"{host['bin']}:/usr/bin:/bin", "UPDATE_HOST_AGENT_SOCKET": str(socket_path),
                       "UPDATE_HOST_AGENT_ENV": str(host["env_file"]), "UPDATE_HOST_POLL_SECONDS": "0"}
        return subprocess.run(["bash", str(host.get("script", SCRIPT)), "--version", "1.1.0", "--sha256", digest, "--lang", "en"],
                              env=environment, capture_output=True, text=True, timeout=120)
    finally:
        server.shutdown()
        server.server_close()


def test_updates_the_panel_then_rebuilds_the_router_and_starts_the_bridge(host):
    agent = Agent()
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert agent.updates == [{"component": "panel", "version": "1.1.0", "expected_current": "1.0.3"}]
    calls = host["log"].read_text().splitlines()
    up = [line for line in calls if " up -d --build --no-deps --wait " in line]
    assert len(up) == 1 and up[0].endswith("xray-router xray-router-ingress")
    assert "--env-file .env.xray-router" in up[0] and f"-f {host['project']}/compose.xray-router.yaml" in up[0]
    assert "done: Proxy Control 1.1.0" in result.stdout


def test_a_host_not_moved_yet_is_updated_in_its_old_project(host):
    """3.0: until the migration at the end, the script addresses the project the panel runs in."""
    docker = host["bin"] / "docker"
    legacy = (
        "case \"$*\" in\n"
        "  *'compose.project\"}} proxy-control-panel') echo mtproxy; exit 0 ;;\n"
        f"  *\"ps --filter label=com.docker.compose.project=mtproxy --format \"*) cat {host['running_services']}; exit 0 ;;\n"
    )
    docker.write_text(docker.read_text().replace("case \"$*\" in\n", legacy, 1))
    result = _run(host, Agent())
    assert result.returncode == 0, result.stderr
    calls = host["log"].read_text().splitlines()
    [up] = [line for line in calls if " up -d --build --no-deps --wait " in line]
    assert up.startswith("compose --project-name mtproxy ")
    assert any(line.startswith("tag ") and "mtproxy-xray-router:rollback-" in line for line in calls)


def test_a_digest_other_than_the_verified_one_changes_nothing(host):
    agent = Agent(offered_digest="b" * 64)
    result = _run(host, agent)
    assert result.returncode != 0 and "verified" in result.stderr
    assert agent.updates == [] and not host["log"].exists()


@pytest.mark.parametrize("service,overlay", [("mcp", "compose.mcp.yaml"),
                                            ("mieru-manager", "compose.mieru.yaml"),
                                            ("awg-manager", "compose.amneziawg.yaml")])
def test_running_optional_service_missing_from_scope_refuses_before_panel_update(host, service, overlay):
    host["running_services"].write_text(service + "\n")
    agent = Agent()
    result = _run(host, agent)
    assert result.returncode != 0 and overlay in result.stderr
    assert agent.updates == []
    assert not any(" up -d " in line for line in host["log"].read_text().splitlines())


def test_declared_running_mcp_is_allowed(host):
    host["running_services"].write_text("mcp\n")
    with host["env_file"].open("a") as stream:
        stream.write("PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.mcp.yaml\n")
    result = _run(host, Agent(pending=()))
    assert result.returncode == 0, result.stderr


def test_compose_service_lookup_failure_refuses_before_panel_update(host):
    docker = host["bin"] / "docker"
    docker.write_text(docker.read_text().replace(f"cat {host['running_services']}; exit 0", "exit 1"))
    agent = Agent()
    result = _run(host, agent)
    assert result.returncode != 0 and "could not determine running Compose services" in result.stderr
    assert agent.updates == []


def test_a_host_already_on_the_release_only_rebuilds_what_is_missing(host):
    agent = Agent(current="1.1.0")
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert agent.updates == []
    up = [line for line in host["log"].read_text().splitlines() if " up -d " in line]
    assert len(up) == 1 and up[0].endswith("--wait xray-router-ingress")


def test_a_host_without_the_shared_rust_crate_gets_it_and_rebuilds_the_router(host):
    """4.0: the router's manager is Rust and builds against `pc_common`, which agents before 4.0 do
    not sync: the script completes it from the verified release and rebuilds the router with it."""
    shutil.rmtree(host["project"] / "pc_common")
    agent = Agent(current="1.1.0")
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert (host["project"] / "pc_common" / "Cargo.toml").read_bytes() == (ROOT / "pc_common" / "Cargo.toml").read_bytes()
    up = [line for line in host["log"].read_text().splitlines() if " up -d " in line]
    # Every Rust manager on the host is rebuilt against it: this host also runs naive-manager.
    assert len(up) == 1 and set(up[0].split(" --wait ", 1)[1].split()) == {
        "naive-manager", "xray-router", "xray-router-ingress"}
    assert any("xray_router_manager" in ack["names"] for ack in agent.acks)


def test_without_an_agent_it_points_to_the_manual_upgrade(host):
    environment = {"PATH": "/usr/bin:/bin", "UPDATE_HOST_AGENT_SOCKET": str(host["tmp"] / "none.sock")}
    result = subprocess.run(["bash", str(SCRIPT), "--version", "1.1.0", "--sha256", DIGEST], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 and "UPGRADING" in result.stderr


def test_the_published_script_offers_update():
    text = (ROOT / "scripts" / "install-release.sh").read_text()
    assert "--update) MODE=update" in text and 'scripts/update-host.sh" --version "$VERSION" --sha256 "$actual"' in text


def test_mcp_changes_are_rebuilt_with_the_installed_overlay(host):
    with host["env_file"].open("a") as stream:
        stream.write("PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.mcp.yaml\n")
    (host["project"] / ".env.mcp").write_text("MCP_DOMAIN=example.test\n")
    result = _run(host, Agent(pending=("mcp_server",)))
    assert result.returncode == 0, result.stderr
    calls = host["log"].read_text().splitlines()
    up = next(line for line in calls if " up -d --build --no-deps --wait " in line)
    assert up.endswith("--wait mcp") and "--env-file .env.mcp" in up
    assert any(line.startswith(f"tag {RUNNING_IMAGE} proxy_panel_by_dubr1k-mcp:rollback-") for line in calls)
    assert not any(line.startswith("tag proxy_panel_by_dubr1k-mcp:latest ") for line in calls)


def test_failed_mcp_rebuild_restores_previous_image_and_reports_failure(host):
    with host["env_file"].open("a") as stream:
        stream.write("PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.mcp.yaml\n")
    docker = host["bin"] / "docker"
    docker.write_text(docker.read_text().replace('case "$1 $2" in',
        'case "$*" in *" up -d --build "*) exit 1 ;; esac\ncase "$1 $2" in'))
    result = _run(host, Agent(pending=("mcp_server",)))
    assert result.returncode != 0 and "done:" not in result.stdout
    calls = host["log"].read_text().splitlines()
    assert any(line.startswith(f"tag {RUNNING_IMAGE} proxy_panel_by_dubr1k-mcp:rollback-") for line in calls)
    assert not any(line.startswith(f"tag {CACHED_IMAGE} ") for line in calls)
    assert any(line.startswith("tag proxy_panel_by_dubr1k-mcp:rollback-") and line.endswith(" proxy_panel_by_dubr1k-mcp:latest") for line in calls)
    assert any(" up -d --no-build --no-deps --wait mcp" in line for line in calls)
    assert "previous images restored" in result.stderr


@pytest.mark.parametrize("image_reply", ["echo invalid", "echo", "exit 1"])
def test_existing_container_without_verified_image_refuses_manager_build(host, image_reply):
    docker = host["bin"] / "docker"
    docker.write_text(docker.read_text().replace(f'"inspect --format") echo {RUNNING_IMAGE}',
                                               f'"inspect --format") {image_reply}'))
    result = _run(host, Agent())
    assert result.returncode != 0
    calls = host["log"].read_text().splitlines()
    assert not any(" up -d --build " in line for line in calls)
    assert not any(line.startswith("tag ") for line in calls)


def test_new_service_cached_image_is_preserved_but_never_claimed_as_restored(host):
    docker = host["bin"] / "docker"
    source = docker.read_text().replace(f'echo {CONTAINER}; exit 0', 'exit 0')
    source = source.replace('case "$1 $2" in',
                            'case "$*" in *" up -d --build "*) exit 1 ;; esac\ncase "$1 $2" in')
    docker.write_text(source)
    result = _run(host, Agent())
    assert result.returncode != 0
    calls = host["log"].read_text().splitlines()
    assert any(line.startswith(f"tag {CACHED_IMAGE} proxy_panel_by_dubr1k-xray-router:rollback-") for line in calls)
    assert any(line.startswith("tag proxy_panel_by_dubr1k-xray-router:rollback-")
               and line.endswith(" proxy_panel_by_dubr1k-xray-router:latest") for line in calls)
    assert not any(" up -d --no-build " in line for line in calls)
    assert "previous images restored" not in result.stderr
    assert "new services need operator recovery" in result.stderr


@pytest.mark.parametrize("container_reply", ["exit 1", "echo invalid"])
def test_container_lookup_failure_refuses_manager_build(host, container_reply):
    docker = host["bin"] / "docker"
    docker.write_text(docker.read_text().replace(f'echo {CONTAINER}; exit 0', container_reply))
    result = _run(host, Agent())
    assert result.returncode != 0
    calls = host["log"].read_text().splitlines()
    assert not any(" up -d --build " in line for line in calls)
    assert not any(line.startswith("tag ") for line in calls)


def test_legacy_agent_missing_mcp_sync_is_completed_from_verified_release(host):
    with host["env_file"].open("a") as stream:
        stream.write("PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.mcp.yaml\n")
    release = host["tmp"] / "release"
    (release / "scripts").mkdir(parents=True)
    (release / "mcp_server").mkdir()
    (release / "mcp_server/server.py").write_text("new mcp")
    shutil.copytree(ROOT / "installer", release / "installer")
    host["script"] = release / "scripts/update-host.sh"
    shutil.copy2(SCRIPT, host["script"])
    shutil.copy2(ROOT / "scripts" / "migrate-compose-project.sh", release / "scripts")
    source = host["project"] / "mcp_server"
    source.mkdir()
    (source / "server.py").write_text("old mcp")
    result = _run(host, Agent(pending=()))
    assert result.returncode == 0, result.stderr
    assert (source / "server.py").read_text() == "new mcp"
    assert any((p / "server.py").read_text() == "old mcp" for p in (host["project"] / "version-overrides").glob("mcp-source-previous-*"))
    assert any(" up -d --build --no-deps --wait mcp" in line for line in host["log"].read_text().splitlines())


def test_python_mcp_sources_are_replaced_by_the_rust_crate(host):
    """4.0: a host still carrying the Python MCP package gets the Rust crate from the verified
    release; the old tree (with its bytecode) goes to the backup and `mcp` is rebuilt once."""
    with host["env_file"].open("a") as stream:
        stream.write("PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.mcp.yaml\n")
    release = host["tmp"] / "release"
    (release / "scripts").mkdir(parents=True)
    (release / "mcp_server/src").mkdir(parents=True)
    (release / "mcp_server/Cargo.toml").write_text('[package]\nname = "mcp-server"\n')
    (release / "mcp_server/src/main.rs").write_text("fn main() {}\n")
    shutil.copytree(ROOT / "installer", release / "installer")
    host["script"] = release / "scripts/update-host.sh"
    shutil.copy2(SCRIPT, host["script"])
    shutil.copy2(ROOT / "scripts" / "migrate-compose-project.sh", release / "scripts")
    source = host["project"] / "mcp_server"
    (source / "__pycache__").mkdir(parents=True)
    (source / "server.py").write_text("old mcp")
    (source / "__pycache__/server.cpython-313.pyc").write_bytes(b"\0")
    result = _run(host, Agent(pending=("mcp_server",)))
    assert result.returncode == 0, result.stderr
    assert sorted(path.relative_to(source).as_posix() for path in source.rglob("*")) == ["Cargo.toml", "src", "src/main.rs"]
    previous = list((host["project"] / "version-overrides").glob("mcp-source-previous-*"))
    assert len(previous) == 1 and (previous[0] / "server.py").read_text() == "old mcp"
    rebuilds = [line for line in host["log"].read_text().splitlines() if " up -d --build --no-deps --wait " in line]
    assert len(rebuilds) == 1 and rebuilds[0].endswith("--wait mcp")


@pytest.mark.parametrize("migration_exit", [0, 1])
def test_verified_update_runs_ingress_migration_and_reports_failure(host, migration_exit):
    wrapper = host["bin"] / "python3"
    migration_log = host["tmp"] / "migration.log"
    wrapper.write_text(f'''#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "installer.ingress_upgrade" ]; then
  printf '%s\\n' "$PWD" "$*" > "{migration_log}"
  exit {migration_exit}
fi
exec /usr/bin/python3 "$@"
''')
    wrapper.chmod(0o755)
    result = _run(host, Agent())
    assert migration_log.exists()
    calls = migration_log.read_text().splitlines()
    assert calls[0] == str(ROOT)
    assert calls[1] == f"-m installer.ingress_upgrade --project-dir {host['project']} --apply"
    assert (result.returncode == 0) == (migration_exit == 0)
    assert ("done: Proxy Control" in result.stdout) == (migration_exit == 0)


def test_amneziawg_manager_changes_are_rebuilt_with_the_installed_overlay(host):
    """The tunnels drop while the manager restarts and the peers reconnect; its state directory is
    never named by the script. The overlay's env file rides along like the other overlays'."""
    with host["env_file"].open("a") as stream:
        stream.write("PROXY_CONTROL_COMPOSE_FILES=compose.yaml:compose.amneziawg.yaml\n")
    (host["project"] / ".env.amneziawg").write_text("AWG_VERSIONS=1.5\n")
    (host["project"] / "compose.amneziawg.yaml").write_text("services:\n  awg-manager:\n    image: x\n")
    result = _run(host, Agent(pending=("awg_manager",)))
    assert result.returncode == 0, result.stderr
    calls = host["log"].read_text().splitlines()
    up = next(line for line in calls if " up -d --build --no-deps --wait " in line)
    assert up.endswith("--wait awg-manager") and "--env-file .env.amneziawg" in up
    assert f"-f {host['project']}/compose.amneziawg.yaml" in up
    assert any(line.startswith(f"tag {RUNNING_IMAGE} proxy_panel_by_dubr1k-awg-manager:rollback-") for line in calls)
    assert not any("/var/lib/awg-manager" in line for line in calls)


def test_a_host_without_amneziawg_does_not_rebuild_the_manager(host):
    result = _run(host, Agent(pending=("awg_manager",)))
    assert result.returncode == 0, result.stderr
    assert not any("awg-manager" in line for line in host["log"].read_text().splitlines())


def test_rebuilt_managers_are_acknowledged_to_the_agent(host):
    agent = Agent()
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert agent.acks == [{"names": ["xray_router_manager"]}]


def test_a_host_before_4_0_gets_pc_common_and_rebuilds_the_rust_naive_manager(host):
    shutil.rmtree(host["project"] / "pc_common")
    agent = Agent(pending=())
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert (host["project"] / "pc_common" / "Cargo.toml").is_file()
    up = next(line for line in host["log"].read_text().splitlines() if " up -d --build --no-deps --wait " in line)
    assert "naive-manager" in up.split(" --wait ", 1)[1].split()
    assert agent.acks == [{"names": ["naive_manager", "xray_router_manager"]}]


def test_an_agent_without_the_ack_endpoint_does_not_fail_the_update(host):
    agent = Agent()
    agent.ack_status = 404
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert agent.acks and "done: Proxy Control 1.1.0" in result.stdout


def test_it_waits_while_the_agent_rebuilds_the_managers_itself(host):
    agent = Agent(pending=())
    agent.rebuilding_polls = 3
    result = _run(host, agent)
    assert result.returncode == 0, result.stderr
    assert agent.rebuilding_polls <= 0 and agent.acks == []
