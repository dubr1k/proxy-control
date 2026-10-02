"""Upgrade only exact installer-owned predecessor configs; never edit a foreign frontend."""
from pathlib import Path

import pytest


STREAM = """# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER
map $ssl_preread_server_name $proxy_control_backend {
    mt.example.com 127.0.0.1:8445;
    panel.example.com 127.0.0.1:8443;
    default 127.0.0.1:8443;
}
server {
    listen 443;
    ssl_preread on;
    proxy_pass $proxy_control_backend;
}
# END PROXY-CONTROL GENERATED STREAM ROUTER
"""
PANEL = ('server { listen 127.0.0.1:8443 ssl; server_name panel.example.com; '
         'ssl_certificate /etc/letsencrypt/live/mt.example.com/fullchain.pem; '
         'ssl_certificate_key /etc/letsencrypt/live/mt.example.com/privkey.pem; '
         'location ^~ /s/ { access_log off; return 404; } '
         'location / { proxy_pass http://127.0.0.1:8787; proxy_set_header Host $host; '
         'proxy_set_header X-Forwarded-Proto https; '
         'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; } }\n')


def fake_reload(run):
    run(("systemctl", "reload", "nginx"))


@pytest.fixture
def predecessor(tmp_path):
    project = tmp_path / "opt/mtproxy-shared443"
    project.mkdir(parents=True)
    (project / ".mtproxy-owned").write_text("owned")
    paths = (tmp_path / "etc/nginx/stream.d/proxy-control.conf",
             tmp_path / "etc/nginx/conf.d/proxy-control-panel.conf")
    for path, content in zip(paths, (STREAM, PANEL)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return tmp_path, project, paths


def test_predecessor_plan_is_read_only_then_apply_is_idempotent(predecessor):
    from installer.ingress_upgrade import upgrade

    root, project, paths = predecessor
    calls = []
    result = upgrade(project, root=root, run=calls.append)
    assert result["status"] == "pending" and not calls
    assert [p.read_text() for p in paths] == [STREAM, PANEL]
    result = upgrade(project, root=root, apply=True, run=calls.append, reload=fake_reload)
    assert result["status"] == "applied"
    assert "proxy_protocol on;" in paths[0].read_text()
    assert "real_ip_header proxy_protocol;" in paths[1].read_text()
    assert calls == [("nginx", "-t"), ("systemctl", "reload", "nginx")]
    backup = Path(result["backup"])
    assert backup.stat().st_mode & 0o777 == 0o700
    assert (backup / "stream.conf").read_text() == STREAM
    assert (backup / "panel.conf").read_text() == PANEL
    assert upgrade(project, root=root, apply=True, run=calls.append, reload=fake_reload)["status"] == "current"
    assert len(calls) == 2


@pytest.mark.parametrize("fail_on", [("nginx", "-t"), ("systemctl", "reload", "nginx")])
def test_invalid_config_or_failed_reload_restores_both_configs(predecessor, fail_on):
    from installer.ingress_upgrade import UpgradeError, upgrade

    root, project, paths = predecessor
    calls = []

    def run(command):
        calls.append(command)
        if command == fail_on and calls.count(command) == 1:
            raise RuntimeError("injected failure")

    with pytest.raises(UpgradeError, match="restored"):
        upgrade(project, root=root, apply=True, run=run, reload=fake_reload)
    assert [p.read_text() for p in paths] == [STREAM, PANEL]
    assert calls[-2:] == [("nginx", "-t"), ("systemctl", "reload", "nginx")]


def test_edited_owned_config_is_refused_and_foreign_missing_is_skipped(predecessor):
    from installer.ingress_upgrade import UpgradeError, upgrade

    root, project, paths = predecessor
    paths[1].write_text(PANEL.replace("8787", "8788") + "# custom edit\n")
    before = paths[1].read_text()
    with pytest.raises(UpgradeError, match="template"):
        upgrade(project, root=root, apply=True)
    assert paths[1].read_text() == before and paths[0].read_text() == STREAM
    paths[0].unlink()
    assert upgrade(project, root=root, apply=True)["status"] == "coexist_manual"


def test_socket_collision_is_refused_without_unlinking_foreign_path(predecessor):
    from installer.ingress_upgrade import UpgradeError, upgrade

    root, project, paths = predecessor
    occupied = root / "run/proxy-control-panel-tls.sock"
    occupied.parent.mkdir()
    occupied.write_text("foreign socket placeholder")
    with pytest.raises(UpgradeError, match="socket path is occupied"):
        upgrade(project, root=root, apply=True)
    assert occupied.read_text() == "foreign socket placeholder"
    assert [p.read_text() for p in paths] == [STREAM, PANEL]


def test_async_reload_failure_restores_configuration(predecessor):
    from installer.ingress_upgrade import UpgradeError, upgrade

    root, project, paths = predecessor
    calls = []

    def reload(run):
        run(("systemctl", "reload", "nginx"))
        if len(calls) == 2:
            raise UpgradeError("old workers still serving after reload exit zero")

    with pytest.raises(UpgradeError, match="restored"):
        upgrade(project, root=root, apply=True, run=calls.append, reload=reload)
    assert [p.read_text() for p in paths] == [STREAM, PANEL]
    assert calls[-2:] == [("nginx", "-t"), ("systemctl", "reload", "nginx")]


def test_reload_requires_a_live_new_worker_generation(monkeypatch):
    from installer import ingress_upgrade as module

    states = iter([(10, {20}), (10, {20}), (10, {20, 21}), (10, {21})])
    monkeypatch.setattr(module, "_workers", lambda: next(states))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    calls = []
    module._reload(calls.append)
    assert calls == [("systemctl", "reload", "nginx")]
