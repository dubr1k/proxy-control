"""Bounded host migration for the installer's pre-client-IP Nginx templates.

The foreign coexist frontend is never edited. Run without --apply to inspect the
plan; the one-command host updater applies this after its panel update succeeds.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from installer.adapters.core import _mcp_vhost_text, _panel_vhost_text, _subscription_vhost_text
from installer.adapters.nginx import _render_fresh
from installer.transaction import atomic_write

STREAM = Path("etc/nginx/stream.d/proxy-control.conf")
PANEL = Path("etc/nginx/conf.d/proxy-control-panel.conf")
STATE = Path("var/lib/proxy-control/ingress-backups")
PROXY_LISTENER = ("listen unix:/run/proxy-control-panel-tls.sock ssl proxy_protocol; "
                  "set_real_ip_from unix:; real_ip_header proxy_protocol; ")


class UpgradeError(RuntimeError):
    pass


def _read(path: Path) -> bytes:
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise UpgradeError("ingress path crosses a symlink")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid()):
        raise UpgradeError("ingress file ownership or permissions are unsafe")
    return path.read_bytes()


def _panel_template(data: bytes) -> tuple[bytes, str]:
    lines, port = [], None
    for line in data.decode().splitlines(keepends=True):
        match = re.search(r"^server \{ listen 127\.0\.0\.1:([0-9]+) ssl; ", line)
        domain = re.search(r"server_name ([a-z0-9.-]+); ", line)
        cert = re.search(r"ssl_certificate /etc/letsencrypt/live/([A-Za-z0-9_.-]+)/fullchain.pem; ", line)
        app = re.search(r"proxy_pass http://127\.0\.0\.1:([0-9]+); ", line)
        if not all((match, domain, cert, app)):
            raise UpgradeError("panel config differs from an owned template")
        if port is not None and port != match[1]:
            raise UpgradeError("panel TLS listeners disagree")
        port = match[1]
        kwargs = {"certificate": cert[1], "tls_port": int(port)}
        if "location /mcp " in line:
            rendered = _mcp_vhost_text(mcp_domain=domain[1], mcp_port=int(app[1]), **kwargs)
            legacy = rendered.replace(PROXY_LISTENER, "").replace("proxy_set_header X-Forwarded-For $remote_addr; ", "")
        else:
            if "location / { return 404; }" in line:
                rendered = _subscription_vhost_text(subscription_domain=domain[1], app_port=int(app[1]), **kwargs)
            else:
                rendered = _panel_vhost_text(panel_domain=domain[1], app_port=int(app[1]), **kwargs)
            legacy = rendered.replace(PROXY_LISTENER, "").replace(
                "X-Forwarded-For $remote_addr;", "X-Forwarded-For $proxy_add_x_forwarded_for;")
        if line not in (rendered, legacy):
            raise UpgradeError("panel config differs from an owned template")
        lines.append(rendered)
    if not lines or port is None:
        raise UpgradeError("panel config differs from an owned template")
    return "".join(lines).encode(), f"127.0.0.1:{port}"


def _stream_template(data: bytes, panel_backend: str) -> bytes:
    match = re.search(r"map \$ssl_preread_server_name \$proxy_control_backend \{\n(.*?)    default ",
                      data.decode(), re.DOTALL)
    if match is None:
        raise UpgradeError("stream config differs from an owned template")
    routes = []
    for line in match[1].splitlines():
        entry = re.fullmatch(r"    ([a-z0-9.-]+) (\S+);", line)
        if entry is None:
            raise UpgradeError("stream config differs from an owned template")
        backend = entry[2]
        if backend == "unix:/run/proxy-control-panel-tls.sock":
            backend = panel_backend
        elif raw := re.fullmatch(r"unix:/run/proxy-control-raw-([0-9]+)\.sock", backend):
            backend = f"127.0.0.1:{raw[1]}"
        if re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", backend) is None:
            raise UpgradeError("stream config differs from an owned template")
        routes.append((entry[1], backend))
    spec = {"routes": tuple(routes), "panel_tls_backend": panel_backend}
    legacy = _render_fresh(spec)
    current = _render_fresh({**spec, "client_ip": "proxy"})
    if data not in (legacy, current) or len(routes) < 2:
        raise UpgradeError("stream config differs from an owned template")
    return current


def _run(command: tuple[str, ...]) -> None:
    # Do not echo nginx -t diagnostics: foreign vhosts may contain private URLs.
    subprocess.run(command, check=True, capture_output=True, timeout=30)


def _workers() -> tuple[int, set[int]]:
    master = subprocess.run(("systemctl", "show", "nginx", "--property=MainPID", "--value"),
                            check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    if not master.isdigit() or int(master) <= 1:
        raise UpgradeError("Nginx master process is unavailable")
    children = Path(f"/proc/{master}/task/{master}/children").read_text().split()
    workers = set()
    for child in children:
        try:
            command = Path(f"/proc/{child}/cmdline").read_bytes()
        except FileNotFoundError:
            continue
        if command.startswith(b"nginx: worker process") and b"shutting down" not in command:
            workers.add(int(child))
    return int(master), workers


def _reload(run) -> None:
    # Sending HUP is asynchronous: systemctl can succeed while a bind error leaves
    # the old workers serving. The master starts new workers only after accepting
    # the new configuration and opening every listener.
    master, old = _workers()
    if not old:
        raise UpgradeError("Nginx has no serving workers before reload")
    run(("systemctl", "reload", "nginx"))
    deadline = time.monotonic() + 10
    previous = set()
    while time.monotonic() < deadline:
        current_master, workers = _workers()
        if current_master != master:
            raise UpgradeError("Nginx master changed during reload")
        fresh = workers - old
        if fresh & previous:
            return
        previous = fresh
        time.sleep(0.2)
    raise UpgradeError("Nginx did not activate a new worker generation")


def _upgrade(project: Path, *, root: Path, apply: bool, run, reload) -> dict:
    marker = project / ".mtproxy-owned"
    stream, panel = root / STREAM, root / PANEL
    if not marker.exists() or not stream.exists():
        return {"status": "coexist_manual", "client_ip": "not_verified",
                "reason": "foreign or legacy ingress is unchanged; verify client-IP forwarding separately"}
    _read(marker)
    before = {stream: _read(stream), panel: _read(panel)}
    new_panel, backend = _panel_template(before[panel])
    desired = {stream: _stream_template(before[stream], backend), panel: new_panel}
    if desired == before:
        return {"status": "current", "client_ip": "proxy_protocol"}
    if not apply:
        return {"status": "pending", "files": ["stream.d/proxy-control.conf", "conf.d/proxy-control-panel.conf"]}
    old_sockets = set(re.findall(rb"listen unix:([^ ;]+)", b"\n".join(before.values())))
    new_sockets = set(re.findall(rb"listen unix:([^ ;]+)", b"\n".join(desired.values())))
    for name in new_sockets - old_sockets:
        path = root / name.decode().lstrip("/")
        if path.exists() or path.is_symlink():
            raise UpgradeError("a new ingress Unix socket path is occupied")
    backup = Path(tempfile.mkdtemp(prefix="backup-", dir=root / STATE))
    metadata = {}
    for path, name in ((stream, "stream.conf"), (panel, "panel.conf")):
        info = path.stat()
        metadata[name] = {"path": str(path), "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
        atomic_write(backup / name, before[path], mode=0o600)
    atomic_write(backup / "metadata.json", json.dumps(metadata).encode(), mode=0o600)

    def write(contents):
        for path, name in ((stream, "stream.conf"), (panel, "panel.conf")):
            meta = metadata[name]
            atomic_write(path, contents[path], mode=meta["mode"], owner=(meta["uid"], meta["gid"]))

    # A foreign concurrent edit is not ours to roll back.
    if any(_read(path) != data for path, data in before.items()):
        raise UpgradeError("ingress changed while preparing its backup")
    try:
        write(desired)
        run(("nginx", "-t"))
        reload(run)
    except Exception as exc:
        try:
            write(before)
            run(("nginx", "-t"))
            reload(run)
        except Exception:
            raise UpgradeError(f"ingress rollback failed; private backup: {backup}") from None
        raise UpgradeError(f"ingress upgrade failed; original configuration restored; private backup: {backup}") from exc
    return {"status": "applied", "client_ip": "proxy_protocol", "backup": str(backup)}


def upgrade(project: Path, *, root: Path = Path("/"), apply: bool = False, run=_run, reload=_reload) -> dict:
    if not apply:
        return _upgrade(project, root=root, apply=False, run=run, reload=reload)
    if not project.is_dir() or project.is_symlink():
        raise UpgradeError("project directory is unavailable or unsafe")
    plan = _upgrade(project, root=root, apply=False, run=run, reload=reload)
    if plan["status"] != "pending":
        return plan
    state = root / STATE
    for path in (state, *state.parents):
        if path.is_symlink():
            raise UpgradeError("ingress backup path crosses a symlink")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = state.stat()
    if info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise UpgradeError("ingress backup directory ownership or permissions are unsafe")
    fd = os.open(state / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _upgrade(project, root=root, apply=True, run=run, reload=reload)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, default=Path("/opt/mtproxy-shared443"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.apply and os.geteuid() != 0:
            raise UpgradeError("applying ingress changes requires root")
        print(json.dumps(upgrade(args.project_dir, apply=args.apply)))
    except (UpgradeError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
