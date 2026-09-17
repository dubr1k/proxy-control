#!/usr/bin/env python3
"""Backup and restore drill (v0.6) on an installed node, as root, the way docs/BACKUP_RESTORE
says: fixture data through the panel API → a backup (the panel's online SQLite copy, the
master key apart, each manager's state directory and the router's state and secrets with
their writers stopped, SHA256SUMS) → the generation broken on purpose (database, states,
secrets gone) → restored from the backup (`master-key-verify` first) → the same users,
grants, policies, subscription URL and ingress credentials as before, byte for byte where
bytes are the contract. Everything it creates carries its own prefix and is removed.

    backup-restore-drill.py --project /opt/mtproxy-shared443 --node-url https://panel.lab.test
                            --password-file …/panel-bootstrap-password --ca-file …/ca.crt --output <dir>
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

NAIVE_STATE = Path("/var/lib/naive-manager")
MIERU_STATE = Path("/var/lib/mieru-manager")
ROUTER_STATE = Path("/var/lib/xray-router")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*argv: str, check: bool = True, timeout: int = 600) -> str:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and completed.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:3])} -> {completed.returncode}: {(completed.stdout + completed.stderr)[-400:]}")
    return completed.stdout


class Api:
    def __init__(self, base: str, ca_file: str | None):
        self.base = base.rstrip("/")
        context = ssl.create_default_context(cafile=ca_file)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=context))

    def request(self, path: str, method: str = "GET", payload=None) -> tuple[int, dict]:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if method != "GET":
            headers["X-CSRF-Token"] = next((c.value for c in self.jar if c.name == "panel_csrf"), "")
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                body, status = response.read(), response.status
        except urllib.error.HTTPError as error:
            body, status = error.read(), error.code
        except urllib.error.URLError:
            return 0, {}
        try:
            return status, json.loads(body) if body else {}
        except ValueError:
            return status, {}

    def json(self, path: str, method: str = "GET", payload=None):
        status, body = self.request(path, method, payload)
        if status >= 400 or status == 0:
            raise RuntimeError(f"{method} {path} -> {status} {json.dumps(body)[:200]}")
        return body

    def login(self, password: str) -> None:
        self.request("/login")
        status, _ = self.request("/api/auth/login", "POST", {"username": "owner", "password": password})
        if status not in (200, 204):
            raise RuntimeError(f"login refused: {status}")


class Drill:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.project = Path(args.project)
        self.output = Path(args.output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.prefix = f"br-{secrets.token_hex(3)}"
        self.report: dict = {"prefix": self.prefix, "checks": {}, "details": {}, "facts": {}, "failed": []}
        self.password = Path(args.password_file).read_text().strip().splitlines()[-1].split("=")[-1].strip()
        self.api = Api(args.node_url, args.ca_file)
        self.backup = Path(tempfile.mkdtemp(prefix="proxy-control-backup-", dir="/root"))
        self.keys = Path(tempfile.mkdtemp(prefix="proxy-control-backup-keys-", dir="/root"))
        os.chmod(self.backup, 0o700)
        os.chmod(self.keys, 0o700)
        self.client_id: str | None = None

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.report["checks"][name] = bool(ok)
        if not ok:
            self.report["details"][name] = str(detail)[:400]
            self.report["failed"].append(name)
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {str(detail)[:200]}"), flush=True)
        return bool(ok)

    # -- compose with the node's own env files -------------------------------------------

    def compose(self, *args: str) -> str:
        argv = ["docker", "compose", "--project-directory", str(self.project), "--env-file", str(self.project / ".env"), "-f", str(self.project / "compose.yaml")]
        for runtime in ("naive", "mieru", "xray-router"):
            if (self.project / f".env.{runtime}").is_file():
                argv += ["--env-file", str(self.project / f".env.{runtime}"), "-f", str(self.project / f"compose.{runtime}.yaml")]
        return run(*argv, *args)

    def panel_volume(self) -> str:
        mounts = json.loads(run("docker", "inspect", "proxy-control-panel"))[0]["Mounts"]
        return next(m["Name"] for m in mounts if m["Destination"] == "/data")

    # -- the state that must survive --------------------------------------------------------

    def snapshot(self) -> dict:
        users = {p: sorted(u["username"] for u in self.api.json(path)["items"])
                 for p, path in (("mtproxy", "/api/users"), ("naive", "/api/naive/users"), ("mieru", "/api/mieru/users"))}
        clients = {e["client"]["display_name"]: sorted((g["protocol"], g["runtime_username"], g["desired_state"]) for g in e["grants"])
                   for e in self.api.json("/api/clients")["items"] if e["client"]["state"] != "archived"}
        policies = {i["protocol"]: (i.get("policy") or {}).get("revision") for i in self.api.json("/api/routing/targets")["items"] if i["node_id"] == "local"}
        secrets_dir = self.project / "secrets"
        return {
            "users": users, "clients": clients, "policies": policies,
            "caddyfile": sha256(NAIVE_STATE / "Caddyfile"),
            "mita": run("mita", "describe", "config", check=False)[:4000],
            "ingress": {s: sha256(secrets_dir / f"xray-router-ingress-{s}") for s in ("naive", "mieru") if (secrets_dir / f"xray-router-ingress-{s}").is_file()},
            "router_generation": self.router_status().get("running", {}).get("generation"),
        }

    def router_status(self) -> dict:
        out = run("docker", "exec", "proxy-control-xray-router", "python", "-m", "xray_router_manager.healthcheck", "--status", check=False)
        try:
            return json.loads(out)
        except ValueError:
            return {}

    # -- steps ----------------------------------------------------------------------------

    def fixture(self) -> dict:
        self.api.login(self.password)
        self.api.json("/api/users", "POST", {"username": f"{self.prefix}-tg"})
        self.api.json("/api/naive/users", "POST", {"username": f"{self.prefix}-nv", "quota_bytes": 104857600})
        revision = self.api.json("/api/mieru/users")["service"]["revision"]
        self.api.json("/api/mieru/users", "POST", {"username": f"{self.prefix}-mr", "quotas": [{"days": 7, "megabytes": 256}], "expected_revision": revision})
        client = self.api.json("/api/clients", "POST", {"display_name": f"{self.prefix}-client"})
        self.client_id = client["id"]
        started = self.api.json(f"/api/clients/{self.client_id}/grants", "POST",
                                {"grants": [{"protocol": "naive", "node_id": "local", "runtime_username": f"{self.prefix}-cl", "options": {}}]})
        self.check("fixture.grant_issued", started["status"] == "succeeded", json.dumps(started))
        url = None
        status, body = self.api.request(f"/api/clients/{self.client_id}/subscription")
        if status == 200 and body.get("configured"):
            reveal = self.api.json(f"/api/clients/{self.client_id}/subscription", "POST")
            url = self.api.json(f"/api/reveal/{reveal['reveal_token']}").get("url")
        self.report["facts"]["subscription_configured"] = bool(url)
        policy = self.api.json("/api/routing/policies/local/naive", "PUT",
                               {"default_action": "direct", "default_egress": None, "fallback": "fail_closed",
                                "rules": [{"action": "block", "match": {"domains": ["drill.example"]}}], "expected_revision": None})
        self.check("fixture.policy_saved", policy["revision"] >= 1)
        before = self.snapshot()
        before["subscription_url"] = url
        return before

    def fetch(self, url: str) -> int:
        argv = ["curl", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", "20"]
        argv += ["--cacert", self.args.ca_file] if self.args.ca_file else ["--insecure"]
        try:
            return int(subprocess.run(argv + [url], capture_output=True, text=True, timeout=30).stdout.strip() or 0)
        except (subprocess.SubprocessError, ValueError):
            return 0

    def take_backup(self) -> None:
        # The panel: SQLite through the online backup API, integrity checked, the master key apart.
        out = run("docker", "exec", "-i", "proxy-control-panel", "python", "-c",
                  "import sqlite3; s=sqlite3.connect('/data/panel.sqlite3'); d=sqlite3.connect('/data/panel.backup.sqlite3');\n"
                  "d.execute('PRAGMA journal_mode=DELETE')\n"
                  "with d: s.backup(d)\n"
                  "print(d.execute('PRAGMA integrity_check').fetchone()[0]); d.close(); s.close()")
        self.check("backup.sqlite_online_copy_ok", out.strip() == "ok", out[-100:])
        run("docker", "cp", "proxy-control-panel:/data/panel.backup.sqlite3", str(self.backup / "panel.sqlite3"))
        run("docker", "exec", "proxy-control-panel", "rm", "-f", "/data/panel.backup.sqlite3")
        shutil.copyfile(self.project / "secrets/panel-master-key", self.keys / "panel-master-key")
        os.chmod(self.keys / "panel-master-key", 0o600)
        # Each generation with its writer stopped: the managers and the router, not the daemons.
        self.compose("stop", "panel", "naive-manager", "mieru-manager", "xray-router")
        for name, source in (("naive-manager", NAIVE_STATE), ("mieru-manager", MIERU_STATE), ("xray-router", ROUTER_STATE)):
            with tarfile.open(self.backup / f"{name}.tar", "w") as archive:
                archive.add(source, arcname=source.name)
        with tarfile.open(self.backup / "router-secrets.tar", "w") as archive:
            for member in ("secrets/xray-router-manager-token", "secrets/xray-router-ingress-naive", "secrets/xray-router-ingress-mieru", ".env.xray-router"):
                if (self.project / member).exists():
                    archive.add(self.project / member, arcname=member)
        self.compose("up", "-d", "--wait", "panel", "naive-manager", "mieru-manager", "xray-router")
        sums = []
        for path in sorted(self.backup.rglob("*")):
            if path.is_file():
                sums.append(f"{sha256(path)}  {path.relative_to(self.backup)}")
        (self.backup / "SHA256SUMS").write_text("\n".join(sums) + "\n")
        os.chmod(self.backup / "SHA256SUMS", 0o600)
        self.check("backup.checksums_written", len(sums) >= 5, str(len(sums)))

    def break_generation(self) -> None:
        self.compose("stop", "panel", "naive-manager", "mieru-manager", "xray-router")
        volume = self.panel_volume()
        run("docker", "run", "--rm", "-v", f"{volume}:/data", "--entrypoint", "sh", "mtproxy-panel:latest", "-c",
            "rm -f /data/panel.sqlite3 /data/panel.sqlite3-wal /data/panel.sqlite3-shm")
        for state in (NAIVE_STATE, MIERU_STATE, ROUTER_STATE):
            for child in state.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        for member in ("secrets/xray-router-manager-token", "secrets/xray-router-ingress-naive", "secrets/xray-router-ingress-mieru"):
            (self.project / member).unlink(missing_ok=True)
        self.check("break.states_and_database_gone", not any(NAIVE_STATE.iterdir()) and not any(ROUTER_STATE.iterdir())
                   and not (self.project / "secrets/xray-router-ingress-naive").exists())

    def restore(self) -> None:
        verified = run("sh", "-c", f"cd {self.backup} && sha256sum -c SHA256SUMS", check=False)
        self.check("restore.checksums_verify", "FAILED" not in verified and verified.count(": OK") >= 5, verified[-200:])
        volume = self.panel_volume()
        run("docker", "run", "--rm", "-v", f"{volume}:/data", "-v", f"{self.backup}:/backup:ro", "--entrypoint", "sh", "mtproxy-panel:latest", "-c",
            "cp /backup/panel.sqlite3 /data/panel.sqlite3 && chown 10001:10001 /data/panel.sqlite3 && chmod 0600 /data/panel.sqlite3")
        # The pair proven before the panel starts: `master-key-verify` exits non-zero when the
        # key and the database do not belong together (docs/BACKUP_RESTORE).
        verify = subprocess.run(["docker", "run", "--rm", "-v", f"{volume}:/data", "-v", f"{self.keys}:/key:ro", "--entrypoint", "python",
                                 "mtproxy-panel:latest", "-m", "panel.cli", "--database", "/data/panel.sqlite3", "master-key-verify", "--path", "/key/panel-master-key"],
                                capture_output=True, text=True, timeout=120)
        self.check("restore.master_key_verify_matches", verify.returncode == 0, (verify.stdout + verify.stderr)[-200:])
        self.report["facts"]["master_key_verify"] = verify.stdout.strip()[-160:]
        for name, target in (("naive-manager", NAIVE_STATE), ("mieru-manager", MIERU_STATE), ("xray-router", ROUTER_STATE)):
            with tarfile.open(self.backup / f"{name}.tar") as archive:
                archive.extractall(target.parent, filter="fully_trusted")
        with tarfile.open(self.backup / "router-secrets.tar") as archive:
            archive.extractall(self.project, filter="fully_trusted")
        # The contracts docs/BACKUP_RESTORE names: identities and modes proven by the state preparers.
        gid = run("getent", "group", "mita").split(":")[2].strip()
        scripts = Path(__file__).resolve().parents[1]  # the release tree's scripts/, as the document runs them
        run("env", f"MIERU_MITA_GID={gid}", str(scripts / "prepare-mieru-state.sh"), "verify", str(MIERU_STATE))
        run(str(scripts / "prepare-xray-router-state.sh"), "verify", str(ROUTER_STATE))
        self.compose("up", "-d", "--wait", "panel", "naive-manager", "mieru-manager", "xray-router")
        self.check("restore.services_healthy", all("healthy" in run("docker", "inspect", "--format", "{{.State.Health.Status}}", f"proxy-control-{s}", check=False)
                                                    for s in ("panel", "naive-manager", "mieru-manager", "xray-router")))

    def verify(self, before: dict) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and self.api.request("/healthz")[0] != 200:
            time.sleep(1)
        self.api.login(self.password)
        after = self.snapshot()
        self.check("verify.users_equal", after["users"] == before["users"], json.dumps({"before": before["users"], "after": after["users"]})[:400])
        self.check("verify.clients_and_grants_equal", after["clients"] == before["clients"], json.dumps(after["clients"])[:300])
        self.check("verify.policies_equal", after["policies"] == before["policies"], json.dumps(after["policies"]))
        self.check("verify.caddyfile_byte_for_byte", after["caddyfile"] == before["caddyfile"])
        self.check("verify.mita_config_equal", after["mita"] == before["mita"])
        self.check("verify.router_ingress_credentials_equal", after["ingress"] == before["ingress"] and after["ingress"], json.dumps(after["ingress"]))
        status = self.router_status()
        self.check("verify.router_verified_and_running", status.get("phase") == "idle" and (status.get("running") or {}).get("generation", 0) >= 1
                   and all((status.get("artifacts") or {}).get(n, {}).get("verified") for n in ("xray", "geoip", "geosite")), json.dumps(status)[:300])
        if before.get("subscription_url"):
            self.check("verify.subscription_url_serves_again", self.fetch(before["subscription_url"]) == 200)
        reveal = self.api.json(f"/api/naive/users/{self.prefix}-nv/access", "POST")
        self.check("verify.naive_credential_decrypts_after_restore", "native" in (reveal.get("clients") or {}), json.dumps(reveal)[:100])

    def cleanup(self) -> None:
        try:
            self.api.login(self.password)
            self.api.request("/api/routing/policies/local/naive", "DELETE")
            if self.client_id:
                for entry in self.api.json("/api/clients")["items"]:
                    if entry["client"]["id"] == self.client_id:
                        for grant in entry["grants"]:
                            self.api.request(f"/api/clients/grants/{grant['id']}/delete", "POST")
                time.sleep(2)
                self.api.request(f"/api/clients/{self.client_id}/state", "POST", {"state": "archived"})
            self.api.request(f"/api/users/{self.prefix}-tg", "DELETE")
            self.api.request(f"/api/naive/users/{self.prefix}-nv", "DELETE")
            revision = self.api.json("/api/mieru/users")["service"]["revision"]
            self.api.request(f"/api/mieru/users/{self.prefix}-mr", "DELETE", {"expected_revision": revision})
        finally:
            shutil.rmtree(self.backup, ignore_errors=True)
            shutil.rmtree(self.keys, ignore_errors=True)

    def run(self) -> bool:
        started = time.monotonic()
        initial: dict = {}
        try:
            self.api.login(self.password)
            initial = self.snapshot()
            before = self.fixture()
            self.take_backup()
            self.break_generation()
            self.restore()
            self.verify(before)
        except Exception as error:
            self.check("drill.completed", False, f"{type(error).__name__}: {error}")
            import traceback
            self.report["traceback"] = traceback.format_exc()[-1500:]
            # Whatever happened, the generation must be back before anything else runs.
            try:
                self.compose("up", "-d", "--wait", "panel", "naive-manager", "mieru-manager", "xray-router")
            except Exception as again:
                self.report["recovery_error"] = str(again)[-300:]
        finally:
            try:
                self.cleanup()
                final = self.snapshot()
                self.check("final.users_equal_initial", final["users"] == initial["users"], json.dumps({"initial": initial["users"], "final": final["users"]})[:400])
            except Exception as error:
                self.check("final.cleanup_completed", False, str(error)[:200])
        self.report["elapsed_seconds"] = round(time.monotonic() - started, 1)
        self.report["ok"] = not self.report["failed"]
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
        print(("BACKUP_RESTORE_OK" if self.report["ok"] else "BACKUP_RESTORE_FAILED " + str(self.report["failed"])) + f" ({len(self.report['checks'])} checks, {self.report['elapsed_seconds']} s)")
        return self.report["ok"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", default="/opt/mtproxy-shared443")
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--password-file", "--node-password-file", dest="password_file", required=True)
    parser.add_argument("--ca-file", default=None)
    parser.add_argument("--output", required=True)
    if os.geteuid() != 0:
        print("run as root on the node", file=sys.stderr)
        return 2
    return 0 if Drill(parser.parse_args()).run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
