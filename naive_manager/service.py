from __future__ import annotations

import copy
import difflib
import functools
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import quote

from . import egress as egress_block
from . import lanes as lanes_block
from .egress import EgressInvalid, EgressUnreachable
from .traffic import (
    ACCOUNTING_ROLL_KEEP,
    ACCOUNTING_ROLL_SIZE_BYTES,
    MAX_COUNTER,
    REDACTION_SENTINEL,
    TrafficCollector,
)


BEGIN = "# BEGIN NAIVE-MANAGER USERS"
END = "# END NAIVE-MANAGER USERS"
ACCOUNTING_BEGIN = "# BEGIN NAIVE-MANAGER ACCOUNTING"
ACCOUNTING_END = "# END NAIVE-MANAGER ACCOUNTING"
USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
DISABLED_REASONS = {None, "manual", "quota"}


def synchronized(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


def lifecycle_synchronized(method):
    """Acquire the accounting operation boundary before manager state."""
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        traffic = self.traffic
        if traffic is None:
            with self._lock:
                return method(self, *args, **kwargs)
        with traffic.operation(), self._lock:
            return method(self, *args, **kwargs)
    return wrapped


# A caller may supply the credential so that the panel can store it before the
# manager commits; the manager still refuses anything outside this shape.
PASSWORD = re.compile(r"^[A-Za-z0-9_.~-]{16,128}$")
OPERATION_ID = re.compile(r"^[A-Za-z0-9_:.-]{1,128}$")
# How long a completed operation stays replayable. Long enough for a retry after an
# outage, short enough that the state file does not grow without bound.
OPERATION_RETENTION_SECONDS = 7 * 86400


class ManagerConflict(RuntimeError):
    """A refused operation. `code` names the reason for callers to act on."""

    def __init__(self, message: str, code: str = "configuration_conflict"):
        super().__init__(message)
        self.code = code


class ManagerNotFound(RuntimeError):
    pass


class ManagerRecoveryError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _durable_mkdir(path: Path, mode: int = 0o700) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise ManagerConflict(f"refusing unsafe directory: {current}")
    for directory in reversed(missing):
        os.mkdir(directory, mode)
        _fsync_directory(directory.parent)


def _assert_safe_parent_chain(path: Path) -> None:
    parent = path.absolute().parent
    for directory in (*reversed(parent.parents), parent):
        if directory == directory.parent:
            continue
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ManagerConflict(f"refusing unsafe directory: {directory}")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    _assert_safe_parent_chain(path)
    _durable_mkdir(path.parent)
    _assert_safe_parent_chain(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def _durable_unlink(path: Path) -> None:
    path.unlink(missing_ok=True)
    _durable_mkdir(path.parent)
    _fsync_directory(path.parent)


def _assert_regular(path: Path) -> None:
    _assert_safe_parent_chain(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ManagerConflict(f"refusing unsafe file: {path}")
    if info.st_mode & 0o022:
        raise ManagerConflict(f"refusing writable config: {path}")


@dataclass
class NaiveCredentialManager:
    caddyfile: Path
    state_file: Path
    backup_dir: Path
    public_host: str
    validate: Callable[[Path], dict]
    reload: Callable[[], None]
    probe: Callable[[], None]
    caddyfile_mode: int = 0o640
    traffic: TrafficCollector | None = None
    # The host's WARP proxy-mode endpoint (`NAIVE_EGRESS_WARP`), or None without WARP; the
    # only address the egress API ever writes into the Caddyfile (v0.4 routing).
    provider_url: str | None = None
    # This service's private ingress on the node's Xray-router (`NAIVE_EGRESS_ROUTER`) and the
    # file holding its `user:password` (`NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE`), or None without
    # a router (v0.5). The credential is read when a line is rendered and never leaves the manager.
    router_url: str | None = None
    router_credential_file: Path | None = None
    reachability: Callable[..., bool] = egress_block.check_reachable
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _recovery_failed: bool = field(default=False, init=False, repr=False)

    @lifecycle_synchronized
    def bootstrap(self) -> None:
        _assert_regular(self.caddyfile)
        if self._transaction_file.exists():
            self._recover_transaction()
        if self.state_file.exists():
            _assert_regular(self.state_file)
            state = self._read_state()
            text = self.caddyfile.read_text()
            if ACCOUNTING_BEGIN not in text and ACCOUNTING_END not in text:
                self._migrate_accounting(state, text)
            else:
                self._assert_consistent(state)
            self._archive_tombstones(state)
            self._refresh_router_credential(self._read_state())
            return
        text = self.caddyfile.read_text()
        legacy_credentials = self._legacy_credentials(text)
        try:
            for username, _password in legacy_credentials:
                self._valid_username(username)
        except ValueError as exc:
            raise ManagerConflict("reserved accounting username in imported credentials") from exc
        users = [
            {
                "username": username,
                "password": password,
                "enabled": True,
                "quota_bytes": None,
                "disabled_reason": None,
                "created_at": _now(),
                "updated_at": _now(),
            }
            for username, password in legacy_credentials
        ]
        if not users:
            raise ManagerConflict("no NaiveProxy credentials found for initial import")
        state = {"version": 1, "host": self.public_host, "users": users, "tombstones": []}
        rendered = self._render_initial(text, state)
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, self.caddyfile.read_bytes())
        _atomic_write(state_backup, b"")
        transaction = {
            "version": 1,
            "phase": "bootstrap_prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
            "state_existed": False,
        }
        self._write_transaction(transaction)
        self._write_validated_config(rendered)
        _atomic_write(self.state_file, self._encode_state(state))
        self._clear_transaction()
        self._prune_backups()

    def health(self) -> dict:
        try:
            traffic = self.traffic
            operation = traffic.operation() if traffic is not None else self._lock
            with operation, self._lock:
                if self._recovery_failed or self._transaction_file.exists():
                    raise ManagerRecoveryError("transaction recovery required")
                state = self._read_state()
                self._assert_consistent(state)
                self.probe()
                if traffic is not None:
                    # Health reports; it never rewrites the managed config.
                    # Quota enforcement runs on its own schedule.
                    traffic.collect()
                    if traffic.health().get("ready") is not True:
                        raise ManagerConflict("traffic accounting is unavailable")
                return {"ready": True, "host": self.public_host}
        except Exception:
            return {"ready": False, "host": self.public_host}

    @synchronized
    def list_users(self) -> list[dict]:
        state = self._read_state()
        return [
            {
                "username": row["username"],
                "enabled": bool(row["enabled"]),
                "quota_bytes": row["quota_bytes"],
                "disabled_reason": row["disabled_reason"],
                "lane": row.get("lane"),
            }
            for row in state["users"]
        ]

    def traffic_report(self) -> dict:
        if self.traffic is None:
            raise ManagerConflict("traffic accounting is unavailable")
        try:
            with self.traffic.operation(), self._lock:
                self.traffic.collect()
                return self.traffic.list_traffic()
        except (ManagerConflict, ManagerRecoveryError):
            raise
        except RuntimeError as exc:
            raise ManagerConflict("traffic accounting is degraded") from exc

    def enforce_quotas(self) -> list[str]:
        """Collect completed CONNECT records and disable newly exhausted users."""
        traffic = self.traffic
        if traffic is None:
            return []
        with traffic.operation(), self._lock:
            traffic.collect()
            report = traffic.list_traffic()
            return self._enforce_quotas_from_report_locked(report)

    def _used_bytes_locked(self, username: str) -> int:
        """Payload bytes recorded for a user, or 0 when accounting is unavailable."""
        traffic = self.traffic
        if traffic is None:
            return 0
        traffic.collect()
        report = traffic.list_traffic()
        return next(
            (
                row["total_bytes"]
                for row in report.get("users", [])
                if isinstance(row, dict)
                and row.get("username") == username
                and type(row.get("total_bytes")) is int
            ),
            0,
        )

    def _enforce_quotas_from_report_locked(self, report: dict) -> list[str]:
        usage = {
            row["username"]: row["total_bytes"]
            for row in report.get("users", [])
            if isinstance(row, dict)
            and isinstance(row.get("username"), str)
            and type(row.get("total_bytes")) is int
        }
        state = self._read_state()
        exhausted = []
        for row in state["users"]:
            quota = row["quota_bytes"]
            if row["enabled"] and quota is not None and usage.get(row["username"], 0) >= quota:
                row["enabled"] = False
                row["disabled_reason"] = "quota"
                row["updated_at"] = _now()
                exhausted.append(row["username"])
        if exhausted:
            self._apply(state)
        return exhausted

    def reset_traffic(self, username: str) -> dict:
        traffic = self.traffic
        if traffic is None:
            raise ManagerConflict("traffic accounting is unavailable")
        with traffic.operation(), self._lock:
            self._find(self._read_state(), username)
            try:
                if not traffic.drain():
                    raise ManagerConflict("traffic backlog remains pending")
                return traffic.reset(username)
            except ManagerConflict:
                raise
            except RuntimeError as exc:
                raise ManagerConflict("traffic accounting is degraded") from exc

    @synchronized
    def managed_usernames(self) -> set[str]:
        return {row["username"] for row in self._read_state()["users"]}

    @synchronized
    def reveal(self, username: str) -> dict:
        return self._reveal_row(self._find(self._read_state(), username))

    def _reveal_row(self, row: dict) -> dict:
        user = quote(row["username"], safe="")
        password = quote(row["password"], safe="")
        proxy_url = f"https://{user}:{password}@{self.public_host}"
        return {
            "username": row["username"],
            "proxy_url": proxy_url,
            "config": {"listen": "socks://127.0.0.1:1080", "proxy": proxy_url},
        }

    @lifecycle_synchronized
    def create(
        self,
        username: str,
        quota_bytes: int | None = None,
        *,
        password: str | None = None,
        operation_id: str | None = None,
    ) -> dict:
        self._valid_username(username)
        self._validate_quota(quota_bytes)
        self._validate_password(password)
        state = self._read_state()
        replay = self._replay(state, operation_id, "create", username)
        if replay is not None:
            return replay
        if any(row["username"] == username for row in state["users"]):
            raise ManagerConflict("user already exists")
        if any(row["username"] == username for row in state["tombstones"]):
            raise ManagerConflict("username is permanently retired")
        timestamp = _now()
        row = {
            "username": username,
            "password": password or secrets.token_urlsafe(18),
            "enabled": True,
            "quota_bytes": quota_bytes,
            "disabled_reason": None,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        state["users"].append(row)
        result = self._reveal_row(row)
        self._remember(state, operation_id, "create", username, result)
        self._apply(state)
        return result

    @lifecycle_synchronized
    def rotate(
        self, username: str, *, password: str | None = None, operation_id: str | None = None
    ) -> dict:
        self._validate_password(password)
        state = self._read_state()
        replay = self._replay(state, operation_id, "rotate", username)
        if replay is not None:
            return replay
        row = self._find(state, username)
        row["password"] = password or secrets.token_urlsafe(18)
        row["updated_at"] = _now()
        result = self._reveal_row(row)
        self._remember(state, operation_id, "rotate", username, result)
        self._apply(state)
        return result

    @lifecycle_synchronized
    def set_enabled(self, username: str, enabled: bool) -> dict:
        state = self._read_state()
        row = self._find(state, username)
        if enabled and row["quota_bytes"] is not None:
            if self._used_bytes_locked(username) >= row["quota_bytes"]:
                raise ManagerConflict(
                    "quota exhausted; reset traffic or remove quota first", "quota_exhausted"
                )
        row["enabled"] = bool(enabled)
        row["disabled_reason"] = None if enabled else "manual"
        row["updated_at"] = _now()
        self._apply(state)
        return {
            "username": username,
            "enabled": bool(enabled),
            "disabled_reason": row["disabled_reason"],
        }

    @lifecycle_synchronized
    def set_quota(self, username: str, quota_bytes: int | None) -> dict:
        self._validate_quota(quota_bytes)
        state = self._read_state()
        row = self._find(state, username)
        used = self._used_bytes_locked(username)
        row["quota_bytes"] = quota_bytes
        if row["enabled"] and quota_bytes is not None and used >= quota_bytes:
            row["enabled"] = False
            row["disabled_reason"] = "quota"
        elif row["disabled_reason"] == "quota" and (quota_bytes is None or used < quota_bytes):
            # The quota no longer holds this user back, but access stays off
            # until the operator enables it: that remains a separate decision.
            row["disabled_reason"] = "manual"
        row["updated_at"] = _now()
        self._apply(state)
        return {
            "username": username,
            "quota_bytes": quota_bytes,
            "enabled": row["enabled"],
            "disabled_reason": row["disabled_reason"],
        }

    @lifecycle_synchronized
    def delete(self, username: str) -> None:
        traffic = self.traffic
        if traffic is None:
            raise ManagerConflict("traffic accounting is unavailable")
        state = self._read_state()
        self._find(state, username)
        try:
            if not traffic.drain():
                raise ManagerConflict("traffic backlog remains pending")
        except ManagerConflict:
            raise
        except RuntimeError as exc:
            raise ManagerConflict("traffic accounting is degraded") from exc
        state["users"] = [row for row in state["users"] if row["username"] != username]
        state["tombstones"].append({"username": username, "deleted_at": _now()})
        self._apply(state)
        traffic.archive_user(username)

    # ------------------------------------------------------------- lanes (v0.7)

    @synchronized
    def set_lanes(self, body: object) -> dict:
        """Replace the lanes: every named user moves into its lane's handler with the
        lane's router-ingress account as the upstream; users not named go back to the
        service's own handler. One transaction, one reload, the same recovery as users."""
        state = self._read_state()
        try:
            lanes = lanes_block.validate_request(body, {row["username"] for row in state["users"]})
        except lanes_block.LanesInvalid as exc:
            raise ManagerConflict(str(exc), "lanes_invalid") from exc
        if lanes and not self.router_url:
            raise EgressInvalid("egress provider router is not configured on this node")
        desired = copy.deepcopy(state)
        by_user = {user: entry["lane"] for entry in lanes for user in entry["users"]}
        for row in desired["users"]:
            row["lane"] = by_user.get(row["username"])
        desired["lanes"] = {entry["lane"]: {"upstream": egress_block.with_credential(
            self.router_url, (entry["upstream"]["user"], entry["upstream"]["password"]))} for entry in lanes}
        self._apply(desired)
        return self._lanes_view(desired)

    @synchronized
    def lanes(self) -> dict:
        return self._lanes_view(self._read_state())

    @staticmethod
    def _lanes_view(state: dict) -> dict:
        view = []
        for lane, entry in state.get("lanes", {}).items():
            members = [row for row in state["users"] if row.get("lane") == lane]
            view.append({"lane": lane, "users": [row["username"] for row in members],
                         "upstream": egress_block.redact_userinfo(entry["upstream"]),
                         "enabled_users": sum(1 for row in members if row["enabled"])})
        return {"lanes": view}

    def _archive_tombstones(self, state: dict) -> None:
        if self.traffic is None:
            return
        for row in state["tombstones"]:
            self.traffic.archive_user(row["username"])

    # ------------------------------------------------------------------
    # egress (v0.4 routing): the managed block inside forward_proxy
    # ------------------------------------------------------------------

    def _providers(self, *, probe: bool) -> dict:
        providers = {}
        if self.provider_url:
            providers["warp"] = {"url": self.provider_url,
                                 "reachable": self.reachability(self.provider_url, 3.0) if probe else None}
        if self.router_url:
            providers["router"] = {"url": egress_block.strip_userinfo(self.router_url),
                                   "reachable": self.reachability(self.router_url, 3.0, auth=True) if probe else None}
        return providers

    def _router_credential(self) -> tuple[str, str]:
        if not self.router_url or self.router_credential_file is None:
            raise egress_block.EgressInvalid("egress provider router is not configured on this node")
        return egress_block.read_credential(self.router_credential_file)

    def _render_providers(self, document: dict) -> dict[str, str | None]:
        """The URLs the block may name: WARP as configured, the router with the credential the
        file holds right now (read only when the document asks for it)."""
        providers: dict[str, str | None] = {"warp": self.provider_url, "router": None}
        if document.get("upstream") and document["upstream"]["provider"] == "router" and self.router_url:
            providers["router"] = egress_block.with_credential(self.router_url, self._router_credential())
        return providers

    def _provider_of(self, upstream: str | None) -> str | None:
        if upstream is None:
            return None
        bare = egress_block.strip_userinfo(upstream)
        if self.provider_url and bare == egress_block.strip_userinfo(self.provider_url) and "@" not in upstream:
            return "warp"
        if self.router_url and bare == egress_block.strip_userinfo(self.router_url):
            return "router"
        return None

    def _router_credential_stale(self, parsed: egress_block.ParsedEgress) -> bool:
        """The router line carries a credential other than the file's (a rotation happened
        while this manager was down): the block is re-rendered at bootstrap."""
        if self._provider_of(parsed.upstream) != "router":
            return False
        try:
            expected = egress_block.with_credential(self.router_url, self._router_credential())
        except egress_block.EgressInvalid:
            return False
        return parsed.upstream != expected

    def _egress_document(self, parsed: egress_block.ParsedEgress) -> dict | None:
        """The compiled document the block (or the adopted line) amounts to, or None for a
        `custom` upstream this host has no provider for."""
        if parsed.upstream is None:
            upstream = None
        else:
            provider = self._provider_of(parsed.upstream)
            if provider is None:
                return None
            upstream = {"provider": provider}
        acl = [{"deny": list(parsed.acl_deny)}] if parsed.acl_deny else []
        return {"schema": egress_block.SCHEMA, "upstream": upstream, "acl": acl}

    def _egress_view(self, state: dict, parsed: egress_block.ParsedEgress, *, probe: bool) -> dict:
        document = self._egress_document(parsed)
        mode = parsed.mode
        if mode == "custom" and document is not None:
            mode = "proxy"  # an unmanaged line that already names the provider
        journal = state["egress"]
        warnings = ["adopts_unmanaged_upstream"] if parsed.upstream and not parsed.managed else []
        if self._router_credential_stale(parsed):
            warnings.append("router_credential_stale")
        return {
            "revision": parsed.revision, "mode": mode,
            "upstream": None if parsed.upstream is None else egress_block.redact_userinfo(parsed.upstream),
            "acl": list(parsed.acl_deny),
            "document": document, "managed": parsed.managed, "providers": self._providers(probe=probe),
            "capabilities": list(egress_block.CAPABILITIES), "restart_required": False,
            "warnings": warnings,
            "previous": None if journal["previous"] is None else {"revision": journal["previous"]["revision"]},
            "current": None if journal["current"] is None else {
                key: journal["current"][key] for key in ("revision", "rendered_sha256", "operation_id", "applied_at")},
        }

    @synchronized
    def egress(self) -> dict:
        state = self._read_state()
        parsed = egress_block.parse(self.caddyfile.read_text())
        return self._egress_view(state, parsed, probe=True)

    def _egress_target(self, expected_revision: str, document: object) -> tuple[dict, egress_block.ParsedEgress, dict, str]:
        """Validate, check the revision, render: what every plan/apply starts with."""
        normalised = egress_block.validate_document(document)
        state = self._read_state()
        self._assert_consistent(state)
        text = self.caddyfile.read_text()
        parsed = egress_block.parse(text)
        if not isinstance(expected_revision, str) or not secrets.compare_digest(parsed.revision, expected_revision):
            raise ManagerConflict("egress revision does not match", "egress_conflict")
        rendered = egress_block.render(text, normalised, self._render_providers(normalised))
        return state, parsed, normalised, rendered

    def _provider_reachable(self, document: dict) -> bool:
        """The provider the document names answers its SOCKS5 greeting (direct: nothing to ask)."""
        if document.get("upstream") is None:
            return True
        if document["upstream"]["provider"] == "router":
            return bool(self.router_url) and self.reachability(self.router_url, 3.0, auth=True)
        return self.reachability(self.provider_url, 3.0)

    @synchronized
    def egress_plan(self, expected_revision: str, document: object) -> dict:
        state, parsed, normalised, rendered = self._egress_target(expected_revision, document)
        before = "\n".join(parsed.raw_lines).splitlines()
        after = "\n".join(egress_block.parse(rendered).raw_lines).splitlines()
        diff = [egress_block.redact_userinfo(line)
                for line in difflib.unified_diff(before, after, "current", "planned", lineterm="", n=0)
                if not line.startswith(("---", "+++", "@@"))]
        reachability = {}
        if normalised["upstream"] is not None:
            reachability[normalised["upstream"]["provider"]] = self._provider_reachable(normalised)
        return {
            "revision": parsed.revision, "target_revision": egress_block.revision_of(rendered),
            "rendered_sha256": hashlib.sha256(rendered.encode()).hexdigest(), "diff": diff,
            "warnings": ["adopts_unmanaged_upstream"] if parsed.upstream and not parsed.managed else [],
            "reachability": reachability, "restart_required": False,
        }

    @lifecycle_synchronized
    def egress_apply(self, expected_revision: str, document: object, operation_id: str) -> dict:
        """Write the block, reload, read the running config back; the previous entry stays in
        the journal for `egress_rollback`. Idempotent by `operation_id`: a retry after a lost
        reply gets the same answer without a second reload."""
        if not isinstance(operation_id, str) or OPERATION_ID.fullmatch(operation_id) is None:
            raise ValueError("invalid operation id")
        normalised = egress_block.validate_document(document)
        state = self._read_state()
        current = state["egress"]["current"]
        if current is not None and current.get("operation_id") == operation_id:
            if current["document"] != normalised:
                raise ManagerConflict("operation id already used for another request", "operation_conflict")
            return {"revision": current["revision"], "applied": current["document"],
                    "readback_sha256": current["rendered_sha256"], "replayed": True}
        state, parsed, normalised, rendered = self._egress_target(expected_revision, document)
        if not self._provider_reachable(normalised):
            raise EgressUnreachable(f"egress provider {normalised['upstream']['provider']} is unreachable")
        entry = {"document": normalised, "revision": egress_block.revision_of(rendered),
                 "rendered_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
                 "operation_id": operation_id, "applied_at": _now()}
        self._egress_transaction(state, rendered, entry, parsed)
        return {"revision": entry["revision"], "applied": normalised, "readback_sha256": entry["rendered_sha256"],
                "replayed": False}

    @lifecycle_synchronized
    def egress_rollback(self, expected_revision: str) -> dict:
        """Back to the previous journal entry: a managed document, or the unmanaged lines the
        first apply adopted (restored verbatim)."""
        state = self._read_state()
        self._assert_consistent(state)
        text = self.caddyfile.read_text()
        parsed = egress_block.parse(text)
        if not isinstance(expected_revision, str) or not secrets.compare_digest(parsed.revision, expected_revision):
            raise ManagerConflict("egress revision does not match", "egress_conflict")
        previous = state["egress"]["previous"]
        if previous is None:
            raise ManagerConflict("no previous egress to roll back to", "egress_no_previous")
        if previous.get("document") is not None:
            rendered = egress_block.render(text, previous["document"], self._render_providers(previous["document"]))
            if not self._provider_reachable(previous["document"]):
                raise EgressUnreachable(f"egress provider {previous['document']['upstream']['provider']} is unreachable")
        else:
            rendered = egress_block.render_raw(text, tuple(previous["raw_lines"]))
        entry = {"document": previous.get("document"), "revision": egress_block.revision_of(rendered),
                 "rendered_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
                 "operation_id": None, "applied_at": _now(), "raw_lines": previous.get("raw_lines")}
        self._egress_transaction(state, rendered, entry, parsed, rollback=True)
        return {"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["rendered_sha256"]}

    def _egress_transaction(self, state: dict, rendered: str, entry: dict, parsed: egress_block.ParsedEgress,
                            *, rollback: bool = False) -> None:
        """The journal is a stack of what was applied, oldest first; its floor is what the
        Caddyfile had before the first apply (the adopted lines, kept verbatim). An apply
        pushes, a rollback pops — so repeated rollbacks walk back to the floor."""
        history = list(state["egress"]["history"])
        if rollback:
            history = history[:-1]
            history[-1] = entry  # the restored entry, re-stamped
        else:
            if state["egress"]["current"] is None:
                history = [{"document": None, "revision": parsed.revision, "raw_lines": list(parsed.raw_lines),
                            "rendered_sha256": None, "operation_id": None, "applied_at": None}]
            history = [*history, entry][-10:]
        desired = copy.deepcopy(state)
        desired["egress"] = {"current": history[-1], "previous": history[-2] if len(history) > 1 else None,
                             "history": history}
        self._commit(rendered, desired, readback=self._egress_readback(entry))

    def _refresh_router_credential(self, state: dict) -> None:
        """After a credential rotation the router line still carries the old key: the block
        is a function of the document and the file, so it is rendered again. A managed block
        keeps its journal entry (re-stamped, nothing pushed); the installer's seed — an
        unmanaged line naming the router — is adopted the way a first apply would adopt it,
        so the old line stays in the journal's floor for a rollback."""
        text = self.caddyfile.read_text()
        try:
            parsed = egress_block.parse(text)
        except egress_block.EgressInvalid:
            return
        if not self._router_credential_stale(parsed):
            return
        document = self._egress_document(parsed)
        if document is None:
            return
        rendered = egress_block.render(text, document, self._render_providers(document))
        if not parsed.managed or state["egress"]["current"] is None:
            entry = {"document": document, "revision": egress_block.revision_of(rendered),
                     "rendered_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
                     "operation_id": None, "applied_at": _now()}
            self._egress_transaction(state, rendered, entry, parsed)
            return
        desired = copy.deepcopy(state)
        current = dict(desired["egress"]["current"])
        current.update({"revision": egress_block.revision_of(rendered),
                        "rendered_sha256": hashlib.sha256(rendered.encode()).hexdigest()})
        desired["egress"]["current"] = current
        if desired["egress"]["history"]:
            desired["egress"]["history"][-1] = current
        self._commit(rendered, desired, readback=self._egress_readback(current))

    def _egress_readback(self, entry: dict) -> Callable[[dict], None]:
        expected_upstream = None
        expected_deny: list[str] = []
        if entry.get("document") is not None:
            expected_upstream = egress_block.resolve_provider(entry["document"], self._render_providers(entry["document"]))
            expected_deny = [item for rule in entry["document"]["acl"] for item in rule["deny"]]
        elif entry.get("raw_lines"):
            parsed = egress_block.parse("forward_proxy {\n" + "\n".join(entry["raw_lines"]) + "\n}\n")
            expected_upstream, expected_deny = parsed.upstream, list(parsed.acl_deny)

        def check(config: dict) -> None:
            handler = self._forward_proxy_handler(config)
            if handler.get("upstream") != expected_upstream:
                raise ManagerConflict("running upstream differs from the applied egress", "egress_readback_mismatch")
            subjects = [item for rule in handler.get("acl") or [] for item in rule.get("subjects", [])]
            if sorted(subjects) != sorted(expected_deny):
                raise ManagerConflict("running acl differs from the applied egress", "egress_readback_mismatch")

        return check

    @staticmethod
    def _forward_proxy_handler(config: dict) -> dict:
        found = []

        def walk(value) -> None:
            if isinstance(value, dict):
                if value.get("handler") == "forward_proxy":
                    found.append(value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(config)
        if not found:
            raise ManagerConflict("unexpected proxy handler", "egress_readback_mismatch")
        # The service's own handler is the last one: lane handlers (v0.7) precede it.
        return found[-1]

    def _commit(self, rendered: str, desired: dict, *, readback: Callable[[dict], None] | None = None) -> None:
        """`_apply`'s transaction for a rendered Caddyfile that is not a user change: backup,
        write, reload, probe, read back — and restore the previous bytes on any failure."""
        if self._recovery_failed or self._transaction_file.exists():
            raise ManagerRecoveryError("transaction recovery required before mutation")
        config_before = self.caddyfile.read_bytes()
        state_before = self.state_file.read_bytes()
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, config_before)
        _atomic_write(state_backup, state_before)
        transaction = {"version": 1, "phase": "prepared", "config_backup": config_backup.name,
                       "state_backup": state_backup.name}
        self._write_transaction(transaction)
        try:
            self._write_validated_config(rendered)
            _atomic_write(self.state_file, self._encode_state(desired))
            transaction["phase"] = "rollback_pending"
            self._write_transaction(transaction)
            self.reload()
            self.probe()
            if readback is not None:
                readback(self.validate(self.caddyfile))
        except BaseException as operation_error:
            self._recovery_failed = True
            transaction["phase"], transaction["recovery_from"] = "recovery_failed", transaction["phase"]
            try:
                self._write_transaction(transaction)
                _atomic_write(self.caddyfile, config_before, self.caddyfile_mode)
                _atomic_write(self.state_file, state_before)
                self._validate_config(self.caddyfile)
                self.reload()
                self.probe()
            except Exception as rollback_error:
                raise ManagerRecoveryError("rollback failed; manager requires recovery") from rollback_error
            self._clear_transaction()
            self._recovery_failed = False
            self._prune_backups()
            raise operation_error
        self._clear_transaction()
        self._prune_backups()

    def _apply(self, desired: dict) -> None:
        if self._recovery_failed or self._transaction_file.exists():
            raise ManagerRecoveryError("transaction recovery required before mutation")
        current = self._read_state()
        self._assert_consistent(current)
        config_before = self.caddyfile.read_bytes()
        state_before = self.state_file.read_bytes()
        rendered = self._render_managed(config_before.decode(), desired)
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, config_before)
        _atomic_write(state_backup, state_before)
        transaction = {
            "version": 1,
            "phase": "prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
        }
        self._write_transaction(transaction)
        try:
            self._write_validated_config(rendered)
            _atomic_write(self.state_file, self._encode_state(desired))
            transaction["phase"] = "rollback_pending"
            self._write_transaction(transaction)
            self.reload()
            self.probe()
        except BaseException as operation_error:
            self._recovery_failed = True
            recovery_from = transaction["phase"]
            transaction["phase"] = "recovery_failed"
            transaction["recovery_from"] = recovery_from
            try:
                self._write_transaction(transaction)
                _atomic_write(self.caddyfile, config_before, self.caddyfile_mode)
                _atomic_write(self.state_file, state_before)
                self._validate_config(self.caddyfile)
                self.reload()
                self.probe()
            except Exception as rollback_error:
                raise ManagerRecoveryError("rollback failed; manager requires recovery") from rollback_error
            self._clear_transaction()
            self._recovery_failed = False
            self._prune_backups()
            raise operation_error
        self._clear_transaction()
        self._prune_backups()

    def _migrate_accounting(self, state: dict, text: str) -> None:
        actual = self._managed_credentials(text)
        expected = [(row["username"], row["password"]) for row in state["users"] if row["enabled"]]
        if actual != expected:
            raise ManagerConflict("managed Caddy credentials changed outside manager")
        self._validate_config(self.caddyfile)
        rendered = self._render_accounting_migration(text)
        config_before = self.caddyfile.read_bytes()
        state_before = self.state_file.read_bytes()
        _durable_mkdir(self.backup_dir)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        config_backup = self.backup_dir / f"{stamp}.Caddyfile"
        state_backup = self.backup_dir / f"{stamp}.users.json"
        _atomic_write(config_backup, config_before)
        _atomic_write(state_backup, state_before)
        transaction = {
            "version": 1,
            "phase": "prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
            "operation": "accounting_migration",
        }
        self._write_transaction(transaction)
        try:
            self._write_validated_config(rendered)
            _atomic_write(self.state_file, state_before)
            transaction["phase"] = "files_replaced"
            self._write_transaction(transaction)
            transaction["phase"] = "rollback_pending"
            self._write_transaction(transaction)
            self.reload()
            self.probe()
        except BaseException as operation_error:
            self._recovery_failed = True
            recovery_from = transaction["phase"]
            transaction["phase"] = "recovery_failed"
            transaction["recovery_from"] = recovery_from
            try:
                self._write_transaction(transaction)
                _atomic_write(self.caddyfile, config_before, self.caddyfile_mode)
                _atomic_write(self.state_file, state_before)
                self._validate_config(self.caddyfile)
                self.reload()
                self.probe()
            except Exception as rollback_error:
                raise ManagerRecoveryError("rollback failed; manager requires recovery") from rollback_error
            self._clear_transaction()
            self._recovery_failed = False
            self._prune_backups()
            raise operation_error
        self._clear_transaction()
        self._prune_backups()

    def _write_validated_config(self, rendered: str) -> None:
        _durable_mkdir(self.caddyfile.parent)
        fd, temporary = tempfile.mkstemp(prefix=".Caddyfile.naive.", dir=self.caddyfile.parent)
        path = Path(temporary)
        try:
            os.fchmod(fd, self.caddyfile_mode)
            with os.fdopen(fd, "w") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            self._validate_config(path)
            os.replace(path, self.caddyfile)
            os.chmod(self.caddyfile, self.caddyfile_mode)
            _fsync_directory(self.caddyfile.parent)
        finally:
            path.unlink(missing_ok=True)

    def _read_state(self) -> dict:
        _assert_regular(self.state_file)
        try:
            state = json.loads(self.state_file.read_text())
        except (OSError, ValueError) as exc:
            raise ManagerConflict("invalid manager state") from exc
        if state.get("version") != 1 or state.get("host") != self.public_host or not isinstance(state.get("users"), list):
            raise ManagerConflict("unsupported manager state")
        if set(state) - {"version", "host", "users", "tombstones", "operations", "egress", "lanes"}:
            raise ManagerConflict("unsupported manager state")
        # Lanes (v0.7) are optional: a state file from an older manager has none.
        lanes = state.setdefault("lanes", {})
        if not isinstance(lanes, dict) or any(
            lanes_block.LANE_ID.fullmatch(lane) is None or not isinstance(entry, dict) or set(entry) != {"upstream"}
            or not isinstance(entry["upstream"], str) for lane, entry in lanes.items()
        ):
            raise ManagerConflict("invalid lanes state")
        state["operations"] = self._pruned_operations(state.get("operations"))
        state.setdefault("tombstones", [])
        # The egress journal (v0.4) is optional: a state file from an older manager has none.
        journal = state.setdefault("egress", {"current": None, "previous": None, "history": []})
        if (not isinstance(journal, dict) or set(journal) != {"current", "previous", "history"}
                or not isinstance(journal["history"], list)):
            raise ManagerConflict("invalid egress journal")
        if not isinstance(state["tombstones"], list):
            raise ManagerConflict("invalid tombstone state")
        seen = set()
        for row in state["users"]:
            if not isinstance(row, dict):
                raise ManagerConflict("invalid user state")
            row.setdefault("quota_bytes", None)
            row.setdefault("disabled_reason", None)
            row.setdefault("lane", None)
            if set(row) - {
                "username", "password", "enabled", "quota_bytes", "disabled_reason",
                "created_at", "updated_at", "lane",
            }:
                raise ManagerConflict("invalid user state")
            if row["lane"] is not None and row["lane"] not in lanes:
                raise ManagerConflict("invalid user state")
            try:
                self._valid_username(row.get("username", ""))
            except ValueError as exc:
                if row.get("username") == REDACTION_SENTINEL:
                    raise ManagerConflict(
                        "reserved accounting username in manager state"
                    ) from exc
                raise ManagerConflict("invalid user state") from exc
            if (
                row["username"] in seen
                or not isinstance(row.get("password"), str)
                or not row["password"]
                or type(row.get("enabled")) is not bool
                or not (
                    row["quota_bytes"] is None
                    or (
                        type(row["quota_bytes"]) is int
                        and 1 <= row["quota_bytes"] <= MAX_COUNTER
                    )
                )
                or row["disabled_reason"] not in DISABLED_REASONS
                or (row["enabled"] and row["disabled_reason"] is not None)
                or (
                    row["disabled_reason"] == "quota"
                    and row["quota_bytes"] is None
                )
            ):
                raise ManagerConflict("invalid user state")
            seen.add(row["username"])
        retired = set()
        for row in state["tombstones"]:
            if (
                not isinstance(row, dict)
                or set(row) != {"username", "deleted_at"}
                or not isinstance(row.get("deleted_at"), str)
            ):
                raise ManagerConflict("invalid tombstone state")
            try:
                self._valid_username(row.get("username", ""))
            except ValueError as exc:
                if row.get("username") == REDACTION_SENTINEL:
                    raise ManagerConflict(
                        "reserved accounting username in manager state"
                    ) from exc
                raise ManagerConflict("invalid tombstone state") from exc
            if row["username"] in seen or row["username"] in retired:
                raise ManagerConflict("invalid tombstone state")
            retired.add(row["username"])
        return copy.deepcopy(state)

    @property
    def _transaction_file(self) -> Path:
        return self.state_file.parent / "transaction.json"

    def _read_transaction(self) -> dict:
        _assert_regular(self._transaction_file)
        try:
            transaction = json.loads(self._transaction_file.read_text())
        except (OSError, ValueError) as exc:
            raise ManagerRecoveryError("invalid transaction journal") from exc
        phases = {"bootstrap_prepared", "prepared", "files_replaced", "rollback_pending", "recovery_failed"}
        if (
            not isinstance(transaction, dict)
            or type(transaction.get("version")) is not int
            or transaction["version"] != 1
            or transaction.get("phase") not in phases
        ):
            raise ManagerRecoveryError("invalid transaction journal")
        base_keys = {"version", "phase", "config_backup", "state_backup"}
        operation = transaction.get("operation")
        if operation is not None:
            if operation != "accounting_migration":
                raise ManagerRecoveryError("invalid transaction journal")
            base_keys.add("operation")
        phase = transaction["phase"]
        if phase == "bootstrap_prepared":
            allowed_keys = base_keys | {"state_existed"}
            valid_shape = transaction.get("state_existed") is False
        elif phase == "recovery_failed":
            recovery_from = transaction.get("recovery_from")
            valid_origins = {"bootstrap_prepared", "prepared", "files_replaced", "rollback_pending"}
            allowed_keys = base_keys | {"recovery_from"}
            valid_shape = recovery_from in valid_origins
            if recovery_from == "bootstrap_prepared":
                allowed_keys.add("state_existed")
                valid_shape = valid_shape and transaction.get("state_existed") is False
        else:
            allowed_keys = base_keys
            valid_shape = True
        if not valid_shape or set(transaction) != allowed_keys:
            raise ManagerRecoveryError("invalid transaction journal")
        config_name = transaction.get("config_backup")
        state_name = transaction.get("state_backup")
        if (
            not isinstance(config_name, str)
            or not isinstance(state_name, str)
            or Path(config_name).name != config_name
            or Path(state_name).name != state_name
            or not config_name.endswith(".Caddyfile")
            or not state_name.endswith(".users.json")
            or config_name.removesuffix(".Caddyfile") != state_name.removesuffix(".users.json")
            or not config_name.removesuffix(".Caddyfile")
        ):
            raise ManagerRecoveryError("invalid transaction journal")
        return transaction

    def _write_transaction(self, transaction: dict) -> None:
        _atomic_write(self._transaction_file, (json.dumps(transaction, separators=(",", ":")) + "\n").encode())

    def _clear_transaction(self) -> None:
        _durable_unlink(self._transaction_file)

    def _recover_transaction(self) -> None:
        transaction = self._read_transaction()
        original_phase = transaction.get("recovery_from", transaction["phase"])
        transaction["phase"] = "recovery_failed"
        transaction["recovery_from"] = original_phase
        self._write_transaction(transaction)

        def restore_backups() -> None:
            config_backup = self.backup_dir / transaction["config_backup"]
            state_backup = self.backup_dir / transaction["state_backup"]
            _assert_regular(config_backup)
            _assert_regular(state_backup)
            _atomic_write(self.caddyfile, config_backup.read_bytes(), self.caddyfile_mode)
            if transaction.get("state_existed", True):
                _atomic_write(self.state_file, state_backup.read_bytes())
            else:
                _durable_unlink(self.state_file)

        def activate_current() -> None:
            state = self._read_state()
            self._assert_consistent(state)
            self.reload()
            self.probe()

        def activate_pre_accounting() -> None:
            state = self._read_state()
            text = self.caddyfile.read_text()
            actual = self._managed_credentials(text)
            expected = [
                (row["username"], row["password"])
                for row in state["users"] if row["enabled"]
            ]
            if actual != expected:
                raise ManagerConflict("managed Caddy credentials changed outside manager")
            self._validate_config(self.caddyfile)
            self.reload()
            self.probe()

        try:
            if original_phase == "bootstrap_prepared":
                restore_backups()
                self._clear_transaction()
                self._recovery_failed = False
                return
            if transaction.get("operation") == "accounting_migration":
                restore_backups()
                activate_pre_accounting()
            elif original_phase in {"prepared", "rollback_pending", "recovery_failed"}:
                restore_backups()
                activate_current()
            else:
                try:
                    activate_current()
                except Exception:
                    restore_backups()
                    activate_current()
            self._clear_transaction()
            self._recovery_failed = False
        except Exception as exc:
            self._recovery_failed = True
            raise ManagerRecoveryError("transaction recovery failed") from exc

    def _assert_consistent(self, state: dict) -> None:
        text = self.caddyfile.read_text()
        self._assert_accounting_config(text)
        actual = self._managed_credentials(text)
        expected = [(row["username"], row["password"]) for row in state["users"] if row["enabled"] and row.get("lane") is None]
        if actual != expected:
            raise ManagerConflict("managed Caddy credentials changed outside manager")
        if lanes_block.lane_credentials(text) != [users for users, _url in self._lane_handlers(state) if users]:
            raise ManagerConflict("managed Caddy lane credentials changed outside manager")
        self._validate_config(self.caddyfile)

    def _validate_config(self, path: Path) -> None:
        text = path.read_text()
        expected = [len(users) for users in lanes_block.lane_credentials(text)] + [len(self._managed_credentials(text))]
        config = self.validate(path)
        self._assert_adapted_semantics(config, expected)

    @staticmethod
    def _assert_adapted_semantics(config: dict, expected_credentials: int | list[int]) -> None:
        """One `forward_proxy` handler per expected count, in Caddyfile order — the lane
        handlers first, the service's own last — each with exactly that many credentials."""
        if not isinstance(config, dict):
            raise ManagerConflict("invalid adapted Caddy configuration")
        expected = [expected_credentials] if isinstance(expected_credentials, int) else list(expected_credentials)
        handlers = []

        def walk(value) -> None:
            if isinstance(value, dict):
                if isinstance(value.get("handler"), str):
                    handlers.append(value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(config)
        forward = [node for node in handlers if node["handler"] == "forward_proxy"]
        authentication = [node for node in handlers if node["handler"] == "authentication"]
        if len(forward) != len(expected) or authentication:
            raise ManagerConflict("unexpected proxy or authentication handler")
        for node, count in zip(forward, expected, strict=True):
            credentials = node.get("auth_credentials")
            if (
                not isinstance(credentials, list)
                or len(credentials) != count
                or any(not isinstance(value, str) or not value for value in credentials)
            ):
                raise ManagerConflict("adapted proxy credentials do not match managed state")

    @staticmethod
    def _find(state: dict, username: str) -> dict:
        for row in state["users"]:
            if row["username"] == username:
                return row
        raise ManagerNotFound("user not found")

    @staticmethod
    def _valid_username(username: str) -> None:
        if not isinstance(username, str) or USERNAME.fullmatch(username) is None:
            raise ValueError("invalid username")
        if username == REDACTION_SENTINEL:
            raise ValueError("reserved username")

    @staticmethod
    def _pruned_operations(operations) -> dict:
        """Records are kept only long enough for a retry; a state file must not grow forever."""
        if operations is None:
            return {}
        if not isinstance(operations, dict):
            raise ManagerConflict("invalid operation state")
        cutoff = datetime.now(UTC).timestamp() - OPERATION_RETENTION_SECONDS
        kept = {}
        for key, record in operations.items():
            if (
                not isinstance(key, str)
                or OPERATION_ID.fullmatch(key) is None
                or not isinstance(record, dict)
                or set(record) != {"operation", "username", "completed_at", "result"}
                or record["operation"] not in {"create", "rotate"}
                or not isinstance(record["result"], dict)
                or not isinstance(record["completed_at"], str)
            ):
                raise ManagerConflict("invalid operation state")
            try:
                completed = datetime.fromisoformat(record["completed_at"]).timestamp()
            except ValueError as exc:
                raise ManagerConflict("invalid operation state") from exc
            if completed >= cutoff:
                kept[key] = record
        return kept

    @staticmethod
    def _validate_password(password: str | None) -> None:
        if password is not None and (not isinstance(password, str) or PASSWORD.fullmatch(password) is None):
            raise ValueError("invalid password")

    @staticmethod
    def _validate_operation_id(operation_id: str | None) -> None:
        if operation_id is not None and (
            not isinstance(operation_id, str) or OPERATION_ID.fullmatch(operation_id) is None
        ):
            raise ValueError("invalid operation id")

    def _replay(self, state: dict, operation_id: str | None, operation: str, username: str) -> dict | None:
        """Return the recorded result when this exact request already completed.

        A lost response is the normal case: the caller retries with the same id and
        must get the same credential back, not a second account or a refusal.
        """
        self._validate_operation_id(operation_id)
        if operation_id is None:
            return None
        record = state["operations"].get(operation_id)
        if record is None:
            return None
        if record["operation"] != operation or record["username"] != username:
            raise ManagerConflict(
                "operation id already used for another request", "operation_conflict"
            )
        return {**record["result"], "replayed": True}

    @staticmethod
    def _remember(state: dict, operation_id: str | None, operation: str, username: str, result: dict) -> None:
        if operation_id is None:
            return
        state["operations"][operation_id] = {
            "operation": operation,
            "username": username,
            "completed_at": _now(),
            "result": result,
        }

    @staticmethod
    def _validate_quota(quota_bytes: int | None) -> None:
        if quota_bytes is not None and (
            type(quota_bytes) is not int or not 1 <= quota_bytes <= MAX_COUNTER
        ):
            raise ValueError("invalid quota bytes")

    @staticmethod
    def _encode_state(state: dict) -> bytes:
        return (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode()

    @staticmethod
    def _forward_bounds(lines: list[str]) -> tuple[int, int]:
        try:
            outside = lanes_block.outside_lanes(lines)
        except lanes_block.LanesInvalid as exc:
            raise ManagerConflict(str(exc)) from exc
        directives = [index for index in outside if re.match(r"^\s*forward_proxy(?:\s|$)", lines[index])]
        if len(directives) != 1:
            raise ManagerConflict("exactly one forward_proxy block is required")
        start = directives[0]
        if re.fullmatch(r"\s*forward_proxy\s*\{\s*(?:#.*)?", lines[start]) is None:
            raise ManagerConflict("forward_proxy must use managed block form")
        depth = 0
        for index in range(start, len(lines)):
            depth += lines[index].count("{") - lines[index].count("}")
            if index > start and depth == 0:
                return start, index
        raise ManagerConflict("unterminated forward_proxy block")

    @classmethod
    def _legacy_credentials(cls, text: str) -> list[tuple[str, str]]:
        lines = text.splitlines()
        start, end = cls._forward_bounds(lines)
        credentials = []
        for line in lines[start + 1:end]:
            match = re.match(r"^\s*basic_auth\s+(\S+)\s+(\S+)\s*$", line)
            if match:
                credentials.append((match.group(1), match.group(2)))
        return credentials

    @classmethod
    def _managed_bounds(cls, lines: list[str]) -> tuple[int, int]:
        begin_indexes = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
        end_indexes = [i for i, line in enumerate(lines) if line.strip() == END]
        if len(begin_indexes) != 1 or len(end_indexes) != 1:
            raise ManagerConflict("managed credential block must have exactly one marker pair")
        start, end = begin_indexes[0], end_indexes[0]
        forward_start, forward_end = cls._forward_bounds(lines)
        if not forward_start < start < end < forward_end:
            raise ManagerConflict("managed credential block is outside forward_proxy")
        span = lanes_block.lanes_span(lines)
        for index in range(len(lines)):
            if re.match(r"^\s*basic_auth\s+", lines[index]) and not start < index < end:
                if span is not None and span[0] < index < span[1]:
                    continue  # a lane handler's user (v0.7)
                raise ManagerConflict("basic_auth directive outside managed credential block")
        return start, end

    @classmethod
    def _managed_credentials(cls, text: str) -> list[tuple[str, str]]:
        lines = text.splitlines()
        start, end = cls._managed_bounds(lines)
        credentials = []
        for line in lines[start + 1:end]:
            match = re.match(r"^\s*basic_auth\s+(\S+)\s+(\S+)\s*$", line)
            if not match:
                raise ManagerConflict("invalid managed credential directive")
            credentials.append((match.group(1), match.group(2)))
        return credentials

    @classmethod
    def _render_initial(cls, text: str, state: dict) -> str:
        lines = text.splitlines()
        if any(line.strip() in {BEGIN, END, ACCOUNTING_BEGIN, ACCOUNTING_END} for line in lines):
            raise ManagerConflict("managed credential markers already present")
        start, end = cls._forward_bounds(lines)
        auth_indexes = [i for i in range(start + 1, end) if re.match(r"^\s*basic_auth\s+", lines[i])]
        if not auth_indexes:
            raise ManagerConflict("basic_auth directives not found")
        indent = re.match(r"^(\s*)", lines[auth_indexes[0]]).group(1)
        block = cls._credential_lines(state, indent)
        first = auth_indexes[0]
        lines = [line for i, line in enumerate(lines) if i not in set(auth_indexes)]
        lines[first:first] = block
        route_indexes = [i for i, line in enumerate(lines) if re.match(r"^\s*route\s*\{", line)]
        if len(route_indexes) != 1:
            raise ManagerConflict("exactly one route block is required")
        route_index = route_indexes[0]
        site_indent = re.match(r"^(\s*)", lines[route_index]).group(1)
        lines[route_index:route_index] = cls._accounting_lines(site_indent)
        return "\n".join(lines) + "\n"

    @classmethod
    def _render_managed(cls, text: str, state: dict) -> str:
        lines = text.splitlines()
        start, end = cls._managed_bounds(lines)
        indent = re.match(r"^(\s*)", lines[start]).group(1)
        lines[start:end + 1] = cls._credential_lines(state, indent)
        try:
            return lanes_block.render("\n".join(lines) + "\n", cls._lane_handlers(state))
        except lanes_block.LanesInvalid as exc:
            raise ManagerConflict(str(exc)) from exc

    @staticmethod
    def _lane_handlers(state: dict) -> list[tuple[list[tuple[str, str]], str]]:
        """Per lane, in state order: its enabled users and its upstream URL."""
        handlers = []
        for lane, entry in state.get("lanes", {}).items():
            users = [(row["username"], row["password"]) for row in state["users"] if row["enabled"] and row.get("lane") == lane]
            handlers.append((users, entry["upstream"]))
        return handlers

    @classmethod
    def _render_accounting_migration(cls, text: str) -> str:
        lines = text.splitlines()
        if any(line.strip() in {ACCOUNTING_BEGIN, ACCOUNTING_END} for line in lines):
            raise ManagerConflict("partial accounting markers are not migratable")
        cls._managed_bounds(lines)
        route_indexes = [i for i, line in enumerate(lines) if re.match(r"^\s*route\s*\{", line)]
        if len(route_indexes) != 1:
            raise ManagerConflict("exactly one route block is required")
        route_index = route_indexes[0]
        indent = re.match(r"^(\s*)", lines[route_index]).group(1)
        lines[route_index:route_index] = cls._accounting_lines(indent)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _credential_lines(state: dict, indent: str) -> list[str]:
        rows = [f"{indent}basic_auth {row['username']} {row['password']}"
                for row in state["users"] if row["enabled"] and row.get("lane") is None]
        return [f"{indent}{BEGIN}", *rows, f"{indent}{END}"]

    @staticmethod
    def _accounting_lines(indent: str) -> list[str]:
        inner = indent + "    "
        deep = inner + "    "
        return [
            f"{indent}{ACCOUNTING_BEGIN}",
            f"{indent}log naive_accounting {{",
            f"{inner}output file /var/log/naive-proxy/access.json {{",
            f"{deep}mode 0640",
            f"{deep}roll_size {ACCOUNTING_ROLL_SIZE_BYTES // (1024 * 1024)}MiB",
            f"{deep}roll_keep {ACCOUNTING_ROLL_KEEP}",
            f"{deep}roll_keep_for 168h",
            f"{deep}roll_uncompressed",
            f"{inner}}}",
            f"{inner}format filter {{",
            f"{deep}wrap json",
            f"{deep}fields {{",
            f"{deep}    request>headers>Proxy-Authorization delete",
            f"{deep}    user_id regexp ^(invalidbase64|invalidformat|invalid):.*$ invalid",
            f"{deep}}}",
            f"{inner}}}",
            f"{indent}}}",
            f"{indent}{ACCOUNTING_END}",
        ]

    @classmethod
    def _assert_accounting_config(cls, text: str) -> None:
        lines = text.splitlines()
        begins = [i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_BEGIN]
        ends = [i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_END]
        if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
            raise ManagerConflict("managed accounting block must have exactly one marker pair")
        indent = re.match(r"^(\s*)", lines[begins[0]]).group(1)
        if lines[begins[0]:ends[0] + 1] != cls._accounting_lines(indent):
            raise ManagerConflict("managed accounting block changed outside manager")

    def _prune_backups(self) -> None:
        backups = sorted(self.backup_dir.glob("*.Caddyfile"), reverse=True)
        for old in backups[20:]:
            old.unlink(missing_ok=True)
            old.with_name(old.name.removesuffix(".Caddyfile") + ".users.json").unlink(missing_ok=True)
