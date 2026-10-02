"""MTProxy through Telemt: the manager owns the secret, and the live link carries it.

Telemt has no operation id, so a lost reply cannot be replayed. What saves the grant is
that the credential is readable back: after an indeterminate call the adapter asks what
the runtime holds now rather than guessing or creating a second account.
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import json
import os
import socket
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

from ..clients.models import AccessGrant, GrantIntent
from ..routing.document import (
    MTPROXY_BRIDGE_ADDRESS,
    TELEMT_DIRECT_DOCUMENT,
    attach_document,
    attached_to_router,
    canonical,
    document_digest,
)
from ..telemt import TelemtError, TelemtIndeterminate, access_from_user
from .base import (
    AccessArtifact,
    AdapterError,
    AppliedEgress,
    AppliedGrant,
    CredentialPlan,
    EgressTarget,
    GrantRef,
    ObservedGrant,
    ObservedInventory,
    Preflight,
)

OPTION_FIELDS = (
    "data_quota_bytes",
    "rate_limit_up_bps",
    "rate_limit_down_bps",
    "max_tcp_conns",
    "max_unique_ips",
)


# What «direct» puts back when no earlier upstream is on record: the entrypoint's own.
DIRECT_UPSTREAMS = [{"type": "direct", "ipv4": True, "ipv6": False}]


def probe_bridge(ingress: dict, timeout: float = 3.0) -> bool:
    """The bridge answers a SOCKS5 greeting and takes Telemt's login — what attach needs
    before Telemt is pointed at it. Never raises."""
    host, _sep, port = str(ingress.get("address", "")).rpartition(":")
    username, password = str(ingress.get("username", "")).encode(), str(ingress.get("password", "")).encode()
    if not host or not port.isdigit() or not 0 < len(username) < 256 or not 0 < len(password) < 256:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as stream:
            stream.settimeout(timeout)
            stream.sendall(b"\x05\x01\x02")
            if stream.recv(2) != b"\x05\x02":
                return False
            stream.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
            return stream.recv(2) == b"\x01\x00"
    except OSError:
        return False


async def _probe_bridge(ingress: dict) -> bool:
    return await asyncio.to_thread(probe_bridge, ingress)


def _link(host: str, port: int, secret: str) -> str:
    return f"tg://proxy?server={quote(host, safe='')}&port={port}&secret={quote(secret, safe='')}"


class TelemtAdapter:
    protocol = "mtproxy"
    credential_origin = "manager"
    capture_supported = True
    accepts_caller_credential = True
    UPDATABLE = set(OPTION_FIELDS)

    def __init__(self, client, *, public_host: str = "", public_port: int = 443, router=None,
                 journal_path: Path | str | None = None, bridge_probe=None):
        # Telemt owns the public host: it comes back inside the connection link, so the
        # panel has no configured value to insist on here.
        self.client = client
        self.public_host = public_host
        self.public_port = public_port
        # v1.1 routing: the node's Xray-router adapter (set once the app has one), the journal
        # file (None = in memory), how the bridge is probed, how long a reload may take.
        self.router = router
        self.journal_path = None if journal_path is None else Path(journal_path)
        self._journal = {"current": None, "previous": None, "direct_upstreams": None}
        self.bridge_probe = bridge_probe or (lambda ingress: _probe_bridge(ingress))  # late-bound: tests replace it
        self.reload_timeout, self.reload_poll = 30.0, 0.5
        self._lock = asyncio.Lock()

    def batch(self):
        """Reuse inventory between mutations; post-write readback is fresh. A client
        without one (a fake) gets a no-op context."""
        batch = getattr(self.client, "batch", None)
        return batch() if batch is not None else contextlib.nullcontext()

    async def _row(self, username: str) -> dict | None:
        for row in await self.client.list_users():
            if isinstance(row, dict) and row.get("username") == username:
                return row
        return None

    @staticmethod
    def _endpoint(row: dict) -> dict:
        """Where the user's link points (`host`/`port` of `MtproxyOptions`), never its secret:
        Telemt owns the endpoint, so an inventory row is the only place to learn it from."""
        access = access_from_user(row) or {}
        return {key: value for key, value in (("host", access.get("server")), ("port", access.get("port")))
                if value not in (None, "")}

    async def discover(self) -> ObservedInventory:
        rows = await self.client.list_users()
        return ObservedInventory(
            tuple(
                ObservedGrant(
                    runtime_username=row["username"],
                    enabled=row.get("enabled") is not False,
                    options={**{key: row[key] for key in OPTION_FIELDS if key in row}, **self._endpoint(row)},
                )
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("username"), str)
            )
        )

    async def preflight(self, intent: GrantIntent) -> Preflight:
        if await self._row(intent.runtime_username) is not None:
            return Preflight(False, "runtime username already exists")
        return Preflight(True)

    def _applied(self, username: str, access: dict, *, enabled: bool, recovered: bool) -> AppliedGrant:
        """Everything a link needs comes out of the link Telemt returned.

        The host and port are learned the same way Mieru's share template is: Telemt
        owns them, the panel is not configured with them, and a subscription rebuilt
        from escrow must point where the runtime actually listens.
        """
        return AppliedGrant(
            runtime_username=username,
            enabled=enabled,
            credential=(access.get("secret") or "").encode(),
            artifact_template={
                "host": access.get("server") or self.public_host,
                "port": access.get("port") or self.public_port,
            },
            recovered=recovered,
        )

    @staticmethod
    def _link_access(result: dict) -> dict | None:
        """The credential is what the link carries, not the bare `secret` field.

        Telemt reports the raw secret while the Fake-TLS link prefixes it with `ee`.
        Escrowing the bare value would store something that cannot rebuild the link,
        so the adapter always takes the secret out of the link itself.
        """
        access = access_from_user(result.get("user") if isinstance(result, dict) else None)
        return None if access is None or not access.get("secret") else access

    async def _read_back(self, username: str) -> dict | None:
        """The link after a mutation. A Telemt failure here is an `AdapterError` like the
        mutation's own would be — never a raw `TelemtError` that the routes turn into a 502."""
        try:
            return await self.client.current_access(username)
        except TelemtError as exc:  # a read: an indeterminate one changed nothing either
            raise AdapterError("Telemt refused the request") from exc

    async def _recover(self, username: str) -> AppliedGrant | None:
        access = await self.client.current_access(username)
        if access is None or not access.get("secret"):
            return None
        return self._applied(username, access, enabled=True, recovered=True)

    async def _create_with(self, username: str, secret: str | None):
        try:
            return await self.client.create_user(username, secret=secret)
        except TelemtIndeterminate:
            recovered = await self._recover(username)
            if recovered is not None:
                return recovered
            # Nothing was created, so a single retry is safe rather than a guess. If
            # this also comes back indeterminate, it propagates raw: the outcome is
            # still unknown and the saga must resume, not compensate.
            return await self.client.create_user(username, secret=secret)

    async def _with_caller_fallback(self, secret, attempt):
        """Try a caller-chosen secret; on a runtime that refuses it, fall back to a
        manager-generated one and say so via the returned origin.

        `TelemtIndeterminate` is never turned into `AdapterError`: an unknown outcome
        must resume, not be compensated, so it always propagates raw.
        """
        origin = "caller" if secret is not None else "manager"
        try:
            result = await attempt(secret)
        except TelemtIndeterminate:
            raise
        except TelemtError as exc:
            if secret is None or getattr(exc, "status_code", 502) not in (400, 422):
                raise AdapterError("Telemt refused the request") from exc
            # This build generates its own secret: fall back and report the origin.
            origin = "manager"
            try:
                result = await attempt(None)
            except TelemtIndeterminate:
                raise
            except TelemtError as inner:
                raise AdapterError("Telemt refused the request") from inner
        return result, origin

    async def create(
        self, operation_id: str, intent: GrantIntent, credential: CredentialPlan
    ) -> AppliedGrant:
        secret = credential.plaintext.decode() if credential.origin == "caller" else None
        created, origin = await self._with_caller_fallback(
            secret, lambda s: self._create_with(intent.runtime_username, s)
        )
        if isinstance(created, AppliedGrant):
            return created
        access = self._link_access(created)
        if access is None:
            raise AdapterError("Telemt returned a user without a connection link")
        applied = self._applied(intent.runtime_username, access, enabled=True, recovered=False)
        return replace(applied, credential_origin=origin)

    async def _set_enabled(self, grant: GrantRef, enabled: bool) -> AppliedGrant:
        try:
            await self.client.set_enabled(grant.runtime_username, enabled)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc
        access = await self._read_back(grant.runtime_username)
        return self._applied(grant.runtime_username, access or {}, enabled=enabled, recovered=False)

    async def enable(self, grant: GrantRef) -> AppliedGrant:
        return await self._set_enabled(grant, True)

    async def disable(self, grant: GrantRef) -> AppliedGrant:
        return await self._set_enabled(grant, False)

    async def _rotate_with(self, username: str, secret: str | None):
        try:
            return await self.client.rotate(username, secret=secret)
        except TelemtIndeterminate:
            recovered = await self._recover(username)
            if recovered is not None:
                return recovered
            raise

    async def rotate(
        self, operation_id: str, grant: GrantRef, credential: CredentialPlan
    ) -> AppliedGrant:
        secret = credential.plaintext.decode() if credential.origin == "caller" else None
        rotated, origin = await self._with_caller_fallback(
            secret, lambda s: self._rotate_with(grant.runtime_username, s)
        )
        if isinstance(rotated, AppliedGrant):
            return rotated
        access = self._link_access(rotated)
        if access is None:
            raise AdapterError("Telemt returned a user without a connection link")
        applied = self._applied(grant.runtime_username, access, enabled=True, recovered=False)
        return replace(applied, credential_origin=origin)

    async def update_options(self, grant: GrantRef, options: dict) -> AppliedGrant | None:
        fields = {key: options[key] for key in self.UPDATABLE if key in options}
        if not fields:
            return None
        try:
            await self.client.update_user(grant.runtime_username, fields)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc
        access = await self._read_back(grant.runtime_username)
        applied = self._applied(grant.runtime_username, access or {}, enabled=True, recovered=False)
        return replace(applied, credential_origin="manager")

    async def delete(self, grant: GrantRef) -> None:
        try:
            await self.client.delete_user(grant.runtime_username)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request", already_gone=exc.status_code == 404) from exc

    async def capture(self, grant: GrantRef) -> bytes | None:
        """The live link is the credential, so an existing account needs no rotation. A
        Telemt failure is an `AdapterError` like everywhere else in this adapter: the node's
        capture route turns it into `null` for that label, never into a 5xx."""
        try:
            access = await self.client.current_access(grant.runtime_username)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc
        secret = (access or {}).get("secret")
        return None if not secret else secret.encode()

    def render_artifacts(
        self, grant: AccessGrant, credential: bytes, *, public_host: str
    ) -> list[AccessArtifact]:
        options = grant.options.model_dump() if hasattr(grant.options, "model_dump") else {}
        # What the saga learned from Telemt's own link wins over any configured fallback.
        host = options.get("host") or public_host
        port = options.get("port") or self.public_port
        link = _link(host, port, credential.decode())
        return [
            AccessArtifact(
                kind="link",
                label="Ссылка Telegram",
                media_type="text/uri-list",
                value=link,
            )
        ]

    # egress (v1.1): Telemt's upstream — direct, or handed whole to the node's Xray-router
    # through the `xray-router-ingress` bridge. No manager stands in between: the panel speaks
    # Telemt's config API itself (PATCH `upstreams` → runtime reload → read back) and keeps the
    # journal a manager would keep, secret-free, for «rollback».

    def _journal_read(self) -> dict:
        if self.journal_path is None:
            return copy.deepcopy(self._journal)
        try:
            return json.loads(self.journal_path.read_text())
        except FileNotFoundError:
            return {"current": None, "previous": None, "direct_upstreams": None}
        except (OSError, ValueError) as exc:
            raise AdapterError("the Telemt egress journal is unreadable", code="manual_intervention_required") from exc

    def _journal_write(self, journal: dict) -> None:
        if self.journal_path is None:
            self._journal = copy.deepcopy(journal)
            return
        temporary = self.journal_path.with_name(f".{self.journal_path.name}.tmp")
        temporary.write_text(json.dumps(journal, sort_keys=True))
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.journal_path)

    async def _config(self) -> tuple[list[dict], str]:
        """(upstreams, the whole config's revision) — `telemt_api_unsupported` for a Telemt
        without the config API, `manager_unavailable` for one that does not answer."""
        try:
            data, revision = await self.client.config()
        except TelemtError as exc:
            if exc.status_code == 404:
                raise AdapterError("this Telemt has no config API", code="telemt_api_unsupported") from exc
            raise AdapterError("Telemt does not answer", code="manager_unavailable") from exc
        upstreams = data.get("upstreams") if isinstance(data, dict) else None
        if not isinstance(upstreams, list) or not isinstance(revision, str):
            raise AdapterError("Telemt answered an unexpected config", code="manager_unavailable")
        return [item for item in upstreams if isinstance(item, dict)], revision

    @staticmethod
    def _document_of(upstreams: list[dict]) -> dict | None:
        """The document Telemt runs, or None for upstreams written by hand."""
        live = [item for item in upstreams if item.get("enabled", True) is not False]
        if len(live) != 1:
            return None
        upstream = live[0]
        if (upstream.get("type") == "direct" and not upstream.get("interface") and not upstream.get("bind_addresses")
                and not upstream.get("scopes")):
            return copy.deepcopy(TELEMT_DIRECT_DOCUMENT)
        if upstream.get("type") == "socks5" and upstream.get("address") == MTPROXY_BRIDGE_ADDRESS and not upstream.get("scopes"):
            return attach_document("mtproxy")
        return None

    @staticmethod
    def _revision(upstreams: list[dict]) -> str:
        """The upstreams' own revision (never the config's: that one moves with every user),
        without the password — what the routing screen compares and a log may show."""
        redacted = [{key: value for key, value in item.items() if key != "password"} for item in upstreams]
        return hashlib.sha256(canonical({"upstreams": redacted})).hexdigest()

    async def _router_ingress(self) -> dict | None:
        if self.router is None:
            return None
        try:
            ingress = await self.router.ingress("mtproxy")
        except AdapterError:
            return None
        return ingress if isinstance(ingress, dict) and ingress.get("address") == MTPROXY_BRIDGE_ADDRESS else None

    async def egress_target(self) -> EgressTarget | None:
        upstreams, _config_revision = await self._config()
        document = self._document_of(upstreams)
        revision = self._revision(upstreams)
        providers: dict[str, dict] = {}
        ingress = await self._router_ingress()
        if ingress is not None:
            providers["router"] = {"reachable": await self.bridge_probe(ingress)}
        mode = "custom" if document is None else ("proxy" if document["upstream"] else "direct")
        return EgressTarget(
            protocol="mtproxy", backend="mtproxy_native", capabilities=frozenset({"whole_direct"}),
            providers=providers, revision=revision,
            applied=None if document is None else {"revision": revision, "digest": document_digest(document),
                                                   "document": document},
            mode=mode, restart_required=False, router_attached=attached_to_router("mtproxy", document),
        )

    @staticmethod
    def _valid(document: dict) -> dict:
        if document == TELEMT_DIRECT_DOCUMENT or document == attach_document("mtproxy"):
            return copy.deepcopy(document)
        raise AdapterError("Telemt runs direct or through the router, nothing else", code="egress_invalid")

    async def plan_egress(self, document: dict, *, expected_revision: str) -> dict:
        document = self._valid(document)
        upstreams, _config_revision = await self._config()
        if self._revision(upstreams) != expected_revision:
            raise AdapterError("Telemt's upstreams changed", code="egress_conflict")
        current = self._document_of(upstreams)
        return {"revision": expected_revision, "diff": [] if current == document else ["-current", "+planned"],
                "warnings": [], "restart_required": False}

    async def _upstreams_for(self, document: dict, journal: dict) -> list[dict]:
        if document["upstream"] is None:
            return copy.deepcopy(journal.get("direct_upstreams") or DIRECT_UPSTREAMS)
        if self.router is None:
            raise AdapterError("this node has no Xray-router", code="router_unavailable")
        ingress = await self.router.ingress("mtproxy")  # AdapterError `router_lacks_mtproxy` as it is
        if not await self.bridge_probe(ingress):
            raise AdapterError("the xray-router-ingress bridge does not answer", code="ingress_unreachable")
        return [{"type": "socks5", "address": ingress["address"], "username": ingress["username"],
                 "password": ingress["password"], "weight": 1, "enabled": True}]

    async def _wait_reload(self, reload_id) -> None:
        deadline = time.monotonic() + self.reload_timeout
        while True:
            try:
                status = await self.client.reload_status(reload_id)
            except TelemtError as exc:
                raise AdapterError("Telemt lost the reload", code="egress_reload_failed") from exc
            state = status.get("state") if isinstance(status, dict) else None
            if state in ("draining", "succeeded"):
                return
            if state in ("failed", "rolled_back") or time.monotonic() >= deadline:
                raise AdapterError(f"Telemt did not activate the new upstream ({state or 'unknown'})",
                                   code="egress_reload_failed")
            await asyncio.sleep(self.reload_poll)

    async def _write(self, upstreams: list[dict], config_revision: str) -> None:
        """PATCH, then the runtime reload, then wait for it. A lost PATCH reply is decided
        by reading the upstreams back, never by guessing."""
        try:
            _data, revision = await self.client.patch_config({"upstreams": upstreams}, config_revision)
        except TelemtIndeterminate:
            current, revision = await self._config()
            if self._revision(current) != self._revision(upstreams):
                raise AdapterError("Telemt lost the upstream change", code="manager_unavailable") from None
        except TelemtError as exc:
            if exc.status_code in (409, 412):
                raise AdapterError("Telemt's config changed meanwhile", code="egress_conflict") from exc
            raise AdapterError("Telemt refused the upstream", code="egress_invalid" if exc.status_code in (400, 422)
                               else "manager_unavailable") from exc
        try:
            accepted = await self.client.reload(revision)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the reload", code="egress_reload_failed") from exc
        await self._wait_reload(accepted.get("reload_id") if isinstance(accepted, dict) else None)

    async def _apply(self, document: dict, *, expected_revision: str, operation_id: str, rollback: bool) -> AppliedEgress:
        async with self._lock:
            journal = self._journal_read()
            upstreams, config_revision = await self._config()
            current = self._document_of(upstreams)
            revision = self._revision(upstreams)
            entry = journal.get("current") or {}
            if (not rollback and entry.get("operation_id") == operation_id and current == document
                    and entry.get("document") == document):
                return AppliedEgress(revision=revision, digest=document_digest(document), readback_sha256=revision,
                                     replayed=True)
            if revision != expected_revision:
                raise AdapterError("Telemt's upstreams changed", code="egress_conflict")
            if current is None:
                raise AdapterError("Telemt carries upstreams written by hand: set them back to direct first",
                                   code="manual_intervention_required")
            if current != document:
                if current["upstream"] is None and document["upstream"] is not None:
                    journal["direct_upstreams"] = upstreams  # what «direct» goes back to (no secrets in it)
                target = await self._upstreams_for(document, journal)
                try:
                    await self._write(target, config_revision)
                except AdapterError:
                    # Telemt's runtime stays on the old generation; its file goes back with it.
                    with contextlib.suppress(AdapterError, TelemtError):
                        _now, now_revision = await self._config()
                        await self.client.patch_config({"upstreams": upstreams}, now_revision)
                    raise
                upstreams, _config_revision = await self._config()
                if self._document_of(upstreams) != document:
                    raise AdapterError("Telemt reads back another upstream", code="egress_readback_mismatch")
            revision = self._revision(upstreams)
            record = {"document": document, "operation_id": operation_id, "revision": revision}
            if rollback:
                journal["current"], journal["previous"] = record, None
            else:
                journal["previous"], journal["current"] = journal.get("current"), record
            self._journal_write(journal)
            return AppliedEgress(revision=revision, digest=document_digest(document), readback_sha256=revision)

    async def apply_egress(self, document: dict, *, expected_revision: str, operation_id: str) -> AppliedEgress:
        return await self._apply(self._valid(document), expected_revision=expected_revision, operation_id=operation_id,
                                 rollback=False)

    async def rollback_egress(self, *, expected_revision: str) -> AppliedEgress:
        previous = self._journal_read().get("previous")
        if not previous or not isinstance(previous.get("document"), dict):
            raise AdapterError("no previous Telemt upstream to roll back to", code="egress_no_previous")
        return await self._apply(self._valid(previous["document"]), expected_revision=expected_revision,
                                 operation_id=f"rollback:{previous.get('operation_id')}", rollback=True)
