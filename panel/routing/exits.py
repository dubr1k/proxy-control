"""Custom exits (v0.8): the operator's own outbounds a policy may leave through.

An exit belongs to one node — it is an outbound of that node's Xray-router — and is named
by a policy as `exit:<id>`. The row keeps everything but the credential; the credential
(password, UUID) is escrowed in the secret store under `exit.credential`, permitted to the
node the exit belongs to, and revealed only into the intent compiled for that node. The
panel never logs a share link: importing one records the protocol and the host.

The shape mirrors `validate_exit` of the router manager (the panel image does not ship the
manager's package): a test keeps the two in step.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import uuid as uuid_module
from typing import Literal
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..secrets_store import SecretError, SecretRef
from .models import Reason, normalise_domain

EXIT_PURPOSE = "exit.credential"
EXIT_PROTOCOLS = ("socks", "http", "vless", "trojan", "shadowsocks")
EXIT_NETWORKS = ("tcp", "ws", "grpc", "xhttp")
EXIT_SECURITY = ("none", "tls", "reality")
SS_METHODS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
              "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none")
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
MAX_EXITS_PER_NODE = 16
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SHORT_ID = re.compile(r"(?:[0-9a-f]{2}){0,8}\Z")
_NAME = re.compile(r"[^\r\n\x00]{1,48}\Z")


class ExitInUse(Exception):
    """Policies still leave through the exit; `where` names them."""

    def __init__(self, where: list[dict]):
        super().__init__("the exit is used by a policy")
        self.where = where


def _host(value: str) -> str:
    text = value.strip()
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        host = normalise_domain(text)
        if host.startswith("*."):
            raise ValueError("an exit address is one host, not a wildcard")
        return host


class ExitTransport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    network: Literal["tcp", "ws", "grpc", "xhttp"] = "tcp"
    path: str | None = Field(default=None, max_length=512)
    host: str | None = Field(default=None, max_length=253)
    service_name: str | None = Field(default=None, max_length=512)

    def wire(self) -> dict:
        out: dict = {"network": self.network}
        for key in ("path", "host", "service_name"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out


class ExitSecurity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["none", "tls", "reality"] = "none"
    server_name: str | None = Field(default=None, max_length=253)
    fingerprint: str = "chrome"
    alpn: list[str] | None = Field(default=None, max_length=4)
    public_key: str | None = Field(default=None, max_length=64)
    short_id: str | None = Field(default=None, max_length=16)
    insecure: bool = False

    @field_validator("fingerprint")
    @classmethod
    def _fingerprint(cls, value: str) -> str:
        if value not in FINGERPRINTS:
            raise ValueError("invalid fingerprint")
        return value

    @field_validator("server_name")
    @classmethod
    def _server_name(cls, value: str | None) -> str | None:
        return None if value in (None, "") else _host(value)

    @model_validator(mode="after")
    def _reality(self):
        if self.kind == "reality":
            if not self.public_key or _PUBLIC_KEY.fullmatch(self.public_key) is None:
                raise ValueError("reality needs a public key")
            if self.short_id and _SHORT_ID.fullmatch(self.short_id) is None:
                raise ValueError("invalid short id")
            if not self.server_name:
                raise ValueError("reality needs a server name")
        return self

    def wire(self) -> dict:
        out: dict = {"kind": self.kind}
        if self.kind == "none":
            return out
        if self.server_name:
            out["server_name"] = self.server_name
        out["fingerprint"] = self.fingerprint
        if self.alpn:
            out["alpn"] = list(self.alpn)
        if self.kind == "tls" and self.insecure:
            out["insecure"] = True
        if self.kind == "reality":
            out.update({"public_key": self.public_key, "short_id": self.short_id or ""})
        return out


class ExitCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=256)
    uuid: str | None = Field(default=None, max_length=36)


class ExitInput(BaseModel):
    """What `POST /api/routing/exits` and the link importer produce; on an update a missing
    `credential` keeps the escrowed one."""

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=48)
    protocol: Literal["socks", "http", "vless", "trojan", "shadowsocks"]
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    credential: ExitCredential | None = None
    method: str | None = Field(default=None, max_length=40)
    flow: Literal["", "xtls-rprx-vision"] = ""
    transport: ExitTransport = Field(default_factory=ExitTransport)
    security: ExitSecurity = Field(default_factory=ExitSecurity)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        text = value.strip()
        if _NAME.fullmatch(text) is None:
            raise ValueError("invalid exit name")
        return text

    @field_validator("address")
    @classmethod
    def _address(cls, value: str) -> str:
        return _host(value)

    @model_validator(mode="after")
    def _shape(self):
        if self.protocol == "shadowsocks":
            if self.method not in SS_METHODS:
                raise ValueError("shadowsocks needs a method")
        elif self.method is not None:
            raise ValueError("only shadowsocks names a method")
        if self.protocol != "vless" and self.flow:
            raise ValueError("only vless names a flow")
        if self.protocol in ("socks", "http", "shadowsocks") and self.transport.network != "tcp":
            raise ValueError("this exit protocol runs over tcp only")
        if self.protocol in ("socks", "http", "shadowsocks") and self.security.kind == "reality":
            raise ValueError("reality needs vless or trojan")
        if self.protocol == "vless" and self.flow and (self.transport.network != "tcp" or self.security.kind == "none"):
            raise ValueError("xtls-rprx-vision needs tcp with tls or reality")
        credential = self.credential
        if credential is not None:
            if self.protocol in ("socks", "http"):
                if (credential.username is None) != (credential.password is None):
                    raise ValueError("username and password go together")
                if credential.uuid is not None:
                    raise ValueError("socks and http carry a username and password, not a uuid")
            elif self.protocol == "vless":
                if not credential.uuid or _UUID.fullmatch(credential.uuid.lower()) is None:
                    raise ValueError("vless needs a uuid")
                credential.uuid = credential.uuid.lower()
            else:
                if not credential.password:
                    raise ValueError(f"{self.protocol} needs a password")
        return self

    def credential_bytes(self) -> bytes | None:
        """The secret to escrow: None when nothing was given (an update keeping the old one,
        or an unauthenticated socks/http exit)."""
        if self.credential is None:
            return None
        if self.protocol in ("socks", "http"):
            if self.credential.username is None:
                return None
            return json.dumps({"username": self.credential.username, "password": self.credential.password}).encode()
        if self.protocol == "vless":
            return json.dumps({"uuid": self.credential.uuid}).encode()
        return json.dumps({"password": self.credential.password}).encode()

    def needs_credential(self) -> bool:
        return self.protocol not in ("socks", "http")

    def settings(self) -> dict:
        """Everything but the credential, as the row keeps it and the intent carries it."""
        out: dict = {"protocol": self.protocol, "address": self.address, "port": self.port,
                     "transport": self.transport.wire(), "security": self.security.wire()}
        if self.protocol == "shadowsocks":
            out["method"] = self.method
        if self.protocol == "vless":
            out["flow"] = self.flow
        return out


# --------------------------------------------------------------------- share links

def _query(parts) -> dict[str, str]:
    return {key: values[-1] for key, values in parse_qs(parts.query, keep_blank_values=True).items()}


def _name_from(parts, default: str) -> str:
    fragment = unquote(parts.fragment).strip()
    return (fragment or default)[:48]


def _transport_from(query: dict[str, str]) -> dict:
    network = query.get("type", "tcp") or "tcp"
    if network == "raw":
        network = "tcp"
    if network not in EXIT_NETWORKS:
        raise ValueError(f"unsupported transport in link: {network}")
    out: dict = {"network": network}
    if query.get("path"):
        out["path"] = query["path"]
    if query.get("host"):
        out["host"] = query["host"]
    if query.get("serviceName"):
        out["service_name"] = query["serviceName"]
    return out


def _security_from(query: dict[str, str], *, default: str = "none") -> dict:
    kind = query.get("security", default) or default
    if kind not in EXIT_SECURITY:
        raise ValueError(f"unsupported security in link: {kind}")
    out: dict = {"kind": kind}
    if kind == "none":
        return out
    if query.get("sni"):
        out["server_name"] = query["sni"]
    if query.get("fp"):
        out["fingerprint"] = query["fp"]
    if query.get("alpn"):
        out["alpn"] = [item for item in query["alpn"].split(",") if item][:4]
    if query.get("allowInsecure") in ("1", "true") and kind == "tls":
        out["insecure"] = True
    if kind == "reality":
        out["public_key"] = query.get("pbk", "")
        out["short_id"] = query.get("sid", "")
    return out


def parse_share_link(link: str) -> ExitInput:
    """`vless://`, `trojan://`, `ss://`, `socks://`, `http://`/`https://` → an ExitInput.
    `ValueError` for anything else; the link itself is never kept."""
    text = link.strip()
    if len(text) > 4096 or not text:
        raise ValueError("empty or oversized link")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    query = _query(parts)
    if scheme == "vless":
        if not parts.username or not parts.hostname or not parts.port:
            raise ValueError("a vless link is vless://<uuid>@host:port")
        data = {"name": _name_from(parts, parts.hostname), "protocol": "vless", "address": parts.hostname, "port": parts.port,
                "credential": {"uuid": unquote(parts.username)}, "flow": query.get("flow", ""),
                "transport": _transport_from(query), "security": _security_from(query)}
        return ExitInput.model_validate(data)
    if scheme == "trojan":
        if not parts.username or not parts.hostname or not parts.port:
            raise ValueError("a trojan link is trojan://<password>@host:port")
        data = {"name": _name_from(parts, parts.hostname), "protocol": "trojan", "address": parts.hostname, "port": parts.port,
                "credential": {"password": unquote(parts.username)},
                "transport": _transport_from(query), "security": _security_from(query, default="tls")}
        return ExitInput.model_validate(data)
    if scheme == "ss":
        body = text[len("ss://"):]
        fragment = ""
        if "#" in body:
            body, fragment = body.split("#", 1)
        body = body.split("?", 1)[0]
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            decoded = _b64(unquote(userinfo)) if ":" not in unquote(userinfo) else unquote(userinfo)
        else:
            decoded = _b64(body)
            if "@" not in decoded:
                raise ValueError("a shadowsocks link carries method:password@host:port")
            decoded, hostport = decoded.rsplit("@", 1)
        if ":" not in decoded or ":" not in hostport:
            raise ValueError("a shadowsocks link carries method:password@host:port")
        method, password = decoded.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        data = {"name": (unquote(fragment).strip() or host)[:48], "protocol": "shadowsocks", "address": host.strip("[]"),
                "port": int(port), "credential": {"password": password}, "method": method}
        return ExitInput.model_validate(data)
    if scheme in ("socks", "socks5", "http", "https"):
        if not parts.hostname or not parts.port:
            raise ValueError(f"a {scheme} link is {scheme}://[user:pass@]host:port")
        credential = None
        if parts.username is not None:
            credential = {"username": unquote(parts.username), "password": unquote(parts.password or "")}
        data = {"name": _name_from(parts, parts.hostname), "protocol": "socks" if scheme.startswith("socks") else "http",
                "address": parts.hostname, "port": parts.port, "credential": credential,
                "security": {"kind": "tls", "server_name": parts.hostname} if scheme == "https" else {"kind": "none"}}
        return ExitInput.model_validate(data)
    raise ValueError("supported links: vless://, trojan://, ss://, socks://, http://, https://")


def _b64(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        try:
            return base64.b64decode(padded).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("a shadowsocks link is not valid base64") from exc


# ---------------------------------------------------------------------------- store

def _row(row) -> dict:
    settings = json.loads(row["settings_json"])
    return {"id": row["id"], "node_id": row["node_id"], "name": row["name"], "protocol": row["protocol"],
            "enabled": bool(row["enabled"]), "has_credential": row["secret_id"] is not None,
            "last_test": json.loads(row["last_test_json"]) if row["last_test_json"] else None,
            "created_at": row["created_at"], "updated_at": row["updated_at"], **settings}


class ExitStore:
    def __init__(self, secrets):
        self.secrets = secrets

    @staticmethod
    def list(db, node_id: str) -> list[dict]:
        return [_row(row) for row in db.execute("SELECT * FROM egress_exits WHERE node_id=? ORDER BY created_at, rowid", (node_id,))]

    @staticmethod
    def get(db, exit_id: str) -> dict | None:
        row = db.execute("SELECT * FROM egress_exits WHERE id=?", (exit_id,)).fetchone()
        return None if row is None else _row(row)

    def _escrow(self, db, exit_id: str, node_id: str, plaintext: bytes, version: int) -> str:
        secret_id = f"exit:{exit_id}"
        self.secrets.store(db, secret_id=secret_id, version=version, purpose=EXIT_PURPOSE, grant_id=None,
                           permitted_node_id=node_id, plaintext=plaintext, state="active")
        return secret_id

    def create(self, db, node_id: str, data: ExitInput, *, now: int) -> dict:
        count = db.execute("SELECT COUNT(*) FROM egress_exits WHERE node_id=?", (node_id,)).fetchone()[0]
        if count >= MAX_EXITS_PER_NODE:
            raise ValueError(f"a node has at most {MAX_EXITS_PER_NODE} exits")
        if db.execute("SELECT 1 FROM egress_exits WHERE node_id=? AND name=?", (node_id, data.name)).fetchone():
            raise ValueError("an exit with this name exists on the node")
        plaintext = data.credential_bytes()
        if data.needs_credential() and plaintext is None:
            raise ValueError(f"{data.protocol} needs a credential")
        exit_id = str(uuid_module.uuid4())
        secret_id = None if plaintext is None else self._escrow(db, exit_id, node_id, plaintext, 1)
        db.execute("INSERT INTO egress_exits(id,node_id,name,protocol,settings_json,secret_id,secret_version,enabled,created_at,updated_at)"
                   " VALUES(?,?,?,?,?,?,?,1,?,?)",
                   (exit_id, node_id, data.name, data.protocol, json.dumps(data.settings(), sort_keys=True), secret_id,
                    None if secret_id is None else 1, now, now))
        return self.get(db, exit_id)

    def update(self, db, exit_id: str, data: ExitInput, *, now: int) -> dict:
        row = db.execute("SELECT * FROM egress_exits WHERE id=?", (exit_id,)).fetchone()
        if row is None:
            raise KeyError(exit_id)
        if data.protocol != row["protocol"]:
            raise ValueError("an exit keeps its protocol; create another for a different one")
        clash = db.execute("SELECT 1 FROM egress_exits WHERE node_id=? AND name=? AND id<>?", (row["node_id"], data.name, exit_id)).fetchone()
        if clash:
            raise ValueError("an exit with this name exists on the node")
        plaintext = data.credential_bytes()
        secret_id, version = row["secret_id"], row["secret_version"]
        if plaintext is not None:
            version = (version or 0) + 1
            secret_id = self._escrow(db, exit_id, row["node_id"], plaintext, version)
            if row["secret_id"] is not None and row["secret_version"]:
                try:
                    self.secrets.transition(db, SecretRef(row["secret_id"], row["secret_version"]), "revoked")
                except SecretError:
                    pass
        elif data.credential is not None and data.protocol in ("socks", "http"):
            # An explicit empty credential on socks/http: the exit becomes unauthenticated.
            if row["secret_id"] is not None and row["secret_version"]:
                try:
                    self.secrets.transition(db, SecretRef(row["secret_id"], row["secret_version"]), "revoked")
                except SecretError:
                    pass
            secret_id, version = None, None
        if data.needs_credential() and secret_id is None:
            raise ValueError(f"{data.protocol} needs a credential")
        db.execute("UPDATE egress_exits SET name=?, settings_json=?, secret_id=?, secret_version=?, updated_at=? WHERE id=?",
                   (data.name, json.dumps(data.settings(), sort_keys=True), secret_id, version, now, exit_id))
        return self.get(db, exit_id)

    @staticmethod
    def set_enabled(db, exit_id: str, enabled: bool, *, now: int) -> dict:
        if db.execute("UPDATE egress_exits SET enabled=?, updated_at=? WHERE id=?", (1 if enabled else 0, now, exit_id)).rowcount != 1:
            raise KeyError(exit_id)
        return ExitStore.get(db, exit_id)

    def delete(self, db, exit_id: str) -> None:
        row = db.execute("SELECT * FROM egress_exits WHERE id=?", (exit_id,)).fetchone()
        if row is None:
            raise KeyError(exit_id)
        if row["secret_id"] is not None and row["secret_version"]:
            try:
                self.secrets.transition(db, SecretRef(row["secret_id"], row["secret_version"]), "revoked")
            except SecretError:
                pass
        db.execute("DELETE FROM egress_exits WHERE id=?", (exit_id,))

    @staticmethod
    def record_test(db, exit_id: str, result: dict, *, now: int) -> None:
        kept = {key: result.get(key) for key in ("ok", "ip", "colo", "latency_ms", "error", "code") if key in result}
        db.execute("UPDATE egress_exits SET last_test_json=? WHERE id=?", (json.dumps({**kept, "at": now}, sort_keys=True), exit_id))

    def spec(self, db, exit_id: str, *, node_id: str) -> tuple[dict | None, Reason | None]:
        """The exit as the router's intent carries it — credential revealed for its node —
        or the reason it cannot be used from this policy."""
        row = db.execute("SELECT * FROM egress_exits WHERE id=?", (exit_id,)).fetchone()
        if row is None:
            return None, Reason(code="exit_unknown", message="the policy names an exit that does not exist")
        if row["node_id"] != node_id:
            return None, Reason(code="exit_other_node", message="an exit belongs to the node whose router dials it")
        if not row["enabled"]:
            return None, Reason(code="exit_disabled", message=f"exit «{row['name']}» is disabled")
        settings = json.loads(row["settings_json"])
        credential: dict = {}
        if row["secret_id"] is not None:
            try:
                plaintext = self.secrets.reveal(db, SecretRef(row["secret_id"], row["secret_version"]), purpose=EXIT_PURPOSE,
                                                grant_id=None, permitted_node_id=row["node_id"])
            except SecretError:
                return None, Reason(code="exit_secret_pending", message=f"exit «{row['name']}» has no readable credential")
            credential = json.loads(plaintext)
        return {**settings, "credential": credential}, None

    @staticmethod
    def usage(db, exit_id: str) -> list[dict]:
        """Every policy (node, protocol, lane, rule) that leaves through the exit."""
        needle = f"exit:{exit_id}"
        found = []
        for row in db.execute("SELECT id, node_id, protocol, lane, default_egress FROM routing_policies"):
            if row["default_egress"] == needle:
                found.append({"policy_id": row["id"], "node_id": row["node_id"], "protocol": row["protocol"], "lane": row["lane"], "rule": None})
            for rule in db.execute("SELECT position FROM routing_rules WHERE policy_id=? AND egress=? ORDER BY position", (row["id"], needle)):
                found.append({"policy_id": row["id"], "node_id": row["node_id"], "protocol": row["protocol"], "lane": row["lane"],
                              "rule": rule["position"] + 1})
        return found
