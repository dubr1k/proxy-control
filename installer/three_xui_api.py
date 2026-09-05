"""Pinned local 3x-ui 3.7.0 API client and the managed inbound templates.

Every request goes to a loopback address, carries its secrets in the request
body rather than in argv, and is bounded by an explicit timeout and response
size.  Errors never carry a response body, a cookie, a UUID, a password, or a
Reality private key: the client raises fixed, sanitized messages instead.
"""

from __future__ import annotations

import http.client
import json
import re
import secrets
import urllib.parse
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from installer.model import InstallerConfig


_CONTRACT = "tests/fixtures/three_xui/api-contract-3.7.0.json"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_TIMEOUT = 30.0
_VERSION = "3.7.0"

# Managed loopback backends; Nginx keeps the shared 443 listener.
VLESS_TCP_PORT = 8449
VLESS_XHTTP_PORT = 8450
PANEL_PORT = 8451
HYSTERIA_PORT = 443
API_INBOUND_PORT = 8452

WARP_OUTBOUND_TAG = "warp"
_MANDATORY_FINAL_RULE = {"outboundTag": "direct", "network": "tcp,udp"}
_SAFE_TAG = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_SAFE_PATH = re.compile(r"/[A-Za-z0-9_./{}-]{0,255}\Z")


class ThreeXuiApiError(RuntimeError):
    """A local 3x-ui request failed; the message never carries secrets."""


class SecretGenerator(Protocol):
    """Every managed secret comes from one injectable generator."""

    def client_id(self) -> str: ...

    def password(self) -> str: ...

    def reality_keypair(self) -> tuple[str, str]: ...

    def short_id(self) -> str: ...


class SystemSecrets:
    """Cryptographically random managed secrets."""

    def __init__(self, *, keypair: Sequence[str] | None = None) -> None:
        # The Reality keypair is produced by the pinned Xray build; it is read
        # from the runner, never derived here, and never passed on a command
        # line.
        self._keypair = tuple(keypair) if keypair is not None else None

    def client_id(self) -> str:
        return str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))

    def password(self) -> str:
        return secrets.token_urlsafe(24)

    def reality_keypair(self) -> tuple[str, str]:
        if self._keypair is None or len(self._keypair) != 2:
            raise ThreeXuiApiError("a Reality keypair was not provided")
        return self._keypair[0], self._keypair[1]

    def short_id(self) -> str:
        return secrets.token_hex(8)


@dataclass(frozen=True)
class ManagedClient:
    """One managed client; persistent or a removable acceptance client."""

    email: str
    client_id: str
    password: str | None = None
    acceptance: bool = False

    def __post_init__(self) -> None:
        if _SAFE_TAG.fullmatch(self.email) is None:
            raise ThreeXuiApiError("managed client email is invalid")

    def secret_values(self) -> frozenset[str]:
        values = {self.client_id}
        if self.password:
            values.add(self.password)
        return frozenset(values)

    def settings(self, protocol: str) -> dict[str, object]:
        if protocol == "hysteria":
            return {"email": self.email, "password": self.password or ""}
        return {
            "id": self.client_id,
            "email": self.email,
            "flow": "",
            "enable": True,
        }


@dataclass(frozen=True)
class ManagedInbound:
    """One reference inbound template with its generated secret material."""

    tag: str
    protocol: str
    network: str
    security: str
    listen: str
    port: int
    stream_settings: Mapping[str, object]
    sniffing: Mapping[str, object]
    clients: tuple[ManagedClient, ...] = ()
    extra_settings: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if _SAFE_TAG.fullmatch(self.tag) is None:
            raise ThreeXuiApiError("managed inbound tag is invalid")
        if not 1 <= self.port <= 65535:
            raise ThreeXuiApiError("managed inbound port is invalid")

    def secret_values(self) -> frozenset[str]:
        values: set[str] = set()
        for client in self.clients:
            values |= client.secret_values()
        reality = self.stream_settings.get("realitySettings")
        if isinstance(reality, Mapping):
            for key in ("privateKey", "publicKey"):
                value = reality.get(key)
                if isinstance(value, str) and value:
                    values.add(value)
            for value in reality.get("shortIds", []):
                if isinstance(value, str) and value:
                    values.add(value)
        return frozenset(values)

    def with_clients(self, clients: Sequence[ManagedClient]) -> ManagedInbound:
        return ManagedInbound(
            tag=self.tag,
            protocol=self.protocol,
            network=self.network,
            security=self.security,
            listen=self.listen,
            port=self.port,
            stream_settings=self.stream_settings,
            sniffing=self.sniffing,
            clients=tuple(clients),
            extra_settings=self.extra_settings,
        )

    def request_body(self) -> dict[str, object]:
        settings = {
            **dict(self.extra_settings),
            "clients": [client.settings(self.protocol) for client in self.clients],
        }
        return {
            "enable": True,
            "remark": self.tag,
            "listen": self.listen,
            "port": self.port,
            "protocol": self.protocol,
            "settings": json.dumps(settings, separators=(",", ":")),
            "streamSettings": json.dumps(
                dict(self.stream_settings),
                separators=(",", ":"),
            ),
            "sniffing": json.dumps(dict(self.sniffing), separators=(",", ":")),
        }


def build_managed_inbounds(
    config: InstallerConfig,
    *,
    generator: SecretGenerator,
) -> tuple[ManagedInbound, ...]:
    """Build the three reference inbounds with freshly generated secrets."""
    three_xui = config.three_xui
    for name, domain in (
        ("VLESS TCP", three_xui.vless_tcp_domain),
        ("VLESS XHTTP", three_xui.vless_xhttp_domain),
        ("Hysteria2", three_xui.hysteria_domain),
    ):
        if domain is None:
            raise ThreeXuiApiError(f"managed 3x-ui requires the {name} domain")
    sniffing = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": True,
    }
    inbounds = []
    for tag, network, port, domain in (
        (
            "managed-vless-reality-tcp",
            "tcp",
            VLESS_TCP_PORT,
            three_xui.vless_tcp_domain,
        ),
        (
            "managed-vless-reality-xhttp",
            "xhttp",
            VLESS_XHTTP_PORT,
            three_xui.vless_xhttp_domain,
        ),
    ):
        private_key, public_key = generator.reality_keypair()
        stream: dict[str, object] = {
            "network": network,
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": f"{domain}:443",
                "serverNames": [domain],
                "privateKey": private_key,
                "publicKey": public_key,
                "shortIds": [generator.short_id()],
            },
        }
        if network == "xhttp":
            stream["xhttpSettings"] = {"path": "/", "mode": "auto"}
        else:
            stream["tcpSettings"] = {"header": {"type": "none"}}
        inbounds.append(
            ManagedInbound(
                tag=tag,
                protocol="vless",
                network=network,
                security="reality",
                listen="127.0.0.1",
                port=port,
                stream_settings=stream,
                sniffing=sniffing,
                extra_settings={"decryption": "none", "fallbacks": []},
            )
        )
    inbounds.append(
        ManagedInbound(
            tag="managed-hysteria2-tls",
            protocol="hysteria",
            network="udp",
            security="tls",
            listen="0.0.0.0",
            port=HYSTERIA_PORT,
            stream_settings={
                "network": "udp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": three_xui.hysteria_domain,
                    "certificates": [
                        {
                            "certificateFile": (
                                "/etc/letsencrypt/live/"
                                f"{three_xui.hysteria_domain}/fullchain.pem"
                            ),
                            "keyFile": (
                                "/etc/letsencrypt/live/"
                                f"{three_xui.hysteria_domain}/privkey.pem"
                            ),
                        }
                    ],
                },
            },
            sniffing=sniffing,
        )
    )
    return tuple(inbounds)


def build_managed_clients(
    inbounds: Sequence[ManagedInbound],
    *,
    generator: SecretGenerator,
    prefix: str,
    acceptance: bool = False,
) -> tuple[ManagedInbound, ...]:
    """Attach one distinct client per inbound; acceptance clients are removable."""
    attached = []
    for index, inbound in enumerate(inbounds):
        client = ManagedClient(
            email=f"{prefix}-{index}",
            client_id=generator.client_id(),
            password=generator.password() if inbound.protocol == "hysteria" else None,
            acceptance=acceptance,
        )
        attached.append(inbound.with_clients([client]))
    return tuple(attached)


def warp_routing(
    config: InstallerConfig,
    *,
    existing_rules: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    """Return the WARP outbound and rules, or nothing when WARP is disabled."""
    if not config.three_xui.warp:
        return {"outbounds": [], "rules": list(existing_rules)}
    domains = tuple(config.three_xui.warp_domains)
    if not domains:
        raise ThreeXuiApiError("WARP requires operator-confirmed domains")
    outbound = {
        "tag": WARP_OUTBOUND_TAG,
        "protocol": "socks",
        "settings": {
            "servers": [{"address": "127.0.0.1", "port": 45000}],
        },
    }
    rules = [rule for rule in existing_rules if rule != _MANDATORY_FINAL_RULE]
    rules.append(
        {
            "type": "field",
            "domain": [f"domain:{domain}" for domain in domains],
            "outboundTag": WARP_OUTBOUND_TAG,
        }
    )
    # The mandatory final policy always stays last and is never replaced.
    rules.append(dict(_MANDATORY_FINAL_RULE))
    return {"outbounds": [outbound], "rules": rules}


class ThreeXuiClient:
    """One bounded loopback HTTP connection factory."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = PANEL_PORT,
        *,
        timeout: float = _TIMEOUT,
        connection_factory=None,
    ) -> None:
        if host not in _LOOPBACK_HOSTS:
            raise ThreeXuiApiError("the 3x-ui API is only reachable on loopback")
        if not 1 <= port <= 65535:
            raise ThreeXuiApiError("the 3x-ui API port is invalid")
        self.host = host
        self.port = port
        self.timeout = timeout
        self._factory = connection_factory or self._default_factory

    def _default_factory(self):
        return http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=self.timeout,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None,
        headers: Mapping[str, str],
    ) -> tuple[int, bytes, tuple[str, ...]]:
        if _SAFE_PATH.fullmatch(path) is None:
            raise ThreeXuiApiError("the 3x-ui request path is invalid")
        connection = self._factory()
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(payload) > _MAX_RESPONSE_BYTES:
                raise ThreeXuiApiError("the 3x-ui response exceeded its bound")
            cookies = tuple(
                value for name, value in response.getheaders()
                if name.lower() == "set-cookie"
            )
            return response.status, payload, cookies
        except ThreeXuiApiError:
            raise
        except Exception as exc:
            raise ThreeXuiApiError(
                f"the local 3x-ui request to {path} failed"
            ) from _Sanitized(exc)
        finally:
            try:
                connection.close()
            except Exception:
                pass


class _Sanitized(Exception):
    """A cause whose text is reduced to the original exception type only."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(type(original).__name__)


class ThreeXuiApi:
    """The pinned 3.7.0 request surface, and nothing else."""

    def __init__(
        self,
        client: ThreeXuiClient,
        *,
        contract: Mapping[str, object] | None = None,
        source_dir: Path | None = None,
    ) -> None:
        self.client = client
        self.contract = contract or self._load_contract(source_dir)
        self._cookie: str | None = None

    @staticmethod
    def _load_contract(source_dir: Path | None) -> Mapping[str, object]:
        root = Path(source_dir or Path(__file__).resolve().parents[1])
        try:
            document = json.loads((root / _CONTRACT).read_text())
        except (OSError, UnicodeError, ValueError) as exc:
            raise ThreeXuiApiError("the 3x-ui API contract is unavailable") from exc
        if document.get("version") != _VERSION:
            raise ThreeXuiApiError("the 3x-ui API contract is not the pinned version")
        return document

    def _endpoint(self, name: str, **parameters: object) -> tuple[str, str, str]:
        endpoints = self.contract.get("endpoints", {})
        entry = endpoints.get(name) if isinstance(endpoints, Mapping) else None
        if not isinstance(entry, Mapping):
            raise ThreeXuiApiError(f"the 3x-ui endpoint {name} is not in the contract")
        path = str(entry["path"])
        for key, value in parameters.items():
            rendered = str(value)
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", rendered):
                raise ThreeXuiApiError("a 3x-ui path parameter is invalid")
            path = path.replace("{" + key + "}", rendered)
        if "{" in path:
            raise ThreeXuiApiError("a 3x-ui path parameter is missing")
        return str(entry["method"]), path, str(entry["encoding"])

    def _call(
        self,
        name: str,
        *,
        payload: Mapping[str, object] | None = None,
        parameters: Mapping[str, object] | None = None,
        authenticated: bool = True,
    ) -> Mapping[str, object]:
        method, path, encoding = self._endpoint(name, **(parameters or {}))
        headers: dict[str, str] = {"Accept": "application/json"}
        if authenticated:
            if self._cookie is None:
                raise ThreeXuiApiError("the 3x-ui session is not authenticated")
            headers["Cookie"] = self._cookie
        body: bytes | None = None
        if encoding == "json":
            body = json.dumps(payload or {}, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        elif encoding == "form":
            body = urllib.parse.urlencode(
                {key: str(value) for key, value in (payload or {}).items()}
            ).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload:
            raise ThreeXuiApiError("this 3x-ui endpoint takes no body")
        if body is not None:
            headers["Content-Length"] = str(len(body))
        status, raw, cookies = self.client.request(
            method,
            path,
            body=body,
            headers=headers,
        )
        if status != 200:
            raise ThreeXuiApiError(
                f"the local 3x-ui request to {path} returned status {status}"
            )
        try:
            document = json.loads(raw.decode())
        except (UnicodeError, ValueError) as exc:
            raise ThreeXuiApiError(
                f"the local 3x-ui response for {path} was not valid JSON"
            ) from _Sanitized(exc)
        if not isinstance(document, Mapping) or "success" not in document:
            raise ThreeXuiApiError(
                f"the local 3x-ui response for {path} did not match the contract"
            )
        if document.get("success") is not True:
            raise ThreeXuiApiError(
                f"the local 3x-ui request to {path} was rejected"
            )
        if name == "login":
            self._store_cookie(cookies)
        return document

    def _store_cookie(self, cookies: Sequence[str]) -> None:
        for value in cookies:
            name = value.split("=", 1)[0].strip()
            if name and "session" in name.lower():
                self._cookie = value.split(";", 1)[0].strip()
                return
        if cookies:
            self._cookie = cookies[0].split(";", 1)[0].strip()
            return
        raise ThreeXuiApiError("the local 3x-ui login returned no session cookie")

    @property
    def authenticated(self) -> bool:
        return self._cookie is not None

    def login(self, username: str, password: str) -> None:
        self._cookie = None
        self._call(
            "login",
            payload={"username": username, "password": password},
            authenticated=False,
        )

    def rotate_credentials(
        self,
        *,
        old_username: str,
        old_password: str,
        new_username: str,
        new_password: str,
        web_path: str,
    ) -> None:
        """Replace the upstream first-run credential and the panel web path."""
        if _SAFE_PATH.fullmatch(web_path) is None:
            raise ThreeXuiApiError("the 3x-ui web path is invalid")
        self._call(
            "update_user",
            payload={
                "oldUsername": old_username,
                "oldPassword": old_password,
                "newUsername": new_username,
                "newPassword": new_password,
            },
        )
        self._call("update_settings", payload={"webBasePath": web_path})
        self._cookie = None

    def add_inbound(
        self,
        template: ManagedInbound,
        client: ManagedClient | None = None,
    ) -> int:
        inbound = template.with_clients(
            [client] if client is not None else list(template.clients)
        )
        document = self._call("add_inbound", payload=inbound.request_body())
        value = document.get("obj")
        identifier = value.get("id") if isinstance(value, Mapping) else None
        if not isinstance(identifier, int) or isinstance(identifier, bool):
            raise ThreeXuiApiError(
                "the local 3x-ui add-inbound response carried no inbound id"
            )
        return identifier

    def delete_client(self, inbound_id: int, client_id: str) -> None:
        if not isinstance(inbound_id, int) or isinstance(inbound_id, bool):
            raise ThreeXuiApiError("the 3x-ui inbound id is invalid")
        self._call(
            "del_client",
            parameters={"inbound_id": inbound_id, "client_id": client_id},
        )

    def effective_config(self) -> dict[str, object]:
        """Return the effective inbound view, with no client credentials."""
        document = self._call("list_inbounds")
        rows = document.get("obj")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            raise ThreeXuiApiError(
                "the local 3x-ui inbound list did not match the contract"
            )
        inbounds = []
        emails: set[str] = set()
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            settings = row.get("settings")
            if isinstance(settings, str):
                try:
                    settings = json.loads(settings)
                except ValueError:
                    settings = {}
            clients = (
                settings.get("clients", []) if isinstance(settings, Mapping) else []
            )
            for entry in clients:
                if isinstance(entry, Mapping) and isinstance(entry.get("email"), str):
                    emails.add(entry["email"])
            inbounds.append(
                {
                    "tag": row.get("remark"),
                    "protocol": row.get("protocol"),
                    "port": row.get("port"),
                    "listen": row.get("listen"),
                    "client_count": len(clients) if isinstance(clients, list) else 0,
                }
            )
        return {"inbounds": inbounds, "client_emails": sorted(emails)}
