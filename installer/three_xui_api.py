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
import ssl
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
# The panel's own TLS listener, which Reality uses as its cover site. It is
# owned by the installer, so it is always there and always answers.
PANEL_COVER_PORT = 8443

# Verified against a running 3x-ui 3.7.0: `configure_panel` stores the new
# address and the new base path takes effect at once, but the listener itself
# does not move until the service restarts. Anything that calls it must restart
# x-ui and then confirm the move, or the panel goes on answering on *:2053.
PANEL_MOVE_REQUIRES_RESTART = True

WARP_OUTBOUND_TAG = "WARP"
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
    # Vision is the flow a Reality TCP inbound is served with. XHTTP has no
    # flow, and sending one there breaks the inbound.
    flow: str = ""
    subscription_id: str | None = None

    def __post_init__(self) -> None:
        if _SAFE_TAG.fullmatch(self.email) is None:
            raise ThreeXuiApiError("managed client email is invalid")

    def secret_values(self) -> frozenset[str]:
        values = {self.client_id}
        if self.password:
            values.add(self.password)
        if self.subscription_id:
            values.add(self.subscription_id)
        return frozenset(values)

    def settings(self, protocol: str) -> dict[str, object]:
        # Hysteria2 authenticates with "auth"; a client sent as "password" is
        # stored and then never authenticates anybody.
        if protocol == "hysteria":
            return {"email": self.email, "auth": self.password or "", **({"subId": self.subscription_id} if self.subscription_id else {})}
        return {
            "id": self.client_id,
            "email": self.email,
            "flow": self.flow,
            "enable": True,
            **({"subId": self.subscription_id} if self.subscription_id else {}),
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
            # 3x-ui's subscription renderer otherwise advertises this
            # loopback backend and its private port.  The shared 443 router
            # selects the inbound by this public SNI name, so each managed
            # inbound must publish exactly that endpoint instead.
            "externalProxy": [{"dest": domain, "port": 443, "forceTls": "same"}],
            "realitySettings": {
                "show": False,
                # Reality hides behind a cover site. This one is the panel's
                # own local TLS listener, which the installer owns and keeps
                # running: a foreign site can change its certificate or
                # disappear, and Reality then fails for every client at once.
                "dest": f"127.0.0.1:{PANEL_COVER_PORT}",
                "xver": 0,
                "serverNames": [domain],
                "privateKey": private_key,
                "publicKey": public_key,
                "shortIds": [generator.short_id()],
            },
        }
        if network == "xhttp":
            # A bare "/" is the one path a probe tries first. This one reads
            # like a site's own asset route.
            stream["xhttpSettings"] = {"host": "", "path": "/assets/", "mode": "auto"}
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
            network="hysteria",
            security="tls",
            listen="0.0.0.0",
            port=HYSTERIA_PORT,
            stream_settings={
                "externalProxy": [
                    {"dest": three_xui.hysteria_domain, "port": 443, "forceTls": "same"}
                ],
                # Read off running servers: Xray serves Hysteria2 only on the
                # "hysteria" network with its own settings block. It accepts
                # the row on "udp" and then never opens the port, with nothing
                # in the log to say so.
                "network": "hysteria",
                "security": "tls",
                "hysteriaSettings": {"udpIdleTimeout": 60, "version": 2},
                "tlsSettings": {
                    "alpn": ["h3"],
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
            extra_settings={"version": 2},
        )
    )
    return tuple(inbounds)


def build_managed_clients(
    inbounds: Sequence[ManagedInbound],
    *,
    generator: SecretGenerator,
    prefix: str,
    acceptance: bool = False,
    subscription_id: str | None = None,
) -> tuple[ManagedInbound, ...]:
    """Attach one distinct client per inbound; acceptance clients are removable."""
    attached = []
    for index, inbound in enumerate(inbounds):
        client = ManagedClient(
            email=f"{prefix}-{index}",
            client_id=generator.client_id(),
            password=generator.password() if inbound.protocol == "hysteria" else None,
            acceptance=acceptance,
            subscription_id=subscription_id if not acceptance else None,
            # Vision belongs to Reality over TCP only.
            flow=(
                "xtls-rprx-vision"
                if inbound.protocol == "vless" and inbound.network == "tcp"
                else ""
            ),
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
            "servers": [{"address": "127.0.0.1", "port": config.three_xui.warp_port}],
        },
    }
    rules = [rule for rule in existing_rules if rule != _MANDATORY_FINAL_RULE]
    rules.append(
        {
            "type": "field",
            "domain": [domain if domain.startswith(("domain:", "geosite:")) else f"domain:{domain}" for domain in domains],
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
        certificate: Path | None = None,
    ) -> None:
        if host not in _LOOPBACK_HOSTS:
            raise ThreeXuiApiError("the 3x-ui API is only reachable on loopback")
        if not 1 <= port <= 65535:
            raise ThreeXuiApiError("the 3x-ui API port is invalid")
        self.host = host
        self.port = port
        self.timeout = timeout
        self._pin = None
        if certificate is not None:
            try:
                leaf = certificate.read_text().split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----\n'
                self._pin = ssl.PEM_cert_to_DER_cert(leaf)
            except Exception as exc:
                raise ThreeXuiApiError("invalid managed panel certificate") from _Sanitized(exc)
        self._factory = connection_factory or self._default_factory

    def _default_factory(self):
        if self._pin is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Exact leaf pin is checked after TLS handshake, BEFORE any request.
            # This intentionally authenticates the installed certificate rather
            # than a loopback hostname which is absent from public certificates.
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=context)
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
            if self._pin is not None:
                connection.connect()
                if connection.sock is None or not secrets.compare_digest(connection.sock.getpeercert(binary_form=True), self._pin):
                    raise ThreeXuiApiError("managed panel certificate pin mismatch")
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
                "the local 3x-ui request failed"
            ) from _Sanitized(exc)
        finally:
            try:
                connection.close()
            except Exception:
                pass


# 3x-ui embeds its CSRF token in a meta tag on every page it serves. A request
# that changes state and carries no token is answered 403, which is
# indistinguishable from a credential problem, so the token is mandatory here.
_CSRF_META = re.compile(
    r"<meta\s+name=[\"']csrf-token[\"']\s+content=[\"']([A-Za-z0-9_\-+/=]{16,256})[\"']",
    re.IGNORECASE,
)


def parse_csrf_token(page: str) -> str:
    """Read the CSRF token out of a panel page, or fail closed."""
    found = _CSRF_META.search(page)
    if found is None:
        raise ThreeXuiApiError("the 3x-ui page carried no usable CSRF token")
    return found.group(1)


def _form_value(value: object) -> object:
    """Render one setting the way the panel's own form does."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


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
        base_path: str = "/",
    ) -> None:
        self.client = client
        self.contract = contract or self._load_contract(source_dir)
        # Once the panel has a private base path, every one of its paths moves
        # under it -- the login page included. A client that does not know the
        # path talks to a panel that answers 404 to everything.
        if _SAFE_PATH.fullmatch(base_path) is None:
            raise ThreeXuiApiError("the 3x-ui base path is invalid")
        self.base_path = base_path
        self._cookie: str | None = None
        self._csrf: str | None = None

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
        if self.base_path != "/":
            path = self.base_path.rstrip("/") + path
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
        if authenticated and self._cookie is None:
            raise ThreeXuiApiError("the 3x-ui session is not authenticated")
        # The CSRF token is bound to the cookie the panel issued with it, so
        # the pre-login cookie travels with the login too, not only after it.
        if self._cookie is not None:
            headers["Cookie"] = self._cookie
        if self._csrf is not None and name != "csrf_page":
            headers["X-CSRF-Token"] = self._csrf
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

    def _begin_session(self) -> None:
        """Take the pre-login cookie and the CSRF token the panel expects.

        3x-ui answers 403 to a login that carries no token, and a 403 reads
        exactly like a wrong password, so this runs before every login rather
        than being retried after a confusing failure.
        """
        method, path, _encoding = self._endpoint("csrf_page")
        status, raw, cookies = self.client.request(
            method,
            path,
            body=None,
            headers={"Accept": "text/html"},
        )
        if status != 200:
            raise ThreeXuiApiError("the 3x-ui panel did not serve its login page")
        # The panel hands out a pre-login cookie here, but a build that does
        # not is still fine: the login response carries the session cookie, and
        # that one is mandatory.
        for value in cookies:
            self._cookie = value.split(";", 1)[0].strip()
            break
        try:
            page = raw.decode("utf-8", errors="replace")
        except Exception as exc:  # pragma: no cover - decode never raises here
            raise ThreeXuiApiError("the 3x-ui login page was unreadable") from exc
        self._csrf = parse_csrf_token(page)

    def login(self, username: str, password: str) -> None:
        self._cookie = None
        self._csrf = None
        self._begin_session()
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
    ) -> None:
        """Replace the upstream first-run credential.

        Changing the credential invalidates the session that changed it, so
        this makes exactly one call and then drops the session. Anything
        further has to sign in again -- verified against a running 3.7.0,
        where a second call on the old cookie is answered 404.
        """
        self._call(
            "update_user",
            payload={
                "oldUsername": old_username,
                "oldPassword": old_password,
                "newUsername": new_username,
                "newPassword": new_password,
            },
        )
        self._cookie = None
        self._csrf = None

    def configure_panel(
        self,
        *,
        web_path: str,
        port: int,
        listen: str,
        certificate: str | None = None,
        private_key: str | None = None,
    ) -> None:
        """Move the panel onto loopback and give it a private base path.

        A fresh 3x-ui listens on *:2053 and *:2096, reachable from anywhere.
        Behind a shared 443 it must answer only locally.

        The settings form is sent whole: verified against a running 3.7.0, a
        partial form is answered `request body failed validation`, so every
        other setting is read and sent back unchanged. Fields the panel
        reports but does not accept back -- the derived `has...` flags that
        say whether a secret is set -- are dropped.
        """
        if _SAFE_PATH.fullmatch(web_path) is None:
            raise ThreeXuiApiError("the 3x-ui web path is invalid")
        if listen not in _LOOPBACK_HOSTS:
            raise ThreeXuiApiError("the 3x-ui panel must listen on loopback")
        if not 1 <= port <= 65535:
            raise ThreeXuiApiError("the 3x-ui panel port is invalid")
        # Nginx routes the panel's domain straight to this port by SNI, so the
        # panel terminates TLS itself. Without a certificate it answers plain
        # HTTP to a TLS client and the panel never opens.
        for label, value in (("certificate", certificate), ("private key", private_key)):
            if value is not None and not value.startswith("/"):
                raise ThreeXuiApiError(f"the 3x-ui panel {label} path must be absolute")
        document = self._call("all_settings")
        current = document.get("obj")
        if not isinstance(current, Mapping):
            raise ThreeXuiApiError("the 3x-ui settings did not match the contract")
        payload: dict[str, object] = {
            key: _form_value(value)
            for key, value in current.items()
            if not key.startswith("has")
        }
        payload.update(
            {
                "webListen": listen,
                "webPort": port,
                "webBasePath": web_path,
                "subListen": listen,
            }
        )
        if certificate is not None and private_key is not None:
            payload.update({"webCertFile": certificate, "webKeyFile": private_key})
        self._call("update_settings", payload=payload)

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

    def replace_clients(self, inbound_id: int, inbound: ManagedInbound) -> None:
        """Rewrite one inbound so it carries exactly the clients given.

        3x-ui 3.7.0 has no delete-client endpoint -- verified against a running
        panel, where every spelling of one answers 404. An inbound is updated
        whole, which is also the only way to remove a client without touching
        anything else about it.
        """
        if not isinstance(inbound_id, int) or isinstance(inbound_id, bool):
            raise ThreeXuiApiError("the 3x-ui inbound id is invalid")
        self._call(
            "update_inbound",
            payload=inbound.request_body(),
            parameters={"inbound_id": inbound_id},
        )

    def configure_subscription(self, domain: str, *, certificate: str, private_key: str) -> None:
        desired = {
            "subEnable": True, "subListen": "127.0.0.1", "subPort": 2096,
            "subPath": "/sub/", "subURI": f"https://{domain}/sub/",
            "subDomain": domain, "subCertFile": certificate, "subKeyFile": private_key,
            "subJsonEnable": False, "subEncrypt": False,
        }
        current = self._call("all_settings").get("obj")
        if not isinstance(current, Mapping):
            raise ThreeXuiApiError("invalid subscription settings response")
        self._call("update_settings", payload={key: _form_value(value) for key, value in {**current, **desired}.items() if not key.startswith("has")})
        observed = self._call("all_settings").get("obj")
        if not isinstance(observed, Mapping):
            raise ThreeXuiApiError("invalid subscription settings read-back")
        if any(str(_form_value(observed.get(key))) != str(_form_value(value)) for key, value in desired.items()):
            raise ThreeXuiApiError("subscription settings read-back mismatch")

    def xray_settings(self) -> dict[str, object]:
        value = self._call("xray_settings").get("obj")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                raise ThreeXuiApiError("invalid Xray settings response") from None
        if not isinstance(value, dict) or not isinstance(value.get("xraySetting"), dict):
            raise ThreeXuiApiError("Xray settings response has no template")
        return value

    def configure_warp(self, config: InstallerConfig) -> None:
        current = self.xray_settings()
        template = current["xraySetting"]
        if not isinstance(template, dict):
            raise ThreeXuiApiError("invalid Xray template")
        outbounds = template.get("outbounds", [])
        routing = template.get("routing", {})
        if not isinstance(outbounds, list) or not isinstance(routing, dict):
            raise ThreeXuiApiError("invalid Xray outbound/routing template")
        if any(item.get("tag") == WARP_OUTBOUND_TAG for item in outbounds):
            raise ThreeXuiApiError("pre-existing WARP outbound requires explicit migration")
        policy = warp_routing(config, existing_rules=routing.get("rules", []))
        candidate = {
            **template,
            "outbounds": [*outbounds, *policy["outbounds"]],
            "routing": {**routing, "rules": policy["rules"]},
        }
        self._call("update_xray_settings", payload={
            "xraySetting": json.dumps(candidate, separators=(",", ":")),
            "outboundTestUrl": current.get("outboundTestUrl", "https://www.google.com/generate_204"),
        })
        if self.xray_settings()["xraySetting"] != candidate:
            raise ThreeXuiApiError("WARP template read-back mismatch")

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
