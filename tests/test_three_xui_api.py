from __future__ import annotations

import json
from pathlib import Path

import pytest

from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.three_xui_api import (
    WARP_OUTBOUND_TAG,
    ManagedClient,
    ManagedInbound,
    ThreeXuiApi,
    ThreeXuiApiError,
    ThreeXuiClient,
    build_managed_clients,
    build_managed_inbounds,
    warp_routing,
)


ROOT = Path(__file__).parents[1]

COOKIE = "3x-ui-session=abc123def456"
UUID_VALUE = "6f2c1d4e-6a2b-4c8f-9f0d-2a7b5c8e1d33"
PASSWORD = "hysteria-secret-password"
PRIVATE_KEY = "wPJ8Zk1TLbQ0YyC7mF3sJd9nR2vX5hK8aE4uG6iO1cQ"


def config(warp: bool = False, warp_domains: tuple[str, ...] = ()) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=Profile.CORE,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com"),
        mieru=None,
        three_xui=ThreeXuiConfig(
            mode=ThreeXuiMode.MANAGED_NEW,
            panel_domain="xui.example.com",
            vless_tcp_domain="vless.example.com",
            vless_xhttp_domain="xhttp.example.com",
            hysteria_domain="hysteria.example.com",
            warp=warp,
            warp_domains=warp_domains,
        ),
        firewall=FirewallConfig(manage_ufw=False),
    )


class DeterministicSecrets:
    """A reproducible generator; two seeds must never share a secret."""

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self._counter = 0

    def _next(self, label: str) -> str:
        self._counter += 1
        return f"{label}-seed{self.seed}-{self._counter}"

    def client_id(self) -> str:
        return f"00000000-0000-4000-8000-{self.seed:06d}{self._bump():06d}"

    def _bump(self) -> int:
        self._counter += 1
        return self._counter

    def password(self) -> str:
        return self._next("password")

    def reality_keypair(self) -> tuple[str, str]:
        return self._next("private"), self._next("public")

    def short_id(self) -> str:
        return self._next("shortid")


def secret_values(inbounds) -> set[str]:
    values: set[str] = set()
    for inbound in inbounds:
        values |= set(inbound.secret_values())
    return values


def template() -> ManagedInbound:
    return build_managed_inbounds(config(), generator=DeterministicSecrets(seed=7))[0]


def client() -> ManagedClient:
    return ManagedClient(email="acceptance-0", client_id=UUID_VALUE)


def sensitive_values() -> set[str]:
    return {COOKIE, UUID_VALUE, PASSWORD, PRIVATE_KEY}


class FakeResponse:
    def __init__(self, status: int, payload: bytes, cookies: tuple[str, ...]) -> None:
        self.status = status
        self._payload = payload
        self._cookies = cookies

    def read(self, amount: int) -> bytes:
        return self._payload[:amount]

    def getheaders(self):
        return [("Set-Cookie", value) for value in self._cookies]


class FakeConnection:
    def __init__(self, script) -> None:
        self.script = script
        self.requests: list[tuple[str, str, bytes | None, dict]] = []

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        return self.script(self.requests[-1])

    def close(self):
        return None


def api_with(script, *, authenticated: bool = True) -> ThreeXuiApi:
    connection = FakeConnection(script)
    client_object = ThreeXuiClient(connection_factory=lambda: connection)
    api = ThreeXuiApi(client_object, source_dir=ROOT)
    api.recorded = connection  # type: ignore[attr-defined]
    if authenticated:
        api._cookie = COOKIE
    return api


def ok(payload: dict, cookies: tuple[str, ...] = ()) -> FakeResponse:
    return FakeResponse(200, json.dumps(payload).encode(), cookies)


def failing_api() -> ThreeXuiApi:
    def script(_request):
        return FakeResponse(
            500,
            json.dumps(
                {
                    "success": False,
                    "msg": (
                        f"internal error cookie={COOKIE} id={UUID_VALUE} "
                        f"password={PASSWORD} privateKey={PRIVATE_KEY}"
                    ),
                }
            ).encode(),
            (COOKIE,),
        )

    return api_with(script)


# ----------------------------------------------------------------------
# templates
# ----------------------------------------------------------------------


def test_managed_templates_match_reference_transports_without_reusing_secrets():
    first = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=1))
    second = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=2))
    first = build_managed_clients(
        first,
        generator=DeterministicSecrets(seed=1),
        prefix="initial",
    )
    second = build_managed_clients(
        second,
        generator=DeterministicSecrets(seed=2),
        prefix="initial",
    )
    assert [(x.protocol, x.network, x.security) for x in first] == [
        ("vless", "tcp", "reality"),
        ("vless", "xhttp", "reality"),
        ("hysteria", "udp", "tls"),
    ]
    assert secret_values(first).isdisjoint(secret_values(second))


def test_managed_templates_keep_vless_on_loopback_and_publish_only_hysteria():
    inbounds = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=3))
    assert [(x.listen, x.port) for x in inbounds] == [
        ("127.0.0.1", 8449),
        ("127.0.0.1", 8450),
        ("0.0.0.0", 443),
    ]


def test_managed_templates_set_reality_and_sniffing_selectors():
    inbounds = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=4))
    reality = inbounds[0].stream_settings["realitySettings"]
    assert reality["serverNames"] == ["vless.example.com"]
    assert reality["target"] == "vless.example.com:443"
    assert inbounds[1].stream_settings["xhttpSettings"]["mode"] == "auto"
    assert inbounds[0].sniffing["destOverride"] == ["http", "tls", "quic"]
    certificates = inbounds[2].stream_settings["tlsSettings"]["certificates"]
    assert certificates[0]["certificateFile"].endswith(
        "hysteria.example.com/fullchain.pem"
    )


def test_managed_templates_require_every_domain():
    broken = config()
    incomplete = InstallerConfig(
        **{
            **{
                name: getattr(broken, name)
                for name in broken.__dataclass_fields__
            },
            "three_xui": ThreeXuiConfig(mode=ThreeXuiMode.MANAGED_NEW),
        }
    )
    with pytest.raises(ThreeXuiApiError, match="requires the VLESS TCP domain"):
        build_managed_inbounds(incomplete, generator=DeterministicSecrets(seed=5))


def test_acceptance_clients_are_distinct_from_persistent_clients():
    inbounds = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=6))
    persistent = build_managed_clients(
        inbounds,
        generator=DeterministicSecrets(seed=6),
        prefix="initial",
    )
    acceptance = build_managed_clients(
        inbounds,
        generator=DeterministicSecrets(seed=9),
        prefix="acceptance",
        acceptance=True,
    )
    assert all(item.clients[0].acceptance for item in acceptance)
    assert not any(item.clients[0].acceptance for item in persistent)
    # The inbounds are shared, so only the client credentials must differ.
    persistent_clients = {
        value for item in persistent for value in item.clients[0].secret_values()
    }
    acceptance_clients = {
        value for item in acceptance for value in item.clients[0].secret_values()
    }
    assert persistent_clients.isdisjoint(acceptance_clients)


def test_inbound_request_body_serializes_settings_as_pinned_strings():
    inbound = build_managed_clients(
        build_managed_inbounds(config(), generator=DeterministicSecrets(seed=8)),
        generator=DeterministicSecrets(seed=8),
        prefix="initial",
    )[0]
    body = inbound.request_body()
    assert body["protocol"] == "vless"
    assert body["listen"] == "127.0.0.1"
    settings = json.loads(body["settings"])
    assert settings["decryption"] == "none"
    assert len(settings["clients"]) == 1


# ----------------------------------------------------------------------
# WARP
# ----------------------------------------------------------------------


def test_warp_emits_nothing_when_disabled():
    assert warp_routing(config()) == {"outbounds": [], "rules": []}


def test_warp_appends_rules_without_replacing_the_final_policy():
    existing = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
        {"outboundTag": "direct", "network": "tcp,udp"},
    ]
    routing = warp_routing(
        config(warp=True, warp_domains=("openai.com",)),
        existing_rules=existing,
    )
    assert routing["outbounds"][0]["tag"] == WARP_OUTBOUND_TAG
    assert routing["rules"][0] == existing[0]
    assert routing["rules"][1]["domain"] == ["domain:openai.com"]
    assert routing["rules"][-1] == {"outboundTag": "direct", "network": "tcp,udp"}


def test_warp_requires_operator_confirmed_domains():
    with pytest.raises(ThreeXuiApiError, match="operator-confirmed domains"):
        warp_routing(config(warp=True))


# ----------------------------------------------------------------------
# API surface
# ----------------------------------------------------------------------


def test_api_failure_log_contains_no_cookie_uuid_password_or_private_key():
    with pytest.raises(ThreeXuiApiError) as caught:
        failing_api().add_inbound(template(), client())
    assert sensitive_values().isdisjoint(set(str(caught.value).split()))


def test_api_failure_chain_never_carries_the_response_body():
    with pytest.raises(ThreeXuiApiError) as caught:
        failing_api().effective_config()
    rendered = " ".join(
        str(item) for item in (caught.value, caught.value.__cause__)
    )
    assert all(secret not in rendered for secret in sensitive_values())


def test_api_refuses_a_non_loopback_endpoint():
    with pytest.raises(ThreeXuiApiError, match="loopback"):
        ThreeXuiClient(host="203.0.113.10")


def test_api_requires_authentication_before_any_managed_request():
    api = api_with(lambda _request: ok({"success": True}), authenticated=False)
    with pytest.raises(ThreeXuiApiError, match="not authenticated"):
        api.add_inbound(template(), client())


def test_login_stores_the_session_cookie_in_memory_only():
    api = api_with(
        lambda _request: ok({"success": True}, ("3x-ui-session=abc; Path=/",)),
        authenticated=False,
    )
    api.login("admin", "admin")
    assert api.authenticated
    assert api.recorded.requests[0][1] == "/login"
    assert b"password=admin" in api.recorded.requests[0][2]


def test_login_without_a_session_cookie_fails_closed():
    api = api_with(lambda _request: ok({"success": True}), authenticated=False)
    with pytest.raises(ThreeXuiApiError, match="session cookie"):
        api.login("admin", "admin")


def test_add_inbound_posts_the_pinned_contract_path_and_returns_the_id():
    api = api_with(lambda _request: ok({"success": True, "obj": {"id": 4}}))
    identifier = api.add_inbound(template(), client())
    method, path, body, headers = api.recorded.requests[-1]
    assert (method, path) == ("POST", "/panel/api/inbounds/add")
    assert headers["Cookie"] == COOKIE
    assert identifier == 4
    assert UUID_VALUE in body.decode()


def test_add_inbound_rejects_a_response_without_an_identifier():
    api = api_with(lambda _request: ok({"success": True, "obj": {}}))
    with pytest.raises(ThreeXuiApiError, match="no inbound id"):
        api.add_inbound(template(), client())


def test_delete_client_uses_the_contract_path_parameters():
    api = api_with(lambda _request: ok({"success": True}))
    api.delete_client(4, UUID_VALUE)
    assert api.recorded.requests[-1][1] == f"/panel/api/inbounds/4/delClient/{UUID_VALUE}"


def test_effective_config_reports_inbounds_without_credentials():
    rows = [
        {
            "remark": "managed-vless-reality-tcp",
            "protocol": "vless",
            "port": 8449,
            "listen": "127.0.0.1",
            "settings": json.dumps(
                {"clients": [{"id": UUID_VALUE, "email": "initial-0"}]}
            ),
        }
    ]
    api = api_with(lambda _request: ok({"success": True, "obj": rows}))

    effective = api.effective_config()

    assert effective["inbounds"][0]["client_count"] == 1
    assert effective["client_emails"] == ["initial-0"]
    assert UUID_VALUE not in json.dumps(effective)


def test_rotate_credentials_replaces_defaults_and_drops_the_session():
    api = api_with(lambda _request: ok({"success": True}))
    api.rotate_credentials(
        old_username="admin",
        old_password="admin",
        new_username="operator",
        new_password="generated-password",
        web_path="/managed-path/",
    )
    paths = [request[1] for request in api.recorded.requests]
    assert paths == ["/panel/setting/updateUser", "/panel/setting/update"]
    assert not api.authenticated


def test_rotate_credentials_refuses_an_unsafe_web_path():
    api = api_with(lambda _request: ok({"success": True}))
    with pytest.raises(ThreeXuiApiError, match="web path is invalid"):
        api.rotate_credentials(
            old_username="admin",
            old_password="admin",
            new_username="operator",
            new_password="generated-password",
            web_path="not-absolute",
        )


def test_api_refuses_an_endpoint_outside_the_pinned_contract():
    api = api_with(lambda _request: ok({"success": True}))
    with pytest.raises(ThreeXuiApiError, match="not in the contract"):
        api._call("delete_everything")


def test_api_refuses_an_oversized_response():
    def script(_request):
        return FakeResponse(200, b"x" * (4 * 1024 * 1024 + 1), ())

    api = api_with(script)
    with pytest.raises(ThreeXuiApiError, match="exceeded its bound"):
        api.effective_config()


def test_api_refuses_a_response_outside_the_contract_schema():
    api = api_with(lambda _request: ok({"result": "ok"}))
    with pytest.raises(ThreeXuiApiError, match="did not match the contract"):
        api.effective_config()
