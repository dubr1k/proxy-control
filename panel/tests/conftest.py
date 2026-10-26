from __future__ import annotations

import functools
import inspect
from pathlib import Path

import pytest

from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.telemt import MemoryTelemt
from panel.tests.harness import fake_managers, markers
from panel.tests.harness.server import BRIDGE, IMPL, start_panel

# `PANEL_IMPL=rust` runs the black-box tests against the binary from `PANEL_RUST_BIN`
# (panel/tests/harness/server.py); the legacy writer is not ported, so it has only `domain`.
WRITERS = ["legacy", "domain"]


def pytest_configure(config):
    markers.register(config)
    config.addinivalue_line("markers", "panel_settings(**settings): extra settings of the shared panel (`server`)")


def pytest_collection_modifyitems(config, items):
    markers.apply(config, items, impl=IMPL)


@pytest.hookimpl(hookwrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    """The doubles created in sync fixtures start accepting once the test's event loop runs."""
    original = pyfuncitem.obj
    if inspect.iscoroutinefunction(original):
        @functools.wraps(original)
        async def attached(*args, **kwargs):
            fake_managers.attach_pending()
            return await original(*args, **kwargs)

        pyfuncitem.obj = attached
    try:
        yield
    finally:
        pyfuncitem.obj = original


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_fixture_setup(fixturedef, request):
    """…and so do they before an async fixture runs (it may already call the panel)."""
    original = fixturedef.func
    if inspect.isfunction(original) and inspect.isasyncgenfunction(original):
        @functools.wraps(original)
        async def attached(*args, **kwargs):
            fake_managers.attach_pending()
            async for value in original(*args, **kwargs):
                yield value

        fixturedef.func = attached
    elif inspect.isfunction(original) and inspect.iscoroutinefunction(original):
        @functools.wraps(original)
        async def attached(*args, **kwargs):
            fake_managers.attach_pending()
            return await original(*args, **kwargs)

        fixturedef.func = attached
    try:
        yield
    finally:
        fixturedef.func = original


@pytest.fixture(autouse=True)
def _close_fake_managers():
    yield
    failures = fake_managers.assertion_failures()
    fake_managers.close_all()
    if failures:
        pytest.fail("a manager double was called against the test's expectation:\n" + "\n".join(failures))


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def bridge_answers(monkeypatch):
    """The MTProxy ingress bridge (v1.1) is a container on the Compose network: in tests it
    answers, instead of a DNS lookup of `xray-router-ingress` that would only time out
    (`server.probe_bridge(False)` makes it fail; the Rust binary gets `/__test/probe-bridge`)."""
    import panel.protocols.telemt as telemt_adapter

    BRIDGE["answer"] = True

    async def probe(_ingress):
        return BRIDGE["answer"]

    monkeypatch.setattr(telemt_adapter, "_probe_bridge", probe)


@pytest.fixture
def telemt() -> MemoryTelemt:
    return MemoryTelemt(public_host="proxy.example.com", public_port=443)


@pytest.fixture
def naive() -> MemoryNaive:
    return MemoryNaive()


@pytest.fixture
def mieru() -> MemoryMieru:
    return MemoryMieru()


@pytest.fixture
def panel_server(tmp_path: Path):
    """A factory of panels under test (`start_panel` with `tmp_path` as the work directory);
    every panel it made is stopped after the test."""
    made = []

    def factory(**options):
        value = start_panel(tmp_path, **options)
        made.append(value)
        return value

    yield factory
    for value in made:
        value.close()


@pytest.fixture
def xray_router():
    """The Xray-router double; a test that asks for it gets the shared panel wired to it."""
    from panel.xray_router import MemoryXrayRouter

    return MemoryXrayRouter()


@pytest.fixture(params=WRITERS)
async def server(request, panel_server, telemt: MemoryTelemt, naive: MemoryNaive, mieru: MemoryMieru):
    """Every API test runs against both writers.

    The domain writer must be indistinguishable from the outside: same status codes,
    same response shapes, same audit actions. Anything that differs is a regression,
    not a new feature.
    """
    # Credential escrow is part of the panel now, so the shared panel has a keyring.
    extra = {"router": request.getfixturevalue("xray_router")} if "xray_router" in request.fixturenames else {}
    marker = request.node.get_closest_marker("panel_settings")
    if marker is not None:
        extra.update(marker.kwargs)
    value = panel_server(
        name="panel", key_name="panel-master-key", telemt=telemt, naive=naive, mieru=mieru,
        login_attempts=3, login_window_seconds=60, reveal_ttl_seconds=60,
        naive_public_host="naive.example.com", naive_enabled=True, mieru_enabled=True,
        vnext_writer=request.param, **extra,
    )
    value.create_admin("owner", "correct horse battery staple", "owner")
    yield value
    await value.aclose()


@pytest.fixture
def client(server):
    """The shared panel's HTTP client (`http://testserver`)."""
    return server.client


def _panel(panel_server, name: str, **options):
    """One panel with its own database and master key, reachable from a central as
    `https://<name>.example` (Fleet v2 central↔node tests)."""
    defaults = {"hosts": ("testserver", f"{name}.example"), "naive_public_host": f"{name}.example",
                "naive_enabled": True, "telemt": MemoryTelemt(public_host=f"{name}.example"),
                "naive": MemoryNaive(), "mieru": MemoryMieru()}
    return panel_server(name=name, **{**defaults, **options})


@pytest.fixture
def pair_factory(panel_server):
    """`pair_factory(node={...}, central={...})`: a node panel and a central panel that reaches it as
    `https://node.example`, each with extra `start_panel` options (e.g. `router=MemoryXrayRouter()`);
    returns `(node, central, node_api_key_plaintext)`."""
    def make(*, node: dict | None = None, central: dict | None = None):
        node_server = _panel(panel_server, "node", **(node or {}))
        central_server = _panel(panel_server, "central", node_routes={"node.example": node_server}, **(central or {}))
        return node_server, central_server, node_server.create_api_key("central", "node-sync")

    return make


@pytest.fixture
def pair(pair_factory):
    """A node panel and a central panel that reaches it as `https://node.example`;
    yields `(node, central, node_api_key_plaintext)` (two `PanelServer`s)."""
    return pair_factory()


async def login(client, username="owner", password="correct horse battery staple"):
    page = await client.get("/login")
    csrf = page.cookies["panel_csrf"]
    return await client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf},
    )


@pytest.fixture
def login_user():
    return login
