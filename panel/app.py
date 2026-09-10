from __future__ import annotations

import asyncio
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .auth_routes import register_auth_admin_audit_routes
from .client_routes import register_client_routes
from .clients.facade import DomainFacade
from .clients.provisioning import ProvisioningService
from .clients.service import ClientService
from .database import Database
from .fleet import FleetStore
from .fleet_routes import register_fleet_routes
from .keyring import Keyring
from .mieru import MieruClient, MieruError
from .mieru_routes import register_mieru_routes
from .naive import NaiveClient, NaiveError
from .naive_routes import register_naive_routes
from .node_routes import register_node_routes
from .protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from .nodes.service import NodeLifecycleService
from .secrets_store import SecretStore
from .settings import Settings
from .store import Store
from .telemt import TelemtClient, TelemtError
from .telemt_routes import register_telemt_dashboard_routes
from .version_routes import register_version_routes
from .versions import VersionAgentError, VersionClient
from .web_context import RequestContext, install_security_middleware


def create_app(
    settings: Settings | None = None,
    *,
    telemt=None,
    naive=None,
    mieru=None,
    version_client=None,
):
    settings = settings or Settings()
    if settings.vnext_writer not in {"legacy", "domain"}:
        raise ValueError("PANEL_VNEXT_WRITER must be 'legacy' or 'domain'")
    if settings.naive_enabled and not settings.naive_public_host.strip():
        raise ValueError("NAIVE_PUBLIC_HOST is required when NaiveProxy is enabled")
    if settings.login_verify_concurrency < 1:
        raise ValueError("login_verify_concurrency must be positive")

    app = FastAPI(
        title="Proxy Control API", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts)
    )
    app.state.database = Database(settings.database_path)
    app.state.store = Store(settings.database_path)
    app.state.fleet = FleetStore(settings.database_path)
    keyring = Keyring.load(settings.master_key_file) if settings.master_key_file else None
    if keyring is None:
        with app.state.database.connect() as db:
            if db.execute("SELECT count(*) FROM secret_versions").fetchone()[0]:
                raise ValueError(
                    "PANEL_MASTER_KEY_FILE is required: the database holds encrypted secrets"
                )
    app.state.secrets = SecretStore(keyring)
    app.state.nodes = NodeLifecycleService(app.state.database, app.state.fleet)
    app.state.clients = ClientService(app.state.database, app.state.secrets)
    app.state.telemt = telemt or TelemtClient(
        settings.telemt_url, settings.telemt_token
    )
    app.state.naive = naive or NaiveClient(
        settings.naive_socket, settings.naive_token
    )
    app.state.mieru = mieru or MieruClient(
        settings.mieru_socket, settings.mieru_token
    )
    # Only NaiveProxy's public host is panel configuration; Telemt and mita report
    # theirs inside the link they return.
    app.state.adapters = {
        "mtproxy": TelemtAdapter(app.state.telemt),
        "naive": NaiveAdapter(app.state.naive, public_host=settings.naive_public_host),
        "mieru": MieruAdapter(app.state.mieru),
    }
    app.state.clients.adapters = app.state.adapters
    app.state.domain_facade = None  # filled in below once provisioning exists
    app.state.provisioning = ProvisioningService(
        app.state.database, app.state.secrets, app.state.adapters, app.state.clients
    )
    app.state.domain_facade = DomainFacade(
        app.state.clients, app.state.provisioning, app.state.adapters
    )
    app.state.versions = version_client or VersionClient(settings.version_agent_socket)
    app.state.settings = settings
    app.state.reveals = {}
    app.state.clock = time
    app.state.login_verify_slots = asyncio.Semaphore(
        settings.login_verify_concurrency
    )

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")
    install_security_middleware(app, settings)
    context = RequestContext(app, settings)
    app.state.request_context = context

    @app.exception_handler(TelemtError)
    async def telemt_error(_request, _exc):
        return JSONResponse({"detail": "Telemt service unavailable"}, 502)

    @app.exception_handler(NaiveError)
    async def naive_error(_request, exc):
        code = getattr(exc, "code", None)
        if code == "quota_exhausted":
            return JSONResponse(
                {
                    "detail": "Quota exhausted: reset traffic or raise the quota first",
                    "code": code,
                },
                exc.status_code,
            )
        return JSONResponse(
            {"detail": "NaiveProxy manager unavailable"}, exc.status_code
        )

    @app.exception_handler(MieruError)
    async def mieru_error(_request, exc):
        return JSONResponse(
            {"detail": "Mieru manager unavailable"}, exc.status_code
        )

    @app.exception_handler(VersionAgentError)
    async def version_agent_error(_request, exc):
        return JSONResponse({"detail": str(exc)}, exc.status_code)

    register_auth_admin_audit_routes(app, context, static)
    register_version_routes(app, context)
    register_telemt_dashboard_routes(app, context)
    register_naive_routes(app, context)
    register_mieru_routes(app, context)
    register_fleet_routes(app, context)
    register_node_routes(app, context)
    register_client_routes(app, context)
    return app
