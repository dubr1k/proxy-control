"""Renderers are pure functions over a manifest and its artifacts.

Three things are checked here beyond "each format parses". A renderer never emits a
link a target client cannot parse — MTProxy is `unsupported` in sing-box and Clash, naive
is `unsupported` in Clash — and says so with a reason instead of staying silent. A grant
without a stored credential, or one that is not effective right now, never turns into a
link in any format. And the plaintext credential exists only inside the render call: it
is not in the database, not in logs, and not in the text of an error.
"""

from __future__ import annotations

import dataclasses
import json
import re
import uuid


import pytest

from panel.clients.models import (
    AccessGrant,
    Client,
    MieruOptions,
    MtproxyOptions,
    NaiveOptions,
    TrusttunnelOptions,
)
from panel.clients.service import CREDENTIAL_PURPOSE
from panel.clients.store import ClientStore
from panel.database import Database
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter, TrusttunnelAdapter
from panel.secrets_store import SecretStore
from panel.subscriptions.compatibility import MATRIX, NOTES
from panel.subscriptions.models import Manifest, ManifestGrant
from panel.subscriptions.renderers import RENDERERS, RenderError, resolve_artifacts

from panel.tests.harness.memories.telemt import MemoryTelemt
from panel.tests.harness.memories.trusttunnel import MemoryTrusttunnel
from panel.trusttunnel_link import decode_deeplink


HOSTS = {"mtproxy": "proxy.example.com", "naive": "naive.example.com", "mieru": "mieru.example.com"}
NOW = 1_800_000_000
MIERU_TEMPLATE = "mierus://{username}:{password}@mieru.example.com?profile={profile}&port=8443&protocol=TCP"
MIERU_RANGE_TEMPLATE = "mierus://{username}:{password}@mieru.example.com?profile={profile}&port=8000-8010&protocol=TCP"


@pytest.fixture
def database(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        ClientStore.insert_client(
            db,
            Client(id="c1", display_name="Sergey <b>&</b>", state="active", metadata={},
                   created_at=NOW, updated_at=NOW),
        )
    return database


@pytest.fixture
def secrets():
    return SecretStore(Keyring.generate())


@pytest.fixture
def adapters():
    return {
        "mtproxy": TelemtAdapter(
            MemoryTelemt(public_host="proxy.example.com", public_port=443), public_host="proxy.example.com"
        ),
        "naive": NaiveAdapter(MemoryNaive(), public_host="naive.example.com"),
        "mieru": MieruAdapter(MemoryMieru(), public_host="mieru.example.com"),
    }


def _seed(database, secrets, protocol, username, *, password=None, enabled=True, template=None):
    """One grant row, escrowed when `password` is given — the shape provisioning leaves behind."""
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(),
        "mieru": MieruOptions(quotas=[], share_template=template),
    }[protocol]
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id="c1", protocol=protocol, node_id="local",
        endpoint_id="default", runtime_username=username,
        desired_state="enabled" if enabled else "disabled", observed_state="enabled",
        options=options, origin="provisioned" if password else "imported",
        created_at=NOW, updated_at=NOW,
    )
    version = 0
    store = ClientStore(database)
    with database.transaction() as db:
        store.insert_grant(db, grant)
        if password is not None:
            reference = secrets.store(
                db, secret_id=f"grant:{grant.id}", version=1, purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id, permitted_node_id="local", plaintext=password, state="active",
            )
            store.update_grant(
                db, grant.id, secret_id=reference.secret_id, secret_version=reference.version,
            )
            version = reference.version
    return ManifestGrant(
        grant_id=grant.id, protocol=protocol, node_id="local", endpoint_id="default",
        runtime_username=username, secret_version=version, options=options.model_dump(),
        enabled=enabled,
    )


@pytest.fixture
def manifest(database, secrets):
    grants = [
        _seed(database, secrets, "mtproxy", "alice", password=b"ee00112233445566778899aabbccddeeff"),
        _seed(database, secrets, "naive", "bob", password=b"naive-pass-01"),
        _seed(database, secrets, "mieru", "carol", password=b"mieru-pass-01", template=MIERU_TEMPLATE),
        # Imported from a running mita: no credential, so nothing can be rendered.
        _seed(database, secrets, "mieru", "dave"),
        # Suspended right now: has a credential, must still produce no link.
        _seed(database, secrets, "naive", "erin", password=b"naive-pass-02", enabled=False),
        # A port range: fine for Clash, not for the sing-box outbound shape we ship.
        _seed(database, secrets, "mieru", "frank", password=b"mieru-pass-03", template=MIERU_RANGE_TEMPLATE),
    ]
    return Manifest(client_id="c1", client_name="Sergey <b>&</b>", generation=3, grants=grants)


@pytest.fixture
def artifacts(manifest, secrets, adapters, database):
    with database.connect() as db:
        return resolve_artifacts(manifest, secrets, adapters, db, public_hosts=HOSTS)


@pytest.fixture
def manifest_with_canary(database, secrets):
    grant = _seed(database, secrets, "naive", "zed", password=b"CANARY-PASSWORD")
    return Manifest(client_id="c1", client_name="Sergey", generation=1, grants=[grant])


def _database_bytes(database) -> bytes:
    # The WAL holds the newest pages; reading only the main file checks nothing.
    payload = database.path.read_bytes()
    wal = database.path.with_name(database.path.name + "-wal")
    return payload + (wal.read_bytes() if wal.exists() else b"")


# --- every format --------------------------------------------------------------------








# --- what never becomes a link --------------------------------------------------------








# --- sing-box and clash shapes --------------------------------------------------------

















# --- manifest and html ----------------------------------------------------------------








SUB = "https://sub.example.com/s/TOKEN"


def _page(manifest, artifacts, **options):
    return RENDERERS["html"].render(manifest, artifacts, url=SUB, **options).decode()




















# --- secrets and bounds ---------------------------------------------------------------








# --- compatibility matrix -------------------------------------------------------------











# --- TrustTunnel ----------------------------------------------------------------------

SELF_SIGNED_DER_B64 = "MAMCAQU="  # a DER SEQUENCE the adapter can split; the content is irrelevant here
TT_PASSWORD = b"tt-pass-CANARY-01"


def _seed_tt(database, secrets, username, *, certificate=None, name=None, enabled=True):
    options = TrusttunnelOptions(hostname="gate.example.com", port=443, certificate_der_b64=certificate, name=name)
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id="c1", protocol="trusttunnel", node_id="local",
        endpoint_id="default", runtime_username=username,
        desired_state="enabled" if enabled else "disabled", observed_state="enabled",
        options=options, origin="provisioned", created_at=NOW, updated_at=NOW,
    )
    store = ClientStore(database)
    with database.transaction() as db:
        store.insert_grant(db, grant)
        reference = secrets.store(
            db, secret_id=f"grant:{grant.id}", version=1, purpose=CREDENTIAL_PURPOSE,
            grant_id=grant.id, permitted_node_id="local", plaintext=TT_PASSWORD, state="active",
        )
        store.update_grant(db, grant.id, secret_id=reference.secret_id, secret_version=reference.version)
    return ManifestGrant(
        grant_id=grant.id, protocol="trusttunnel", node_id="local", endpoint_id="default",
        runtime_username=username, secret_version=1, options=options.model_dump(), enabled=enabled,
    )


@pytest.fixture
def tt_feed(database, secrets):
    grants = [
        _seed_tt(database, secrets, "trusted"),
        _seed_tt(database, secrets, "selfsigned", certificate=SELF_SIGNED_DER_B64),
        _seed_tt(database, secrets, "paused", enabled=False),
    ]
    manifest = Manifest(client_id="c1", client_name="Sergey", generation=5, grants=grants)
    adapters = {"trusttunnel": TrusttunnelAdapter(MemoryTrusttunnel(), public_host="gate.example.com")}
    with database.connect() as db:
        artifacts = resolve_artifacts(manifest, secrets, adapters, db, public_hosts={"trusttunnel": "gate.example.com"})
    return manifest, artifacts

















HIDDIFY_OUTBOUND = {
    "type": "trusttunnel", "tag": None, "server": "gate.example.com", "server_port": 443,
    "username": None, "password": TT_PASSWORD.decode(), "quic": False,
    "tls": {"enabled": True, "server_name": "gate.example.com"},
}

































