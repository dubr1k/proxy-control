from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .agent_transport import CertificateAuthority
from .database import Database
from .keyring import Keyring
from .migrations import apply_migrations, migration_status
from .nodes.service import NodeConflict, NodeLifecycleService
from .secrets_store import SecretStore
from .settings import Settings
from .fleet import FleetStore
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="Proxy Control administration")
    parser.add_argument("--database", type=Path, default=None, help="override PANEL_DATABASE")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="create the initial administrator")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=("owner", "admin", "viewer"), default="owner")
    create.add_argument("--password-stdin", action="store_true", required=True)

    register = sub.add_parser("fleet-register-node", help="create an unenrolled fleet node")
    register.add_argument("node_id")
    register.add_argument("--display-name", required=True)
    ca_init = sub.add_parser("fleet-ca-init", help="initialize the offline client certificate CA")
    ca_init.add_argument("--ca-dir", type=Path, required=True)
    ca_init.add_argument("--common-name", default="MTProxy fleet client CA")
    sign = sub.add_parser("fleet-sign-csr", help="sign a node-generated CSR and bind its certificate")
    sign.add_argument("node_id")
    sign.add_argument("--ca-dir", type=Path, required=True)
    sign.add_argument("--csr", type=Path, required=True)
    sign.add_argument("--out", type=Path, required=True)
    sign.add_argument("--days", type=int, default=90)
    bind = sub.add_parser("fleet-bind-cert", help="authorize an already-issued node certificate")
    bind.add_argument("node_id")
    bind.add_argument("--cert", type=Path, required=True)
    revoke = sub.add_parser("fleet-revoke-cert", help="immediately reject a node certificate serial")
    revoke.add_argument("node_id")
    revoke.add_argument("--serial", required=True)
    sub.add_parser("db-migrate", help="apply pending schema migrations and print what was applied")
    sub.add_parser("db-status", help="print the migration state of the database as JSON")
    key_init = sub.add_parser("master-key-init", help="create the master keyring file (0600)")
    key_init.add_argument("--path", type=Path, required=True)
    key_rotate = sub.add_parser("master-key-rotate", help="add a new active key, rewrap every secret, retire the old keys")
    key_rotate.add_argument("--path", type=Path, required=True)
    key_rotate.add_argument("--batch-size", type=int, default=200)
    key_verify = sub.add_parser("master-key-verify", help="decrypt every secret version and count them per key")
    key_verify.add_argument("--path", type=Path, required=True)
    operations = sub.add_parser(
        "operations-resume",
        help="resume a provisioning operation that was interrupted, from its journal",
    )
    operations.add_argument("operation_id")
    sub.add_parser("node-list", help="print every node with its enrollment and connectivity state")
    node_disable = sub.add_parser("node-disable", help="refuse this node's transport until it is enabled again")
    node_disable.add_argument("node_id")
    node_enable = sub.add_parser("node-enable", help="allow this node's transport again")
    node_enable.add_argument("node_id")

    args = parser.parse_args()
    database = args.database or Settings().database_path
    if args.command == "create-admin":
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            parser.error("password is required on stdin")
        Store(database).create_admin(args.username, password, args.role)
        print(f"Administrator {args.username!r} created.")
    elif args.command == "fleet-register-node":
        print(json.dumps(FleetStore(database).register_node(args.node_id, args.display_name, {}), sort_keys=True))
    elif args.command == "fleet-ca-init":
        CertificateAuthority(args.ca_dir).initialize(args.common_name)
        print(f"Client CA initialized at {args.ca_dir}; keep ca.key offline/root-only.")
    elif args.command == "fleet-sign-csr":
        if not 1 <= args.days <= 397:
            parser.error("--days must be between 1 and 397")
        metadata = CertificateAuthority(args.ca_dir).sign_node_csr(args.node_id, args.csr, args.out, args.days)
        print(json.dumps(metadata, sort_keys=True))
    elif args.command == "fleet-bind-cert":
        metadata = CertificateAuthority.certificate_metadata(args.cert)
        FleetStore(database).bind_certificate(args.node_id, metadata)
        print(json.dumps(metadata, sort_keys=True))
    elif args.command == "fleet-revoke-cert":
        FleetStore(database).revoke_certificate(args.node_id, args.serial)
        print(f"Certificate {args.serial.upper()} revoked for {args.node_id}.")
    elif args.command == "db-migrate":
        applied = apply_migrations(Database(database))
        print(json.dumps({"database": str(database), "applied": applied}, sort_keys=True))
    elif args.command == "db-status":
        print(json.dumps(migration_status(Database(database)), sort_keys=True))
    elif args.command == "master-key-init":
        if args.path.exists():
            parser.error(f"{args.path} already exists; refusing to overwrite a master key")
        Keyring.generate().save(args.path)
        print(f"Master keyring written to {args.path} (mode 0600). Back it up separately from the database.")
    elif args.command == "master-key-rotate":
        if args.batch_size < 1:
            parser.error("--batch-size must be positive")
        rotated = Keyring.load(args.path).rotate()
        # Overlap first: the file carries both keys while rows are rewrapped, so an
        # interrupted rotation still decrypts everything.
        rotated.save(args.path)
        store = SecretStore(rotated)
        db_handle = Database(database)
        while True:
            with db_handle.transaction() as db:
                if not store.rewrap(db, batch_size=args.batch_size):
                    break
        with db_handle.connect() as db:
            counts = store.verify_all(db)
        if set(counts) - {rotated.active.key_id}:
            parser.error("rewrap left rows under a retiring key; the keyring was not narrowed")
        rotated.retire_all_but_active().save(args.path)
        print(json.dumps({"active_key_id": rotated.active.key_id, "rewrapped": counts}, sort_keys=True))
    elif args.command == "master-key-verify":
        with Database(database).connect() as db:
            print(json.dumps(SecretStore(Keyring.load(args.path)).verify_all(db), sort_keys=True))
    elif args.command == "operations-resume":
        # The journal is the source of truth, so resuming needs no state from the panel
        # process that started the operation.
        import asyncio

        from .clients.provisioning import ProvisioningService
        from .clients.service import ClientService
        from .protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
        from .telemt import TelemtClient
        from .naive import NaiveClient
        from .mieru import MieruClient

        settings = Settings()
        database_boundary = Database(database)
        keyring = Keyring.load(settings.master_key_file) if settings.master_key_file else None
        secrets = SecretStore(keyring)
        adapters = {
            "mtproxy": TelemtAdapter(TelemtClient(settings.telemt_url, settings.telemt_token)),
            "naive": NaiveAdapter(
                NaiveClient(settings.naive_socket, settings.naive_token),
                public_host=settings.naive_public_host,
            ),
            "mieru": MieruAdapter(MieruClient(settings.mieru_socket, settings.mieru_token)),
        }
        clients = ClientService(database_boundary, secrets)
        clients.adapters = adapters
        service = ProvisioningService(database_boundary, secrets, adapters, clients)
        try:
            result = asyncio.run(service.run(args.operation_id))
        except KeyError:
            parser.error(f"unknown operation {args.operation_id}")
        print(json.dumps({"operation_id": result.operation_id, "status": result.status}, sort_keys=True))
    elif args.command in {"node-list", "node-disable", "node-enable"}:
        service = NodeLifecycleService(Database(database), FleetStore(database))
        context = {"actor": {"username": "cli"}, "ip": "cli"}
        if args.command == "node-list":
            print(json.dumps([asdict(view) for view in service.list()], sort_keys=True, default=str))
        else:
            disabled = args.command == "node-disable"
            try:
                view = service.set_disabled(args.node_id, disabled, **context)
            except NodeConflict as exc:
                parser.error(str(exc))
            except KeyError:
                parser.error(f"unknown node {args.node_id}")
            print(json.dumps({"node_id": view.node_id, "disabled": view.disabled}, sort_keys=True))


if __name__ == "__main__":
    main()
