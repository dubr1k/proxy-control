# Automated Proxy Control installation on Ubuntu 24.04

**English** · [Русский](INSTALL.ru.md)

Root-only `install.sh` invokes transactional `scripts/proxyctl.py install`. Supported lifecycle:

```text
audit → plan → install → repair → uninstall
```

The complete installer deploys Telemt/MTProxy and the panel. NaiveProxy, Mieru, and fleet are separate integrations applied only after core acceptance.

## The primary install path: a verified release

This is the supported way to install Proxy Control. It replaces the manual
`scripts/proxyctl.py` sequence below, which stays documented for an existing
deployment and for reviewing what the installer does.

Download the archive, its `SHA256SUMS`, and `release-manifest.json` from the
release page, then verify provenance **before** anything runs with privilege:

```bash installer-check
gh attestation verify proxy-control-v0.1.0.tar.gz --repo dubr1k/proxy-control
sha256sum --check --ignore-missing SHA256SUMS
./install-bootstrap --archive proxy-control-v0.1.0.tar.gz --checksum SHA256SUMS --manifest release-manifest.json
```

The order matters: the attestation is checked first, and only then is anything
handed to `sudo`. `install-bootstrap` refuses to run as root, verifies that
every input is a regular file you own that is not group- or other-writable,
compares the archive against the published checksum, requires the manifest to
name the same archive and digest, refuses a prerelease version, and preflights
the archive for absolute or escaping members before its single `exec sudo`.
Nothing is ever downloaded and executed in one step.

With no further arguments the installer starts a bilingual wizard that writes a
configuration file, shows a plan, and applies nothing until you confirm the plan
digest. The complete surface - profiles, every configuration field, ownership
boundaries, per-protocol acceptance, WARP and egress, recovery, and reports -
is in the [installer reference](docs/INSTALLER_REFERENCE.en.md).

Before installing a profile that includes Mieru, stage both pinned upstream
packages for your architecture in `/var/lib/proxy-control/`:
`mita_3.36.0_<arch>.deb` (the server) and `mieru_3.36.0_<arch>.deb` (the
official client the acceptance runs). The installer never downloads them and
refuses to continue unless each digest matches its pin; the URLs and digests are
in [`release/external-artifacts.json`](release/external-artifacts.json).

## Requirements

- Ubuntu 24.04 with systemd;
- root/sudo;
- DNS A/AAAA for proxy and panel names points directly to the host;
- TCP/80 available for ACME HTTP-01;
- public TCP/443 owned by an existing Nginx `stream` listener;
- exactly one understandable `$ssl_preread_server_name` map in the selected route file;
- free loopback ports;
- external executable probe that validates real Fake-TLS/Obfuscated2 `req_pq_multi → resPQ`;
- host-level backup of Nginx, services, and adjacent routes.

Disable CDN/proxying for the raw MTProto hostname. Unhandled AAAA, NAT mismatch, ambiguous maps, and port collisions are hard stops.

Use restrictive `umask 077` only inside a secret/backup subshell. Restore `022` before Git clone, Docker build contexts, and APT; public ACME roots and `.well-known/acme-challenge` must be mode `0755`. If the proxy/panel certificate is pre-issued, use `/var/www/<proxy-domain>` and `/var/www/<panel-domain>` in its renewal map from the first issuance.

## The external MTProto probe

MTProxy acceptance runs a real TDLib probe. You do not build or install it by
hand: the installer takes it from the `probe/` directory inside the release,
verifies its digest, and installs it itself at the fixed path
`/usr/local/libexec/mtproxy-respq-probe` with mode `0750`.

The probe accepts exactly `--domain DOMAIN --secrets-file PATH`, mounts the
secrets file read-only at `/run/mtproxy/users.conf`, and asks TDLib to
`addProxy` then `pingProxy` once for every secret. Individual secrets never
enter the installer's argv, the Docker argv, shell history, or probe output. The
container has a read-only root filesystem, a dedicated tmpfs for TDLib state,
dropped capabilities, and `no-new-privileges`. A failure on any secret stops the
installation.

## 1. Audit and plan

There is no separate `audit` subcommand: the audit happens inside `plan`, which
changes nothing and prints both the observed facts and the complete list of
actions to come.

Every command below runs from the unpacked release — the directory
`install-bootstrap` printed. They do not work from a Git clone, which has no
`release/release.json`, and the installer refuses to run without a release
identity.

```bash installer-check
python3 -m installer.cli plan --config examples/installer/core.toml --json
```

Point it at your own file instead of the example — the one the wizard wrote.

Review the output: the owner of TCP/443 and the Nginx topology, DNS and CAA for
every domain, free local ports, identity collisions, project paths, the package
list, certificate names, and the routes that will be added.

The plan contains no passwords, tokens, user secrets, or access links, and
cannot.

## 2. Rollback readiness

Before installing, save:

- the selected Nginx route file and its includes, with owner and mode;
- `nginx -T` into a private artifact;
- active listeners and unit files;
- the current Docker/Compose state;
- adjacent SNI acceptance results.

The installer keeps its own ownership journal and exact backups, but that is not
a substitute for an independent host backup.

## 3. Install

The plan has a digest, and installation does not start until you approve that
exact digest:

```bash installer-check
sudo python3 -m installer.cli install --config examples/installer/core.toml --accept-plan DIGEST
```

The installer:

1. installs only the missing Ubuntu packages;
2. issues certificates grouped by service and immediately proves renewal with
   `certbot renew --dry-run`;
3. creates mode-restricted secrets;
4. renders the `mtproxy` Compose project;
5. bootstraps the panel owner through stdin without printing the password;
6. adds only its own Nginx routes in a validated transaction;
7. waits for services to be ready and runs the acceptance for every protocol.

It does not touch DNS, WARP, Fleet, foreign containers, or foreign Nginx routes.
It manages UFW rules and 3x-ui only when your configuration says so.

## 4. Acceptance

```bash
docker compose -f /opt/mtproxy-shared443/compose.yaml ps
curl -fsS -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
```

Then do these by hand:

- a real Telegram client test;
- an HTTPS login to the panel;
- an adjacent SNI regression check;
- SQLite integrity and a backup checksum;
- a check that the Telemt API is not published on the host.

## 5. Status, resume, and repair

```bash installer-check
sudo python3 -m installer.cli status --json
sudo python3 -m installer.cli resume --json
sudo python3 -m installer.cli repair --json
```

`resume` continues an interrupted installation from its recorded phase. `repair`
reads the private ownership journal at
`/var/lib/proxy-control/installer/state.json`, completes an interrupted
recovery, checks for foreign drift, and restarts only its own services. Neither
command accepts arbitrary paths.

## 6. Uninstall

```bash installer-check
sudo python3 -m installer.cli uninstall --json
sudo python3 -m installer.cli uninstall --purge-data --json
```

Uninstall checkpoints its phases, removes only installer-owned routes, files,
and packages, and by default preserves Compose volumes, the credential backup,
certificates, and cover roots until a separate ownership review. Re-running is
safe; an interrupted data purge must be continued with the same `--purge-data`.
Use that flag only after verifying an independent copy of the volumes.

Afterwards check `nginx -t`, the public listeners, and adjacent SNI routes
again.

## Interrupted SSH

An SSH exit code of `255` proves only that the transport dropped. On the target
host check `sudo python3 -m installer.cli status --json`, the phase, the
installer-owned files, the services, and the acceptance result. Do not blindly
re-run the installation.

## Next integrations

- [Panel and NaiveProxy](PANEL.en.md)
- [Mieru/mita](MIERU.en.md)
- [Fleet mTLS](FLEET.en.md)

See [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md), [operations](docs/OPERATIONS.en.md), [backup](docs/BACKUP_RESTORE.en.md), and [validation](docs/VALIDATION.md).
