# Interactive Release Installer Design

## Status

Approved design for a safe, interactive, release-distributed installer covering Proxy Control Core, NaiveProxy, Mieru, and optional 3x-ui coexistence or managed installation. Fleet mTLS remains a separate advanced procedure.

## Goal

A new operator must be able to install a supported Proxy Control profile on Ubuntu 24.04 from a verified GitHub Release without assembling long command lines or manually stitching together Compose overlays, host services, Nginx routes, certificates, and credentials.

The same engine must also integrate with an existing Nginx/3x-ui host without overwriting foreign state. Every mutating operation must be deterministic, journaled, resumable, secret-safe, and reversible within its declared ownership boundary.

Development and acceptance run only in disposable isolated environments. The production servers used to derive the reference topology are read-only design inputs and are not deployment targets for this work.

## Non-goals

- Fleet CA creation, enrollment, agent installation, or central ingress.
- DNS provider API integrations or storage of DNS API tokens.
- Automatic cloud-firewall changes.
- Automatic MSS clamping without the documented retransmission signature and explicit operator approval.
- Importing, copying, or exposing existing 3x-ui client credentials.
- Updating an existing 3x-ui installation as an implicit side effect of installing Proxy Control.
- Running mutable upstream `latest` scripts or `curl | sudo bash`.
- Supporting operating systems other than Ubuntu 24.04 in the first release.
- Pretending a partially configured component is installed successfully.

## Supported platforms

- Ubuntu 24.04 with systemd.
- Linux `amd64` and `arm64`.
- Root execution, entered through `sudo` from an interactive operator session or an explicit non-interactive invocation.
- Python from the Ubuntu base system; the installer user interface and plan parser use the standard library.

Unsupported OS, architecture, init system, or package manager is a hard stop before mutation.

## User experience

### Entry points

The release archive exposes one front door:

```text
sudo ./install.sh
```

With a TTY and no lifecycle arguments, this opens the wizard. Automation uses the same engine:

```text
sudo ./install.sh plan --config proxy-control.toml
sudo ./install.sh install --config proxy-control.toml --accept-plan <sha256>
sudo ./install.sh status
sudo ./install.sh repair
sudo ./install.sh uninstall
sudo ./install.sh upgrade plan --release-manifest <path>
```

Existing core lifecycle commands remain backed by the same internal model. The new wizard is not a second installer and does not shell out to the legacy installer as a black box.

### Wizard stages

1. Select language, defaulting from `LANG`; Russian and English are first-class.
2. Explain release verification and confirm that the archive passed checksum and provenance verification.
3. Audit OS, architecture, privileges, disks, memory, network, package manager, services, listeners, Nginx, Docker, firewall, certificates, DNS, and existing Proxy Control/3x-ui state.
4. Select host mode: `fresh` or `coexist`.
5. Select Proxy Control profile.
6. Select 3x-ui mode.
7. Enter all required domains, ports, ACME email, initial safe usernames, and optional WARP policy.
8. Display required DNS and cloud-firewall actions. Recheck until they pass or the operator exits without mutation.
9. Render a secret-free deterministic plan.
10. Show an explicit mutation and rollback summary.
11. Require confirmation of the plan digest.
12. Apply with phase checkpoints and live, secret-free progress.
13. Run component acceptance and reboot-persistence checks.
14. Write a sanitized report and a separate root-only credential handoff.

Back, edit, save-config, and quit-without-changes are available before apply. There is no generic "continue anyway" for hard stops.

### Configuration file

The wizard exports versioned TOML because Ubuntu 24.04 Python can parse it with `tomllib`, it supports comments, and it avoids an additional YAML dependency. The config is declarative and contains no generated credentials.

Illustrative shape:

```toml
schema = 1
host_mode = "fresh"
profile = "full"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"
naive = "edge.example.com"
mieru = "mieru.example.com"

[mieru]
tcp_ports = [46001]
udp_ports = [46001]

[three_xui]
mode = "managed-new"
panel_domain = "xui.example.com"
vless_tcp_domain = "vless.example.com"
vless_xhttp_domain = "xhttp.example.com"
hysteria_domain = "hy2.example.com"
warp = false
warp_domains = []

[firewall]
manage_ufw = true
```

Unknown keys, missing required keys, duplicate incompatible domains, unsafe names, relative paths, invalid ports, and fields that do not apply to the selected profile are rejected. The normalized configuration is included in the plan without secrets.

## Profiles and component matrix

### Proxy Control profiles

| Profile | Core | Naive | Mieru |
|---|---:|---:|---:|
| `core` | yes | no | no |
| `core-naive` | yes | yes | no |
| `core-mieru` | yes | no | yes |
| `full` | yes | yes | yes |

Core means Telemt/MTProxy plus the Proxy Control panel. Optional Compose overlays are selected from the typed profile, not a free-form `COMPOSE_FILE` supplied by the operator.

### 3x-ui modes

| Mode | Behavior |
|---|---|
| `none` | No 3x-ui/Xray mutation or route creation. Existing unrelated state is still protected by collision checks. |
| `existing` | Discover and validate an installed 3x-ui/Xray topology, preserve its database/configuration/clients, and add only explicitly selected SNI routes. |
| `managed-new` | Install the release-pinned stable 3x-ui asset and create the supported reference inbounds and routing policy. Refuse if an existing installation is detected. |

3x-ui mode is independent from the Proxy Control profile to avoid a combinatorial list of profile names.

## Domain and certificate model

The wizard collects every domain needed by the selected profile and renders a table with these columns:

```text
domain | component | public transport/port | local backend | TLS/Reality | certificate owner
```

Required inputs are:

- Proxy Control panel domain.
- Telemt/MTProxy Fake-TLS domain.
- Naive domain when Naive is enabled.
- Mieru hostname and explicit TCP/UDP listeners when Mieru is enabled.
- 3x-ui panel, VLESS Reality TCP, VLESS Reality XHTTP, and Hysteria2 domains for `managed-new`.
- A repeatable explicit `domain -> loopback backend` selection for `existing` 3x-ui and preserved adjacent routes.

Incompatible services cannot claim the same TCP SNI domain. Hysteria2 on UDP/443 may share a DNS hostname with a TCP service because the listener transport differs. A Mieru hostname on dedicated ports may reuse an existing hostname after explicit validation.

The preflight checks:

- normalized DNS names and duplicates;
- A records reaching a local public address;
- AAAA records reaching a handled local IPv6 address, otherwise a hard stop;
- CAA compatibility with the selected ACME issuer;
- direct DNS rather than a CDN proxy for raw MTProto and other incompatible protocols;
- required TCP/UDP reachability where it can be observed safely;
- local listener and backend-port collisions;
- existing certificate SANs, expiry, key permissions, renewal configuration, and ownership.

DNS is never changed. The wizard prints the exact required records and waits for strict validation.

Certificate boundaries are per terminating service so one unrelated SAN cannot break renewal for the full stack. Reality inbounds do not require certificates. Hysteria2, Naive, Proxy Control panel/cover, and a published 3x-ui panel each receive an explicit certificate plan. Existing foreign certificates are reused only when ownership and renewal paths are proven; otherwise the installer stops rather than replacing them.

## Architecture

### Package structure

The installer becomes a focused Python package rather than adding more responsibilities to one large module:

```text
installer/
  cli.py
  model.py
  config.py
  wizard.py
  audit.py
  planner.py
  transaction.py
  release.py
  report.py
  adapters/
    packages.py
    nginx.py
    firewall.py
    core.py
    naive.py
    mieru.py
    three_xui.py
```

`scripts/proxyctl.py` delegates lifecycle operations to these typed modules as functionality is migrated. Existing durable filesystem primitives and ownership semantics are reused. There is one transaction engine, one plan model, and one state schema.

Every adapter implements the same conceptual boundary:

```text
audit() -> facts
plan(facts, config) -> ordered secret-free actions
apply(action, transaction) -> checkpoint
verify(expected) -> evidence
rollback(checkpoint) -> restored evidence
```

Adapters cannot directly mutate another adapter's owned paths. Cross-component dependencies are explicit plan edges.

### Deterministic plan

The normalized config plus audit facts produce a plan with:

- schema and release identity;
- exact component versions and artifact digests;
- packages to install and package ownership;
- files, directories, users, groups, units, containers, volumes, listeners, routes, certificates, and firewall rules to create or preserve;
- ordered apply and rollback actions;
- acceptance commands and expected observations;
- warnings and hard stops;
- a SHA-256 over canonical JSON.

The same config and equivalent audit facts produce the same plan digest. Apply refuses a stale plan when relevant host facts have changed.

### Transaction state

Private state lives under `/var/lib/proxy-control/installer/` with root-only permissions:

- normalized secret-free config;
- canonical plan and digest;
- release manifest and digest;
- phase journal;
- ownership manifest;
- backup-generation metadata;
- sanitized acceptance report;
- root-only generated credential handoff.

Each mutation has a durable precondition snapshot, ownership assertion, apply checkpoint, verification result, and inverse action. State is fsynced before the next mutation. A global operation lock prevents concurrent install, repair, upgrade, and uninstall.

On startup:

- `active` verifies and repairs only owned runtime state;
- `installing` resumes from the last committed checkpoint;
- `rollback_required` continues rollback;
- `uninstalling` continues uninstall with the original data-retention policy;
- a plan/config/release mismatch is a hard stop.

## Fresh-host behavior

Fresh mode requires a host without conflicting managed state. It:

1. Installs only missing supported packages.
2. Creates a Proxy Control-owned Nginx stream listener on TCP/443 and one owned SNI registry.
3. Creates HTTP-01 webroots and service-specific certificates.
4. Installs selected host services and Compose components.
5. Creates only the firewall rules required by the selected profile.
6. Runs full acceptance before committing the transaction.

UFW management is allowed only in fresh mode. The plan discovers the active SSH listener, preserves existing rules, adds narrowly scoped rules with ownership comments, and never changes the default policy or disables another firewall. It refuses to apply if the SSH preservation rule is ambiguous. Cloud firewall changes remain an explicit external prerequisite.

The MSS clamp is not a normal fresh-profile rule. It is a separate post-install diagnostic action requiring observed Send-Q/cwnd/retransmission/RTO evidence, a tested reduced MSS, and a second explicit confirmation.

## Coexistence behavior

Coexistence mode never modifies UFW/nftables/iptables. It audits:

- effective Nginx configuration from `nginx -T`;
- the active TCP/443 listener owner;
- stream listener, `proxy_pass` variable, and the map that supplies it;
- every included file and duplicate domain;
- existing Xray/3x-ui inbounds and loopback backends;
- Docker Compose projects, systemd units, certificates, and local ports.

It supports several independent Nginx maps. It does not assume there is exactly one map in the entire configuration. A new route is allowed only when the active 443 data path resolves to exactly one editable ownership target and the requested domain has no effective collision. This covers complex hosts while preserving fail-closed behavior.

Before mutation, coexistence captures a private generation of affected Nginx files with owner, group, mode, inode/symlink identity, hash, and validated restore command. Existing 3x-ui database, generated Xray config, client state, and service files are hashed before and after Proxy Control installation and must remain unchanged unless the operator separately selects an explicit 3x-ui upgrade transaction.

## Managed 3x-ui

### Artifact policy

A Proxy Control release pins the newest reviewed stable 3x-ui release available when that Proxy Control version is cut. At design time this is 3x-ui `3.7.0`. Runtime resolution of `latest`, development releases, and mutable branch scripts is forbidden.

The release manifest records, per architecture:

- upstream repository and tag;
- official asset URL;
- GitHub release asset digest;
- reviewed SHA-256;
- expected binary version;
- expected archive layout;
- license metadata.

The installer downloads to a private staging directory, verifies the digest before extraction, rejects absolute paths, `..`, device nodes, setuid/setgid files, links escaping staging, duplicate paths, and unexpected owners/modes, then verifies the executable version and expected layout. The upstream installer script is not executed.

### Installation and configuration

The 3x-ui panel binds to loopback. Random admin credentials and web path are generated without entering argv, environment logs, terminal echo, or the secret-free plan. The official local CLI is used for supported panel settings.

The pinned local authenticated API creates:

- internal API inbound;
- VLESS with Reality over TCP on a loopback backend;
- VLESS with Reality over XHTTP on a separate loopback backend;
- Hysteria2 with TLS on public UDP/443;
- `direct` and `blocked` outbounds;
- rules blocking private destinations and BitTorrent;
- optional WARP outbound and an operator-confirmed domain list.

Generated client UUIDs, passwords, Reality key pairs, short IDs, transport paths, and Hysteria credentials are unique. The API request body is written to a private file or stdin, never passed in argv. Direct edits to the 3x-ui SQLite database are forbidden.

Effective `/usr/local/x-ui/bin/config.json` is inspected after 3x-ui generates it. Acceptance verifies protocol, listen address, port, transport, security, Reality server name/target, TLS certificate paths, sniffing policy, routing order, and outbound tags without serializing client secrets.

At least one persistent initial operator client is created for each managed inbound and delivered through the root-only handoff. Acceptance uses separate temporary clients and removes them after testing.

### Existing 3x-ui

Existing mode is read-only with respect to 3x-ui. It displays secret-free inbound facts and lets the operator select eligible loopback backends for SNI routing. It never reads or exports client credentials.

Version drift is reported. An optional `upgrade existing 3x-ui` is a separate explicit lifecycle transaction with its own plan, full database/binary/unit backup, upstream digest verification, migration rehearsal against a copy, restart, protocol acceptance, and rollback constraints. It is not implicitly coupled to Proxy Control installation because database migrations may not be backward-compatible with the previous binary.

## Naive and Mieru integration

Naive installation automates the current split identities, fixed-ID collision checks, manager state, token generation, log permissions, pinned Caddy build verification, systemd unit, bootstrap-only manager pass, Caddy reload, full Compose overlay, authenticated CONNECT, and accounting check. It refuses recursive ownership changes on restored non-empty state.

Mieru installation pins the supported `mita` artifact by architecture and digest, creates the non-login identity and stable UDS directory, creates one valid bootstrap generation, installs the token/state boundaries, starts the manager overlay, and validates exact RUNNING status plus official-client data transfer over the configured listener. Empty/zero-user configurations are forbidden.

The full profile renders one canonical Compose file list for Core, Naive, and Mieru. It never depends on an interactive shell's exported environment. A root-only generated environment file provides only non-secret runtime paths and public hostnames; secret values remain files.

## Release distribution and trust

### Release assets

Each `vX.Y.Z` GitHub Release contains:

```text
proxy-control-vX.Y.Z.tar.gz
proxy-control-vX.Y.Z.sha256
proxy-control-vX.Y.Z.spdx.json
release-manifest.json
install-bootstrap
GitHub artifact provenance attestation
```

The source archive contains tracked release files only. It excludes Git metadata, ignored files, local environment files, secrets, runtime state, caches, reports, and lab disks. Archive order, uid/gid, mode, and mtime are normalized from the release commit and `SOURCE_DATE_EPOCH`, allowing reproducibility checks.

The manifest records the Proxy Control tag and commit, installer/config/state schemas, supported platforms, internal file digests, container image digests, external artifact pins, upstream URLs, and license identifiers.

3x-ui, mita, and other external GPL artifacts are not redistributed inside the MIT source archive. They are downloaded from their official versioned release locations and verified against the release manifest.

### Verification path

The primary documentation does not use `curl | sudo bash`. The supported flow is:

1. Download the selected version's archive, checksum, manifest, bootstrap, and provenance from GitHub Releases.
2. Verify the GitHub artifact attestation against `dubr1k/proxy-control` and the release workflow identity.
3. Verify the SHA-256 file.
4. Run bootstrap as root; bootstrap independently rechecks archive/manifest identity and safe extraction.
5. Enter the wizard.

A convenience downloader may resolve the newest stable release for an unprivileged download, but it must display and pin the resolved version before privilege escalation. It may not execute bytes from `main`, silently follow a prerelease, or bypass provenance verification.

### Release workflow

The release workflow uses minimal permissions, pinned actions, an approval-protected release environment, and separate build/attest/publish jobs. It verifies tag/version/commit consistency, builds reproducible assets twice, compares their hashes, generates SBOM and checksums, attests the exact assets, uploads a draft release, and publishes only after all required gates succeed.

The workflow must not contain production credentials, SSH keys, or deployment steps. A release is tested by installing its archive, not by mounting the repository working tree.

## Isolated verification strategy

### TDD and local gates

Implementation follows red-green-refactor for every observable contract. Tests cover:

- TOML schema and profile-dependent fields;
- wizard transcripts through a pseudo-terminal;
- secret-free canonical plans and stable digests;
- changed-fact stale-plan rejection;
- path, archive, symlink, hardlink, ownership, and permission attacks;
- adapter ownership boundaries;
- checkpoint/resume/rollback at each phase;
- Nginx effective-map selection and ambiguity;
- UFW ownership and SSH preservation;
- 3x-ui release manifest and API payload generation without secrets in diagnostics;
- deterministic release packaging and provenance inputs.

Repository gates include Ruff, pytest/unittest, Bash parse, ShellCheck, document-link checking, Compose render/build checks, container health, and secret scans.

### Disposable VM matrix

The existing checksum-pinned Ubuntu 24.04 QEMU lab is extended. It uses disposable qcow2 overlays, loopback-only host port forwarding, synthetic DNS/ACME, no production credentials, and no host firewall or Docker mutation.

Required scenarios include:

- fresh and coexistence;
- every Proxy Control profile;
- no 3x-ui, managed-new 3x-ui, and existing 3x-ui;
- amd64 and arm64;
- one Nginx map, several unrelated maps, preserved adjacent SNI routes, duplicate domains, ambiguous include graphs, and a non-Nginx TCP/443 owner;
- valid and invalid A/AAAA/CAA, occupied ports, missing UDP exposure, unavailable ACME/GitHub, truncated downloads, wrong digests, and corrupt archives;
- failure injection after every durable phase;
- SIGKILL, SSH loss, reboot, disk-full simulation, Compose/systemd/Certbot failure, repeated install, repair, uninstall, and rollback;
- byte-identical foreign Nginx/3x-ui state in coexistence;
- secret absence from argv, process listings, environment dumps, logs, reports, plans, archives, and CI artifacts.

### Protocol acceptance

The release candidate must pass real protocol behavior in the isolated lab:

- Telemt Fake-TLS/Obfuscated2 `req_pq_multi -> resPQ` plus a client session;
- Naive TLS and authenticated CONNECT, known payload transfer, connection closure, and accounting observation;
- official Mieru client using a full Native configuration, SOCKS request, and HTTP 204 over configured TCP and UDP listeners;
- VLESS Reality TCP, VLESS Reality XHTTP, and Hysteria2 TLS with compatible disposable clients;
- Proxy Control HTTPS health, login, authorization, test-user creation, rotation, and deletion;
- adjacent SNI probes before install, after install, after repair, after reboot, and after uninstall.

Acceptance clients and credentials are ephemeral and destroyed with the VM.

### Release gate

A release is not publishable until the exact release archive completes:

```text
verify -> install -> protocol acceptance -> reboot -> status/repair
-> repeated install -> interrupted recovery -> uninstall -> foreign-state comparison
```

A failed scenario blocks publication. Fixes require a new release candidate and a complete rerun of affected unit/integration gates plus the full release lifecycle matrix. Production servers are never used as a substitute for an isolated acceptance pass.

## Documentation deliverables

Russian and English documentation must include:

1. Verified GitHub Release download and attestation.
2. Five-minute wizard quick start.
3. Screen-by-screen wizard reference.
4. Complete TOML schema with one example per profile and 3x-ui mode.
5. Domain, DNS, CAA, certificate, TCP/UDP, UFW, and cloud-firewall tables.
6. Fresh-host and coexistence architecture, including multiple Nginx maps.
7. Managed and existing 3x-ui procedures and version policy.
8. Backup inventory and restore generation boundaries.
9. Failure recovery, repair, upgrade, rollback, and uninstall.
10. Per-protocol acceptance and troubleshooting.
11. Security assumptions, secret handling, ownership, and non-goals.
12. Fleet and diagnostic-only MSS clamp links.

Commands in documentation are executed in the isolated lab. Example domains and credentials are synthetic. Each document states which steps are read-only, mutating, destructive, or external.

## Compatibility and migration

Existing installations remain valid. The first new installer release imports the current `/var/lib/proxy-control/runtime.json` and ownership manifest only after validating their exact schemas and hashes. Import writes a new installer state generation without rotating credentials or changing routes.

Existing `install.sh` flag-based Core automation remains a supported front end to the same typed plan during the migration window. It does not retain a second implementation path. Existing Compose project name, volume names, container names, fixed identities, service/unit names, and documented paths remain compatible unless a future versioned migration explicitly changes them.

Existing 3x-ui installations are always treated as foreign in `existing` mode. A managed-new installation is owned by Proxy Control from its first staged artifact and records every installed path.

## Completion criteria

The feature is complete only when:

- wizard and TOML modes produce the same canonical plan;
- all selected profiles install end to end from a verified release archive;
- all required domains are collected and strictly validated;
- managed-new 3x-ui creates working VLESS Reality TCP, VLESS Reality XHTTP, and Hysteria2 inbounds using the release-pinned newest reviewed stable version;
- existing 3x-ui and adjacent Nginx routes remain unchanged outside the explicit owned route block;
- no secret appears in non-secret state or diagnostic surfaces;
- every failure-injection phase resumes or rolls back deterministically;
- fresh UFW rules are ownership-scoped and coexistence never mutates firewall;
- reboot, repair, repeated install, upgrade planning, uninstall, and data-preservation behavior pass;
- amd64 and arm64 isolated acceptance pass;
- the exact reproducible release assets pass checksum, SBOM, and provenance verification;
- complete Russian and English instructions have been executed against the release candidate in the isolated lab;
- no production host is changed during development or acceptance.
