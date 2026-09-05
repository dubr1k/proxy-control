# Interactive release installer reference

[Русский](INSTALLER_REFERENCE.ru.md) · **English**

This is the complete reference for the typed release installer: the release you
verify, the wizard you answer, the configuration it writes, the plan it derives,
the boundaries it owns, and the evidence it produces. Every command block marked
`installer-check` is executed against the shipped argument parser and
configuration loader by `tests/test_installer_docs.py`, so nothing here can
drift from the code.

The installer never installs from a working tree. It installs from a built,
checksummed release that carries its own identity at `release/release.json`.

## Verifying a release

Download the archive, its `SHA256SUMS`, and `release-manifest.json` from the
release page, then verify provenance before anything runs with privilege.

```bash installer-check
gh attestation verify proxy-control-v0.1.0.tar.gz --repo dubr1k/proxy-control
sha256sum --check --ignore-missing SHA256SUMS
./install-bootstrap --archive proxy-control-v0.1.0.tar.gz --checksum SHA256SUMS --manifest release-manifest.json
```

`install-bootstrap` refuses to run as root. Before its single `exec sudo` it
checks that every input is a regular file you own and that is not
group- or other-writable, compares the archive against the published checksum,
requires the manifest to name the same archive and digest, refuses a prerelease
version, and preflights the archive for absolute or escaping members. It never
downloads and executes in one step.

`release-manifest.json` records the archive name and digest, the commit, the
external artifact manifest digest, the file count, and the tag. `sbom.spdx.json`
lists every packaged file with its SHA-256 and every pinned external artifact
with its licence.

The build is reproducible: the release workflow builds the same commit twice and
refuses to continue unless the bytes match. Rebuilding that commit on Ubuntu
24.04 reproduces the published archive digest exactly, because every member
carries uid/gid 0, the mode from the git executable bit, and the commit
timestamp. The gzip container around the archive is produced by the local zlib,
so a system with a different zlib version yields a different `.tar.gz` digest
even though the archive contents are identical - which is why a download is
verified against the published `SHA256SUMS` and the attestation.

## Interactive wizard

With no arguments the installer starts the bilingual wizard:

```bash installer-check
python3 -m installer.cli wizard --lang en --config-output proxy-control.toml
```

The wizard asks, in order: language, host mode, profile, every required domain,
the ACME e-mail, the initial panel user, Mieru listeners when the profile
includes Mieru, the 3x-ui mode and its domains, whether WARP is enabled and for
which domains, and whether the installer manages UFW. It writes the answers to a
TOML file, renders the plan, and asks you to confirm the first twelve characters
of the plan digest before anything is mutated. Quitting at any prompt leaves the
host untouched.

## Commands

| Command | What it does |
| --- | --- |
| `wizard` | Ask the questions, write the configuration, show the plan, apply it after digest confirmation |
| `plan` | Audit the host and render the deterministic plan; mutates nothing |
| `install` | Apply a plan whose complete digest you pass to `--accept-plan` |
| `status` | Print the sanitized transaction state |
| `resume` | Continue an interrupted transaction from its durable journal |
| `repair` | Re-verify owned files and restart the owned runtimes |
| `report` | Write the public acceptance report and the root-only credential handoff |
| `uninstall` | Remove the owned generation; `--purge-data` also removes persistent state |

```bash installer-check
python3 -m installer.cli plan --config examples/installer/full-three-xui.toml --json
python3 -m installer.cli status --json
python3 -m installer.cli report --config examples/installer/full-three-xui.toml --output /var/lib/proxy-control/reports
```

`plan` is read-only. `install` refuses a digest that does not match the plan it
just derived, so an approved plan cannot be swapped for another.

## Configuration file

```toml
schema = 1
host_mode = "fresh"        # fresh | coexist
profile = "full"           # core | core-naive | core-mieru | full
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"
naive = "edge.example.com"     # required by core-naive and full
mieru = "mieru.example.com"    # required by core-mieru and full

[mieru]                        # only with a Mieru profile
tcp_ports = [46001]
udp_ports = [46001]

[three_xui]
mode = "managed-new"           # none | existing | managed-new
panel_domain = "xui.example.com"
vless_tcp_domain = "vless.example.com"
vless_xhttp_domain = "xhttp.example.com"
hysteria_domain = "hy2.example.com"
warp = false
warp_domains = []

[firewall]
manage_ufw = true
```

`schema` is the integer `1`. `host_mode` selects a fresh host or coexistence
with an existing shared-443 Nginx router. `initial_user` is the first panel
owner and the Mieru bootstrap user, so it must be a safe name. Under
`three_xui`, `mode = "none"` accepts no other key, `existing` accepts only the
domains you want routed, and `managed-new` requires all four domains plus `warp`
and `warp_domains`. `warp_domains` without `warp = true` is rejected.
`manage_ufw` only takes effect on a fresh host.

## Profiles and examples

Every profile is a prefix of the same order, and unsupported combinations are
rejected rather than silently reduced.

```toml
profile = "core"        # Telemt/MTProto and the panel
profile = "core-naive"  # plus NaiveProxy behind the private Caddy listener
profile = "core-mieru"  # plus Mieru/mita on its own TCP and UDP listeners
profile = "full"        # Telemt, panel, NaiveProxy, and Mieru together
```

Ready-made examples live in `examples/installer/`:

```bash installer-check
python3 -m installer.cli plan --config examples/installer/core.toml --json
python3 -m installer.cli plan --config examples/installer/core-naive.toml --json
python3 -m installer.cli plan --config examples/installer/core-mieru.toml --json
python3 -m installer.cli plan --config examples/installer/existing-three-xui.toml --json
```

Managed 3x-ui publishes three reference inbounds: **VLESS Reality TCP** and
**VLESS Reality XHTTP** on loopback backends behind the shared 443 router, and
**Hysteria2** over TLS on public UDP/443 with its own certificate. Each gets
freshly generated Reality keys, short IDs, and client credentials; nothing is
copied from a reference server.

## Ownership boundaries and order

The plan runs adapters in one documented order, and each owns exactly one
boundary:

| Adapter | Owns |
| --- | --- |
| `packages` | Only the exact package selections it had to install on a fresh host |
| `nginx` | One owned block inside the selected shared-443 route file |
| `certificates` | The owned HTTP-01 vhosts and the per-service Certbot lineages |
| `firewall` | Only the UFW rules it added, and only on a managed fresh host |
| `core` | The `mtproxy` Compose project, its secrets, and the pinned TDLib probe |
| `naive` | The pinned Caddy build, split identities, manager state and token, the accounting log boundary, and the Naive route |
| `mieru` | The pinned mita executable, the mita identity and stable UDS, manager token and state, and the selected listeners |
| `three_xui` | Nothing in `existing` mode beyond the owned route; one staged generation in `managed-new` |

Each action is applied through a durable journal: prepare, apply, verify. An
interrupted step is resumable, and every adapter's inverse restores what it
found.

## Acceptance per protocol

A healthy process is not a protocol test. The installer accepts a generation
only on end-to-end evidence:

- **Core**: Compose model, every health check, panel health and an HTTPS
  authenticated session, Telemt management API private to Compose, a validated
  `resPQ` for every temporary MTProto credential, adjacent SNI routes, and a
  bounded secret scan.
- **NaiveProxy**: the Caddy Admin API and the private listener both loopback
  only, public cover HTTPS without credentials, one authenticated `CONNECT`
  carrying a known payload, a closed tunnel, a closed-tunnel accounting delta at
  least as large as the payload, manager and panel health, adjacent SNI, and the
  accounting log boundary.
- **Mieru**: both pinned digests, the exact `mita server status is "RUNNING"`
  output, the `0770` management socket, one official-client SOCKS request per
  enabled transport family, a drained send queue, manager and panel health, and
  untouched adjacent listeners.
- **3x-ui**: the staged binary reports the pinned version, and the effective
  generated configuration matches the templates.

Every acceptance run creates temporary credentials and removes them. A failed
cleanup is reported and stays retryable rather than being silently dropped.

## WARP and egress

WARP is one loopback **SOCKS5** endpoint at `127.0.0.1:45000`. The installer
never provisions WARP itself; it wires the protocols to it when you enable it.

The split is deliberate and differs per protocol:

- **Xray / 3x-ui** routes **only the selected traffic** through WARP. The rules
  are keyed to `warp_domains`, everything else stays direct, and the mandatory
  final policy is appended after them, never replaced.
- **NaiveProxy** sends **all** tunnelled traffic through WARP. There is no
  per-domain split: the managed `forward_proxy` block gets
  `upstream socks5://127.0.0.1:45000`.
- **Mieru** sends **all** traffic through WARP as well, as a single
  all-domain/all-IP egress rule that names the WARP proxy.

With `warp = false` no WARP outbound, upstream, or rule is emitted anywhere, and
Mieru's egress rule stays `DIRECT`.

## Hard stops

The audit refuses to plan rather than guess. A hard stop is reported and nothing
is mutated:

- AAAA records pointing outside addresses this host handles;
- CAA records that do not authorize Let's Encrypt over HTTP-01;
- an ambiguous shared-443 Nginx topology, or a fresh-mode host that already runs
  a stream router;
- a public listener already claimed by another service;
- a foreign holder of a reserved UID or GID (`10002`, `10003`, `10005`, and the
  groups `101`, `10004`, `10005`);
- a pre-existing x-ui database, binary tree, unit, service user, or listener in
  `managed-new` mode;
- an artifact whose digest does not match its pin.

## Recovery, repair, rollback, and uninstall

```bash installer-check
python3 -m installer.cli status --json
python3 -m installer.cli resume --json
python3 -m installer.cli repair --json
python3 -m installer.cli uninstall --json
```

`resume` continues from the durable journal and performs each committed
mutation exactly once. `repair` re-verifies every owned file against its
recorded digest and refuses to continue when one has drifted. `uninstall`
removes only the owned generation and preserves credentials, manager state, and
named volumes; `--purge-data` is the explicit opt-in that also removes them and,
for Naive and Mieru, the identities the installer itself created.

## Reports and credential handoff

`report` writes two documents with disjoint schemas:

- `report.json`, mode `0644`, carries only named acceptance facts from an
  allowlist: health state, response status, byte counts, versions and digests,
  listener owners, certificate SANs, and route results. It refuses to name or
  describe a credential at all, and any fact outside the allowlist is dropped
  rather than summarized.
- `credentials/handoff.json`, mode `0600` inside a `0700` directory, carries the
  credentials the installation produced. The public report never links, quotes,
  or summarizes it.

## Upgrading an existing 3x-ui

An existing 3x-ui is never upgraded as part of a normal install. That is a
separate, explicitly invoked transaction: it requires the complete recorded byte
identity of the installation, snapshots the database, binary tree, and unit as
one generation, rehearses the new binary's migration against a private database
copy before the live database is touched, and restores the whole generation on
any late failure, failing closed unless the restored install is byte-identical
again.

## Release acceptance lab

Two disposable labs validate a release candidate. Neither uses production
credentials, DNS, or SSH keys.

```bash
make lab-release RELEASE_ARCHIVE=dist/proxy-control-v0.1.0.tar.gz RELEASE_SHA256=<sha256> LAB_ARCH=amd64
make lab-container RELEASE_ARCHIVE=dist/proxy-control-v0.1.0.tar.gz RELEASE_SHA256=<sha256>
```

The QEMU lab boots a checksum-pinned Ubuntu image and runs the full release
matrix. The container lab runs the part a disposable systemd container can prove
and records which scenarios ran, so a partial run can never stand in for a full
release report. Details: [tests/lab/README.md](../tests/lab/README.md).

## Limits

- Fleet v1 works with Telemt only. It neither declares nor accepts Naive, Mieru,
  or 3x-ui lifecycle operations.
- Per-user Mieru accounting is deliberately reported as unavailable; the quota
  is a rolling admission check, not a billing counter.
- The Mieru MSS clamp is a diagnostic-only host firewall change. The installer
  never enables it.
- The installer does not provision WARP, and it does not manage DNS.
