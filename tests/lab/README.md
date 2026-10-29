# Isolated Ubuntu 24.04 installer lab

This lab boots an official, checksum-pinned Ubuntu 24.04 cloud image in QEMU. It does not use KVM, TAP, bridges, host firewall rules, host Docker, or production credentials. QEMU always uses TCG, two virtual CPUs, 3 GiB RAM, and a disposable qcow2 overlay. `smoke` keeps restricted user-mode networking with no guest outbound access. The other modes use user-mode NAT behind a fail-closed nftables policy allowing established SSH replies, slirp DNS, DHCP and public TCP ports 80/443, while rejecting private, metadata and other special-purpose destinations. The only inbound mapping is a checked random loopback TCP port forwarded to guest SSH.

## Prerequisites

Ubuntu host packages: `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`, `openssh-client`, `curl`, `shellcheck`, and Python 3 for the external controller. Every run requires an exact release archive containing the native host binaries. `smoke` makes no network requests and installs no packages; the full matrix needs guest package/image access. No ACME request is made: a local Certbot-compatible certificate generator issues lab certificates, with guest-only DNS.

## Commands

```bash
make lab-test       # host helper tests, Bash parse check, ShellCheck
make lab-prepare    # verify/download pinned base; create key, seed, overlay
make lab-start      # boot and wait for cloud-init/SSH readiness
make lab-smoke RELEASE_ARCHIVE=dist/proxy-control-vX.Y.Z.tar.gz RELEASE_SHA256=<sha256>
make lab-reset      # stop and create a fresh overlay/ephemeral key
make lab-full RELEASE_ARCHIVE=dist/proxy-control-vX.Y.Z.tar.gz RELEASE_SHA256=<sha256>
make lab-release RELEASE_ARCHIVE=dist/proxy-control-vX.Y.Z.tar.gz \
                 RELEASE_SHA256=<sha256> \
                 [LAB_SCENARIOS="audit plan"]
make lab-container RELEASE_ARCHIVE=dist/proxy-control-vX.Y.Z.tar.gz \
                   RELEASE_SHA256=<sha256> [LAB_SCENARIOS="audit plan"]
make lab-stop
make lab-clean      # remove all lab-created state; retain pinned base cache
```

Direct CLI equivalents are available through `python3 scripts/lab/qemu_lab.py {prepare,start,reset,run,stop,cleanup}`. `start` requires an explicit `--mode`; a disk may not change modes without `reset`. Add `cleanup --purge-cache` to delete the verified base image too. `run --output PATH` writes sanitized `report.json`, JUnit `report.xml`, and `guest.log` outside the guest. A failed full-mode package/network setup emits a named `environment-preflight` failure and marks every unstarted scenario missing. Any missing result, failed guest command, checksum mismatch, readiness timeout, or failed assertion exits nonzero.

## Modes and isolation

`smoke` verifies the source snapshot and the exact native release archive, checks the native CLI/version and manifest verifier, and proves malformed TOML is refused without changing an operator-owned fixture. It does not install the panel generation, install packages or use guest outbound access. Full audit/plan and DNS/TLS acceptance remain in `full` and `release-amd64`.

`full` runs the complete native release matrix: audit, plan, installation, repair, repeated-install idempotence, restart recovery, interrupted-journal recovery, uninstall twice, shared-443/3x-ui preservation, real protocol clients, image checks and secret scans. Interrupted native checkpoints are replayed through the real installer. Run `make lab-reset` before an independent validation.

The base cache is `${XDG_CACHE_HOME:-~/.cache}/mtproxy-installer-lab`. All mutable state and private ephemeral SSH keys are under ignored `.lab-state/`; reports are under ignored `lab-results/`. The private key is never attached as a VM drive and no production secret is embedded.

## Release acceptance

All three QEMU modes validate one exact release archive, not an interpreter from the checkout.
The tracked source snapshot supplies the harness and synthetic fixtures separately;
`LAB_RELEASE_ROOT` selects the extracted payload (default
`/tmp/proxy-control-release/proxy-control`). Tests and lab scripts are not user archive
members. Only the verified payload supplies the installer being tested. The controller refuses to start a run without `--release-archive` and `--release-sha256`, or when the digest differs. The guest checks the archive again and executes `installer/bin/linux-amd64/proxy-control-installer` from that release. `release-amd64` and `full` select the complete release matrix; `smoke` selects the non-installing subset.

Each architecture is pinned separately in `scripts/lab/image.json` (schema 2) with its official image URL, SHA-256, QEMU binary, machine, CPU, and minimum QEMU version. An architecture whose `sha256` is still `null` fails closed with a named error instead of trusting a download; record the official checksum from the `source_checksums` URL before using it. Both shipped architectures are pinned, and `test_an_unpinned_image_fails_closed` proves the refusal on a synthetic entry rather than by leaving a real one unpinned.

The release matrix (`qemu_lab.release_scenarios()`) covers a full install onto the coexistence topology the fixture builds - an existing shared-443 stream router and a foreign 3x-ui the installer adopts without touching. A `fresh` host and `managed-new` 3x-ui are not covered here: the fixture always installs a stream router, and `fresh` is refused against one. That mode has its own run instead, `scripts/lab/managed-xui-acceptance.sh`, which installs the pinned 3x-ui on a disposable server, drives the installer's own provisioning against it, and requires every promised inbound to be listening afterwards -- an inbound 3x-ui stores but Xray refuses to serve fails there, which is exactly the failure that path had. It refuses to run where a 3x-ui already exists and removes what it created; `KEEP=1` leaves the staged panel in place for inspection. The matrix deliberately does **not** run the second-client probes in
`tests/lab/clients/compose.yaml`. Each needs a pinned probe image implementing a
`--config … --expect-status` contract, and this project publishes none of them,
so listing those scenarios only made the gate unreachable. The protocols the
installer owns are proven inside `install-full-xui` by the installer's own
acceptance, with a real client for each: a TDLib `resPQ` exchange for MTProto,
an authenticated `CONNECT` with closed-tunnel accounting for NaiveProxy, and the
official Mieru client over every transport. 3x-ui's own protocols - VLESS
Reality TCP and XHTTP, Hysteria2 - are **not** client-tested by this matrix;
the separate gate below is pending native-stand execution. In `existing`
mode the installer only adopts and routes them.

The matrix includes coexistence with an existing 3x-ui and an ambiguous multi-map Nginx, real protocol clients for Telemt, Naive and Mieru, image verification, repair, idempotence, restart recovery, replay of each durable checkpoint phase, secret scans, DNS/TLS preflight, repeated uninstall, foreign-identity refusal and interrupted native uninstall recovery. VLESS TCP/XHTTP and Hysteria2 are not client-tested by this matrix, as described above.

### Pending managed 3x-ui real-client gate

Run this gate only on a **complete disposable managed-new installer topology**:
the installed shared-443 ingress must route VLESS TCP/XHTTP by SNI to the
provisioned 3x-ui loopback inbounds, UDP/443 must reach its Hysteria2 inbound,
`vless.lab.test`, `xhttp.lab.test` and `hy2.lab.test` must resolve to that
host, and the stand must have valid, trusted TLS material. Verify those facts
and retain the actual provisioned inbound credentials before preparing client
configs. `KEEP=1 scripts/lab/managed-xui-acceptance.sh` alone only stages 3x-ui
and checks listeners: it does **not** install shared ingress, DNS or client
trust, so it cannot satisfy this probe's prerequisites. On the complete stand,
run
`python3 scripts/lab/managed-xui-clients.py --manifest "$CLIENT_MANIFEST" --report "$CLIENT_REPORT"`.
The manifest is a root-only JSON
file on the disposable host; it names real Xray and Hysteria client executables
with full SHA-256 digests, and six root-only client configs. The executables
must be independently pinned for that run (the server's pinned Xray is not
automatically a client pin). Its shape is:

```json
{
  "xray": {"path": "/path/to/xray", "sha256": "<64 lowercase hex>"},
  "hysteria": {"path": "/path/to/hysteria", "sha256": "<64 lowercase hex>"},
  "cases": {
    "vless-tcp": {"positive": "vless-tcp.json", "negative": "vless-tcp-bad.json", "socks_port": 18080, "credential_path": "outbounds.0.settings.vnext.0.users.0.id"},
    "xhttp": {"positive": "xhttp.json", "negative": "xhttp-bad.json", "socks_port": 18081, "credential_path": "outbounds.0.settings.vnext.0.users.0.id"},
    "hysteria2": {"positive": "hysteria2.json", "negative": "hysteria2-bad.json", "socks_port": 18082, "credential_path": "auth"}
  }
}
```

Place root-owned mode-0600 JSON configs beside a root-owned mode-0600 manifest.
The official Hysteria client is a separate implementation from 3x-ui's bundled
Xray Hysteria2 server; interoperability is a stand prerequisite, **not** an
assumed property. Pin the exact client build and verify its CLI/config format.
For a local self-signed lab certificate, issue a SAN for `hy2.lab.test` from a
lab CA trusted by the Hysteria client; do not set `tls.insecure` or bypass
verification. The JSON Hysteria config must use that SNI and the trusted
system roots. Both Hysteria config variants must set top-level `"lazy": true`:
the official client otherwise authenticates eagerly and exits on the wrong
credential before opening its SOCKS listener, invalidating the negative
probe's live-listener control. A staging-only CN certificate is not sufficient
evidence.
The preflight rejects symlinks, other owners, group/world permissions,
unrelated routes, unexpected domains/ports, and any positive/negative change
other than the one supported credential field. Each pair must expose the same
loopback SOCKS5 port and target its provisioned `*.lab.test` inbound.
Xray is run as
`xray run -config FILE`; Hysteria is run as `hysteria client -c FILE`.
The gate runs positive → bad credential → positive for each protocol, POSTing
a fixed harmless payload through the SOCKS port to an ephemeral loopback echo
server. Both positives must return the exact payload and each must add one
echo hit; the negative must fail transfer, add no echo hit, and leave its
client and owned SOCKS listener alive. The SOCKS port must be free before launch
and its listener must belong to the spawned client process group. It terminates
the whole process group and echo server, even if the leader exits early. The
report contains booleans only, never config contents or credentials. Missing
binary, bad digest, config, curl, `ss`, or manifest is a failure, not a skip.
The report separates `positive_payload_before`, `negative_attempt`,
`positive_payload_after`, and `controlled_differential_denial` for each case;
`pass` means only all three **controlled differential client probes** passed.
The positive recheck controls for a transient outage, and config comparison
limits the negative to one syntactically valid wrong credential. It does not
assert that a server authentication log was observed: `server_auth_log_verified`
remains false. For full stand acceptance, correlate UTC time and inbound tag
with a secret-free 3x-ui server-side auth-denial event for each bad credential,
and show the intended inbound's per-client traffic counter (or equivalent
server-side trace) increased for the positive payload but not the negative.
If 3x-ui/Xray exposes no trustworthy denial event, record that evidence as
unverified rather than converting a curl error into server proof. Do not copy
credentials, links, full access logs or client configs into the report.
The operator must remove the staged 3x-ui or rotate every credential used
after the run. A prepared script alone is not protocol evidence: attach the
actual run results for the tested archive. A listener-only `managed-xui-acceptance.sh` success
does not satisfy this gate.

### Synthetic Fleet capacity measurement

`python3 scripts/lab/fleet-measure.py --nodes 40 --profile wan --seed 1`
produces a credential-free JSON model and exits nonzero when its policy fails.
`lan`, `wan` and `degraded` profiles state request/apply/retry latency ranges
in milliseconds in the report. `--failure-every N` injects a terminal failed
cycle (after one retry) at every Nth node. The model queues one cycle per node
at time zero against the Fleet pusher's eight shared slots and reports
nearest-rank p50/p95/max for cycle, queue, retry and successful convergence,
plus failure count. Policy inputs are `--max-p95-convergence-ms` (default
30000) and `--max-failures` (default zero). This is a deterministic sizing
model, **not** an HTTP/mTLS load test, heartbeat measurement, or proof of live
Fleet convergence. A native stand run must separately capture real per-node
enqueue/start/attempt/observed-generation timestamps, retries, failures and
the same distributions while checking the eight-slot active-cycle ceiling.

### Manual Telegram and coexist evidence

The TDLib `req_pq_multi` → `resPQ` probe proves an MTProto exchange, not that
the Telegram application can connect and use a proxy. On the disposable stand,
import one ephemeral `tg://` link into an actual Telegram mobile/desktop
client, record client/platform version, UTC start/end, whether proxy connection
shows connected, and whether a message/media request completes. Repeat with a
revoked link and record refusal. Keep screenshots cropped/redacted so no link,
secret, QR, account, chat content, or public node address enters the report;
store only pass/fail and timing in the shared evidence. Cleanup revokes the
ephemeral grant and removes it from the client.

For a foreign coexist frontend, inventory the actual 443 owner, stream maps,
trusted PROXY senders and the panel TLS backend before any change. The contract
is: PROXY is accepted only from a pinned loopback bridge; the bridge preserves
the original source address for the panel's PROXY-aware Unix TLS listener;
raw Telemt, Naive and 3x-ui TLS backends receive no PROXY header. Never trust
arbitrary `X-Forwarded-For` from the public socket. Verify with two distinct
test source addresses and a forged `X-Forwarded-For`, confirming the panel's
observed client IP follows the transport source, not the forged header. Check
each adjacent SNI before/after with a real TLS request and compare the foreign
route config digest. An unknown frontend or missing PROXY bridge is a manual
blocker; do not edit a foreign route to satisfy this checklist.

`--scenario NAME` (repeatable, or `LAB_SCENARIOS` through the Makefile) runs a subset. A filtered run is recorded as `filtered_scenarios` in the report and is only valid against what it declared: it can never stand in for a full release report. `qemu_lab.validate_report()` treats any required scenario missing from a full report as a failure even when the guest exits zero.

### First Rust-only update

The supported migration is `3.3.0 → 4.0` through the candidate's verified
`install-release.sh --update`, not through the old Python agent's UI update.
Keep the SHA-256-pinned candidate archive and a pre-update backup. Exercise hosts
both with and without an installer journal: replace and verify the Rust agent
before requesting the panel update, then check code, unit/tmpfiles and journal
ownership, retained operator settings, manager reconciliation and neighboring SNI.

The old UI update must fail closed without replacing the installed generation.
A wrong digest, missing agent binary, empty running image identity or unrelated
owned-file drift must also fail without rewriting ownership. Force a failed
handoff in a disposable host and verify the previous code, unit/tmpfiles and
journal are restored. Record native installer status and SQLite integrity before
and after repair; exercise uninstall and rollback in a separately reset run.
Then exercise a native `4.0 → 4.0.1` agent update. A healthy panel or the old
agent's `ready` state is not proof that any of these transitions passed.


`report.json` is schema 2 and records the mode, architecture, pinned image, source archive digest, release archive digest, and the plan digest the guest accepted, next to per-scenario results. `report.xml` and the sanitized `guest.log` are written beside it.

## Fixtures

- `tests/lab/fixtures/three-xui-existing.sh` materializes a foreign 3x-ui install - config with clients and a Reality private key, database, binary, and unit - which is hashed before and after the run to prove byte identity.
- `tests/lab/fixtures/nginx-multi-map.conf` provides an ambiguous shared-443 topology with two candidate stream maps; the installer must resolve it or refuse, never guess.
- `tests/lab/clients/compose.yaml` runs each protocol probe in its own read-only, capability-dropped container against the guest's synthetic DNS. Every probe image is a required pinned input, the ephemeral credentials are mounted read-only from the guest overlay, and only a status and a byte count are recorded.

## Bare-metal acceptance

`scripts/lab/guest-runner.sh host` runs the complete release matrix on a real
disposable server, with no QEMU and no nesting. It is the only mode that proves
the parts a container cannot: the fresh full install, real protocol clients,
`repair`, a repeated install, reboot recovery, a crash injected into a durable
phase, reporting, uninstall, and final coexistence.

```bash
LAB_RESET=1 bash scripts/lab/guest-runner.sh host "$RELEASE_SHA256"
```

`LAB_RESET=1` is the explicit opt-in that wipes installer-owned state,
identities, units, Compose objects and Nginx fragments before the run. **It
reinstalls the machine.** Run it only on a server you are willing to lose.

### How the lab gets its domains

No ACME request is ever made and no real domain is registered. The fixture
builds the whole naming layer itself, which is what makes the run repeatable:

- every name is a stub under `.lab.test` - `panel.lab.test`, `proxy.lab.test`,
  `naive.lab.test`, `mieru.lab.test`, `xui.lab.test`, `vless.lab.test`,
  `xhttp.lab.test`, `hy2.lab.test`, plus `old-xray.lab.test` as the adjacent
  foreign site;
- they are written into the host's `/etc/hosts` pointing at the host's own
  address, so local clients and probes resolve them;
- a dnsmasq instance answers the zone for real DNS queries with
  `address=/lab.test/<host address>`, which is what the installer's preflight
  actually asks. It sees an `A` record matching a local interface, no `AAAA`,
  and a `CAA` query that answers "no records" - exactly like a fresh domain.
  A preflight that cannot query `CAA` fails closed rather than assuming
  permission, so a resolver is mandatory, not a convenience. Names outside
  `lab.test` keep going to the host's original upstream resolvers, so package
  and image downloads still work;
- `write_fake_certbot` installs a deterministic Certbot-compatible generator: it
  creates a local CA, issues a leaf for the requested names, writes a complete
  `live`/`archive`/`renewal` lineage exactly where real Certbot would, and makes
  the CA trusted on the host. `certbot renew --dry-run` therefore succeeds for
  real, against a real lineage layout.

That is why the acceptance exercises the true certificate code path - grouping
by service, `--cert-name` lineages, `--webroot` per domain, and the renewal dry
run - without ever touching Let's Encrypt or a public DNS zone.

The adjacent foreign site is a real Nginx TLS vhost on `127.0.0.1:9443` behind
the shared router, so "every adjacent SNI still works" is checked against
something that actually terminates TLS.

## Container acceptance

`make lab-container` runs the part of the release matrix a disposable systemd
container can prove, on any machine with Docker and no QEMU at all. The base
image is pinned by digest, systemd is PID 1 so the installer drives real units,
and the verified release archive is the only installer input. The controller extracts
it under `/tmp/proxy-control-release/` and independently stages current tracked source
under `/tmp/mtproxy-source/`, excluding private state, caches, agents and the graph.
It runs that source-side `guest-runner.sh` with `LAB_RELEASE_ROOT` pointing at the
separate payload. Scenarios and synthetic fixtures never enter the user archive;
the exact installer bytes and release identity still come only from that archive.

It covers `environment-preflight`, `release-artifact-integrity`, `audit`,
`plan`, `nginx-multi-map`, `coexist-existing-xui`, `uninstall-foreign-identity`,
`dns-tls-preflight`, and `secrets-scan` against the coexistence topology: an
existing shared-443 stream router, a foreign 3x-ui hashed before and after, a
local resolver so the mandatory CAA query answers instead of failing closed, and
a deterministic Certbot-compatible generator.

It deliberately does not claim the scenarios that need nested Docker or public
network access - the fresh full install, the real protocol clients, the Docker
build, crash-every-phase, reboot recovery, and uninstall. Those stay with the
QEMU release modes. The report records `filtered_scenarios`, so
`qemu_lab.validate_report` treats a container run as the partial run it is: it
can never stand in for a full release report.

Reports go to ignored `lab-results-container/` in the same schema-2 shape as the
QEMU modes, carrying the release digest and the plan digest the guest accepted.
