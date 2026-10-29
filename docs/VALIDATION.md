# Validation gates

## Required repository gates

Run native builds and runtime checks on the disposable Ubuntu host, not a production node.
The commands below assume its root shell: the installer ownership tests intentionally
require real root permissions. Python is the external controller only.

```sh
set -Eeuo pipefail
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$PWD/target"
cargo install cargo-audit --version 0.22.2 --locked
for crate in pc_common pc_host installer_core installer version_agent deploy/mieru-client \
  xray_router_manager naive_manager mcp_server mieru_manager awg_manager trusttunnel_manager panel; do
  cargo audit --file "$crate/Cargo.lock" --deny warnings
  cargo fmt --manifest-path "$crate/Cargo.toml" --all --check
  cargo clippy --manifest-path "$crate/Cargo.toml" --workspace --all-targets --locked -- -D warnings
  cargo test --manifest-path "$crate/Cargo.toml" --workspace --locked
done
cargo build --manifest-path panel/Cargo.toml --locked -p panel-web --features test-hooks
cargo build --manifest-path installer/Cargo.toml --locked --bin proxy-control-installer
cargo build --manifest-path version_agent/Cargo.toml --locked --bin proxy-control-version-agent
install -D -m 0755 "$CARGO_TARGET_DIR/debug/proxy-control-installer" installer/bin/linux-amd64/proxy-control-installer
install -D -m 0755 "$CARGO_TARGET_DIR/debug/proxy-control-version-agent" version_agent/bin/linux-amd64/proxy-control-version-agent
docker build -f panel/Dockerfile -t mtproxy-panel:latest .
docker build -f mieru_manager/Dockerfile -t mtproxy-mieru-manager:latest .
docker build -f xray_router_manager/Dockerfile -t mtproxy-xray-router:latest .
PANEL_IMPL=rust PANEL_RUST_BIN="$CARGO_TARGET_DIR/debug/panel" .venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
python3 scripts/check-doc-links.py
bash scripts/dev/check-js-syntax.sh
```

The container permission probes accept `PANEL_TEST_IMAGE` and `MIERU_TEST_IMAGE`.
Point them at isolated candidate tags built from the extracted archive; do not replace
running-node image aliases just to satisfy the tests. The defaults remain the documented
local test tags above. Run detached test controllers with SIGHUP restored to its default
handler after `nohup`: POSIX shell fixtures cannot trap a signal inherited as ignored.

CI renders every supported Compose overlay against synthetic inputs, including MCP, Xray-router, AmneziaWG and TrustTunnel; the retired Fleet v1 agent and mTLS ingress are not built or rendered. CI builds the Rust panel, Naive/Mieru managers, MCP and Xray-router images, checks the pinned Caddy+forward-proxy artifact and a negative fixture, verifies service units on the ephemeral runner, and enforces diff hygiene and third-party notices. The Python external black-box suite runs against a Rust panel executable (`test-hooks`) and fails the gate on any deselected or skipped test. The independent dependency gate installs `cargo-audit` version `0.22.2` from crates.io with `--locked` and audits **every** shipped native `Cargo.lock` against RustSec; no Python panel or MCP runtime requirements are audited.

The installer unit suite's deliberately ignored real-agent smoke is a separate CI step:
CI builds both native host executables, compiles the installer library test runner,
then executes `isolated_real_agent_engine_and_cli_fresh_repair_resume_smoke` as root
in a private mount namespace with temporary `tmpfs` mounts at `/etc`, `/var/lib`
and `/run`. The gate requires exactly one passing test; an ignored default Cargo
result is not evidence for that smoke, and no host paths are mutated outside the
namespace.

## Static host build inputs

Rust image build stages explicitly set `CARGO_BUILD_JOBS=1` and `CARGO_INCREMENTAL=0`;
the caller's Cargo environment is not inherited by Docker builds. On small hosts also
set `COMPOSE_PARALLEL_LIMIT=1` in each actual Compose caller (including the version-agent
service and privileged installer). The image settings bound each Cargo invocation;
they do not serialize separate image builds. Runtime stages do not inherit these
compiler settings. This build-only change does not change installer CLI or host prerequisites.

`release/build.py --build-binaries DIR` stages tracked files from the listed crates,
VERSION and `release/host-binaries.list`, plus the explicitly declared embedded inputs.
The installer's `include_str!` requires the tracked 3x-ui API contract at
`installer/assets/three-xui-api-contract-3.10.2.json` in that build context. A missing
or untracked declared input is refused before Docker runs; local cache files do
not supply it. The contract is embedded in the binary, so the installed host does
not need the JSON file to run the installer.

Source build inputs and the user archive are separate: `release/runtime-files.json`
selects the tracked deployment files; the host builder still stages the full tracked
crate sources. CI, lab tooling, integration fixtures and development guides stay in Git,
not in the user archive. Operational guides, examples, licenses, Docker build sources,
shared libraries and installation acceptance clients remain. Shipped Markdown links to
omitted tracked material point to the exact source commit on GitHub. Archive and SBOM
hashes describe the resulting bytes, including those adjusted documentation links.

## Lab tiers on the disposable host

`scripts/dev/remote-gate.sh <tier>` syncs the working tree to the lab host (`ams-test` by
default; production hosts are refused) and runs one tier there.

Sync uses checksums without preserving workstation timestamps. Changed source receives
the stand's write time instead of an older workstation time, avoiding stale Cargo output
after cross-host clock skew. Root `.env*` and `secrets/` stay private; frozen synthetic
environment/secret fixtures below the test directories are retained.

| Tier | What it proves | How |
| --- | --- | --- |
| `quick <pytest args…>` | native prerequisites, ruff + the selected external test files; skips/deselection fail | `.venv` on the host |
| `full` | native prerequisites, complete external pytest suite, image builds, doc links, JS syntax, shellcheck, unit files | same |
| `compose` | every supported Compose model renders; native images build | same |
| `lab-container` | the release archive installs into a fresh Ubuntu 24.04 container (audit → plan → coexistence) | `scripts/lab/docker_lab.py` |
| `lab-host` (`LAB_RESET=1`) | the release archive installs the full profile on the bare host: audit, plan, install, repair, idempotence, reboot recovery, crash-every-phase, report, fleet, secrets scan, uninstall, coexistence | source-side `scripts/lab/guest-runner.sh host`, with `LAB_RELEASE_ROOT` pointing at the extracted archive |
| `fleet` | Fleet v2 end-to-end scenarios against the installed node, a native Rust central and a second independently hosted native panel (Node B) | `scripts/lab/fleet-acceptance.py` |

The `fleet` scenario starts a separate native central from `--panel-bin PATH` or copies
`/usr/local/bin/panel` from `--node-container` (default `proxy-control-panel`). `--source`
supplies the Rust panel's static assets and VERSION, not Python modules; `--central-dir`
and `--central-port` isolate its files and listener. Node B uses a private Nginx TLS
proxy over a native loopback panel. The script exercises `node-sync` keys, pin-verified
linking, inventory/import, typed generations, credentials, traffic acceptance, recovery
and unlink. Inside `lab-host` the fleet case runs from the release bytes. A previous
Python-central result is not evidence for this native boundary: require a fresh
successful native run and retain the report without exposing credentials or links.

```sh
LAB_RESET=1 LAB_KEEP_INSTALL=1 scripts/dev/remote-gate.sh lab-host   # REMOTE_GATE_LAB_HOST_OK
scripts/dev/remote-gate.sh fleet                                     # FLEET_ACCEPTANCE_OK, REMOTE_GATE_FLEET_OK
```

Both `quick` and `full` prepare the test-hooks Rust panel and native installer and
version-agent using the same Cargo commands and canonical binary locations as CI.
`PANEL_RUST_BIN`, `PC_INSTALLER_BIN` and `PC_VERSION_AGENT_BIN` may identify already
built **Linux** binaries on the disposable host; they do not select a Python runtime.
Quick accepts positional test files, but `-k`/`-m` deselection and any collection or
runtime skip fail the gate. Python runs only as the external test/lab controller.

Focused native browser and sampler proofs (run on ams-test with its external venv):

```sh
PANEL_RUST_BIN=/path/to/test-hooks/panel .venv/bin/python scripts/lab/ui_awg_check.py
PANEL_RUST_BIN=/path/to/test-hooks/panel .venv/bin/python scripts/lab/ui_protocol_dialog_check.py
PC_VERSION_AGENT_BIN=/path/to/proxy-control-version-agent .venv/bin/python scripts/lab/agent-metrics-check.py --perf 5
PC_MANAGED_XUI_LIVE=ams-test PC_INSTALLER_BIN=/path/to/proxy-control-installer \
  bash scripts/lab/managed-xui-acceptance.sh
```

`ui_awg_check.py` uses fresh SQLite/key/profile files, a native panel process and
test-owned HTTP managers. It proves browser placement/version selection, config
and QR delivery, matching downloadable content, grant windows, actual key rotation
and creation from the AWG screen. It emits only counts/booleans, never screenshots,
DOM/accessibility dumps or config contents. It is a focused desktop smoke, **not**
the installed-stack `ui` tier or a visual layout review. The protocol-dialog smoke
may capture only empty states/unsubmitted dialogs before any issuance.

The sampler proof uses real native-agent HTTP and nft counters in private mount
and network namespaces. The managed 3x-ui proof is an explicitly destructive native
integration test (`real_managed_three_xui_native_provision`), not a Python adapter
import: it stages the pinned upstream bytes and verifies the database, TLS HTTP
API, effective Xray config and actual inbound listeners. It needs a clean test host
and Cargo unless `PC_MANAGED_XUI_TEST_BIN` points at its prebuilt test executable.
An unavailable pinned upstream archive is a blocker, not evidence from a fixture.

`LAB_KEEP_INSTALL=1` leaves the installed node running for the `fleet` tier, but
reports `uninstall` and `coexistence` as `skipped`. This is **not** a full `lab-host`
gate: run `LAB_RESET=1 scripts/dev/remote-gate.sh lab-host` separately without
`LAB_KEEP_INSTALL` and require both checks to pass. The lab certificates are valid
for two days; a kept install older than that needs a fresh `LAB_RESET=1 … lab-host`.
Runtime usernames the scenario creates carry a per-run suffix because the Naive
and Mieru managers retire deleted names for good.

## Runtime acceptance

Validate Nginx before reload, public listener ownership, all adjacent SNI routes, authenticated manager boundaries, backups and rollback. MTProto requires Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` for every secret. Naive requires cover HTTPS, authenticated CONNECT, completed-log collection and failure tests. Mieru requires executable digest/version, UDS/state preflight, transaction recovery and TCP/UDP checks. Fleet v2 requires verified HTTPS or an explicit TLS certificate pin, a scoped `node-sync` key, a typed generation accepted by the node and an observed result; no Fleet v1 mTLS endpoint is shipped.

## Runtime evidence and pending gates

Telemt/MTProto, NaiveProxy/Caddy and Mieru/mita have each passed live end-to-end protocol probes on an operator-controlled deployment, including manager health and panel integration. This evidence does not make host-specific credentials, names, addresses or logs public and does not replace validation on a new target host.

Installer, deployment and installed-component changes require a fresh `lab-host` run against the archive under review. The existence of the QEMU/container/host harness is not evidence that a particular revision passed. Keep a per-revision record of commands, archive digest, exits, skips and the tested host class; an earlier release's results do not satisfy this gate. An installed Fleet v1 service requires a separate explicit migration with backups, not a skipped or silent replacement during a panel update.
