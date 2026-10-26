# Validation gates

## Required repository gates

```sh
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
cargo test --manifest-path panel/Cargo.toml --workspace --locked
cargo test --manifest-path version_agent/Cargo.toml --locked
cargo test --manifest-path installer/Cargo.toml --locked
cargo build --manifest-path panel/Cargo.toml --locked -p panel-web --features test-hooks
cargo build --manifest-path installer/Cargo.toml --locked --bin proxy-control-installer
install -D -m 0755 installer/target/debug/proxy-control-installer installer/bin/linux-amd64/proxy-control-installer
PANEL_IMPL=rust PANEL_RUST_BIN="$PWD/panel/target/debug/panel" \
  sudo --preserve-env=PANEL_IMPL,PANEL_RUST_BIN .venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
python3 scripts/check-doc-links.py
bash scripts/dev/check-js-syntax.sh
```

CI renders every supported Compose overlay against synthetic inputs, including MCP, Xray-router, AmneziaWG and TrustTunnel; the retired Fleet v1 agent and mTLS ingress are not built or rendered. CI builds the Rust panel, Naive/Mieru managers, MCP and Xray-router images, checks the pinned Caddy+forward-proxy artifact and a negative fixture, verifies service units on the ephemeral runner, and enforces diff hygiene and third-party notices. The Python external black-box suite runs against a Rust panel executable (`test-hooks`) and fails the gate on any deselected or skipped test. The independent dependency gate installs `cargo-audit` version `0.22.2` from crates.io with `--locked` and audits **every** shipped native `Cargo.lock` against RustSec; no Python panel or MCP runtime requirements are audited.

## Lab tiers on the disposable host

`scripts/dev/remote-gate.sh <tier>` syncs the working tree to the lab host (`ams-test` by
default; production hosts are refused) and runs one tier there:

| Tier | What it proves | How |
| --- | --- | --- |
| `quick <pytest args…>` | ruff + the selected tests | `.venv` on the host |
| `full` | the required repository gates above, plus image builds, doc links, JS syntax, shellcheck, unit files | same |
| `compose` | every supported Compose model renders; native images build | same |
| `lab-container` | the release archive installs into a fresh Ubuntu 24.04 container (audit → plan → coexistence) | `scripts/lab/docker_lab.py` |
| `lab-host` (`LAB_RESET=1`) | the release archive installs the full profile on the bare host: audit, plan, install, repair, idempotence, reboot recovery, crash-every-phase, report, fleet, secrets scan, uninstall, coexistence | `scripts/lab/guest-runner.sh host` from the extracted archive |
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
