# Validation gates

## Required repository gates

```sh
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 -m unittest -v tests/test_deploy.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
python3 scripts/check-doc-links.py
```

CI also renders core, core+Naive, core+Mieru, combined core+Naive+Mieru, agent and fleet-central Compose models, plus the documented Mieru render with an executable placeholder and an empty secret file. It builds panel/managers/agents/ingress and the pinned Caddy+forward-proxy artifact, executes the bounded Caddy checker against that artifact and a negative fixture, verifies service units where host tooling permits, and enforces diff hygiene and third-party notices.

## Lab tiers on the disposable host

`scripts/dev/remote-gate.sh <tier>` syncs the working tree to the lab host (`ams-test` by
default; production hosts are refused) and runs one tier there:

| Tier | What it proves | How |
| --- | --- | --- |
| `quick <pytest args…>` | ruff + the selected tests | `.venv` on the host |
| `full` | the required repository gates above, plus image builds, doc links, JS syntax, shellcheck, unit files | same |
| `compose` | every Compose model renders; agent/ingress images build | same |
| `lab-container` | the release archive installs into a fresh Ubuntu 24.04 container (audit → plan → coexistence) | `scripts/lab/docker_lab.py` |
| `lab-host` (`LAB_RESET=1`) | the release archive installs the full profile on the bare host: audit, plan, install, repair, idempotence, reboot recovery, crash-every-phase, report, fleet, secrets scan, uninstall, coexistence | `scripts/lab/guest-runner.sh host` from the extracted archive |
| `fleet` | Fleet v2 end to end against the node `lab-host` left installed | `scripts/lab/fleet-acceptance.py` |

The `fleet` scenario (`scripts/lab/fleet-acceptance.py`, v0.3 spec §10) links the installed
node panel (`https://panel.lab.test`, lab-issued certificate → `tls_verify=pin`) to a second,
in-process central panel started on the host from the tree under test (`--python` chooses
the interpreter, `--source` the tree whose `panel` package it imports; `--central-dir`,
`--central-port 8791`). Over HTTPS with real clients it proves: a `node-sync` key, the
fingerprint/test/link flow with `online` within 10 s and `node.up`; import of every runtime
user the node has, untouched and `central`-owned; a client with MTProxy, NaiveProxy and
Mieru grants `enabled` within 30 s, its bundle and subscription carrying the runtime's own
endpoints, traffic through sing-box (naive) and mihomo (mieru, TCP and UDP) and the TDLib
resPQ probe for MTProxy; disable → every client refused, rotate → the old credential refused
and the new one working, delete → the account gone and the grant purged; a grant issued
while the node's panel is stopped converging once it is back; twenty grants with the panel
restarted a second later converging without duplicates; a revoked key → `offline` + `node.down`,
a new key → `online`; and the unlink leaving the node exactly as found (users, ownership,
master GUID, keys). The report (`report.json`, checks `s01_…s11_`) never carries a key, a
password, a token or a link. Inside `lab-host` the same scenario runs as the case `fleet`
right after `report`, with the central started from the release bytes; failure there does
not stop the later cases.

```sh
LAB_RESET=1 LAB_KEEP_INSTALL=1 scripts/dev/remote-gate.sh lab-host   # REMOTE_GATE_LAB_HOST_OK
scripts/dev/remote-gate.sh fleet                                     # FLEET_ACCEPTANCE_OK, REMOTE_GATE_FLEET_OK
```

`LAB_KEEP_INSTALL=1` makes `lab-host` report `uninstall` and `coexistence` as `skipped`
(exit code unaffected) and leaves the installed node running, so the `fleet` tier — and a
live central for the next task — have a node to link. Without it the host ends uninstalled
as before. The lab certificates are valid for two days; a kept install older than that
needs a fresh `LAB_RESET=1 … lab-host`. Runtime usernames the scenario creates carry a
per-run suffix because the Naive and Mieru managers retire deleted names for good.

## Runtime acceptance

Validate Nginx before reload, public listener ownership, all adjacent SNI routes, authenticated manager boundaries, backups and rollback. MTProto requires Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` for every secret. Naive requires cover HTTPS, authenticated CONNECT, completed-log collection and failure tests. Mieru requires executable digest/version, UDS/state preflight, transaction recovery and TCP/UDP checks. Fleet requires negative mTLS tests, certificate binding/revocation, ordered command/result durability, and no public local management API.

## Runtime evidence and pending gates

Telemt/MTProto, NaiveProxy/Caddy and Mieru/mita have each passed live end-to-end protocol probes on an operator-controlled deployment, including manager health and panel integration. This evidence does not make host-specific credentials, names, addresses or logs public and does not replace validation on a new target host.

A reproducible Ubuntu 24.04 QEMU install → audit → repair → upgrade → uninstall → rollback workflow remains pending and is not a required CI gate. Production fleet ingress/enrollment also remains pending until mTLS authorization and a durable command/result cycle are independently confirmed.
