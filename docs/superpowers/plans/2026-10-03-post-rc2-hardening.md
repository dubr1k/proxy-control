# Post-rc.2 hardening implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development or executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Make panel updates compatible with installer repair, detect incomplete Compose update scope, expose honest readiness, and prepare native acceptance gates without running the test stand.

**Architecture:** Preserve independent installer and version-agent state, but serialize mutation and narrowly reconcile ownership after a verified panel update. Keep liveness separate from authenticated readiness and keep acceptance probes isolated from production credentials.

**Tech Stack:** Python 3.12, Bash, FastAPI, SQLite, Docker Compose, pytest.

**Spec:** `docs/superpowers/specs/2026-10-03-post-rc2-hardening-design.md`.

## Global constraints

- Branch from `origin/main`; do not modify the dirty `main` checkout or the installed production host.
- Write a failing regression before each behavioral fix. Verify with the project `.venv` from the worktree.
- No test-stand run, production `repair`, foreign Nginx edit, secrets in logs, or public release.
- Preserve all existing migration, ownership, Compose, route and protocol contracts.

## Review focus

- An agent update races with repair/uninstall: one operation must refuse or wait before either mutates files.
- A pre-existing foreign edit within a sync directory must not be laundered into ownership.
- A crash or failed handoff must not report panel `ready` with stale checkpoint ownership.
- A running MCP container omitted from agent overlays must fail before the panel update.
- Readiness must not mistake a fresh heartbeat for a successful reconcile or expose node identifiers.

## Task 1: Update ownership handoff and legacy recovery

**Files:** `installer/transaction.py`, a focused handoff module if needed, `version_agent/service.py`, `installer/cli.py`, `tests/test_version_agent_panel.py`, `tests/test_installer_transaction.py`, `tests/test_installer_core.py`.

- [ ] Add red tests for active old checkpoint → verified panel archive sync → repair and uninstall, plus foreign drift, removed/new managed files, lock contention, failed handoff/rollback, and explicit legacy recovery with a wrong digest.
- [ ] Implement a narrow handoff under the installer operation lock across agent mutation. Update Core checkpoint data and captured ownership together; leave unrelated entries and plan digest unchanged. Ensure failure is recoverable and never recorded `ready`.
- [ ] Add explicit archive+digest legacy reconciliation for already-updated hosts. Check release identity, running version, Core ownership scope, and unchanged foreign entries before writing state.
- [ ] Run targeted transaction/Core/agent tests and `git diff --check`; commit task.

## Task 2: Compose scope preflight

**Files:** `scripts/update-host.sh`, `version_agent/service.py`, `tests/test_update_host.py`, `tests/test_version_agent_panel.py`, installer/MCP tests only if the root cause requires it.

- [ ] Add red tests where a running project MCP is omitted from `PROXY_CONTROL_COMPOSE_FILES`; both shell and direct agent entry points refuse before panel mutation. Add no-MCP and correctly-declared controls.
- [ ] Implement preflight of known project-managed optional services against overlays; preserve `--no-deps`, rollback image handling and no orphan removal.
- [ ] Run targeted update-host/agent/MCP tests and `git diff --check`; commit task.

## Task 3: Readiness diagnostic

**Files:** `panel/readiness.py`, `panel/auth_routes.py` (or existing route registry), `panel/tests/test_readiness.py`, relevant API docs and verification matrix.

- [ ] Add red tests for unauthenticated/monitor/node-sync rejection, no-link/no-generation baseline, node applying/failed/converged timestamps, central lag, unfinished/manual operations, DB failure, and secret-free output.
- [ ] Implement authenticated no-store aggregate snapshot. Keep `/healthz` unchanged and avoid external network calls.
- [ ] Run targeted panel tests and route/verification-matrix checks; commit task.

## Task 4: Native-stand acceptance preparation

**Files:** focused Fleet measurement helper/tests, `scripts/lab/managed-xui-acceptance.sh` and client fixtures/docs as feasible, `tests/lab/README.md`, Telegram/coexist operator checklist.

- [ ] Add tests for Fleet metric math, bounded concurrency and secret-free report; implement a synthetic configurable multi-node measurement command with stated latency profiles and thresholds.
- [ ] Add pinned real-client probe contracts for VLESS TCP, XHTTP and Hysteria2, including payload, negative credentials and cleanup; reject missing probe images/tools instead of claiming a pass. Do not run the stand.
- [ ] Document manual Telegram-client evidence and coexist client-IP trust/verification without changing foreign ingress.
- [ ] Run local parser/unit/static checks; commit task.

## Integration and handoff

- [ ] Run repository-required local gates where safe, report exact skips due to deferred stand, and inspect the whole diff with an independent reviewer.
- [ ] Fix review findings, re-run affected gates, and make a branch ready for `ams-test` with commands and expected evidence. Do not publish a release or modify the installed host.

## Continuation on 3 October

The owner's later instruction authorizes tests through SSH on `ams-test`, using
the normal installer without QEMU. This supersedes the earlier no-stand
constraint; it does not authorize a public release or changes to other hosts.

Independent review of `512be74` reproduced a missing ownership handoff for
`/opt/proxy-control/version_agent`: the Core-only fixture did not include the
version-agent adapter's immutable code hashes. The fix updates both checkpoints
in one state write, with regressions for the actual two-adapter installation,
legacy reconciliation, foreign code/unit drift, and journal-write recovery.
The second finding was a cached `installer.transaction` import surviving an
installer-only update. Such a change now schedules the agent restart too.
Both findings had failing regressions before their fixes.

Local targeted verification passed (200 tests); native validation is running
from `/root/dev/pc-rc2-20261003-review` on `ams-test`. The pre-mutation audit
found eight healthy containers, rc.2 runtime, and an active v1.1.0 installer
journal. Read-only legacy preparation against the exact installed rc.2 archive
accepted the 32 Core and one agent-code hash differences without writing state.
These observations do not yet prove update/repair or clean-install acceptance.

Fleet's synthetic latency model still does not measure the real pusher. Native
Fleet timing, managed-3x-ui client evidence and Telegram application acceptance
remain separate outstanding requirements.
