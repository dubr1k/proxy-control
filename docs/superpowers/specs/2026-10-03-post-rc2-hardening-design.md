# Post-rc.2 update hardening

## Intent and boundaries

Make an installed Proxy Control host safe to update and subsequently repair, and make the next candidate observable and ready for native acceptance. The owner's later authorization covers native update/repair and clean replacement on `ams-test` after backup, using the stock installer without QEMU. Changes to other hosts, foreign frontend routes and public releases remain outside scope.

## 1. Installer ownership after a panel update

Core's verified transaction checkpoint and `ownership.json` record hashes of project files. Version-agent replaces those same files from a SHA-256-verified release archive, then records a successful panel update independently. The two ownership generations diverge; `repair` and `uninstall` correctly reject the apparent drift. The fix must retain drift detection, not mark the project mutable.

The update operation and installer operations share `/run/lock/proxy-control.lock` for the full mutation/rollback/handoff window. Before replacing the project tree, the agent validates that the active installer checkpoint and all unrelated owned files still match their recorded generation. After the panel container reports the target version, a narrow handoff updates only Core entries corresponding to verified archive-managed paths and their actual final filesystem identities in both the checkpoint and ownership journal. New and removed files inside replaced managed directories are accounted for. Secrets, `.env*`, Nginx, the probe, and other adapters' entries are unchanged. Unsafe paths, foreign drift, incomplete transactions and rollback failures remain hard stops. A failed handoff cannot yield a `ready` update; rollback must restore the old generation or record operator recovery.

For hosts already updated by the old agent, offer an explicit recovery command requiring the exact release archive and pinned digest. It verifies archive bytes and current runtime version before making the same bounded ownership handoff. It never refreshes arbitrary hashes. Do not run this command on a live host in this branch.

Review correction: the same sync replaces `/opt/proxy-control/version_agent`,
whose immutable hashes belong to the version-agent adapter. Include that code
package in the same atomic checkpoint update; preserve its unit, environment,
catalog and mutable state. Restart the agent after changes to either its own
package or its imported installer package. The owner's subsequent instruction
authorizes native update/repair and clean installation on `ams-test` after backup.

## 2. Enabled Compose services

The installer declares profile overlays, while version-agent uses a persisted `PROXY_CONTROL_COMPOSE_FILES`. A separately enabled MCP container can be running even when that list omits `compose.mcp.yaml`, as observed on the current host. Before any panel update, the release updater validates that every running Proxy-Control-managed optional service has its overlay in the agent's list. A mismatch fails with a precise operator action before mutation. The version-agent's direct panel-update path applies the same guard. A correctly declared MCP is synced and rebuilt; no orphan removal is used.

## 3. Readiness

Keep `/healthz` as a cheap liveness response. Add an authenticated, no-store, read-only readiness diagnostic for owner/admin, with no credentials or topology identifiers in the output. It reports DB queryability and aggregate counts for node-local managed generation (including last actual `applied_at`), central linked-node lag, unfinished provisioning, and manual-intervention operations. A panel can be both node and central. Lack of a configured central or links is `not_applicable`, not failure. `reported_at` from polling is not a reconcile timestamp. The response must distinguish healthy-but-work-pending from a hard failure without restarting a container merely because remote work is queued.

## 4. Acceptance readiness

Prepare reproducible, secret-free native-stand scenarios; do not claim they passed. The Fleet measurement harness records configured node count, cycle/queue/retry/convergence distributions and failure counts under defined latency profiles, preserving the eight-slot concurrency cap. The managed-3x-ui acceptance gate must carry payload over VLESS Reality TCP, XHTTP, and Hysteria2, not just check listeners; negative credentials and adjacent-route preservation belong in the gate. Telegram application connectivity remains a manual checklist with pass/fail evidence only; existing `resPQ` probes are not equivalent. Document a separate coexist frontend/client-IP trust contract and diagnostic procedure without editing foreign SNI routes.

## Release criterion

Local unit/static checks and an independent code review precede handoff. Native `1.1.0 → candidate → repair`, fresh/reboot/repair, rollback, protocol-client and Fleet load runs remain explicitly pending on `ams-test`. Public `v1.1.1` is not cut by this branch.
