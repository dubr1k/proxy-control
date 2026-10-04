# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The history starts with 1.0.0, the first stable release.

## [Unreleased]

## [1.1.1] - 2026-10-03

- Includes the client lifecycle, bounded Fleet synchronization, update rollback and native installer fixes from the unpublished rc.1–rc.3 candidates below.
- The native installer pins 3x-ui 3.9.0 and its verified amd64 archive layout (bundled Xray 26.9.30). Managed installation removes its temporary acceptance accounts through the client API; 3x-ui 3.9 no longer changes clients through inbound updates. The wizard, release install script, examples and installation guides name the same pin.
- Managed Hysteria2 clients are explicitly enabled. Without this field, 3x-ui retains the account in its API but omits it from Xray's running configuration.
- Explicit managed 3x-ui purge also removes its SQLite sidecars and metrics cache after stopping the service, leaving unknown files untouched. Fresh installation refuses an orphan database directory.

## [1.1.1-rc.3] - 2026-10-03

Unpublished hardening candidate, checked with the stock installer on a native host.

- Panel updates transfer installer ownership for both Core and version-agent code under the installer lock; exact-archive reconciliation supports the first upgrade with an older agent. Installer-only changes also restart the agent to refresh imported Python modules.
- Updates refuse an incomplete Compose overlay scope before changing running services. Authenticated readiness diagnostics distinguish pending reconciliation from process liveness.
- Explicit installer purge removes an empty updater directory and verified optional-manager socket volumes, allowing a clean reinstall. Foreign files, symlinks and volumes remain protected.
- The release install script and bilingual installation guides describe old-agent reconciliation. Native update/repair, clean install/repair and idempotent install evidence is recorded separately; no public release was published.

## [1.1.1-rc.2] - 2026-10-02

Unpublished candidate with an additional fix found during installer validation.

- Installer command timeouts stop the command's process group and verify termination before returning control to rollback. If termination cannot be confirmed, automatic rollback does not start; remaining processes must be inspected before another operation.

## [1.1.1-rc.1] - 2026-10-02

Unpublished audit candidate; validation results are recorded separately from these changes.

- Client suspension and access validity windows now reach local protocol runtimes and remote nodes; reconciliation verifies the resulting state and retries failures. Stale Fleet reports cannot confirm a pending suspension.
- Client lists use batched reads and server-side pagination/search. Fleet pushes have bounded concurrency and connection-time DNS checks, preserving hostname verification and explicit private-address opt-in.
- Panel updates stop database writers before snapshot/restore, preserve the original WAL after a partial snapshot failure, and include the MCP service in synchronization and rebuilds.
- Request bodies are bounded while receiving; SQLite context managers close connections. Updated FastAPI, Starlette and related dependencies address dependency audit findings.
- Fresh installer ingress preserves client IP through a trusted Unix socket. Host updates migrate only recognized, owned Nginx templates with rollback and worker-generation verification; foreign coexistence frontends require an operator-managed bridge.
- CI validates all shipped Compose overlays, JavaScript syntax, pinned runtime dependencies and reproducible installer artifacts.

## [1.1.0] - 2026-10-01

- MTProxy routing: MTProxy attaches to the node's Xray-router and leaves through WARP, a custom exit or another node of the fleet (a chain); rules by CIDR, `geoip` and port, while rules by domain, `geosite` and protocol are `rule_kind_unsupported` (Telemt reaches Telegram's data centres by IP). Telemt's own policy (`mtproxy_native`) is direct only.
- Attach and detach change Telemt's upstream through its API (`PATCH /v1/config` + `POST /v1/system/reload`) without restarting the container; the rollback journal is the panel's `/data/telemt-egress.json`, secret-free.
- Xray-router: a third ingress `mtproxy` — VLESS on a Unix socket; the `xray-router-ingress` bridge (same image) on the Compose network takes Telemt's SOCKS5 on `:45103`; the router mints the credential; the only bypass exception, on that ingress alone — private networks on `:443` direct (the `mask` TLS front). `GET /v1/ingress/mtproxy`.
- Fleet: capability `egress.mtproxy.v1`, the generation's `egress.mtproxy` section; new codes `router_lacks_mtproxy`, `ingress_unreachable`, `node_lacks_mtproxy_egress`, `telemt_api_unsupported`, `egress_reload_failed`.
- Migration 21 (`routing-mtproxy`): `routing_policies` and `managed_egress` allow `mtproxy`/`mtproxy_native`.
- The installer starts, verifies and removes the bridge with the router; the wizard question and `--requirements` mention MTProxy.
- One-command updates: `bash install-release.sh --update` verifies the release, then `scripts/update-host.sh` (root) asks the version-agent to update the panel to exactly the verified digest and rebuilds the managers in `pending_rebuild` (and the router's bridge).

See [release notes](docs/releases/v1.1.0.md).

## [1.0.3] - 2026-10-01

- The release publishes `install-release.sh` and `install-release.sh.sha256`: the install script with its release's version and archive SHA-256 written in (a swapped archive does not pass even with a swapped `SHA256SUMS`), attested; `SHA256SUMS` still names three files.
- Installer wizard: explanations and defaults for the host mode, the profile and the 3x-ui mode; Mieru ports default to `46001`; the Xray version in the question comes from the external-artifact manifest; an invalid configuration says why; the review omits unused fields.
- Fix: with «apply» straight from the wizard, the typed panel and 3x-ui passwords were replaced by generated ones — they now reach the installation in a private temporary copy.
- Fix: the `initial_user` question says what it is (the first MTProxy and Mieru user; the panel login is always `owner`); «WARP domains» no longer promises «blank for none» and takes `geosite:`/`domain:`; `managed-new` is not offered in `coexist`; `existing` asks only for the VLESS domains (at least one); Mieru TCP ports are checked against the installer's own ports (8443, 8445, 8787, 4443, 8793, WARP, Xray-router, relay, lane slots, the managed 3x-ui); «No changes were made» is printed once; a 3x-ui username is kept with a generated password; the 3x-ui subscription domain joins the SNI uniqueness check.

The panel did not change. See [release notes](docs/releases/v1.0.3.md).

## [1.0.2] - 2026-10-01

- The access window: a click on an access row (client card or client window) opens its details (node, state and the node's report, route, limits, validity, subscription apps, secret, dates, ID), this access's own link with a QR on request («Открыть в Telegram» for MTProxy, «Профили для приложений» for NaiveProxy/Mieru on this server) and its actions: enable/disable, rotate, own lane, delete, adopt. The link does not stay in the window.
- Clients: search by name, account and node; state buttons with counts; filters by protocol, node and the state of accesses (problems, waiting for the node, error, no secret, disabled, own lane, no access); «Показано N из M» and «Сбросить». Filters survive list refreshes.
- API: `POST /api/clients/{id}/links?grant_id=…` reveals one access; links of all three protocols come with a QR.
- Client card and client window: compact clickable access rows, an access's buttons live in its window; one type size in the client window.
- Fix: text left its box (bubbles with vertical text in the client window, pills breaking mid-word); in-between widths — overview metrics, Mieru/NaiveProxy rows, the journal, the header on narrow phones.

Panel only: no migrations, no manager rebuild. See [release notes](docs/releases/v1.0.2.md).

## [1.0.1] - 2026-09-29

- Versions screen: each runtime's dropdown lists several recent releases both ways (newer / roll back, the agent's `newer` flag); the panel is only ever offered forward and the agent refuses a panel downgrade. The same on a node's Updates tab.
- Mieru takes any mita: no list of verified lines. The manager writes the whole config with the verb the binary offers (`replace config` from 3.38, `apply config` before), reads every write back and rolls back on a mismatch; a rollback that does not restore the snapshot is reported as needing recovery.
- Geodata: regional sources «runetfreedom» (Russia), «iran» (chocolate4u) and «v2fly» next to Loyalsoldier and the pin; a new router starts on Loyalsoldier with daily refreshes, an untouched pin moves there on upgrade. A daily refresh waits for `update_hour` (UTC, default 02:00); the line shows the last and next check. Files up to 128 MB (the Russian geosite is ~74 MB); a restart failure after the swap is recorded; the pin follows a new Xray seed; the download runs off the watchdog thread.
- Fix: the NaiveProxy upstream check asked for forwardproxy's `caddy2` branch, which no longer exists (422); it follows the `naive` branch now.
- Routing quick settings «Заблокированное в РФ → через WARP» (needs the runetfreedom source), «Китайские домены и IP → напрямую», «Иранские домены и IP → напрямую»; two new guide scenarios.

After the panel update rebuild `mieru-manager` and `xray-router`. See [release notes](docs/releases/v1.0.1.md).

## [1.0.0] - 2026-09-28

The first stable release: kept Mieru keys, a subscription for Throne, step-by-step routing with a built-in guide, and an English interface.

- Routing is step by step: for whom → where traffic goes → check → apply on the node, each step with a short explanation. A service's capabilities are named in words instead of codes; exits, the Xray-router, geosite/geoip lists and the relay sit in a folded «Возможности узла» block; the check's technical details fold under a plain summary of the draft.
- «Как это работает» (How it works) is a detailed guide inside the panel: the terms, what each service can do, eight step-by-step scenarios with a Start button (all traffic through WARP, some sites through WARP, ads, torrents, Russian sites direct, a chain through another node, your own exit, one client's own route), Save versus Apply, and what to do when the check says it cannot be applied. A scenario only prepares the draft — nothing reaches a node without Save and Apply.
- English interface: an RU/EN switch in the header and on the sign-in page, remembered per browser. Every screen, dialog and notification is translated; dates and numbers follow the chosen language.

- Mieru keys no longer need a rotation to be shown again: the panel keeps every key it issues in its encrypted store, and **Configuration** on the Mieru page shows the current key with no change on the node (`POST /api/mieru/users/{username}/access`). Users issued earlier are marked «Key not kept»; one **New key** keeps it from then on. «New link + QR» is renamed «New key».
- Fix: creating and rotating on the Mieru and NaiveProxy pages bypassed the panel's store, so a client's subscription kept serving the replaced password. The new password now reaches the subscription at once.
- Throne (formerly Nekoray), checked with Throne 1.3.1: it takes NaiveProxy and Mieru from the «sing-box JSON for Karing and Throne» variant and imports nothing from Clash YAML. The client window and the compatibility matrix say so, and grants carry a `throne` mark. Throne 1.3.1 limitation: Mieru over UDP connects only when the server is an IP address.
- Client card: grants line up as a table (protocol · account · state · route · actions) in one order, MTProxy → Naive → Mieru, with a coloured state dot; tidy stacked cards on a phone. Archived clients go last. The route button names the action.
- Overview: the loading placeholder has the real layout (server resources and three protocol cards), so the tiles no longer jump between 3 and 4. The RAM row shows swap (needs the host agent from this release).
- Accent colour: a palette button in the header, seven accents, remembered per browser.

See [release notes](docs/releases/v1.0.0.md).
