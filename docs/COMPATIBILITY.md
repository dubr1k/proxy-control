# Compatibility policy

Proxy Control product naming does not rename deployed runtime contracts.

The following remain supported unchanged: `/opt/mtproxy-shared443`, `.mtproxy-owned`, marker `mtproxy-shared443`, `/etc/nginx/mtproxy-stream`, `.mtproxy-backup`, Compose project `mtproxy`, volume `mtproxy_panel-data`, `/var/lib/mtproxy-panel`, `/opt/mtproxy-panel`, `/etc/mtproxy-agent`, `/var/lib/mtproxy-agent`, unit filenames `mtproxy-agent.service` and `mtproxy-fleet-ingress.service`, fleet URI `urn:mtproxy-panel:node:`, and installed `scripts/mtproxy-deploy`.

Protocol names (`mtproxy`, `protocols.mtproxy`, `MTPROXY_*`) remain protocol-specific and are not deprecated. Historical changelog entries are not rewritten.

A future migration must provide discovery, read-only planning, backups, ownership checks, explicit cutover, rollback, and tests from an actual prior installation. Never silently move databases, volumes, certificates, units, routes, markers, or fleet identities.

## Panel-to-panel contract (frozen)

Two panels of different releases talk to each other only through the identifiers below; they are frozen the same way the runtime paths above are, and a change to any of them is a new `api_version` / `schema_version`, never an edit in place.

- **`panel_guid`** — one uuid4 per panel database, minted in `panel_settings` on the first start and never regenerated. It is the node's `node_id` on every central that links it, the `expected_guid` of every push, the `node_guid` of every generation document and the target of the audit action `fleet.unlink`. A restored database keeps its GUID; a new database is a new panel. `fleet_master_guid` in the same table names the one central allowed to push (one master per node); only `unlink` clears it.
- **`/api/fleet/v2/*`** — `GET identity`, `GET status`, `GET inventory`, `PUT generation`, `GET observed`, `POST credentials/capture`, `POST versions/update`, `POST unlink`; `identity.api_version = 2`; every route accepts only a `node-sync` or `admin` API key. Conflict answers are 409 with `{detail, code}` and the codes `guid_mismatch`, `foreign_master`, `stale_generation`, `digest_conflict`, `secret_store_disabled` are part of the contract (`digest_invalid` is reserved). A push answers `200 {observed, credentials}` or `202 {observed}`; the body limit is 64 KiB. The legacy `/api/fleet/nodes*` and `/agent/v1/*` paths of Fleet v1 stay frozen alongside.
- **API key format `pc_<prefix>_<secret>`** — the literal prefix `pc_`, an 8-character hexadecimal lookup prefix, an underscore, then a URL-safe secret; the database stores the prefix and the SHA-256 hex digest of the whole key. Scopes are exactly `admin`, `monitor`, `node-sync`, and their mapping to roles (`owner`, `viewer`, fleet-only) does not change. A key is presented as `Authorization: Bearer <key>`.
- **Wire fields of `GenerationDocument` (`schema_version: 1`)** — `node_guid`, `master_guid`, `generation` (≥ 1), `previous_generation` (≥ 0), `created_at`, `created_by`, `resources[]`; each `Resource` has `ref` (`grant:<id>`), `protocol` (`mtproxy | naive | mieru`), `runtime_username`, `desired_state` (`enabled | disabled | deleted`), `credential_ref` (`<secret_id>:<version>`), `credential_origin` (`caller | manager`), `origin` (`provisioned | imported`, default `provisioned`), `options`, `valid_from`, `valid_until`. Unknown fields are refused (`extra = forbid`), so a field can only be added together with a new `schema_version`. The digest is the SHA-256 of the canonical JSON (sorted keys, resources sorted by `ref`, compact separators, ASCII).
- **`ObservedGeneration`** — `applied_generation`, `digest`, `reconcile_state` (`idle | applying | converged | failed`), `resources[]` of `{ref, protocol, runtime_username, state: enabled | disabled | missing | failed | drifted, error, revision, learned}`, `reported_at`. `learned` (`{}` when absent) is a bounded map of link facts the runtime taught the node — `host`/`port` for Telemt, `share_template` for mita — never a credential. Observed reports (`ObservedGeneration`, `ObservedResource`, the push response) may gain fields; a central ignores unknown ones, whereas what the node validates (`GenerationDocument`, `Resource`, `PushRequest`) still refuses them with 422.
- **Secret purposes** in `secret_versions` that the two sides rely on: `node-api-key` (the node's key, on the central), `fleet-managed` (pushed credentials, on the node), `grant.credential` (the central's own escrow).

## Routing, frozen alongside

The identifiers above do not change; `schema_version` stays 1 and `api_version` stays 2 because everything routing adds is optional on the wire and ignored by a reader that does not know it:

- **Capability `egress.v1`** in `identity.capabilities`, next to `generation.v1`, `credentials.capture`, `versions.update`, `unlink`; with it `identity.protocols[naive|mieru].egress = {backend: naive_native | mieru_native, capabilities[], providers: {warp: {reachable}}, revision, mode: direct | proxy | custom, restart_required, applied_digest, warnings[]}` (`null` for MTProxy, a disabled service or a manager that does not answer). The provider's endpoint is never part of it.
- **`GenerationDocument.egress`** — optional, `{naive | mieru: EgressDocument{backend, policy_id, policy_revision, document, digest}}` with `digest` = SHA-256 of the canonical JSON of `document` (sorted keys, compact, ASCII) and `document` ≤ 16 KiB. The central sends it only to a node with `egress.v1`; **left out of the wire form and of the digest when absent**, so a document without egress has the same digest for a node with or without `egress.v1`. Present, it is part of `canonical_digest` and of `content_digest`.
- **Compiled documents** (what the managers validate): `naive_native` — `{"schema": 1, "upstream": {"provider": "warp"} | null, "acl": [{"deny": [subject…]}, …]}`; `mieru_native` — `{"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules": [{"domains": [], "cidrs": [], "action": "DIRECT" | "PROXY" | "REJECT", "proxy": "warp" | null}, …]}`. `schema: 1` and the provider name `warp` are frozen; a new provider or field is `schema: 2`.
- **`ObservedGeneration.egress`** — `{protocol: {state: converged | failed | unsupported, revision, digest, error}}`, `{}` when the node has nothing to report; an older central ignores it (observed reports may gain fields).
- **Manager egress API** on the existing UDS with the same token: `GET /v1/egress`, `POST /v1/egress/plan | apply | rollback` with `expected_revision`, `document`, `operation_id`; refusal codes `egress_conflict`, `egress_invalid`, `egress_unreachable`, `egress_readback_mismatch`, `manual_intervention_required`, `egress_no_previous`, `operation_conflict`. The naive-manager's markers `# BEGIN NAIVE-MANAGER EGRESS` / `# END NAIVE-MANAGER EGRESS` and the state key `egress` in `users.json`; the mieru-manager's journal operations `egress.apply` / `egress.rollback`.
- **Environment** `NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP` (`socks5://host:port`, empty = no provider) and the installer section `[egress]` (`warp`, `warp_port`, `naive`, `mieru`) with `[three_xui].warp` / `warp_port` still read as a fallback.
- **Routing API and audit** `/api/routing/*` with the codes `policy_not_found`, `policy_conflict`, `policy_applied`, `unsupported`, `protocol_out_of_scope`, `node_not_found`, `backend_mismatch`, `managed_by_central`, `node_not_local`, `manager_unavailable` and the compiler's reasons (`backend_capability_missing`, `rule_kind_unsupported`, `private_destination`, `provider_unavailable`, `provider_unreachable`, `protocol_disabled_on_node`, `node_lacks_egress_v1`, `document_too_large`); audit actions `routing.policy.update | apply | rollback | delete`; migration 14 (`routing_policies`, `routing_rules`, `routing_applies`, `managed_egress`) is additive.

## The Xray-router, frozen alongside

`schema_version` and `api_version` do not change: everything the router adds is optional on the wire, omitted when absent, and ignored by a reader without `egress.router.v1` (`panel/tests/test_routing_fleet_router.py` and `test_routing_fleet.py` prove both directions).

- **Capability `egress.router.v1`** in `identity.capabilities`; with it `identity.router = {available: true, xray_version, capabilities[], providers: {warp: {reachable}}, services: {naive | mieru: {revision, applied_digest}}}` or `{available: false, reason}`, and `identity.protocols[naive|mieru].egress.router_attached` (boolean). A central without the capability in its vocabulary ignores both.
- **`EgressDocument.backend`** gains the value `xray_router`; **`EgressDocument.companion`** (optional: the document the *other* manager applies right after — the native attach document beside a router pass-through, or the router pass-through beside a native direct) and **`EgressDocument.passthrough`** (optional boolean) are **left out of the wire form and of the digest when absent/false**, so a generation without a router section keeps its digest and a node without `egress.router.v1` never sees them: the central sends a router section only to a node with `egress.router.v1` (`node_lacks_router` otherwise).
- **The router intent** (what the router validates): `{"schema": 1, "default": {"action": "direct" | "egress", "egress": "warp" | null}, "rules": [{"domains": [], "geosites": [], "cidrs": [], "geoips": [], "ports": [], "action": "direct" | "block" | "egress", "egress": "warp" | null}, …]}`, ≤ 128 rules, ≤ 64 selectors of each kind, ≤ 32 ports, ≤ 16 KiB; the pass-through is `{"schema": 1, "default": {"action": "direct", "egress": null}, "rules": []}`. **Attach documents**: `naive_native` `{"schema": 1, "upstream": {"provider": "router"}, "acl": []}`, `mieru_native` `{"schema": 1, "proxies": [{"name": "router", "provider": "router"}], "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]}` — the provider name `router` joins `warp` under `schema: 1`.
- **`ObservedEgress.router`** — `{revision, digest}` of the router section the node applied beside the native one; an older central ignores it. `RoutingPolicy.backend` gains `xray_router`; `Compiled.compiler_version` is `"2"`; `RuleMatch` gains `geosites[]` / `geoips[]` (codes `^[a-z0-9][a-z0-9@!_-]{0,63}$`, `private` refused); migration 15 rebuilds `routing_policies`/`routing_rules`/`routing_applies` with the new backend and adds `managed_egress.router_revision` / `router_digest` (additive: every existing row survives).
- **Router manager API** on its own UDS (`/run/xray-router/manager.sock`, Docker secret `xray-router-manager-token`, header `X-Xray-Router-Token`): `GET /v1/status`, `GET /v1/health`, `GET /v1/egress/{naive|mieru}`, `POST /v1/egress/{svc}/plan | apply | rollback`; codes `egress_invalid`, `geosite_unknown`, `geoip_unknown` (422), `egress_conflict`, `operation_conflict`, `egress_no_previous`, `egress_unreachable` (409), `egress_readback_mismatch` (502), `artifact_mismatch`, `manual_intervention_required` (503). Capabilities: `whole_direct`, `whole_warp`, `block_domain | block_cidr | block_port | block_geosite | block_geoip`, `selective_domain | selective_cidr | selective_port | selective_geosite | selective_geoip`.
- **Host identifiers**: container `proxy-control-xray-router` (Compose service `xray-router`, overlay `compose.xray-router.yaml`, image context `xray_router_manager/`), identity `xray-router` 10006:10006, binaries `/usr/local/lib/proxy-control/xray-router/{xray,geoip.dat,geosite.dat}`, state `/var/lib/xray-router` (0700), ingresses `127.0.0.1:45101` (naive) and `127.0.0.1:45102` (mieru), secrets `secrets/xray-router-manager-token`, `secrets/xray-router-ingress-naive`, `secrets/xray-router-ingress-mieru` (root:10006 0440, `user:password`), the managers' copies `/var/lib/naive-manager/xray-router-ingress` and `/var/lib/mieru-manager/xray-router-ingress` (0400), volume `xray-router-run`, marker `/etc/proxy-control/xray-router-owned`, helpers `/usr/local/libexec/prepare-xray-router-state` and `rotate-xray-router-ingress`, env `.env.xray-router` (`XRAY_ROUTER_BIN_DIR`, `XRAY_ROUTER_STATE_DIR`, `XRAY_ROUTER_XRAY_SHA256`, `XRAY_ROUTER_GEOIP_SHA256`, `XRAY_ROUTER_GEOSITE_SHA256`, `XRAY_ROUTER_EGRESS_WARP`) and the managers' `NAIVE_EGRESS_ROUTER` / `NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE`, `MIERU_EGRESS_ROUTER` / `MIERU_EGRESS_ROUTER_CREDENTIAL_FILE`; the installer's `[egress] router` and the choice `router` for `naive` / `mieru`; the pinned artifact `xray` 26.3.27 (`Xray-linux-64.zip`) in `release/external-artifacts.json` with per-member digests.
- **Routing API and audit**: `POST /api/routing/targets/{node}/{protocol}/attach | detach`; `targets[].router = {available, attached, xray_version, restart_required, reason}` and `targets[].backend = xray_router` for an attached service; `PolicyInput.backend`; the codes `router_unavailable`, `router_unreachable`, `not_attached`, `node_lacks_router`, `artifact_mismatch` (503), `geosite_unknown`, `geoip_unknown` and the warning `router_credential_stale`; audit actions `routing.target.attach | detach`.

## Lanes and chains — additive on the wire

`schema_version` and `api_version` are unchanged. New, all optional and absent from the wire and the digest
when unused: `Resource.lane` (`"own"`), `GenerationDocument.relay` (`{enabled, port, server_name,
accounts[{email: relay:<guid>:<direct|warp>, credential_ref}]}` — the UUIDs travel in the push's `secrets`),
`ObservedGeneration.relay` (`{state, enabled, port, server_name, public_key, short_id, accounts[], error}`),
`ObservedEgress.lanes[]`; capabilities `egress.lanes.v1`, `relay.v1`; `identity.router.relay`
(`{enabled, port, server_name, public_key, short_ids, accounts}`) and `identity.router.lanes`. A central sends the
new fields only to a node that declared the capabilities (`node_lacks_lanes`, `node_lacks_relay` otherwise);
a central that does not know them ignores the new report fields. A policy's exit is a string `warp | node:<guid>[,…][:warp]`, a
policy key carries `lane` (`svc` for the service's own policy); migration 16 is additive in effect. New routes:
`POST /api/routing/lanes/{grant_id}`, `POST /api/routing/policies/{node}/{protocol}/explain`,
`POST /api/routing/relay/{node}/enable | rotate`; every policy route takes `?lane=`. Secret purpose
`relay-account`. Host identifiers: relay port 45443 (`[egress] relay_port`), slot units `mita@<n>` with sockets
`/run/mita/lane-<n>.sock`, state `/var/lib/mita/lanes/<n>`, ports `46100+n`, env `MIERU_LANE_SLOTS`; the
router's `lanes.json` and `relay.json` in `/var/lib/xray-router` (0600); router intent schema 2.

## v1.1: MTProxy routing — additive on the wire

`schema_version` and `api_version` are unchanged. New, optional: capability `egress.mtproxy.v1`; the key
`mtproxy` in `GenerationDocument.egress` (sent only to a node that declared the capability,
`node_lacks_mtproxy_egress` otherwise) and in `identity.protocols[*].egress` / `identity.router.services`
(the latter only when the node's router manager serves it). Backend value `mtproxy_native`; Telemt's native
documents `{"schema": 1, "upstream": null | {"provider": "router"}}`. Codes `router_lacks_mtproxy`,
`ingress_unreachable`, `node_lacks_mtproxy_egress`, `telemt_api_unsupported`, `egress_reload_failed`.
Migration 21 (`routing_policies`, `managed_egress` allow `mtproxy`/`mtproxy_native`) is additive in effect.
Router manager: service `mtproxy`, `GET /v1/ingress/mtproxy`, `ingress-mtproxy.json` in `/var/lib/xray-router`
(0600), env `XRAY_ROUTER_INGRESS_MTPROXY_SOCKET` (empty turns the ingress off). Host identifiers: Compose service
and container `xray-router-ingress` / `proxy-control-xray-router-ingress` (port 45103 on the Compose network,
never published), socket `/run/xray-router/ingress-mtproxy.sock` in the `xray-router-run` volume; the panel's
journal `/data/telemt-egress.json`.

## TrustTunnel (v1.6)

AdGuard's HTTP/2-over-TLS VPN as a fifth protocol, TCP only. Additive: `schema_version` and `api_version` do not change, an older
node simply does not declare the capabilities below.

- **Protocol id** `trusttunnel` (`Resource.protocol`, `identity.protocols.trusttunnel`, placement and routing enums of the MCP
  tools). `credential_origin = caller` (the password is made by the panel and kept in its escrow), capture is not supported, and
  the options are `{hostname, port, certificate_der_b64, name}` (all learned at issue time, `name` optional).
- **Capabilities** in `identity.capabilities`: `protocol.trusttunnel.v1` (the node serves TrustTunnel grants; a central skips a
  node without it and refuses the grant at once) and `egress.trusttunnel.v1` (the node routes TrustTunnel: backend
  `trusttunnel_native`, direct only, or attached to the Xray-router). `GenerationDocument.egress` may carry a `trusttunnel`
  entry only for a node that declared the latter. Routing refusals: `router_lacks_trusttunnel`, `node_lacks_trusttunnel_egress`,
  `lanes_unsupported` (TrustTunnel has no per-client lanes).
- **Manager API** on its own UDS (`/run/trusttunnel-manager/manager.sock`, Docker secret `trusttunnel-manager-token`, header
  `X-Trusttunnel-Token`): `GET /v1/health`, `GET /v1/endpoint`, `GET /v1/clients`, `POST /v1/clients`,
  `POST /v1/clients/{user}/enable | disable | rotate`, `DELETE /v1/clients/{user}`, `GET /v1/egress`,
  `POST /v1/egress/plan | apply | rollback`. Health reports `degraded` with code `certificate_missing` or `endpoint_down`.
- **Host identifiers**: container `proxy-control-trusttunnel-manager` (Compose service `trusttunnel-manager`, overlay
  `compose.trusttunnel.yaml`, image context `trusttunnel_manager/`), state `/var/lib/trusttunnel-manager` (0700), secret
  `secrets/trusttunnel-manager-token`, volume `trusttunnel-manager-run`, marker `/etc/proxy-control/trusttunnel-owned`,
  env `.env.trusttunnel` (`TRUSTTUNNEL_MANAGER_TOKEN_FILE`, `TT_MANAGER_STATE_DIR`, `TT_CERT_DIR`, `TT_HOSTNAME`, `TT_LISTEN`,
  `TT_VERSION`, `TT_SHA256_X86_64`, `TT_SHA256_AARCH64`, `TRUSTTUNNEL_MANAGER_SOCKET_GID`, `TRUSTTUNNEL_PUBLIC_HOST`), the panel's
  `TRUSTTUNNEL_ENABLED`, loopback `127.0.0.1:4453` (the endpoint, `[trusttunnel] listen_port`) and `127.0.0.1:1987` (metrics),
  the Xray-router's no-password SOCKS5 ingress `127.0.0.1:45104` (`XRAY_ROUTER_PORT_TRUSTTUNNEL`), the installer section
  `[trusttunnel]` with `domains.trusttunnel`, and the pinned artifact `trusttunnel` 1.1.0 in `release/external-artifacts.json`.
- **Access artifacts**: `trusttunnel_link` (`text/uri-list`, `tt://?` + base64url without padding of TLV records) and
  `trusttunnel_toml` (`application/toml`) and, since 2.1, `trusttunnel_manual` (`application/json`: `server`, `port`, `username`,
  `password`, `sni`, `protocol` `HTTP/2`, `quic` false, `certificate_pem` or null, `surge` policy line; no QR); the Clash/mihomo feed
  carries `type: trusttunnel`, and the sing-box feed carries the fork cores' `trusttunnel` outbound (`type`, `tag`, `server`,
  `server_port`, `username`, `password`, `quic` false, `tls`) only for a request that names a fork-core client: a User-Agent with
  `Throne`, `NekoBox`, `NyameBox`, `NekoRay` or `Hiddify` (when `format` is absent or `singbox`), `PANEL_SINGBOX_FORK_CLIENTS`
  extra tokens, or an explicit `client=throne|nekobox|nyamebox|hiddify`. `GET /s/{token}` now varies on `User-Agent` and the
  reveal's `variants` gain `singbox-hiddify` and `singbox-nekobox`.
- **Subscription compatibility matrix** (`panel/subscriptions/compatibility.py`, vocabulary `supported | unproven | unsupported`),
  row `trusttunnel`: `mihomo` supported (documented by the core vendor, not verified by us); `hiddify` supported (verified 2026-10-19
  against hiddify-sing-box built from master `ae5cb1488`); `karing`, `shadowrocket`, `nekobox`, `throne`, `v2rayn` unproven (Throne:
  profile type but no `tt://` import, manual steps in the note); `singbox`, `mieru_cli`, `telegram` unsupported. Upstream sing-box has
  no TrustTunnel outbound (SagerNet/sing-box#3723), so the feed leaves it out with a note for official and unknown clients.

## Monitoring (v2.0)

Additive; `schema_version` and `api_version` do not change.

- **Capability** `metrics.v1` in `identity.capabilities`: the node serves its own meters on `GET /api/fleet/v2/metrics`,
  `/api/fleet/v2/metrics/history` and `/api/fleet/v2/metrics/summary` (the `node-sync` key, `no-store`). A central panel pulls them
  only while a person watches; a node without the capability is `unsupported` on the monitoring screen and nothing else changes.
- **Panel API** `GET /api/metrics/live | stream | history | summary` (any signed-in role; the series ids, ranges and statuses are in
  `MONITORING.en.md`). `/api/metrics/stream` is an endless SSE response and is not exposed as an MCP tool; the other three are.
- **Agent API** `GET /v1/metrics` on the version-agent socket (`503 metrics_warming_up` until the first sample).
- **Database** migration 25, table `metric_rollups`; a 1.x image refuses a schema-25 database.
- **Host** one nftables table, `inet proxy_control_metrics`, owned by the agent (counters only, removable with
  `nft delete table inet proxy_control_metrics`), and the optional file `/etc/proxy-control/metrics-ports.json`.

## Verification: nothing new on the wire

`schema_version`, `api_version`, the Fleet v2 documents and every identifier above are unchanged. Two additive
relaxations: `MieruOptions.quotas` defaults to `[]` (a grant request may omit it — the Clients screen always
did), and a local attach/detach records the backend's pass-through digest on the policy (in the existing
columns). `docs/VERIFICATION_MATRIX.md` lists every route with the row that proves it; `scripts/dev/route-coverage.py`
fails the full gate on a route that is not gated, not mentioned by a test, or public without being listed.
