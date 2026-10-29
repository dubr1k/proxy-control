# Architecture

Proxy Control separates public proxy traffic, the panel, local management APIs and
panel-to-panel synchronization. Its panel, managers, installer, version-agent and MCP
server are native Rust programs. Python is used by external development, build and
acceptance tools, not by the shipped runtime.

## Request and management paths

```text
Public TCP/443 → host Nginx stream / SNI
                 ├─ panel HTTPS → loopback HTTP → Rust panel → SQLite + master key
                 ├─ Telemt / MTProxy
                 ├─ Caddy / NaiveProxy
                 ├─ TrustTunnel (optional)
                 └─ existing sites and 3x-ui

Rust panel → authenticated local APIs → protocol managers → protocol runtimes
Central panel → HTTPS + node-sync API key → linked panel → its local managers
```

Mieru uses its own public TCP ports; AmneziaWG uses separate UDP ports. Their traffic
does not pass through the TCP/443 SNI router. 3x-ui remains a separate panel with its
own users and UI; Proxy Control can coexist with it, not replace it.

## Components

| Boundary | Implementation and responsibility |
|---|---|
| Public ingress | Host Nginx owns shared TCP/443 and forwards selected SNI names to loopback listeners. Existing names must keep working. |
| Panel | `panel/crates/web/` builds the `panel` binary. Tokio/Hyper serve HTTP; Axum supplies handlers and extractors. The panel exposes UI, API and `panel cli`, binds to host loopback and has no Docker socket. |
| Clients and state | `panel/crates/clients/`, `model/`, `core/` and `secrets/` hold clients, grants, ownership, sessions, audit and encrypted credentials in SQLite. The separate master key is required to recover retained credentials. |
| Protocol adapters | `panel/crates/protocols/` and `managers/` translate domain operations into bounded local API calls. Protocol-specific capabilities and accounting remain distinct. |
| Telemt | External MTProto runtime with the persistent `telemt-config` volume. Its authenticated API is private to Compose. |
| NaiveProxy and Mieru | External Caddy and mita processes. Rust managers expose token-authenticated Unix APIs and transactional state changes. |
| AmneziaWG | The optional Rust `awg-manager` supervises the pinned `amneziawg-go` runtime and separate interfaces for the enabled versions. |
| TrustTunnel | The optional Rust manager supervises the pinned `trusttunnel_endpoint` subprocess. It uses loopback TLS behind SNI and a token-protected Unix API. Credential changes briefly restart the endpoint. |
| Routing | `panel/crates/routing/` compiles policies. The optional Xray-router adds geosite/geoip, ports, relays and supported per-grant lanes. TrustTunnel routing is per service, not per client. |
| Fleet v2 | `panel/crates/nodes/`, `fleet/` and `fleet-central/` link panels over HTTPS with `node-sync` API keys, desired generations, digests and observed state. No separate Fleet agent or ingress is installed. |
| Host lifecycle | `installer/` applies and repairs the plan from `installer_core/`; `pc_host/` and `pc_common/` provide shared primitives. The release carries verified static installer and version-agent executables. |
| Updates and metrics | `version_agent/` provides the privileged host API through a Unix socket. The panel uses that API rather than mounting Docker's socket. |
| MCP | The optional Rust `mcp_server/` calls the panel HTTPS API with a scoped key. It does not bypass panel authorization. |

## One writer per resource

The Rust clients domain is the only writer behind protocol pages and client APIs.
Import records an existing account without changing it or capturing credentials;
adoption is explicit. Identical usernames across protocols do not establish identity.
A resource owned by a central panel is changed through that central's generation,
not by a second local writer. See [ADR 003](adr/003-one-writer-per-resource.md) and
[Fleet v2](guides/FLEET.en.md).

## One stack per node

All deployed Proxy Control containers share the Compose project
`proxy_panel_by_dubr1k`. Older installations may still use `mtproxy` until explicitly
migrated; never infer that their volumes or state can be deleted.

`compose.yaml` is the base model. NaiveProxy, Mieru, Xray-router, MCP, AmneziaWG and
TrustTunnel use optional overlays of that same model. Persist the complete active
`COMPOSE_FILE` set and its env files, and reuse it for every lifecycle command.
Separate project names or an incomplete overlay list split service discovery,
mounts, ownership, volumes, health checks, backup and rollback.

Fleet v1's mTLS ingress and node agent are retired, not alternative overlays of the
current stack. Existing Fleet v1 state requires explicit migration before an update;
see [compatibility](COMPATIBILITY.md) and [upgrading](UPGRADING.md).

## Monitoring and accounting

The version-agent samples host resources and the counter-only nftables table
`inet proxy_control_metrics`, then serves `GET /v1/metrics` over its Unix socket.
The collector in `panel/crates/metrics/` combines host samples and manager counters,
keeps a live ring and writes rollups to SQLite. `/api/metrics/*` exposes snapshots,
SSE, history and summaries; a central reads linked panels through Fleet v2.
Unavailable sources become `stale` or `unavailable`, never invented values.

Traffic counters differ by protocol and are not an exact billing system. See
[monitoring](guides/MONITORING.en.md) and [accounting semantics](ACCOUNTING.md).

## Trust and compatibility boundaries

Public traffic, panel HTTPS, local management sockets, encrypted persistent state
and linked-panel credentials are separate boundaries. HTTPS peers use WebPKI or an
explicit certificate pin. Request logs and audit must not disclose credentials,
subscription paths or reveal payloads.

A healthy process is not a protocol test. Validate supported mutations through the
real protocol and preserve a complete rollback generation before host changes.
Changing implementation language does not rename deployed paths, identities, API
keys or Fleet contracts. See [compatibility](COMPATIBILITY.md),
[backup and restore](BACKUP_RESTORE.en.md) and [validation](VALIDATION.md).
