# Proxy Control routing (v0.4–v0.5): where each service lets its clients' traffic out

**English** · [Русский](ROUTING.ru.md)

## Overview

Since v0.4 the operator sets, per node and per proxy service, an **egress policy**:
the whole service goes **directly** or **through the host's WARP**, and ordered
first-match **rules** block destinations or (where the backend can) send some of them
the other way. The policy is engine-neutral ([ADR 006](adr/006-routing-policy-ir.md)):
it names domains, networks and the targets `direct | block | egress: warp` — never an
address, a config path or a raw directive. The panel **compiles** it for the backend the
node actually runs, shows the compiled result and every limitation as a **preview**, and
applies it **transactionally** through the service's manager, with a rollback.

Since v0.5 a node may run the dedicated **Xray-router** ([XRAY_ROUTER](XRAY_ROUTER.en.md)):
a service the operator **attaches** to it sends its whole traffic through the router's
private ingress, and its policy is then enforced by Xray — with `geosite`, `geoip` and
port selectors, and a block rule **beside** a WARP default, which the native backends
cannot do. Attaching is an explicit action, never a side effect of a policy.

What can be enforced is what the spikes proved on the stand
(`spikes/VNEXT_ROUTING_ENGINE.md`, `spikes/XRAY_EGRESS_ROUTER.md`), not what the engines'
documentation promises. Where a backend cannot honour a rule, the preview says
`unsupported` and names the rule; nothing is narrowed to «the whole service» silently.

| Service | Backend | Enforces | Does not enforce |
| --- | --- | --- | --- |
| NaiveProxy | `naive_native` — Caddy forwardproxy `upstream` + `acl` | the whole service direct or through WARP; block by domain (`example.com`, `*.example.com`) and by CIDR | selective `direct`/`egress` rules (one upstream per service); a block **beside** a WARP default — forwardproxy skips its ACL when an upstream is set; block by port, geosite, geoip |
| Mieru | `mieru_native` — mita `egress` | the whole service direct or through WARP; block by domain and by CIDR; selective `direct`/`egress` by domain and by CIDR, in order | block by port, geosite, geoip; `*.example.com` and `example.com` are the same selector (mita matches domain suffixes) |
| NaiveProxy or Mieru **attached to the Xray-router** (v0.5) | `xray_router` — Xray `routing` rules per ingress | the whole service direct or through WARP; `block`, `direct` and `egress: warp` rules by domain, `geosite:`, CIDR, `geoip:` and port, in order, any of them beside a WARP default | UDP (mita's UDP stays direct); per-grant rules |
| MTProxy (Telemt) | — | — | out of scope: `protocol_out_of_scope` |

Private destinations — loopback, link-local, RFC 1918, CGNAT and their IPv6
counterparts, plus `localhost` — may be **blocked** but never opened by a `direct` or
`egress` rule (`private_destination`). Caddy denies them by default; mita must not hand a
client the node's loopback.

## The policy

One policy per (node, protocol), edited on the «Маршрутизация» screen or through
`/api/routing/*`:

```text
default_action   direct | egress          default_egress  warp (with egress)
fallback         fail_closed | approved_direct
rules[]          enabled, action: direct | block | egress, egress: warp (with egress),
                 match: {domains[] ≤ 64, geosites[] ≤ 64, cidrs[] ≤ 64, geoips[] ≤ 64, ports[] ≤ 32},
                 note ≤ 120
backend          naive_native | mieru_native | xray_router (v0.5; the target's current one)
```

- domains are lower-cased IDNA; `*.example.com` means «any subdomain», `example.com`
  the host itself (on Mieru both are the suffix `example.com`); CIDRs are normalised
  (`10.1.2.3` → `10.1.2.3/32`); a rule needs at least one selector; `geosites` and
  `geoips` (v0.5) are Xray geodata codes (`category-ads-all`, `cn`, `cloudflare`, …;
  `geoip:private` is never accepted — the router blocks it by itself) and `ports`
  (`443`, `1000-2000`) are enforced only by the `xray_router` backend; on a native
  backend they preview as `rule_kind_unsupported`;
- at most 128 rules; the compiled document is at most 16 KiB per protocol;
- `backend` names the backend the policy is compiled for: the service's native one, or
  `xray_router` while the service is attached. Saving a policy for the other backend is
  refused (`backend_mismatch`); attach/detach retarget the existing policy and leave it
  as a draft to review;
- `revision` grows with every save (`expected_revision` on `PUT` → 409 `policy_conflict`
  when somebody saved in between); `applied_revision`/`applied_digest` say what the node
  runs — `state = applied` **and** `applied_revision = revision` is «applied», otherwise
  the card says «есть неприменённые изменения».

`fallback` is the one explicit way to trade fail-closed for availability: with
`approved_direct`, a WARP the node reports as unreachable makes the compiler replace
`warp` with `direct` and say so in the preview (`provider_unreachable` as a warning).
With `fail_closed` (the default) the preview is `unsupported` and nothing is applied.

## Preview and apply

`POST …/preview` (with a draft body, or without one for the stored policy) returns the
compiled document, its digest, the diff against what the node runs, whether a restart is
needed (mita: yes; Caddy: a reload), the rollback target, and — when unsupported — the
reasons:

| Reason | Meaning |
| --- | --- |
| `backend_capability_missing` | the node's manager does not declare the capability this rule needs (e.g. `selective_domain` on NaiveProxy), or the policy is native while the service is attached to the router |
| `rule_kind_unsupported` | a native backend cannot enforce this (block by port, `geosite`, `geoip`; a block beside a WARP default on NaiveProxy) — the reason names the router |
| `router_unavailable` | the policy is for the router, but the node runs none or it does not answer (v0.5) |
| `not_attached` | the policy is for the router, but the service is not attached to it — attach first (v0.5) |
| `node_lacks_router` | a linked panel without `egress.router.v1`: update it to v0.5 and install the router (v0.5) |
| `artifact_mismatch` | the router refuses to run: its binary or geodata do not match the pinned release (v0.5, 503) |
| `geosite_unknown` / `geoip_unknown` | Xray does not know that geodata code (v0.5, from the router's own test run) |
| `private_destination` | a `direct`/`egress` rule names loopback or a private network |
| `provider_unavailable` | the node has no WARP configured (`NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP` empty) |
| `provider_unreachable` | WARP is configured but does not answer; `fallback = approved_direct` turns this into a warning |
| `protocol_disabled_on_node` | the service is not enabled on that node |
| `node_lacks_egress_v1` | a linked panel older than v0.4 |
| `protocol_out_of_scope` | MTProxy |
| `document_too_large` | over 16 KiB |
| `manager_unavailable` | the local manager did not answer |

Warnings: `adopts_unmanaged_upstream` / `adopts_unmanaged_egress` (the node carries an
`upstream` or an `egress` section somebody wrote by hand — the first apply moves it under
the manager's ownership and keeps the original for a rollback), `policy_empty` (direct,
no rules: what «reset» applies), `router_credential_stale` (v0.5: the ingress key on the
node was rotated while the manager was down; it re-renders its block at its next start).

`POST …/apply` with `expected_revision`:

- **local node** — the panel asks the manager to plan and apply
  (`POST /v1/egress/plan`, `POST /v1/egress/apply` on the manager's socket, idempotent
  by `operation_id = routing:<policy>:<revision>`); the manager probes WARP, writes the
  config, reloads or restarts the service, reads the running config back, and keeps the
  previous entry in its journal. The outcome, the `routing_applies` row and the audit
  event `routing.policy.apply` are written in one transaction *after* the manager
  answered — manager I/O never runs under a database lock;
- **linked panel** — the policy's compiled document becomes the `egress` section of the
  node's next Fleet v2 generation (`state = applying`); the node applies it after the
  resources and reports `converged | failed | unsupported` per protocol, and the central
  moves the policy to `applied` or `failed` from that report (see [FLEET](../FLEET.en.md)).
  A router policy travels the same way with `backend: xray_router`; the node applies it
  through its router and reports the router's revision beside the native one.

### Attach and detach (v0.5)

`POST /api/routing/targets/{node}/{protocol}/attach` hands a service to the node's
Xray-router: the router first gets the service's section as pass-through (direct, no
rules), then the native manager's block is set to the router's ingress (Caddy `upstream
socks5://…@127.0.0.1:45101`, mita `egress` naming the `router` proxy). The service's
policy, if any, is retargeted to `xray_router` as a draft; the target now reports
`backend: xray_router` and `router.attached: true`. `…/detach` is the reverse order: the
native block back to direct, then the router's section to pass-through. Both are
owner-only, audited (`routing.target.attach | detach`) and, on a linked panel, travel as
one generation whose `egress` section carries a **companion** document for the other
manager (`passthrough: true` marks the pass-through). Sessions of the service are
interrupted by an attach or a detach (Caddy reloads, mita restarts). A native policy with
rules that is still applied refuses to attach (`policy_applied`): reset it to direct
first.

Refusals are codes, never manager copy: 409 `policy_conflict`, 422 `unsupported` (with
the compiled preview in the body), the manager's own `egress_conflict`,
`egress_invalid`, `egress_unreachable` (409), `egress_readback_mismatch` (409 — the
manager restored the previous config), `manual_intervention_required` (503 — the manager
could not restore it; its backup path is in the manager's log), `manager_unavailable`
(502), `managed_by_central` (409 — a central manages this node's egress; apply there).

`POST …/rollback` returns the node to the manager's previous journal entry (local) or
to the previous applied document of the central's own history (linked panel — one step
back, not a stack). `DELETE` is allowed only once the node runs «direct, no rules»
(otherwise 409 `policy_applied`): forgetting a policy never changes what a node enforces.

## What the managers own ([ADR 007](adr/007-routing-enforcement-ownership.md))

- **naive-manager** owns exactly one block inside `forward_proxy` of its Caddyfile:

  ```text
  # BEGIN NAIVE-MANAGER EGRESS
  upstream socks5://127.0.0.1:45000
  acl {
      deny example.com *.example.com 10.0.0.0/8
  }
  # END NAIVE-MANAGER EGRESS
  ```

  Everything outside the block — the user block, the accounting block, the cover site —
  stays byte for byte. The provider's URL comes from `NAIVE_EGRESS_WARP`; the panel never
  sends an address. Revision = SHA-256 of the block; the journal (`users.json`, `egress`)
  keeps the last ten entries and the lines a first apply adopted.
- **mieru-manager** owns the `egress` section of mita's config (`proxies` with the WARP
  endpoint from `MIERU_EGRESS_WARP`, `rules` with `domainNames`/`ipRanges`/`action`),
  applied through the same transaction and journal as user changes, in **restart** mode:
  `mita reload` does not pick a new egress up. A direct policy removes the section.
- The mieru-manager container runs on the host network (no listener of its own, still
  `read_only` and `cap_drop: ALL`) so it can probe the WARP endpoint on the host loopback
  before applying.

Both managers refuse a document that is outside their schema (`egress_invalid`), one
whose provider is not configured on the host, and — before writing anything — a
provider that does not answer a TCP connect and a SOCKS5 greeting (`egress_unreachable`).
The WARP endpoint itself refuses loopback and RFC 1918 destinations (Cloudflare's proxy
mode does), which is one more reason the compiler refuses to open them.

- **The Xray-router** (v0.5) owns only its own generations under `/var/lib/xray-router`:
  one Xray configuration rendered from the two services' typed intents, tested with
  `xray run -test`, swapped, read back and committed; the previous generation stays for
  a rollback. Its second provider is the same host WARP (`XRAY_ROUTER_EGRESS_WARP`), and
  the managers know the router as the provider `router` (`NAIVE_EGRESS_ROUTER`,
  `MIERU_EGRESS_ROUTER` with the credential file each manager keeps in its own state
  directory). The credential is the service's identity on the ingress: the router only
  reads it, the managers write it into their own blocks, and no API view, generation,
  audit row or report ever carries it. Details, the DNS semantics and the limits are in
  [XRAY_ROUTER](XRAY_ROUTER.en.md).

## WARP on the host

The installer's `[egress]` section (`warp`, `warp_port`, `naive`, `mieru`) installs
Cloudflare WARP in proxy mode and seeds each service's initial egress once; an upgrade or
a repair never rewrites what the panel applied later
([INSTALLER_REFERENCE](INSTALLER_REFERENCE.en.md)). A host assembled by hand sets
`NAIVE_EGRESS_WARP=socks5://127.0.0.1:<port>` and `MIERU_EGRESS_WARP=…` in `.env`
itself ([UPGRADING](UPGRADING.md)); without them the targets show no `warp` provider
and every WARP policy previews as `provider_unavailable`.

## Security and audit

- Policies, compiled documents, `identity`, observed reports and audit rows are
  secret-free and carry no provider endpoint; `targets` reports `providers: {warp:
  {reachable}, router: {reachable}}` and `router: {available, attached, xray_version}`
  only — the router's ingress credentials appear nowhere (the managers' views show
  `socks5://***@…`).
- Management traffic is never routed: the panel ↔ manager sockets, ACME, Fleet and the
  heartbeat do not pass through `forward_proxy` or mita's egress.
- Owner for every mutation; any role may read and preview. Audit:
  `routing.policy.update | apply | rollback | delete`, `routing.target.attach | detach`
  ([AUDIT_EVENTS](AUDIT_EVENTS.md)).

## Verification

Unit: `panel/tests/test_routing_ir.py` (validation, the compiler against the capability
matrix, the store), `test_routing_service.py`, `test_routing_routes.py`,
`test_routing_fleet.py` (the generation section, the node, the pusher),
`test_egress_adapters.py`, `tests/test_naive_egress.py`, `tests/test_naive_manager_egress.py`,
`tests/test_mieru_egress.py`; for the router `panel/tests/test_xray_routing_compiler.py`,
`test_routing_router_service.py`, `test_routing_router_routes.py`,
`test_routing_fleet_router.py`, `tests/test_xray_router_*.py`. Stand:
`scripts/dev/remote-gate.sh routing` — the node's managers point at
`scripts/lab/socks5-stub.py` (a SOCKS5 that logs every CONNECT target) and
`fleet-acceptance.py --routing` proves whole-service WARP, block by domain and CIDR with
the cover site alive, Mieru's selective rule, rollback byte for byte, a provider down →
fail-closed, and that nginx and nftables stayed untouched; `remote-gate.sh router` adds
the router scenarios router-01…14 (`--router`): attach, whole-WARP and a block beside
it through the router, port/geosite/geoip rules, the ingress refusing a missing or a
cross-service credential, rollback with Caddy untouched, the watchdog after a SIGKILL,
fail-closed without the provider, key rotation, detach and the untouched host. The
full matrix is in [SECURITY_TEST_MATRIX](SECURITY_TEST_MATRIX.md).
