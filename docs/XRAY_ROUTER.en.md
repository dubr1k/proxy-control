# The Xray-router (v0.5): one dedicated egress router per node

**English** · [Русский](XRAY_ROUTER.ru.md)

## What it is

Since v0.5 a node may run a dedicated **Xray** process whose only job is to let NaiveProxy
and Mieru traffic out according to the panel's routing policy ([ROUTING](ROUTING.en.md)).
It is optional (`[egress] router = true` in the installer,
[INSTALLER_REFERENCE](INSTALLER_REFERENCE.en.md)); a node without it works exactly as in
v0.4. It is not 3x-ui's Xray and never touches it ([ADR 007](adr/007-routing-enforcement-ownership.md)):
its binary and geodata come from the pinned upstream archive, it runs in its own
container under its own identity, and nothing of it lives under `/usr/local/x-ui`.

```text
NaiveProxy (Caddy) ──upstream socks5://naive-…:key@127.0.0.1:45101──┐
                                                                    ├──> xray-router ──> direct | warp (127.0.0.1:40000) | block
Mieru (mita) ─────egress proxy "router" 127.0.0.1:45102 + auth ─────┘
```

The router has two **ingresses**, SOCKS5 on the host loopback with username/password
authentication, one per service: `naive` on `127.0.0.1:45101`, `mieru` on `45102`. The
credential of an ingress is the service's identity: the router accepts only that pair on
that port, so a process on the host cannot use another service's ingress, and nothing
without a credential gets through. Per ingress the router applies that service's
**section**: the rules of the policy, then the default (`direct` or `warp`).

A service is **attached** to the router by an explicit owner action on the «Routing»
screen (or `POST /api/routing/targets/{node}/{protocol}/attach`): the router first gets a
pass-through section for the service, then the service's manager writes the router's
ingress into the block it owns (Caddy's `upstream`, mita's `egress` with
`socks5Authentication`). **Detach** is the reverse. A policy never attaches a service by
itself; the seed `[egress] naive = "router"` at install time is the same attach, done once.

## What it enforces

Every cell below was proved on the stand (`spikes/XRAY_EGRESS_ROUTER.md`, Xray-core
26.3.27, Caddy 2.11.4 + forwardproxy, mita 3.36):

| Selector / action | `direct` | `block` | `egress: warp` |
| --- | --- | --- | --- |
| domain (`example.com`, `*.example.com`) | ✓ | ✓ | ✓ |
| `geosite:<code>` | ✓ | ✓ | ✓ |
| CIDR | ✓ | ✓ | ✓ |
| `geoip:<code>` | ✓ | ✓ | ✓ |
| port (`443`, `1000-2000`) | ✓ | ✓ | ✓ |
| default for the whole service | ✓ | — | ✓ |

Rules are first-match, in the order of the policy; a block **beside** a WARP default
works (unlike NaiveProxy's own ACL). What is **not** claimed: UDP through the router
(mita's UDP stays direct; the ingresses do not relay UDP), per-grant rules, regular
expressions, a `geoip:private` selector (see below), MTProxy.

### DNS and private destinations

The router resolves with `domainStrategy: IPOnDemand` (Xray's `dns` uses the host
resolver): a name is resolved when a rule needs its address, and the first rule of every
ingress is `geoip:private → block`. So a destination that is, or resolves to, loopback,
link-local, RFC 1918, CGNAT or their IPv6 counterparts is refused before any policy rule,
including a public name rebinding to `127.0.0.1` (the spike used `localtest.me`). This
bypass cannot be turned off and `private` is refused as a geoip code in a policy.
`localhost` and `full:localhost` are blocked by name as well. Sniffing runs with
`routeOnly: true`: the sniffed host is used for routing decisions, never rewritten into
the connection.

## The runtime

- **Container** `proxy-control-xray-router` (Compose service `xray-router`, overlay
  `compose.xray-router.yaml`), host network, identity `10006:10006`, `read_only`,
  `cap_drop: ALL`, `pids_limit: 128`, tmpfs `/tmp`. Binaries are bound read-only from
  `/usr/local/lib/proxy-control/xray-router` (`xray`, `geoip.dat`, `geosite.dat`), state
  from `/var/lib/xray-router` (0700, `prepare-xray-router-state.sh`), the manager socket
  in the tmpfs volume `xray-router-run` (`/run/xray-router/manager.sock`, mode 660, the
  panel joins group 10006).
- **Artifacts**: the installer extracts exactly three members from the pinned
  `Xray-linux-64.zip` (`release/external-artifacts.json`, each member with its own
  SHA-256 and mode); the manager re-checks all three digests before it starts anything
  (`XRAY_ROUTER_*_SHA256` in `.env.xray-router`) and, on a mismatch, answers
  `artifact_mismatch` (503) instead of running an unpinned binary.
- **Manager** (`xray_router_manager`): a supervisor around one child `xray run`. Its
  state is a sequence of **generations** (`generations/<n>/config.json`), `current.json`
  (the running one), `journal.json` (per service: current, previous, history) and
  `state.json` (`phase: idle | swapping | broken`). It renders one Xray configuration
  from the two services' intents plus the credentials it reads from
  `/run/secrets/xray-router-ingress-*`.
- **API** on the Unix socket, header `X-Xray-Router-Token` (Docker secret
  `xray-router-manager-token`): `GET /v1/status`, `GET /v1/health`,
  `GET /v1/egress/{naive|mieru}`, `POST /v1/egress/{svc}/plan | apply | rollback`. The
  panel is its only client; `docker exec proxy-control-xray-router python -m
  xray_router_manager.healthcheck --status` prints the status for an operator or the
  installer's verify.

### The transaction

`apply` for one service: validate the typed intent (schema 1: `default`, `rules[]` with
`domains/geosites/cidrs/geoips/ports`, `action`, `egress`; never raw Xray JSON) → render
generation *n+1* from **all** services' current intents → `xray run -test` on it (a
wrong geodata code fails here: `geosite_unknown` / `geoip_unknown`) → SIGTERM the child
→ start the new one → wait for both ingress ports → read back → commit `current.json`
and the journal. If the new generation does not come up, the last known good one is
started again and the caller gets `egress_readback_mismatch`; if even that fails, the
router is `broken` and answers `manual_intervention_required` (503) until an operator
looks (`docs/OPERATIONS.en.md`). A `warp` default or rule while the WARP endpoint does not
answer its SOCKS5 greeting is refused before anything changes (`egress_unreachable`,
fail-closed). Applies are idempotent by `operation_id`; a stale `expected_revision` is
`egress_conflict`; a swap takes about 50 ms and interrupts the open sessions of *both*
services. A **watchdog** restarts the current generation if the child dies (after three
failed starts the router is `broken`).

`rollback` for one service pops its journal (the previous intent of that service, the
other service unchanged) and applies it as a new generation.

## Credentials and rotation

- `secrets/xray-router-ingress-naive` and `-mieru` (project `secrets/`, root, 0600):
  one line `user:password`, user `<service>-<8 hex>`, password 43 URL-safe characters.
  The router mounts them as Docker secrets and re-reads them at bootstrap; each manager
  keeps its own copy in its state directory (`/var/lib/naive-manager/xray-router-ingress`,
  `/var/lib/mieru-manager/xray-router-ingress`, 0400) and reads it when it renders the
  `router` provider.
- The credential appears in exactly three places on the node: the secret files, Caddy's
  `upstream` line and mita's `socks5Authentication` — plus the router's rendered
  generations. Every API view redacts it (`socks5://***@…`, `socks5Authentication:
  ***`), `plan` diffs redact it, identity and generations never carry it, and the lab's
  secret scan fails on the shape.
- **Rotation**: `sudo /usr/local/libexec/rotate-xray-router-ingress [naive] [mieru]`
  writes new credentials into `secrets/` and the managers' copies, recreates the router
  (Docker file secrets are read at container creation) and then each manager; at
  bootstrap a manager whose block still carries the old key re-renders it
  (`router_credential_stale` while it has not). Rotation interrupts the sessions of the
  rotated services once.

## Operations

- **Status** on the «Routing» screen: the target shows `Xray-router: available /
  attached / not installed`, its Xray version, and the reasons `router_unavailable`,
  `not_attached`, `artifact_mismatch`, `router_unreachable` (the manager could not reach
  the ingress), `node_lacks_router` (a linked panel older than v0.5).
- **Logs**: `docker logs proxy-control-xray-router` (the manager; the child's access log
  is off, no stats/api inbound).
- **Broken router** (`phase: broken`): every apply answers 503
  `manual_intervention_required`; the services attached to it keep their upstream and
  therefore **fail closed**. Look at the log, fix the cause (a full disk, a wrong
  artifact), then `docker compose … restart xray-router` — bootstrap starts the last
  committed generation; or detach the services on the «Routing» screen to route them
  natively while the router is down. `docs/OPERATIONS.en.md` has the runbook.
- **Removal**: detach every service, then `uninstall` (the installer's rollback stops the
  container and removes the binaries, helpers, env overlay; `--purge-data` also the state
  and the secrets) — see `docs/BACKUP_RESTORE.en.md` for what to keep.

## Limits and what is deferred

Rules ≤ 128 per policy, ≤ 64 selectors of each kind, ≤ 32 ports, the compiled intent
≤ 16 KiB per service; the manager token 64 hex. Deferred beyond v0.5 (spec §15): a static
bridge into 3x-ui's Xray, canary rollouts, per-grant routing, UDP relay, regular
expressions. Compatibility with v0.4 nodes and centrals is in
[COMPATIBILITY](COMPATIBILITY.md) and [FLEET](../FLEET.en.md).
