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
- **Artifacts**: the installer fetches the pinned `Xray-linux-64.zip` from its HTTPS
  URL into `/var/lib/proxy-control/` when it is absent (a hand-staged file is used as it
  is), proves the archive's SHA-256 and extracts exactly three members
  (`release/external-artifacts.json`, each member with its own
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
  `GET /v1/egress/{naive|mieru}`, `POST /v1/egress/{svc}/plan | apply | rollback`; from v0.7
  `GET | POST /v1/lanes/{svc}`, `DELETE /v1/lanes/{svc}/{lane}`, `GET | POST | DELETE /v1/relay`,
  `PUT /v1/relay/accounts` (below); from v0.8 `GET /v1/geodata`, `GET /v1/geodata/codes`,
  `PUT /v1/geodata/settings`, `POST /v1/geodata/update | restore`, `POST /v1/exits/test`
  («Geodata and custom exits» below). The panel is its only client; `docker exec
  proxy-control-xray-router python -m xray_router_manager.healthcheck --status` prints the
  status for an operator or the installer's verify (`--relay`, `--relay-enable <server_name>
  <port>` — the relay).

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

## Lanes, chains and the relay (v0.7)

A **schema 2** intent moves the router from «one policy per service» to **lanes**: `{"schema": 2,
"lanes": {"svc:naive": {default, rules}, "grant:<id>": {…}}, "chains": {"c1": {"hops": [...],
"exit": "direct" | "warp"}}}`. Every lane is a SOCKS account on the service's own ingress; the
rules render with a `user` selector (`grant-<id>` for a grant's lane, the installer's account for
the service's lane, which comes last), so one ingress carries different users along different
policies. Schema 1 renders byte for byte as in v0.5/v0.6.

- **Lane keys**: `POST /v1/lanes/{svc}` `{"lane": "grant:<id>"}` mints (or re-mints) the lane's
  account, puts it on the ingress in a new generation at once and returns it **once** — the panel
  hands it to the service's manager and keeps nothing. `lanes.json` (0600) in the state directory;
  `GET /v1/lanes/{svc}` lists names only; `DELETE /v1/lanes/{svc}/{lane}` forgets one. An intent
  naming a lane without an account is refused (`egress_invalid`).
- **Chains**: every hop carries `guid`, `address`, `port`, `server_name`, `public_key`, `short_id`,
  `uuid`. The render is one `vless` + `reality` outbound per hop (`chain:<svc>:<id>:<n>`), each
  dialled through the previous one (`proxySettings.tag`); a lane rule with `egress: chain:<id>`
  lands on the last hop. On `plan` and `apply` the manager checks every hop's reachability (a TLS
  hello to the cover with its `serverName`, 3 s) and refuses `egress_unreachable` («chain c1 hop 1
  is unreachable») without changing anything. The intent views (`GET /v1/egress/{svc}`) mask the
  hops' `uuid`.
- **Relay**: `POST /v1/relay` `{"server_name", "port"}` brings up a `vless` + `reality` inbound on
  `0.0.0.0:<port>` with the cover `127.0.0.1:8443` (the node panel's TLS); the x25519 keypair is
  minted with `xray x25519` once and lives only in `relay.json` (0600), the `short_id` too.
  `PUT /v1/relay/accounts` `[{"email": "relay:<source guid>:<direct|warp>", "uuid"}]` — the
  accounts the central issued; a `…:warp` account leaves through the router's `warp` (without WARP
  on the node: `egress_invalid`), the others `direct`; `geoip:private → block` holds here too.
  `DELETE /v1/relay` takes the inbound down, the keypair stays. `GET /v1/relay` and
  `status.relay` show the public part only (`enabled, port, server_name, public_key, short_ids,
  accounts` — a count).
- Each of these commits a new generation with the same intents (`_rerender_current`) — the same
  «render → `xray run -test` → swap → readback» transaction, the previous generation kept for a
  rollback; the router's `capabilities` gain `lanes`, `chains`, `relay`.

Limits: ≤ 32 lanes and ≤ 16 chains per service, ≤ 3 hops per chain, a schema-2 intent ≤ 64 KiB.

## Geodata and custom exits (v0.8)

**Geodata.** Xray reads `geosite.dat`/`geoip.dat` from `<state>/geodata` (`XRAY_LOCATION_ASSET`),
not from the binary directory: on first start the manager copies the pinned pair there (their
digests are still checked at start), and from then on the files are the operator's choice —
`xray` (the pin), `loyalsoldier` (`https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/…`)
or two HTTPS URLs of your own. A refresh is a transaction: both files are downloaded under
temporary names (≤ 64 MiB, HTTPS end to end, the `<url>.sha256sum` sidecar checked when the
publisher offers one), the running generation's config is `xray run -test`-ed against the
candidates (a code the new lists lack fails here — `geodata_rejected`), then an atomic swap and
a restart of the current generation. A failure leaves the old files in place and lands in
`last_error` (`geodata_fetch_failed`, `geodata_digest_mismatch`, `geodata_too_large`,
`geodata_corrupt`). Automatic refreshes run from the watchdog thread at `interval_hours`
(1…336, default 24); `meta.json` beside the files keeps the source, the version (release tag),
the date and the sha256s. `restore` returns to the pin and switches the automatic refresh off.
The manager parses the lists' codes from the protobuf itself (`/v1/geodata/codes`, cached by
sha256) for the rule editor's suggestions. Capability `geodata`.

**Custom exits.** A schema-2 intent carries `exits: {<id>: {protocol, address, port, credential,
transport, security, method?, flow?}}` (≤ 16) and a rule or the default names `egress: exit:<id>`;
the renderer emits the outbound `exit:<svc>:<id>` (`socks`/`http` with `users`, `vless` with
`vnext`, `trojan`, `shadowsocks`; `streamSettings` per transport and `tls`/`reality`). The
credential is masked in `redact_intent`, the status and the diff. A rule may stand on
`protocols` (`http | tls | quic | bittorrent`) — Xray's `protocol` rule field on the ingress
sniffer (`routeOnly`). Capabilities `custom_exits`, `block_protocol`, `selective_protocol`.
`POST /v1/exits/test` `{exit}` starts a throwaway `xray` with a `dokodemo-door` on loopback to
`www.cloudflare.com:443` through that outbound and makes one TLS fetch of `/cdn-cgi/trace`:
`{ok, ip, colo, latency_ms}` or `{ok: false, code: exit_invalid | exit_test_failed |
exit_unreachable}`; the running router is untouched, one probe at a time.

## Limits and what is deferred

Rules ≤ 128 per policy, ≤ 64 selectors of each kind, ≤ 32 ports, the compiled intent
≤ 16 KiB per service (schema 2: 64 KiB); the manager token 64 hex. Deferred beyond v0.5
(spec §15): a static bridge into 3x-ui's Xray, canary rollouts, UDP relay, regular
expressions; per-grant routing arrived in v0.7 as lanes. Compatibility with v0.4 nodes and centrals is in
[COMPATIBILITY](COMPATIBILITY.md) and [FLEET](../FLEET.en.md).
