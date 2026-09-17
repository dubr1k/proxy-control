# ADR 009: Lanes per client and chains through the fleet's relays

Status: accepted (v0.7). Extends ADR 006 (the routing policy IR) and ADR 007 (enforcement
ownership); applies ADR 002 (generations), ADR 003 (one writer per resource) and ADR 005
(secret references) unchanged.

## Context

Through v0.6 a routing policy belonged to a *service* on a node: every client of NaiveProxy
or Mieru went where the service's policy said, and the only exits were «direct» and the
node's own WARP. The owner's requirement for v0.7 is the client's view of it: *«I am a
client of node A; I want my own traffic — and only mine — routed by geosite/geoip rules
through a node of my choice (B), the rest through A's WARP, and I want to set this up for
every client I create.»* Three things had no place in the model: a policy that names one
client, an exit that is another node of the fleet, and a way to compose several nodes.

The spikes in `docs/spikes/CHAINS_PER_CLIENT.md` fixed what each runtime can do: Caddy's
`forward_proxy` with `probe_resistance` falls through to the next handler when `basic_auth`
does not match, so one site can carry one handler per group of users; Xray routes by the
`user` of a SOCKS inbound and dials a `vless`+`reality` outbound through another
(`proxySettings`); mita has one `egress` per daemon and no per-user selector, but daemons
are cheap and independent.

## Decision

- **A lane is the routing identity of a group of users.** On the router's existing
  per-service ingress every lane is one more SOCKS account: `svc:<protocol>` is the
  service's lane (the installer's account, the service's policy as before), `grant:<id>`
  one grant's. Rules render with a `user` selector, so nothing new listens and the
  service's manager keeps owning how users reach the ingress: NaiveProxy gets a
  `forward_proxy` handler per lane at the top of `route {}` (the service's handler last),
  Mieru gets a **slot** — one of N idle `mita@<n>` daemons the installer keeps running —
  that mirrors the lane's users from the main daemon and exits through the lane's
  account. A lane's key is minted by the node's router, shown to the service's manager
  once and stored by the panel never.
- **A policy is keyed by (node, protocol, lane).** The service's policy stays `svc`; a
  grant's lane gets its own policy, born as a copy of the service's. The router runs
  every lane of a service as **one intent** (schema 2): applying any lane folds the others
  in and marks them all applied at one digest; a lane's policy is not deletable on its
  own — withdrawing the lane is the operation.
- **An exit is `warp` or a chain of nodes.** `node:<guid>[,<guid>[,<guid>]][:warp]` names
  up to three relays and the last hop's exit. Every node with a router carries a
  **relay**: a `vless`+`reality` inbound on a public port whose cover is the node's own
  panel TLS, accepting only accounts the central issued — one `(source node, direct|warp)`
  pair per source. The central mints the account on `apply`, escrows it
  (`purpose = relay-account`) and delivers it: to its own router at once, to a linked panel
  in the `relay` section of the next generation (the UUID in the push's `secrets`). Until
  the exit node's report confirms it, the apply is refused as `relay_credential_pending`.
  Middle hops of a chain use the `direct` account, the last one the account of its exit.
- **The node builds its own lanes; the central never holds a lane key.** On a linked
  panel a lane travels as a generation resource with `lane: own`; the node's reconciler
  mints the key on its router, moves the user and reports the lane (and, for Mieru, the
  slot's link template as `learned.share_template`).
- **Wire compatibility.** `lane` on a resource, the `relay` section and the observed
  `relay`/`lanes` are absent from the wire and the digest when unused, so a v0.6 node and
  central agree on every generation that carries none; a node without `egress.lanes.v1` /
  `relay.v1` is refused by code (`node_lacks_lanes`, `node_lacks_relay`) before anything
  is sent.

## Consequences

- One ingress per service still; the router's config grows by one SOCKS account per lane,
  one outbound per chain hop and one inbound for the relay. Limits: 32 lanes and 16
  chains per service, 3 hops, a schema-2 intent of 64 KiB.
- A Mieru lane changes the client's link (the slot's port): the subscription follows, a
  hand-copied link does not. A Mieru lane user is still accepted on the main port and
  then follows the service's policy — the slot mirrors, the main daemon stays the source
  of truth (a v0.7 limit).
- The compiled document of a policy that names a chain carries the relay accounts'
  UUIDs. The API, the diff and the history mask them; the panel's own tables
  (`routing_applies`, `routing_policies.desired_json`, `desired_generations`) keep them in
  the clear, as every router intent already lives in the clear on the node. Rotation
  (`POST /api/routing/relay/{node}/rotate`) is the remedy, and moving those copies into
  escrow is deferred.
- The relay is a public port with a real cover: a scanner sees the panel's TLS; only a
  known UUID gets through, and `geoip:private → block` holds for relayed traffic too.
- UDP stays where it was (mita's UDP direct; nothing relays UDP).
