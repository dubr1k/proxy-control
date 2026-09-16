# ADR 007: Routing enforcement ownership

Status: accepted for the native backends (v0.4.0-beta.1, 2026-09-14) and for the
dedicated `xray-router` (v0.5.0-beta.1, 2026-09-16; spec
`superpowers/specs/2026-09-16-v0.5-xray-router-design.md`, spike
`spikes/XRAY_EGRESS_ROUTER.md`)

## Context

On a managed-new host, 3x-ui owns an Xray process, its template and its geodata.
It is tempting to reuse that process as the general router for Naive and Mieru
traffic as well. It does not work: editing the 3x-ui routing template does not
put Naive or Mieru traffic through Xray at all, and two writers against one Xray
template is exactly the drift ADR 003 forbids.

## Decision

Enforcement backends are separate and explicitly owned. **Native backends (v0.4):** the
egress configuration of a data plane belongs to the manager of that service and to
nobody else — the naive-manager owns the marked block `# BEGIN NAIVE-MANAGER EGRESS …
# END` inside `forward_proxy` of its Caddyfile, the mieru-manager owns the `egress`
section of mita's config. The installer seeds the initial state once (the way it seeds
the bootstrap user) and never touches it on upgrade or repair; the panel is the only
client of the managers' egress API (`GET /v1/egress`, `POST /v1/egress/plan | apply |
rollback`); an `upstream` or an `egress` written by hand is adopted as `custom` on the
first apply and restored verbatim by a rollback, never silently overwritten. A node
managed by a central applies what the central's generation says and refuses a local
apply (`managed_by_central`, ADR 003).

**The dedicated router (v0.5):**

- the 3x-ui-owned Xray serves 3x-ui's own inbounds only. Proxy Control never
  writes policy generations into it;
- `xray-router` is a separate service (container `proxy-control-xray-router`, identity
  10006, state `/var/lib/xray-router`), with its own config, generations, journal and
  two private authenticated SOCKS5 ingresses on the host loopback (`naive` 45101,
  `mieru` 45102). It is never executed from `/usr/local/x-ui/bin`: the binary and the
  geodata come from the pinned upstream `Xray-linux-64.zip` the operator stages, each
  member against its own digest, and the manager refuses to start on a mismatch
  (`artifact_mismatch`). The absence of 3x-ui does not enter the routing model at all;
- the router owns nothing but its own generations. The ingress credential is the
  service's identity: the naive-manager writes it into Caddy's `upstream`, the
  mieru-manager into mita's `socks5Authentication`, each inside the block it already
  owns; the router only reads the credential files. Nobody else writes into either;
- a service is handed to the router by an explicit, owner-only action (attach) and
  taken back the same way (detach); a policy never moves a service by itself. The
  policy of an attached service compiles to a typed intent (domains, geosite, CIDR,
  geoip, ports, block/direct/warp) that the router renders into Xray's configuration —
  never raw Xray JSON — with `geoip:private → block` first on every ingress and
  `IPOnDemand` resolution, so a rebinding name cannot reach the host's loopback;
- every apply is a transaction: render, `xray run -test`, swap, readback, commit; a
  failure restores the last known good generation, a provider that does not answer
  is a refusal (fail-closed), and the previous generation is one rollback away;
- Naive and Mieru attach whole-service; per-grant routing stays `unsupported`
  until identity propagation is proven by a spike; UDP through the router is
  `unsupported` (mita's UDP stays direct);
- at most one static, explicitly owned bridge into 3x-ui may be offered later,
  and only after the upgrade/drift gate passes (not in v0.5);
- management access has an immutable bypass so a routing mistake cannot lock the
  operator out; rollback is out-of-band.

## Consequences

- No shared-ownership corruption of the 3x-ui Xray template, and 3x-ui upgrades
  cannot break Proxy Control routing.
- A second Xray process costs memory and one more supervised service.
- Some routing that would "just work" inside 3x-ui requires the dedicated router
  and its spike first.

## Non-goals

- Replacing 3x-ui or taking over its inbounds.
- Routing MTProxy/Telemt traffic (out of scope, ADR 006).
- Routing UDP through the router, or per-grant routing (both `unsupported` in v0.5).
