# ADR 007: Routing enforcement ownership

Status: proposed (v0.5)

## Context

On a managed-new host, 3x-ui owns an Xray process, its template and its geodata.
It is tempting to reuse that process as the general router for Naive and Mieru
traffic as well. It does not work: editing the 3x-ui routing template does not
put Naive or Mieru traffic through Xray at all, and two writers against one Xray
template is exactly the drift ADR 003 forbids.

## Decision

Enforcement backends are separate and explicitly owned:

- the 3x-ui-owned Xray serves 3x-ui's own inbounds only. Proxy Control never
  writes policy generations into it;
- if a dedicated router is used (`xray-router`, v0.5), it is a separate service,
  config, state and generation, with its own private authenticated ingress tags
  for Naive and Mieru. It is never executed from `/usr/local/x-ui/bin`;
- a verified Xray binary from a staged 3x-ui artefact may be copied into a
  Proxy-Control-owned path with its own digest and provenance, as an
  optimisation. The absence of 3x-ui must never break the routing model;
- Naive and Mieru attach whole-service first; per-grant routing stays
  `unsupported` until identity propagation is proven by a spike;
- at most one static, explicitly owned bridge into 3x-ui may be offered later,
  and only after the upgrade/drift gate passes;
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
- Shipping `xray-router` before the v0.5 spike concludes.
