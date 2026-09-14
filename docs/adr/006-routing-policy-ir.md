# ADR 006: Engine-neutral routing policy IR

Status: accepted (v0.4.0-beta.1, 2026-09-14)

## Context

3x-ui's routing UI is, underneath, an editor for Xray JSON: rules reference
string tags, and the domain model is the engine's config format. That is why its
rules cannot describe anything Xray cannot express, and why a rule that a given
data plane cannot enforce still looks enabled in the panel.

Proxy Control routes three unrelated data planes (Telemt/MTProxy, Naive, Mieru)
whose capabilities genuinely differ, so the panel needs a policy model that can
say "this rule cannot be enforced here".

## Decision

Routing policy is stored as an engine-neutral intermediate representation:

- rules are ordered and first-match; every object is referenced by UUID, never by
  a mutable tag or display name;
- targets are domain concepts (`direct`, `WARP`, `block`, a named egress), not
  engine outbounds;
- a compiler translates the IR into an explicitly chosen enforcement backend, and
  the backend is part of the policy, never substituted silently;
- a rule the chosen backend cannot enforce compiles to a `unsupported` capability
  error surfaced in preview and API — selective routing is never downgraded to
  whole-protocol routing without the operator saying so;
- MTProxy/Telemt is out of routing scope entirely and is not offered as a routing
  target;
- preview shows the compiled result before it is applied; enforcement fails
  closed.

## Consequences

- The panel can be honest about per-protocol limits instead of showing rules that
  quietly do nothing.
- Swapping or adding an enforcement backend does not rewrite stored policy.
- Two representations to keep in sync (IR and compiled config), plus a compiler
  test matrix per backend.
- Some rules that a raw Xray user could write will be rejected until a backend
  proves it can enforce them.

## Non-goals

- Routing in v0.2 or v0.3.
- Pools, health-based failover and per-grant selective routing before the
  capability cells are proven.
- Exposing Xray JSON as the domain model.

## As shipped in v0.4

`panel/routing/models.py` is the IR (`RoutingPolicy`, `RoutingRule`, `RuleMatch`,
`PolicyInput`); `panel/routing/compiler.py` compiles it for `naive_native` (Caddy
forwardproxy `upstream` + `acl`) and `mieru_native` (mita `egress`) against the
capabilities each manager declares — the cells proved on the stand
(`docs/spikes/VNEXT_ROUTING_ENGINE.md`), not the engines' documentation. The backend is a
field of the policy; the only egress is the host's WARP (`warp`), extensible without a
migration; pools and named egress endpoints were left out until they have a consumer.
What a backend cannot enforce is `unsupported` with the rule named, in the preview and
the API; a WARP the node reports as down fails closed unless the policy chose
`fallback = approved_direct`, and then the substitution is shown, never silent.
`docs/ROUTING.en.md` describes the result.
