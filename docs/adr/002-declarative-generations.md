# ADR 002: Declarative immutable generations

Status: proposed (v0.3)

## Context

Fleet v1 moves imperative commands: "create this user", "rotate that secret".
After an offline window the panel cannot tell whether a node applied a command,
applied it twice, or never received it, so recovery relies on the operator.
3x-ui converges instead by merging snapshots in both directions, which requires
no formal field ownership and silently resurrects deleted resources.

Fleet v2 (v0.3) needs a model where a node can be offline for a day and still
converge without an operator, and where "what should this node run" is a value
the panel can print, diff and store.

## Decision

Desired state for a node is an immutable `DesiredGeneration`: a numbered,
content-addressed document produced by the panel. Nodes report an
`ObservedGeneration` describing what they actually run.

- A generation is never edited in place. Any change — including a revert —
  produces a new, strictly higher generation number.
- **Rollback is a new higher generation**, never a rewrite of an old one.
- The same generation number with a different content digest is a security
  conflict, not a retry: the node refuses it and the panel raises it.
- The panel owns every managed field; nodes own only observations. There is no
  bidirectional merge.
- Adoption is additive: unknown resources on a node are recorded as `foreign`
  and never deleted implicitly (ADR 003).

## Consequences

- Convergence after an offline window is anti-entropy against the latest
  generation, not command replay, so lost or duplicated deliveries are harmless.
- Every applied change is reproducible from a stored document, which makes
  backup/restore and incident forensics real rather than aspirational.
- Storage grows with history; generations need retention rules.
- Operators lose "just run this one command" — every intent has to be
  expressible in the generation schema.

## Non-goals

- A workflow engine, DAGs or arbitrary task graphs.
- Bidirectional state merge between panel and node.
- Generations in v0.2: the local node applies desired state directly through the
  domain service; the generation store lands with Fleet v2.
