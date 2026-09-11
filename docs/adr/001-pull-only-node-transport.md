# ADR 001: Pull-only node transport

Status: accepted (v0.2); transport direction superseded by [ADR 008](008-panel-to-panel-transport.md) in v0.3 — the typed-payload rule and the frozen Fleet v1 boundary stay in force

## Context

Fleet v1 already ships a working node transport: the agent dials out over mTLS,
polls `GET /agent/v1/commands`, and posts results back. The client certificate is
bound to exactly one `node_id`, the command queue carries a fixed `OPERATIONS`
set for Telemt only, and delivery is ordered by a sequence/outbox pair. Nodes
expose no inbound control port at all.

The obvious alternative is what 3x-ui v3.7.0 does for multi-node: the master
calls the child panel's own administrative HTTP API. That turns a full admin
surface into a node protocol, requires an inbound port on every node, and makes
every future panel endpoint part of the wire contract.

## Decision

The node transport stays pull-only and outbound-only:

- the agent initiates every connection; a node never listens for control traffic;
- the client certificate binds to one `node_id`, and the ingress refuses a
  certificate presented for any other node;
- Fleet v1 remains a Telemt-only compatibility boundary. Its `OPERATIONS` set,
  `TypedCommand` shape, sequence/outbox semantics and `GET /agent/v1/...` paths
  are frozen and byte-compatible;
- the queue never carries shell, a URL, an HTTP method/path, Compose YAML or a
  ready-made runtime config. New capability means a new typed schema (Fleet v2,
  ADR 002), not a more powerful command payload.

## Consequences

- A control-plane outage leaves the data plane running; nodes keep serving with
  their last applied state.
- Reaction time is bounded by the poll interval, which is the accepted cost of
  having no inbound port.
- Adding a protocol to remote provisioning is a schema change with its own
  capability handshake, not a payload trick — deliberately more work up front.
- The panel cannot "reach into" a node for ad-hoc debugging; diagnostics must be
  modelled as typed observations.

## Non-goals

- A push channel or long-lived server-initiated connection.
- An inbound agent API of any shape.
- Generic remote execution, even for operator convenience.
