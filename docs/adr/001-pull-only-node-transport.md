# ADR 001: Pull-only node transport

Status: superseded by [ADR 008](008-panel-to-panel-transport.md). Only the typed-payload invariant remains current; Fleet v1 runtime is retired.

## Context

The retired Fleet v1 transport used an outbound mTLS agent, a Telemt-only typed
command queue and ordered sequence/outbox delivery. Its installed state can still
exist on prior hosts and must be preserved until explicit migration; see
[compatibility](../COMPATIBILITY.md). It is not shipped by the native release.

The obvious alternative is what 3x-ui v3.7.0 does for multi-node: the master
calls the child panel's own administrative HTTP API. That turns a full admin
surface into a node protocol, requires an inbound port on every node, and makes
every future panel endpoint part of the wire contract.

## Decision

The former pull-only transport is not the current architecture. ADR 008 defines
panel-to-panel HTTPS transport. The retained payload boundary is:

- frozen Fleet v1 identifiers describe prior-host state, not supported routes;
- the queue never carries shell, a URL, an HTTP method/path, Compose YAML or a
  ready-made runtime config. New capability means a new typed schema, not a more
  powerful command payload.

## Consequences

- A control-plane outage leaves the data plane running; nodes keep serving with
  their last applied state.
- Adding a protocol to remote provisioning is a schema change with its own
  capability handshake, not a payload trick — deliberately more work up front.
- The panel cannot "reach into" a node for ad-hoc debugging; diagnostics must be
  modelled as typed observations.

## Non-goals

- Generic remote execution, even for operator convenience.
