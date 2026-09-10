# ADR 003: One writer per resource

Status: accepted (v0.2)

## Context

Today two paths can mutate the same runtime user: the legacy protocol endpoints
(`/api/users`, `/api/naive/users`, `/api/mieru/users`) and, from v0.2 on, the
vNext domain service that owns `Client` and `AccessGrant`. Two writers against
one resource produce drift that no amount of reconciliation can explain: neither
side knows whether a difference is a change to apply or a change to keep.

The panel also has to describe resources it did not create — users that already
exist in Telemt, Naive and mita before the import.

## Decision

Exactly one writer owns a resource at a time, and ownership is explicit:

- `managed` — created by the vNext domain service; the panel owns every field;
- `adopted` — pre-existing, explicitly bound to a `Client`; the panel owns it
  from the moment of adoption;
- `foreign` — seen on the node, never adopted; read-only, never deleted;
- `drifted` — observed state disagrees with desired state; surfaced, never
  silently repaired by a second writer;
- `tombstoned` — deletion recorded and pending confirmation; the identity is not
  reused.

After adoption the vNext service is the only writer. Legacy protocol endpoints
become a compatibility façade behind the `PANEL_VNEXT_WRITER` flag: they
translate a legacy request into domain intent (importing the resource on touch),
and later become read-only. Cutover is per node and explicit.

## Consequences

- Every mutation has one owner, so drift is a report rather than a race.
- The façade adds one indirection for existing clients and scripts, but keeps
  them working across the transition.
- Deleting a resource in the panel does not delete a `foreign` resource on the
  node; the operator sees it and decides.
- Import is a decision, not a guess: identical usernames across protocols are a
  hint only (ADR 004).

## Non-goals

- Removing the legacy endpoints in v0.2.
- Automatic merge of `foreign` resources into clients.
- Cross-node ownership transfer.
