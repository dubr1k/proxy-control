# ADR 003: One writer per resource

Status: accepted

## Context

Protocol pages and the client API address the same runtime accounts. Independent
writers against one resource produce drift that reconciliation cannot explain:
neither side knows whether a difference is a change to apply or a change to keep.

The panel also has to describe resources it did not create — users that already
exist in Telemt, Naive and mita before the import.

## Decision

Exactly one writer owns a resource at a time, and ownership is explicit:

- `managed` — created by the domain service; the panel owns every field;
- `adopted` — pre-existing, explicitly bound to a `Client`; the panel owns it
  from the moment of adoption;
- `foreign` — seen on the node, never adopted; read-only, never deleted;
- `drifted` — observed state disagrees with desired state; surfaced, never
  silently repaired by a second writer;
- `tombstoned` — deletion recorded and pending confirmation; the identity is not
  reused.

The Rust clients domain is the only writer. Protocol endpoints
(`/api/users`, `/api/naive/users`, `/api/mieru/users`) remain supported entrypoints
into that domain, not an independent legacy runtime. There is no writer-mode
flag or per-node writer cutover. A resource managed by a central panel is changed
through that central's generation; local protocol-page writes are refused.

## Consequences

- Every mutation has one owner, so drift is a report rather than a race.
- Protocol pages and the client API share ownership and credential escrow.
- Deleting a resource in the panel does not delete a `foreign` resource on the
  node; the operator sees it and decides.
- Import is a decision, not a guess: identical usernames across protocols are a
  hint only (ADR 004).

## Non-goals

- Automatic merge of `foreign` resources into clients.
- Cross-node ownership transfer.
