# ADR 004: Client, AccessGrant and subscription as a projection

Status: accepted (v0.2)

## Context

Until v0.2 a "user" is whatever a protocol calls a user: an MTProxy secret in
Telemt, a Caddy/Naive credential, a mita account. The same person ends up as
three unrelated rows, and the panel has no object to suspend, archive or hand a
single link to. 3x-ui shows the opposite failure too: it uses mutable strings
(email, tags, DB ids) as cross-node identity.

Operators also expect one link per person, kept up to date — the shape 3x-ui's
subscription URL has trained everyone to expect.

## Decision

- `Client` is the subscriber: a UUID, a display name, a state
  (`active | suspended | archived`) and metadata. **A client is not a username.**
- `AccessGrant` is one concrete access — protocol, node, endpoint, runtime
  username, desired state, origin — owned by exactly one client.
- Identical usernames across protocols are a **hint** during import, never an
  automatic merge. The operator decides what belongs to whom.
- `ClientSubscription` is a stable, revocable token per client. The response is a
  **pull projection of the current grants**, recomputed per request; the panel
  never stores a rendered bundle.
- Every change to the effective set bumps a generation; the HTTP `ETag` is
  derived from the effective manifest plus the renderer version, so a client that
  refetches gets `304` until something real changes.
- Auto-refresh is a property of the client application, not of the URL. The
  compatibility matrix names every cell explicitly
  (`supported | unsupported | unproven`); Telegram MTProxy is permanently
  `unsupported`.

## Consequences

- Suspending a person is one action with a predictable effect on every protocol.
- The subscription is always consistent with the database, because it is derived
  from it at request time.
- Renderers must be honest: a protocol a target client cannot parse is emitted as
  an explicit `unsupported` entry, never as a plausible-looking link.
- More objects than "a list of users", and an import step that requires operator
  decisions.

## Non-goals

- `Product`, billing, quotas as a commercial model.
- Automatic placement of grants across nodes.
- Push notifications to client applications.
