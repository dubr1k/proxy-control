# ADR 005: Secrets travel as references

Status: accepted (v0.2)

## Context

Before v0.2 the panel never stores a credential: MTProxy links are read back from
Telemt, Naive passwords live in the manager's own state, and a Mieru password is
visible exactly once, in memory, during a one-time reveal. That is safe, but it
cannot serve a durable subscription — a link that must render tomorrow needs the
credential tomorrow.

Storing credentials is a new breach class. It has to be introduced with an
explicit threat model instead of "the database is private anyway".

## Decision

- Domain state, Fleet payloads, audit records, logs, exceptions and API responses
  carry **references** (`SecretRef`), never values. Scrubbing is recursive and
  applied at the audit boundary, not at each call site.
- Values live in `secret_versions`, encrypted with AES-256-GCM under a master key
  kept in a separate file (`secrets/panel-master-key`, staged to
  `/run/panel/master-key`), outside the database and outside the backup of the
  database.
- The AAD binds each ciphertext to its `secret_id`, version, purpose, grant and
  permitted node, so a row lifted into another context fails to decrypt.
- Plaintext exists only in process memory, only for the request that needs it:
  a one-time reveal, a node-scoped delivery, or rendering a subscription
  response.
- Threat model, stated plainly: this protects a **stolen database or backup**. It
  does not protect against a compromised panel process, which by construction
  holds the key while running.
- Every task that touches secrets carries a negative canary test asserting the
  value is absent from the database file, logs and error messages.

## Consequences

- Subscriptions and re-rendering work without asking the protocol for the
  credential again.
- Losing the master key while encrypted rows exist is fatal by design: the panel
  fails closed rather than serving empty subscriptions.
- Backup procedure gains a second, separately stored artefact.
- Mieru credentials still cannot be recovered from mita, so adopting an imported
  Mieru grant requires rotation — the panel says so instead of pretending.

## Non-goals

- Protecting secrets from a compromised panel process.
- An external KMS or HSM in v0.2.
- Re-revealing a credential after its one-time window.
