# ADR 008: Panel-to-panel transport with scoped API keys

Status: accepted (v0.3). Supersedes the transport direction of ADR 001; keeps its
typed-payload rule. Applies ADR 002 and ADR 003 unchanged.

## Context

ADR 001 chose a pull-only, outbound-only mTLS agent so that a node never listens
for control traffic. The price was an enrollment ritual — an offline CA, CSR
transfer, `fleet-bind-cert` — and a separate ingress and agent process on every
host. Fleet v1 shipped with it, and no production host was ever enrolled.

The owner's requirement for v0.3 is the 3x-ui operating model: a panel issues an
API key from its web interface, and the central panel adds that panel by URL and
key from a "Nodes" screen — no CLI, no certificates to move, nothing installed
beyond the panel image. Every production host already publishes its panel over
HTTPS with a WebPKI certificate, so the inbound surface ADR 001 avoided already
exists; the question is only what that surface accepts.

## Decision

The central panel calls the node panel over the node's own HTTPS panel domain,
authenticated with a scoped Bearer API key:

- **Keys, not sessions.** A key is created in the panel UI with a name, a scope
  (`admin`, `monitor`, `node-sync`), an optional expiry; the database stores a
  SHA-256 hash and a lookup prefix; the plaintext is shown once. Keys can be
  disabled and deleted; revocation is immediate.
- **Scope bounds the surface.** `node-sync` authorises only `/api/fleet/v2/*`.
  `admin` and `monitor` map onto the existing owner/viewer roles for the regular
  API, matching 3x-ui.
- **Typed documents only.** The fleet API accepts an immutable, digested
  `DesiredGeneration` (ADR 002), returns an `ObservedGeneration`, and offers a
  bounded set of typed operations (identity, status, inventory, credential
  capture, component update, unlink). No shell, URL, HTTP method/path, YAML or
  runtime config ever crosses the link.
- **One master per node.** A node records the GUID of the first central panel
  whose generation it accepts and rejects generations from any other GUID until
  the operator unlinks it in the UI.
- **Server identity is WebPKI by default**, with certificate pinning for
  self-signed or lab certificates. There is no "skip verification" mode.
- **Secrets originate centrally.** The central panel generates credentials and
  delivers them next to the generation over the same TLS request; the stored
  document stays secret-free. When a runtime insists on generating its own
  credential, the node returns it in the push response, and the central panel
  escrows it.

## Consequences

- Enrollment is three UI actions; the release adds no system components.
- Reaction time is immediate (push) plus a periodic heartbeat; a control-plane
  outage still leaves the data plane running.
- A node exposes an authenticated API on its public panel vhost. Mitigations:
  hashed scoped keys, per-key rate limits, request-size bounds, audit rows
  without bodies, `no-store` on secret-bearing responses, immediate revocation.
- A compromised central panel can reach every node it manages — the same
  boundary 3x-ui accepts. A compromised node learns nothing about other nodes:
  the key is one-directional and the node holds no central credential.
- Fleet v1 (mTLS, Telemt-only) stays frozen and byte-compatible; it is not
  extended and not removed in v0.3.

## Non-goals

- Transitive nodes, metric history, panel-to-panel mTLS.
- Generic remote execution or a proxy to the node's full admin API.
- Bidirectional state merge; the panel owns managed fields, the node owns
  observations (ADR 002, ADR 003).
