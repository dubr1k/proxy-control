# Architecture

Proxy Control separates public data planes from local management and fleet transport.

## Components

1. Host Nginx owns shared TCP/443, inspects SNI, and forwards selected names to loopback listeners.
2. Telemt serves MTProto and uses a persistent `telemt-config` named volume. Its authenticated API is private to Compose and consumed by the panel.
3. Caddy/NaiveProxy and mita remain protocol runtimes. Their managers expose bounded, token-authenticated Unix APIs and transactional state changes.
4. The FastAPI panel binds to loopback, stores RBAC/session/audit/fleet metadata in SQLite, and never uses a Docker socket.
5. Node agents initiate mTLS connections to central ingress. Certificate identity, typed operations, durable journals, idempotency, and ordered results constrain remote authority.
6. The optional `trusttunnel-manager` (host network, no capabilities) supervises the pinned `trusttunnel_endpoint` (HTTP/2 over TLS, TCP only) as a subprocess. The endpoint listens on a loopback port; Host Nginx forwards the TrustTunnel name there by SNI on the shared TCP/443, so it adds no public port and no UDP. The manager's API is a token-protected Unix socket, its state (client passwords, traffic counters) lives in `/var/lib/trusttunnel-manager`, and any credential change briefly restarts the endpoint because it reads credentials only at start. Its outbound traffic is direct or, when attached, goes to a no-password loopback SOCKS5 ingress of the Xray-router, so routing is per service and never per client.

## One stack per node

All Docker services deployed by Proxy Control on a node share the immutable Compose project name `mtproxy`. `compose.yaml` is the base model; Naive, Mieru, AmneziaWG, TrustTunnel, node-agent, and fleet-ingress files are overlays of that same model. Operators must persist the complete active `COMPOSE_FILE` set and use it unchanged for every lifecycle command. Separate project names would split service discovery, ownership, volumes, health, backup, and rollback and are therefore unsupported. A host may omit a component that is not deployed there, but every container that is deployed there remains in the one stack.

## Trust boundaries

Public proxy traffic, panel HTTPS, private management APIs, secret-bearing persistent state, and fleet PKI are distinct boundaries. A healthy process is not protocol validation. Each mutation validates its target, records durable intent where applicable, applies atomically, probes the new generation, and either commits or restores the exact prior generation.

## Compatibility boundary

Branding is neutral, but migration-sensitive identifiers remain unchanged. See [COMPATIBILITY.md](COMPATIBILITY.md).
