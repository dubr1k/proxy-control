# vNext capability matrix

**Rule: `unsupported` is an explicit cell, not a blank.** A capability that a
protocol cannot do, or that nobody has proven yet, is written down with a status
and a reason. Nothing in the panel may offer a capability whose cell is not
`supported`.

The authoritative source is `tests/fixtures/vnext-capabilities.json`, and
`tests/test_vnext_capabilities.py` fails if any cell is missing or carries an
empty note. The tables below are a rendered snapshot; regenerate them when the
fixture changes.

Statuses: **yes** = `supported`, **no** = `unsupported`, **unproven** = plausible
but not demonstrated on the lab host, **n/a** = `out_of_scope` for that row.

## Protocols and the Fleet v1 transport

| Capability | fleet_v1 | mtproxy | naive | mieru |
| --- | --- | --- | --- | --- |
| `create` | no | yes | yes | yes |
| `enable` | yes | yes | yes | yes |
| `disable` | yes | yes | yes | yes |
| `rotate` | no | yes | yes | yes |
| `delete` | no | yes | yes | yes |
| `quota` | yes | yes | yes | yes |
| `expiry` | no | no | no | no |
| `accounting` | yes | yes | yes | no |
| `stable_access_artifact` | no | yes | yes | no |
| `credential_capture_without_rotation` | no | yes | yes | no |
| `whole_service_socks_upstream` | n/a | n/a | yes | yes |
| `cidr_routing` | n/a | n/a | unproven | unproven |
| `domain_routing` | n/a | n/a | unproven | unproven |
| `per_client_routing` | n/a | n/a | unproven | unproven |
| `hot_reload` | n/a | yes | yes | yes |
| `rollback` | no | no | no | no |
| `dns_ownership` | n/a | n/a | unproven | unproven |
| `socks_hostname_propagation` | n/a | n/a | unproven | unproven |
| `tcp_udp_upstream` | n/a | n/a | no | yes |
| `identity_propagation` | n/a | n/a | no | no |
| `fail_closed` | yes | yes | yes | yes |
| `binary_hot_upgrade` | n/a | no | no | no |
| `exact_geodata_version` | n/a | n/a | n/a | n/a |

The cells that shape v0.2 most:

- **`credential_capture_without_rotation`.** MTProxy keeps `links.tls` in
  `list_users`, and the Naive manager keeps the password in its own state, so an
  imported grant is captured as-is. mita stores only `hashedPassword`, so an
  imported Mieru grant becomes usable only through rotation — the panel says so
  and offers the rotation, including in bulk.
- **`accounting` for Mieru is `no`.** `panel/mieru.py` requires the metrics
  response to be exactly `capability: unavailable`,
  `reason: typed_histories_unavailable`. Any traffic number for Mieru would be
  invented.
- **`expiry` is `no` everywhere.** No protocol has a validity window;
  `AccessGrant.valid_until` is a control-plane concept enforced by disabling.
- **`rollback` is `no` everywhere.** There is no generation history in v0.2
  (ADR 002 lands with Fleet v2).
- **Every routing cell is `unproven` or `n/a`.** Nothing routes per rule today:
  Naive and Mieru have one whole-service SOCKS5 egress each, and MTProxy is
  outside routing scope entirely (ADR 006).

## Subscription clients

Auto-refresh means: the client accepts a subscription URL in a format one of our
renderers emits, and refreshes it on its own schedule. It never means the panel
pushes an update.

| Client | MTProxy | Naive | Mieru |
| --- | --- | --- | --- |
| Karing | no | yes | yes |
| sing-box (≥ 1.13) | no | yes | no |
| mihomo / Clash.Meta | no | no | yes |
| Official mieru client | no | no | no |
| Telegram | no | no | no |
| Shadowrocket | no | unproven | no |
| NekoBox and forks | no | unproven | no |
| v2rayN | no | unproven | unproven |
| Hiddify | no | unproven | no |

Sources, in short: sing-box gained the `naive` outbound in 1.13.0 and has no
`mieru` outbound; mihomo has `type: mieru` and an open request for naive
(`MetaCubeX/mihomo#273`); Karing runs its own sing-box fork and lists Mieru
support for both cores; the official mieru client has no subscription mechanism
at all. Per-cell notes live in the fixture.

## Spike plan before any routing claim

No routing cell moves from `unproven` to `supported` on reasoning alone. Each
one is promoted only after a spike on a disposable host proves it end to end:

1. **Hostname propagation.** Send a request for a hostname through the
   whole-service SOCKS5 upstream and confirm the upstream received the hostname,
   not a pre-resolved address.
2. **DNS ownership.** Establish which resolver answers under the backend, and
   prove there is no leak to the host resolver for routed destinations.
3. **IPv4 and IPv6.** Both families, for both a routed and a direct destination.
4. **Destination-level UDP.** Prove UDP reaches the destination through the
   chosen path, not merely that a listener exists.
5. **Identity propagation.** Prove (or disprove) that the backend can tell one
   grant from another before any per-client routing is offered.
6. **Fail-closed behaviour.** Kill the backend mid-flight and confirm traffic
   stops rather than silently falling back to direct.

A failed probe leaves the cell disabled and the capability unavailable in the
API and the UI. Selective routing is never quietly downgraded to whole-protocol
routing.

See [vNext architecture](VNEXT_ARCHITECTURE.md), [ADR 006](adr/006-routing-policy-ir.md)
and [ADR 007](adr/007-routing-enforcement-ownership.md).
