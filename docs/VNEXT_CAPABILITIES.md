# vNext capability matrix

**Rule: `unsupported` is an explicit cell, not a blank.** A capability that a
protocol cannot do, or that nobody has proven yet, is written down with a status
and a reason. Nothing in the panel may offer a capability whose cell is not
`supported`.

Current protocol declarations live in `panel/crates/model/src/protocols.rs` and
the adapters under `panel/crates/protocols/src/`; subscription-client compatibility
lives in `panel/crates/subscriptions/src/compatibility.rs`. The tables below are a
documentation snapshot, not a fixture consumed by the native runtime.

Statuses: **yes** = `supported`, **no** = `unsupported`, **unproven** = plausible
but not demonstrated on the lab host, **n/a** = `out_of_scope` for that row.

## Native protocol capabilities

This table describes the MTProxy, NaiveProxy and Mieru native backends. It does
not describe the optional Xray-router or its grant lanes (see below). Fleet v2 is
panel-to-panel transport; retired Fleet v1 is not a current protocol capability.
Installed Fleet v1 state requires explicit [migration](COMPATIBILITY.md).

| Capability | mtproxy | naive | mieru |
| --- | --- | --- | --- |
| `create` | yes | yes | yes |
| `enable` | yes | yes | yes |
| `disable` | yes | yes | yes |
| `rotate` | yes | yes | yes |
| `delete` | yes | yes | yes |
| `quota` | yes | yes | yes |
| `expiry` | no | no | no |
| `accounting` | yes | yes | no |
| `stable_access_artifact` | yes | yes | no |
| `credential_capture_without_rotation` | yes | yes | no |
| `whole_service_socks_upstream` | n/a | yes | yes |
| `cidr_routing` | n/a | yes | yes |
| `domain_routing` | n/a | yes | yes |
| `per_client_routing` | n/a | no | no |
| `hot_reload` | yes | yes | yes |
| `rollback` | no | no | no |
| `dns_ownership` | n/a | unproven | unproven |
| `socks_hostname_propagation` | n/a | unproven | unproven |
| `tcp_udp_upstream` | n/a | no | yes |
| `identity_propagation` | n/a | no | no |
| `fail_closed` | yes | yes | yes |
| `binary_hot_upgrade` | no | no | no |
| `exact_geodata_version` | n/a | n/a | n/a |

The cells that shape the control plane most:

- **`credential_capture_without_rotation`.** MTProxy keeps `links.tls` in
  `list_users`, and the Naive manager keeps the password in its own state, so an
  imported grant is captured as-is. mita stores only `hashedPassword`, so an
  imported Mieru grant becomes usable only through rotation — the panel says so
  and offers the rotation, including in bulk. This concerns capture of an
  existing runtime credential: Mieru keys issued or rotated through the panel
  are kept in escrow and can be shown again, including the lane slot port
  (`mieru-kept-keys` in the verification matrix).
- **`accounting` for Mieru is `no`.** The panel requires the metrics
  response to be exactly `capability: unavailable`,
  `reason: typed_histories_unavailable`. Quota usage and any per-period history
  for Mieru would be invented. The panel does show mita's own
  cumulative per-user counters (`mita get metrics`, since the daemon started),
  labelled as such: they are not a quota and not a history.
- **`expiry` is `no` everywhere.** No protocol has a validity window;
  `AccessGrant.valid_until` is a control-plane concept enforced by disabling.
- **`rollback` is `no` everywhere.** A protocol keeps no history of its users to
  return to; immutable generations (ADR 002) belong to Fleet v2.
- **Native routing.** NaiveProxy blocks by domain and CIDR beside a direct
  default, with one upstream per service; forwardproxy skips its ACL when an
  upstream is set. Mieru blocks and selects by domain suffix and literal-IP CIDR,
  applied by restarting mita. Neither native backend provides grant lanes.
- **Xray-router routing.** NaiveProxy and Mieru attached to the router support
  domain, CIDR, geosite, geoip and port rules, custom exits, Fleet chains and
  **per-grant lanes** with independent policies. Naive uses a handler per lane;
  Mieru uses a slot daemon and port reflected in its access and subscription.
  This is supported routing through the router, not native identity propagation.
  MTProxy, AmneziaWG and TrustTunnel have service policies only, without lanes.
  MTProxy rules cannot match domains/geosite because its destinations are IPs.
  Mieru UDP stays direct; Naive/Mieru router ingresses do not relay UDP. AmneziaWG
  has a separate TUN attachment that carries TCP and UDP. See
  [ROUTING](ROUTING.en.md) and [XRAY_ROUTER](XRAY_ROUTER.en.md).

### AmneziaWG and TrustTunnel

These are first-class optional protocols, with local and capability-gated Fleet
access provisioning. Their properties are stated separately rather than inferred
from the older native-backend table.

| Capability | AmneziaWG | TrustTunnel |
| --- | --- | --- |
| `create`, `enable`, `disable`, `rotate`, `delete` | yes | yes |
| Artifact rebuilt from panel escrow | yes: version-specific `.conf` and QR | yes: `tt://`, QR and TOML |
| Mixed subscription feed | no | yes: Clash/mihomo and raw; selected sing-box fork variants (below) |
| Native service exit | direct or own WireGuard WARP tunnel (TCP/UDP) | direct only |
| Xray-router attachment | yes: TUN, TCP/UDP | yes: loopback SOCKS5, TCP only |
| Rules, custom exits and Fleet chains | yes, with router | yes, with router |
| `per_client_routing` | no: service policy only | no: service policy only |
| Native validity window | no: panel/Fleet enforcement below | no: panel/Fleet enforcement below |

AmneziaWG serves versions 1.5, 2.0 and 3.1 on separate interfaces and UDP ports;
one grant targets one version. The panel retains the client's private key in
escrow; the node receives public client material and a preshared key. TrustTunnel
shares TCP/443 via its own SNI and runs a loopback endpoint; credential changes
restart that endpoint, while certificate renewal uses SIGHUP. See the
[AmneziaWG guide](guides/AMNEZIAWG.en.md) and
[TrustTunnel guide](guides/TRUSTTUNNEL.en.md).

The [verification matrix](VERIFICATION_MATRIX.md) binds `routing-lanes`,
`routing-chains`, `routing-over-fleet-chains`, `amneziawg-access`,
`trusttunnel-access`, `trusttunnel-routing` and `trusttunnel-fork-clients` to their
acceptance tests. A proof binding is not evidence that the current tree or a
particular installation has passed those checks.

### Control-plane access enforcement

A grant is enabled only while its client is active, its administrative state is
`enabled`, and `valid_from <= now < valid_until` (an omitted boundary is open).
Suspension preserves each grant's administrative state, so resuming a client does
not enable grants that were disabled individually. Protocol-page enable operations
also obey the client's state and validity window.

Each panel checks local and Fleet-managed grants at startup and on an independent
timer with a nominal 15-second interval. Fleet nodes enforce the validity window
from their last accepted generation even while their central is unreachable; a
new suspension still requires delivery of a generation from the central. Manager
I/O and outages can extend convergence beyond the timer interval. Keep host clocks
synchronized. A local grant stays `pending`, or a managed resource reports `failed`,
until runtime readback confirms the requested state; retries do not rewrite the
operator's administrative choice. The central refreshes observed timed grants on
its heartbeat.

A late `drifted` report never confirms a newer generation's on/off state. The
legacy drift report carries no actual on/off value: for an enabled grant with a
validity window the central therefore shows `pending` until it receives an
explicit `enabled`/`disabled` report. It does not infer the node's state from its
own clock. Option drift on an explicitly disabled generation still confirms
`disabled`, independent of clocks.

Поздний отчёт `drifted` не подтверждает новое поколение. Такой отчёт не содержит
фактическое состояние включения: доступ с временным окном остаётся `pending`,
пока узел не сообщит явно `enabled`/`disabled`. Центр не подменяет подтверждение
расчётом по своим часам. Явно отключённое поколение подтверждает `disabled`
даже при расхождении остальных настроек.

The current managers cannot atomically create a disabled user. Creating an access
outside its window therefore creates, disables and reads it back before provisioning
can succeed. This prevents a false success report but does **not** guarantee an
instantaneous, zero-window access cutoff or disabled-at-birth creation. A strict
data-plane deadline requires native protocol/manager support, which remains
unsupported in the matrix above.

Панель применяет состояние клиента и интервал `valid_from <= now < valid_until`
к реальному доступу, сохраняя индивидуальное отключение каждого доступа при
возобновлении клиента. Проверка выполняется при запуске и периодически (номинально
раз в 15 секунд); время ответов менеджеров и недоступность могут увеличить задержку.
Узел Fleet соблюдает уже полученный срок без связи с центром, но новое отключение
клиента требует доставки поколения. Успех подтверждается чтением состояния runtime;
при ошибке остаётся `pending`/`failed` и выполняется повторная попытка. Атомарного
создания отключённого пользователя менеджеры пока не поддерживают: создание,
отключение и проверка предшествуют успешному завершению операции, но краткое окно
доступа между этими шагами исключить нельзя.

## Subscription clients

Auto-refresh means: the client accepts a subscription URL in a format one of our
renderers emits, and refreshes it on its own schedule. It never means the panel
pushes an update.

| Client | MTProxy | Naive | Mieru | TrustTunnel |
| --- | --- | --- | --- | --- |
| Karing | no | yes | yes | unproven |
| sing-box (≥ 1.13) | no | yes | no | no |
| mihomo / Clash.Meta | no | no | yes | yes |
| Official mieru client | no | no | no | no |
| Telegram | no | no | no | no |
| Shadowrocket | no | unproven | no | unproven |
| NekoBox and forks | no | unproven | no | unproven |
| v2rayN | no | unproven | unproven | unproven |
| Hiddify | no | unproven | no | unproven |
| Throne | no | yes | yes | unproven |

The cells match `panel/crates/subscriptions/src/compatibility.rs`, including its
per-cell notes. AmneziaWG is intentionally outside this feed matrix: configuration
files and QR codes are issued separately, with no mixed-feed auto-refresh.

Official sing-box supports Naive in the builds named by the compatibility notes,
but has no Mieru or TrustTunnel outbound. Karing's fork supports Mieru; Throne
1.3.1 was verified for Naive and Mieru from sing-box JSON (Mieru comes from the
Karing variant, not Throne's Clash parser; its UDP binding requires a server IP).
Mihomo supports Mieru and TrustTunnel; the TrustTunnel feed was checked with
mihomo v1.19.32. A client application also needs a suitable bundled core.

TrustTunnel is emitted in sing-box JSON only for selected fork clients:
Throne, NekoBox/NyameBox/NekoRay and Hiddify, selected by User-Agent or
`?format=singbox&client=throne|nekobox|nyamebox|hiddify`. Explicit `client=singbox`
or `client=karing`, and unrecognised clients, omit it and report the unsupported
entry. A source build of hiddify-sing-box carried traffic in the recorded probe;
that does not prove a released Hiddify application's subscription import. Hiddify,
NekoBox and Throne therefore remain **unproven** for TrustTunnel auto-refresh.
Manual import of `tt://` or a manually created profile is also not a subscription
proof. See the [TrustTunnel client guide](guides/TRUSTTUNNEL.en.md#clients).

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
5. **Identity propagation.** For a new backend or lane mechanism, prove that it
   distinguishes grants before offering per-client routing. Existing Naive/Mieru
   router lanes do not promote native identity-propagation cells.
6. **Fail-closed behaviour.** Kill the backend mid-flight and confirm traffic
   stops rather than silently falling back to direct.

A failed probe leaves the cell disabled and the capability unavailable in the
API and the UI. Selective routing is never quietly downgraded to whole-protocol
routing.

See [vNext architecture](VNEXT_ARCHITECTURE.md), [ADR 006](adr/006-routing-policy-ir.md)
and [ADR 007](adr/007-routing-enforcement-ownership.md).
