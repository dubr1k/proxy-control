# Xray egress-router spike (v0.5, Task 32)

Date: 2026-09-16. Tree: `feature/vnext-v0.5-xray-router` at `adf91ff` (after the Xray artifact
pin). Host: `ams-test` (disposable lab), the `lab-host` install of `v0.4.0-beta.1` left running
by the v0.4 gate: Caddy `v2.11.4` with `klzgrad/forwardproxy@d62c80d3`, mita `3.36.0`, both live
behind the lab's nginx. Router under test: **Xray 26.3.27** (`d2758a0`, go1.26.1 linux/amd64)
from the pinned `Xray-linux-64.zip` (`23cd9af9…`), unpacked by `installer.release.safe_extract_zip`
into a scratch directory with its own `geoip.dat`/`geosite.dat` (`744c97b7…`, `adf92de0…`).
Egress stand-in: `scripts/lab/socks5-stub.py` on `127.0.0.1:45000` as «WARP». Runner:
`scripts/lab/xray-spike.py`; raw result `lab-results/spike/xray-spike.json` on the host.

The router config is the shape of spec §6: two `socks` inbounds on loopback (`naive` 45101,
`mieru` 45102, `auth: password`, `udp: false`, `sniffing {destOverride [http, tls, quic],
routeOnly: true}`), outbounds `block` (blackhole, first), `direct` (freedom, `domainStrategy:
UseIP`), `warp` (socks → stub), `routing.domainStrategy: IPOnDemand`, and per inbound tag:
`geoip:private → block`, `localhost → block`, the policy's rules, a catch-all to the default.
Clients: NaiveProxy through `curl --proxy https://naive.lab.test` (credential up front), Mieru
through `metacubex/mihomo` (`socks5h://`, and `socks5://` where the client must resolve).

The question (spec §10): which capability cells the dedicated router enforces for each data
plane, how each data plane attaches, and whether the bypass, the credentials and the failure
modes behave as the design says.

## Results — the router itself

| Cell | Result | Evidence |
| --- | --- | --- |
| `xray run -test` accepts the rendered config | yes | exit 0 |
| `-test` refuses an unknown `geosite:` / `geoip:` code | **yes, by name** | `code not found in geosite.dat: NO-SUCH-CODE-XYZ` / `… geoip.dat …` — the manager maps this to `geosite_unknown` / `geoip_unknown` |
| unauthenticated SOCKS5 CONNECT | **refused** | `curl 97 No authentication method was acceptable` |
| the `mieru` credential on the `naive` ingress | **refused** | same handshake failure; each ingress knows one account |
| the right credential | ok | `curl 0 200` |
| SOCKS5 UDP ASSOCIATE | refused | `udp: false`; the greeting fails before ASSOCIATE |
| bypass: CONNECT `127.0.0.1:2019` (Caddy Admin API) | **blocked** | `curl 52 Empty reply` — blackhole, no HTTP answer |
| bypass: a public name that resolves to loopback (`localtest.me` → `127.0.0.1`, `::1`) | **blocked with `IPOnDemand`** | `curl 52 Empty reply`; Xray log `[naive -> block]` after `Localhost got answer: localtest.me -> [::1 127.0.0.1]` |
| the same name with `domainStrategy: AsIs` | **reaches loopback** | Caddy Admin answers `403` to the foreign `Host` — the request got through; `AsIs` is not an option for the router |
| idle footprint | RSS ≈ 30 MB | `ps -o rss`: 30 724–30 924 KB idle; 31 372–31 656 KB after ten parallel CONNECTs |
| config swap (`-test` → SIGTERM → start → ports open) | **≈ 0.06 s** | measured 0.055–0.056 s; every session through the router drops |
| `kill -9` of the process | ingress closed until restarted | `curl 35 wrong version number` (Caddy has no upstream); the manager's watchdog owns the restart |

## Results — NaiveProxy via the router (`naive` ingress)

Caddy attaches with `upstream socks5://<user>:<pass>@127.0.0.1:45101` in the managed block:
`caddy adapt` accepts the userinfo, `x/net/proxy.FromURL` performs the SOCKS5 password
handshake, and CONNECT targets reach Xray as hostnames (no sniffing needed on this path).

| Cell | Result | Evidence |
| --- | --- | --- |
| `whole_direct` | **supported** | `curl 0 200`, stub empty |
| `whole_warp` | **supported** | `curl 0 200`, stub saw `('api.ipify.org', 443)` — the hostname is passed to WARP as a domain |
| `block_domain` **beside a `warp` default** | **supported** — the cell `naive_native` could not do | `example.com` → `502` from Caddy (tunnel closed by blackhole), stub empty; `api.ipify.org` still via stub |
| `block_domain` suffix (`domain:example.com`) | supported | `www.example.com` → 502 |
| `block_cidr` by hostname (`IPOnDemand` resolves) | **supported** | deny the three addresses of `api.ipify.org`, CONNECT by name → `curl 35` (no TLS ever starts) |
| `block_cidr` by literal IP | supported | CONNECT `104.26.12.205` → refused |
| `block_port` (`port: "80"`) | **supported** | `http://api.ipify.org` → 502, `https://` → 200 |
| `block_geosite` (`geosite:category-ads-all`) | **supported** | `doubleclick.net` → 502; `api.ipify.org` untouched |
| `block_geoip` (`geoip:cloudflare`) by hostname | **supported** | `api.ipify.org` (Cloudflare) → refused after resolution |
| `selective_geoip` `direct` beside a `warp` default | **supported** | `api.ipify.org` → 200 with stub empty; `www.cloudflare.com` → 200 |
| dead WARP (`warp` default, stub port closed) | **fails closed** | `curl 35`, never direct |
| Caddyfile / running config after the spike | byte-identical / restored | `caddyfile_untouched`, `restored_direct_ok` |

## Results — Mieru via the router (`mieru` ingress)

mita attaches with an egress proxy carrying `socks5Authentication` (`mita apply` accepts it,
`mita describe config` shows it); as in v0.4 the change needs `stop`/`start`.

| Cell | Result | Evidence |
| --- | --- | --- |
| `whole_direct` / `whole_warp` | **supported** | stub empty / stub saw `('api.ipify.org', 443)` |
| hostnames reach WARP as hostnames | yes | stub log carries the name |
| `selective_domain` `direct` beside `warp` default | **supported** | `api.ipify.org` direct, `www.cloudflare.com` via stub |
| sniffing `routeOnly`: client resolves locally, CONNECT by IP, TLS SNI `example.com` | **domain rule still matches** | `curl` refused with `domain:example.com → block`; other IP-literal targets unaffected |
| `destOverride` without `routeOnly` | also works | recorded; `routeOnly` stays the choice (the dial keeps the client's address) |
| UDP through the router | **not relayed** | SOCKS5 UDP ASSOCIATE gets no answer (as in v0.4) |
| loopback as a destination | refused by mita itself | `allowLoopbackIP=false` of the user — the router never sees it |
| wrong credential on mita's side | **fails closed** | `curl 35`; nothing reaches the stub |
| mita config after the spike | restored | `mita describe config` equal; mieru-manager `ready: true` |

## Decision

- `xray_router` capabilities: `whole_direct`, `whole_warp`, `block_domain`, `block_cidr`,
  `block_port`, `block_geosite`, `block_geoip`, `selective_domain`, `selective_cidr`,
  `selective_port`, `selective_geosite`, `selective_geoip` — the whole matrix of spec §6;
  `restart_required: true` (≈ 0.06 s of closed ingress per apply, every session drops).
- `routing.domainStrategy` is **`IPOnDemand`**, not negotiable: the private-destination bypass
  holds for names that rebind to loopback only when the router resolves before matching. The
  price — the node resolves every hostname for policy evaluation — is documented as the router's
  DNS semantics (ROUTING/XRAY_ROUTER docs); WARP still receives hostnames as names.
- `freedom` uses `domainStrategy: UseIP` so the address the decision was made on is the address
  dialled; `sniffing.routeOnly: true` on both inbounds.
- One account per ingress, `auth: password`; a credential from another service is a handshake
  failure. Xray's own error text is what `-test` returns for unknown geo codes — the manager
  surfaces it as `geosite_unknown` / `geoip_unknown`.
- `udp: false` on both inbounds; Mieru UDP stays `unsupported` (mita's SOCKS5 egress does not
  relay it either).
- Attach documents: Caddy `upstream socks5://<user>:<pass>@127.0.0.1:45101` (rendered by the
  naive-manager from its credential file), mita `egress.proxies[]` with `socks5Authentication`
  and `* → PROXY router` (rendered by the mieru-manager); neither credential ever appears in an
  API answer.
