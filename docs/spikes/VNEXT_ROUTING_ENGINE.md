# Routing engine spike (v0.4, Task 30)

Date: 2026-09-14. Tree: `feature/vnext-v0.4-routing` after the v0.3 post-merge fix-wave.
Host: `ams-test` (disposable lab), the `lab-host` install of `v0.3.0-beta.1` left running by the
v0.3 gate: Caddy `v2.11.4` with `klzgrad/forwardproxy@d62c80d3` (the pinned Naive build),
mita `3.36.0`, both live behind the lab's nginx. Egress stand-in: `scripts/lab/socks5-stub.py`
on `127.0.0.1:45000` (logs every CONNECT it accepts, relays as-is, no filtering). Runner:
`scripts/lab/routing-spike.py`; raw result `lab-results/spike/spike.json` on the host.

Clients: NaiveProxy through `curl --proxy https://naive.lab.test` with the credential sent up
front (probe resistance), Mieru through `metacubex/mihomo` (`type: mieru`, host network,
`socks5h://` so hostnames reach the server as hostnames). Targets: `api.ipify.org` (three
Cloudflare addresses), `example.com`, the host's own Caddy Admin API `127.0.0.1:2019`.

The question (spec §9): which cells of the capability matrix can the two data planes enforce
**natively**, and how must the managers apply a change. Variants 3–6 of the vNext Task 30
(Xray/sing-box as a universal selective backend) were not run — v0.4 ships capability-limited
routing, the Xray router is v0.5 (spec §1, §13).

## Results — `naive_native` (Caddy forwardproxy)

| Cell | Result | Evidence |
| --- | --- | --- |
| whole-service `direct` | **supported** | baseline: `curl 0 200`, stub log empty |
| whole-service `warp` (`upstream socks5://127.0.0.1:45000`) | **supported** | `curl 0 200`, stub saw `('api.ipify.org', 443)`; `caddy adapt` accepts the directive |
| `block` by domain (`acl { deny example.com *.example.com }`) | **supported without an upstream** | `example.com` → 403, `www.example.com` → 403, other hosts 200 |
| `block` by CIDR — literal IP target | **supported without an upstream** | `deny 104.26.12.205/32`, CONNECT `104.26.12.205` → 403 |
| `block` by CIDR — hostname target | **supported when every resolved address is denied** | deny all three addresses of `api.ipify.org`, CONNECT by name → refused (TLS never starts); deny one of three → 200 (forwardproxy allows a host as soon as one resolved address is allowed) |
| `block` while `upstream` is set | **unsupported** | `deny example.com` + upstream: the CONNECT reached the stub (`('example.com', 80)`) — the handler hands every CONNECT to the upstream and skips its ACL |
| loopback/private denied by default (no user ACL) | **confirmed** | CONNECT `127.0.0.1:2019` → 403 |
| loopback/private with `upstream` set | **not denied by Caddy** | CONNECT `127.0.0.1:2019` → 200 through the stub (`('127.0.0.1', 2019)`): with an upstream the built-in private-range deny is bypassed too; what reaches the node's loopback is then decided by the upstream. Checked live on `AMS_Z` the same day (read-only probes): WARP proxy mode (`socks5 127.0.0.1:45000`) does not connect to `127.0.0.1` nor to RFC1918 (`curl 000`), and the `privoxy` chain `AMS_Z` runs today answers 503 for loopback — the real WARP egress closes the hole the stub shows |
| `ports` | allow-list, not a deny | `ports 443` blocks port 80 (403); not a `block` primitive for v0.4 |
| ACL enforced before or after the upstream decision | after — i.e. never with an upstream | see above |
| `caddy adapt … validate=true` rejects a bad ACL subject | **no** | `deny "not a host or cidr !!"` adapts fine; `POST /load` (Provision) is the real gate — the manager validates subjects itself and the transaction restores the previous file on a failed load |
| dead upstream | **fails closed** | upstream on a closed port: the tunnel never opens (`curl 35`) |
| reload without disruption | yes | every variant was swapped with `POST /load`; the cover site stayed up; the original running config and the Caddyfile bytes were restored (`restored_running_config`, `caddyfile_untouched`) |

## Results — `mieru_native` (mita `egress`)

| Cell | Result | Evidence |
| --- | --- | --- |
| whole-service `direct` | **supported** | baseline 200, stub empty |
| whole-service `warp` (`proxies=[stub]`, `* → PROXY`) | **supported, restart required** | after `mita reload`: 200 but stub empty — **`reload` does not apply an egress change**; after `stop`/`start`: stub saw `('api.ipify.org', 443)` |
| hostnames reach the egress proxy as hostnames | yes | stub log `api.ipify.org`; a client that resolves locally sends the IP (`104.26.13.205`) |
| `block` by domain (`domainNames: [example.com] → REJECT`) | **supported** | `example.com` → refused (`curl 52`), `www.example.com` → refused (suffix match), only when the client sends the hostname: an IP-only CONNECT to the same site passes (200) — domain rules never resolve |
| `block` by CIDR — literal IP | **supported** | `ipRanges: [104.26.12.205/32] → REJECT`, CONNECT by IP → refused |
| `block` by CIDR — hostname target | **not matched** | CONNECT `api.ipify.org` → 200: mita matches `ipRanges` against literal IP targets only, it does not resolve hostnames for the rule |
| selective `direct` by domain with `PROXY` default | **supported** | `api.ipify.org → DIRECT`, rest `→ PROXY`: 200 with stub empty for the exception, stub saw `www.cloudflare.com` for the rest |
| loopback as a destination | refused by the user's own `allowLoopbackIP=false` | `127.0.0.1:2019` → `curl 52` both with `DIRECT` and with `PROXY` (mita refuses before egress; stub log empty) |
| UDP through the SOCKS5 egress | **unproven / not relayed** | SOCKS5 UDP ASSOCIATE through mihomo with `* → PROXY`: no DNS answer (the stub has no UDP relay; WARP proxy mode does not relay UDP either — the v0.3 live check on `AMS_Z` saw the same) |
| existing sessions across an egress change | interrupted | the change needs `stop`/`start` (see above): every session of every user drops for ~2 s |
| restore | exact | `mita describe config` equal to the original after restore; the mieru-manager stayed consistent (`ready: true`) — its state hash covers content, not bytes |

## Decision

- Native-only, as the spec allows (decision gate of Task 30): no universal selective adapter is
  chosen; Xray/sing-box stay in v0.5.
- `naive_native` capabilities: `whole_direct`, `whole_warp`, `block_domain`, `block_cidr` —
  **and a block rule compiles only when `default_action=direct`**; with `default_action=egress`
  any `block` is `unsupported` (`rule_kind_unsupported`: forwardproxy skips its ACL when an
  upstream is set). With an upstream Caddy's own private-range deny is off as well: WARP proxy mode
  refuses loopback and RFC1918 itself (verified on `AMS_Z`), so the `warp` provider is safe; a
  `custom` upstream adopted from a hand-written Caddyfile gets a preview warning
  (`custom_upstream_decides_private_targets`).
- `mieru_native` capabilities: `whole_direct`, `whole_warp`, `block_domain`, `block_cidr`,
  `selective_domain`, `selective_cidr`; `restart_required: true` — the manager applies egress with
  the `restart` transaction mode (as it already does for `user.rotate`/`enable`/`disable`), and the
  preview says so.
- Documented semantics (ROUTING docs): domain rules match the hostname the client sends
  (NaiveProxy and Mieru clients send hostnames); CIDR rules match literal-IP targets, and on Naive
  also a hostname whose *every* address falls inside; `block` by port is not offered; UDP is not
  carried through the `warp` egress on either data plane.
- `POST /load` (Caddy) and `mita apply` are the validation gates the managers rely on; the
  manager validates the compiled document's shape itself before writing anything.
