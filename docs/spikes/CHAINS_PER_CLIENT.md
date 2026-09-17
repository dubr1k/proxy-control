# Chains and per-client lanes spike (v0.7, Task 1)

Date: 2026-09-17. Tree: `feature/vnext-v0.6-verification` at `55cd862`. Host: `ams-test`, the
`lab-host` install of v0.6 left running by the v0.6 gate: Caddy `v2.11.4` + `forward_proxy`
(`/usr/local/bin/caddy`), mita `3.36.0` (`/usr/bin/mita`, the managed daemon on `46001`), the
pinned Xray `26.3.27` of the node's router (`/usr/local/lib/proxy-control/xray-router/xray`).
Stand-ins: `scripts/lab/socks5-stub.py` on `127.0.0.1:47001` and `:47002` (each logs one line
per CONNECT). Everything ran on throwaway ports beside the managed services; nothing managed
was touched. Runners: `spike-s1.sh`, `spike-s2.sh`, `spike-s3.sh` (kept with the run under
`/root/spike-chains/` on the host; the shapes are reproduced in the tests of v0.7).

The owner's question (2026-09-17): «клиент — это я; я отправляю трафик через AMS_Z, который
отправляет трафик на ams-test … я могу настраивать так, чтобы конкретно мой трафик
маршрутизировался … какой-то трафик по правилам geosite/geoip гонять на сервер, какой-то через
внутренний WARP … и для каждого созданного клиента на сервере это должно настраиваться». Three
things had to be true for that to be buildable on the existing data planes.

## S1 — NaiveProxy: one Caddy site, several `forward_proxy` handlers, one upstream per user

```text
route {
    forward_proxy { basic_auth alice … ; hide_ip; hide_via; probe_resistance; upstream socks5://127.0.0.1:47001 }
    forward_proxy { basic_auth bob …   ; hide_ip; hide_via; probe_resistance; upstream socks5://127.0.0.1:47002 }
    respond "cover" 200
}
```

| Probe (`curl --proxy https://naive.lab.test:46443 --proxy-user …`) | Result | Evidence |
| --- | --- | --- |
| `caddy validate` | accepted | `VALIDATE_OK` |
| alice → `https://example.com/` | **200 through upstream 47001** | `stub-47001.log`: one line, `example.com 443`; 47002 untouched |
| bob → `https://example.com/` | **200 through upstream 47002** | `stub-47002.log`: one line; 47001 untouched |
| mallory (unknown) | refused | no CONNECT reached either stub; the request fell through to the cover |
| cover `GET /` without credentials | 200 | `cover` |

**Conclusion:** with `probe_resistance` a `forward_proxy` handler whose `basic_auth` does not
match passes the request to the next handler, so a chain of handlers gives every user (or
group of users) *its own* `upstream` on the same name and port. Per-client NaiveProxy egress
needs no second domain: the manager renders one handler per lane, the service's default lane
last. This is what naive-manager v0.7 owns inside its `route`.

## S2 — Xray: per-user routing on one ingress, a VLESS+Reality relay to a second Xray

Node A (`xray-a.json`): one `socks` inbound `127.0.0.1:47101` with **two accounts** (`alice`,
`bob`), `sniffing routeOnly`; outbounds `direct`, `block`, `a-warp` (socks → stub 47002),
`node-b` (`vless` + `reality` → `127.0.0.1:47201`, `serverName panel.lab.test`, keypair from
`xray x25519`); routing `IPOnDemand`: `geoip:private → block`, `user: [alice] → node-b`,
`user: [bob] + full:example.com → a-warp`, `user: [bob] → direct`.

Node B (`xray-b.json`): `vless` + `reality` inbound `127.0.0.1:47201` (`dest 127.0.0.1:8443` —
the lab panel's own TLS listener as the cover, `serverNames [panel.lab.test]`), routing:
`geoip:private → block`, `inboundTag relay-in → b-warp` (socks → stub 47001).

| Probe (`curl --proxy socks5h://<user>@127.0.0.1:47101`) | Result | Evidence |
| --- | --- | --- |
| `xray run -test` on both configs | accepted | `CONFIGS_OK` |
| alice → `example.com`, `example.org` | **200, both through node B, out of B's exit** | `stub-47001.log`: `example.com`, `example.org`; nothing on 47002 |
| bob → `example.com` | **200 through A's WARP stand-in** | `stub-47002.log`: `example.com` |
| bob → `example.org` | 200 direct | neither stub saw it |
| eve (unknown) | refused | `curl 97 User was rejected by the SOCKS5 server` |
| Xray logs | no errors | `0` matches for `error|failed` on both |

**Conclusion:** Xray routes by the authenticated inbound account (`user`) together with
domain/geo selectors, so one ingress port serves many *lanes*, each with its own default and
rules; a chain hop is an ordinary `vless` outbound with Reality whose cover is the target node's
panel TLS listener (a real certificate, always up), and the target node decides the exit by
`inboundTag`/`user`. Multi-hop follows from Xray's `proxySettings.tag` (dial the next hop through
the previous outbound) without the middle node knowing anything but «relay this account».

## S3 — Mieru: a second mita daemon beside the managed one

`/var/lib/mita-spike2/server_config.json`: `portBindings [46011/TCP]`, one user, `egress.proxies
[{exit, SOCKS5_PROXY_PROTOCOL, 127.0.0.1:47002}]`, `rules [{* → PROXY exit}]`; started as user
`mita` with `MITA_CONFIG_JSON_FILE` and `MITA_UDS_PATH` pointing at that directory, then
`mita start` through that socket. Client: the pinned official client image
(`proxy-control-mieru-client:3.36.0`, the same probe the installer's acceptance runs) with a
profile for `127.0.0.1:46011`.

| Check | Result | Evidence |
| --- | --- | --- |
| second daemon status | `mita server status is "RUNNING"` | own UDS, own config |
| managed daemon untouched | `RUNNING` before and after, still on `46001` | `ss -lntp` shows both `mita` pids |
| official client → 204 through the second daemon | **ok** | `CLIENT_204_OK` |
| the client's traffic left through the instance's own egress | **yes** | `stub-47002.log`: `api.github.com`, `cp.cloudflare.com` |

**Conclusion:** mita has one `egress` per daemon and no per-user selector (`servercfg.proto`
3.36.0: `Egress` is a top-level field; `User` has name, password, quotas, private/loopback
flags only), but daemons are cheap and independent: a lane for Mieru is a mita instance with its
own port, its own users and its own egress proxy (the router's lane account). Its share link
carries that port, so moving a Mieru grant between lanes re-issues its link.

## What v0.7 builds on this

- **Lanes** on the router: per-lane SOCKS accounts on the existing ingress ports (`svc:<protocol>`
  the service's lane, `grant:<id>` a client's), rules by `user`.
- **Exits** in the policy: `direct`, `warp`, `block`, `node:<guid>` with the target node's exit
  (`direct` or its `warp`), chains of several nodes through `proxySettings`.
- **Relay inbound** on every node with a router: `vless`+`reality` on a dedicated public port,
  cover = the node's own panel TLS listener; accounts per (source node, exit).
- **NaiveProxy lanes** = one `forward_proxy` handler per lane; **Mieru lanes** = one mita
  instance per lane (`mita@<lane>.service`) with a port from a reserved range.
