# TrustTunnel

[Русский](TRUSTTUNNEL.ru.md) · **English**

TrustTunnel is AdGuard's VPN that looks like ordinary HTTPS from the outside: HTTP/2 over TLS on TCP.
Proxy Control runs it as one more protocol beside MTProxy, NaiveProxy, Mieru and AmneziaWG. Unlike
AmneziaWG it is **TCP only** and shares port 443 with the other services through the Nginx SNI route, so
no new port is opened on the server and there is no UDP rule. QUIC/HTTP3 and UDP are not used.

It is handed out as a **`tt://` link** (also a QR code) or a **TOML configuration file**, and as a
`trusttunnel` entry in the Clash/mihomo feed.

## How it works

- One `trusttunnel-manager` container runs on the node (host network, unprivileged, read-only file
  system). It runs the pinned `trusttunnel_endpoint` (v1.1.0, Apache-2.0) as a subprocess, writes the
  endpoint's credential files and keeps them in line with the panel.
- The endpoint listens on **loopback only** (`127.0.0.1:4453` by default; the `[trusttunnel] listen_port`
  key). The Nginx `stream` on 443 sends the TrustTunnel name to that private port by SNI. The manager's
  metrics are on `127.0.0.1:1987`. Both ports are in the installer's list of reserved ports.
- The endpoint accepts a connection only when the name in the TLS hello (SNI) equals the TrustTunnel
  domain: it refuses an IP address or a foreign name.
- **The client's password is created by the panel and stays in its encrypted store.** The node receives it
  to verify incoming clients; the panel builds the link and the config on request without asking the node.
  The manager's working state is `/var/lib/trusttunnel-manager` (a 0700 directory; the accesses' passwords
  and the traffic counters).
- The endpoint reads its credentials **at start only**, so every new, changed or disabled access briefly
  restarts the endpoint. The manager coalesces changes arriving within about two seconds into one restart;
  active sessions drop meanwhile and the apps reconnect by themselves. Traffic counters persist in the
  manager and survive restarts.
- A renewed certificate is picked up with SIGHUP, without a restart. Until the certificate exists the manager
  reports `degraded` (`certificate_missing`) instead of crashing.
- An access is an account on a node; on a central panel with linked nodes it is issued on the chosen node like
  any other. The node must run a version with TrustTunnel (capability `protocol.trusttunnel.v1`), otherwise the
  panel refuses at once instead of leaving the request waiting, and the central panel skips such nodes.

## Enabling it on a server

You need a **domain of its own** for TrustTunnel: an A record to this server, **DNS only** (CDN proxying
off), different from every other domain of the installation. Its Let's Encrypt certificate is issued by the
installer's `certificates` step (HTTP-01, port 80); the manager reads it from `/etc/letsencrypt` read-only.

In the installer's wizard answer «Install TrustTunnel» and enter the domain, or add the section and the domain
key to the TOML (example: [`examples/installer/core-trusttunnel.toml`](../../examples/installer/core-trusttunnel.toml)):

```toml
[domains]
trusttunnel = "gate.example.org"   # its own domain: an A record to the server, DNS only

[trusttunnel]
enabled = true
# listen_port = 4453               # optional: the endpoint's loopback port (1024-65535)
```

The installer creates `/var/lib/trusttunnel-manager`, the manager token `secrets/trusttunnel-manager-token` and
`.env.trusttunnel`, adds a line to the Nginx SNI map, builds the manager image (GitHub must be reachable
during the build: the endpoint archive is downloaded and checked against its SHA-256) and verifies that the
manager answers. No firewall rule is added. All keys and behaviour are in the
[installer reference](../INSTALLER_REFERENCE.en.md).

### A server the installer did not set up

For a hand-installed host, run the supported script from the unpacked release; it does what the installer's
TrustTunnel step does and is safe to repeat:

```bash
sudo scripts/enable-trusttunnel.sh --host gate.example.org
```
The unpacked release must include `installer/bin/linux-amd64/proxy-control-installer`.
The script reads the reviewed endpoint pin through its `release-pin` helper, which validates
the complete release manifest; no host Python interpreter is required.


The certificate for the name must be issued beforehand (a certbot lineage of the same name), and your Nginx
`stream` must send that name to `127.0.0.1:4453` (the line `gate.example.org 127.0.0.1:4453;` in the
`$ssl_preread_server_name` map). The script copies the manager and its Compose overlay, creates the token and the
state directory (credentials are not touched), writes `.env.trusttunnel`, adds the overlay to the version
agent's list, rebuilds the manager and the panel and checks the answer. `--listen-port` changes the loopback
port, `--dir` the project directory.

## The TrustTunnel screen

The left menu of a server with the protocol has a «TrustTunnel» item (shown only where the protocol is
enabled). It shows the domain and the endpoint's state, the version and certificate, the number of accesses,
sessions and traffic, and lists all accesses of the server with the client that holds each. A new access opens
with the «+ TrustTunnel access» button; the same access can be issued from a client's card. A row disables or enables
its access, issues a new password («New password») and deletes it, after a confirmation and without a page reload. A row on the
dashboard card shows the number of accesses and the traffic. In the «Nodes and access» matrix a client has a
TrustTunnel column of its own.

## Granting access

1. Open the client → **Nodes and access** and tick the node's TrustTunnel cell, or create the access on the
   TrustTunnel screen («+ TrustTunnel access»; the optional «Profile» field is the name under which the profile
   appears in the app).
2. Open the access: its window shows the **`tt://?…` link**, its **QR code** and the **TOML config** (copy or
   «Download .toml»). They contain the access's password, so they are built from the panel's store on request,
   do not stay in the window, and showing them is written to the audit log.
3. The person imports the link (or scans the QR) in the **AdGuard TrustTunnel** app for iOS or Android, or uses
   the TOML with the command-line client. The official project and clients:
   [github.com/TrustTunnel/TrustTunnel](https://github.com/TrustTunnel/TrustTunnel).

The full list of apps is in [«Clients»](#clients) below; the access window in the panel shows the same list in a
«How to connect» block, with a «Details for manual setup» card.

Through the API an access is `protocol: "trusttunnel"` (in the MCP `set_client_placement` the `options` field is
optional: `{"name": "<profile>"}`). **Rotation** issues a new password: the old link stops working.
**Disabling** removes the access from the endpoint's credentials but keeps the password: after enabling, the
same link works again; **deleting** removes the account.

## Clients

What takes a TrustTunnel access and how. Compiled from the vendors' documentation (checked 2026-10-19); **«not
verified by us»** means the panel has not run that client itself.

| App | Platforms | How to import | Verified by us |
|---|---|---|---|
| [AdGuard TrustTunnel](https://apps.apple.com/us/app/trusttunnel/id6755807890) ([Google Play](https://play.google.com/store/apps/details?id=com.adguard.trusttunnel)) | iOS, Android (macOS and Windows «coming soon») | the `tt://?…` link or the QR | yes (official client) |
| [TrustTunnel CLI](https://github.com/TrustTunnel/TrustTunnelClient) | Linux, macOS, Windows | the TOML file | yes (official client) |
| Throne | Windows, Linux, macOS, Android | **by hand**: Ctrl+N → Type «TrustTunnel» → address, port, username, password, SNI → OK; leave QUIC off | no |
| [Surge](https://manual.nssurge.com/policies/trust-tunnel.html) | macOS 6.4.4+, iOS | the policy line `Proxy-TrustTunnel = trust-tunnel, <host>, <port>, username=<user>, password=<password>` (no `h3=true`: we are TCP-only) | no |
| Clash Verge Rev, FlClash, Mihomo Party, ClashMi and other mihomo-core clients | Windows, macOS, Linux, Android, iOS | a Clash subscription (`?format=clash`); the bundled mihomo core must be recent | yes, mihomo core v1.19.32 (2026-10-20) |
| Hiddify | Windows, macOS, Linux, Android, iOS | a sing-box subscription (`?format=singbox`; Hiddify is recognised by its User-Agent, or add `&client=hiddify`) | no: only a core built from source was run; the app's releases (4.1.1) lack the outbound (below) |
| NekoBox (NyameBox fork), NekoRay | Android, Windows, Linux | a sing-box subscription (recognised by User-Agent, or add `&client=nekobox`) | no |
| Shadowrocket | iOS | unverified: check whether it imports the `tt://` link, or enter the details by hand | no |
| Trusty, TrustTunnel-GUI-Client, FireTunnel, FreeTunnel | Windows, macOS, Linux | unverified: check whether it imports the `tt://` link or TOML, or enter the details by hand | no |

Community links: [Trusty](https://github.com/Meddelin/trusty), [TrustTunnel-GUI-Client](https://github.com/blazuryk/TrustTunnel-GUI-Client),
[FireTunnel](https://github.com/pnsrc/firetunnel), [FreeTunnel](https://github.com/dimmmmmmmer/freetunnel).

### Details for manual setup

For Throne, Surge, Shadowrocket and the like, the access window shows a card: server,
port, username, password (hidden until you press «Show»; the button copies it), SNI, protocol (**HTTP/2, QUIC off**),
the certificate in PEM when the domain has its own, and the Surge policy line. The subscription page shows the same
fields without the Surge line: it names verified apps only (AdGuard TrustTunnel, TrustTunnel CLI, mihomo-core clients).
It is the `trusttunnel_manual`
artifact (`application/json`, no QR), built from the panel's store on request like the link and the TOML. Do not tick
QUIC in the app: the server is TCP-only (HTTP/2); users reported QUIC problems with uTLS. A domain with a certificate
from a trusted authority needs nothing more; otherwise the client has to trust the PEM shown.

### The sing-box feed and fork cores

**Official sing-box has no TrustTunnel outbound** (planned: [SagerNet/sing-box#3723](https://github.com/SagerNet/sing-box/issues/3723),
milestone 1.14). Official sing-box, SFA and SFI reject a config with an unknown outbound type **as a whole**
(`unknown outbound type: trusttunnel`), so for them, for Karing and for any unrecognised client the sing-box feed
**does not carry** TrustTunnel and names the gap in `proxy_control.unsupported`. A `trusttunnel` outbound exists in
fork cores: hiddify-sing-box (Hiddify), NyameBox (NekoBox) and ThroneCore (Throne 1.4.0-beta.3, on sing-box v1.14.1).

The panel picks the feed by client, and TrustTunnel reaches a subscription like this:

- a request with **no `format`** (or `format=singbox`) whose User-Agent contains `Throne`, `NekoBox`, `NyameBox`,
  `NekoRay` or `Hiddify` gets the sing-box JSON with a `trusttunnel` outbound (Throne together with naive and mieru);
- an explicit `&client=throne|nekobox|nyamebox|hiddify` turns it on whatever the User-Agent; an explicit
  `&client=singbox` or `&client=karing` always stays without it;
- `PANEL_SINGBOX_FORK_CLIENTS` is a comma-separated list of extra User-Agent parts (for example `karing,streisand`)
  whose clients get the Karing feed plus TrustTunnel; it changes without a release (an environment variable of the panel container).

The outbound the feed emits (TCP, HTTP/2, QUIC off; `insecure` only when the access carries its own certificate):

```json
{"type": "trusttunnel", "tag": "…", "server": "gate.example.org", "server_port": 443,
 "username": "…", "password": "…", "quic": false,
 "tls": {"enabled": true, "server_name": "gate.example.org"}}
```

The feed does not emit `health_check`: hiddify-sing-box (a build of master `ae5cb1488`) panics on the first connection
when it is on. Live check (2026-10-19, `scripts/lab/trusttunnel-fork-core-check.py`): that build's `sing-box check`
passes, a request through the outbound returns 200 with the traffic counted on the gate, and official sing-box 1.14.3
rejects the same JSON. No hiddify-sing-box release has TrustTunnel yet (the latest, 1.13.0.h5, predates it), so a source
build was tested. NekoBox and Throne: their cores contain the outbound, but we could not run it or check the
subscription import, so their cells in the compatibility matrix are `unproven`. **If Throne ignores the outbound from
the subscription, the fallback is the «Details for manual setup» card and a profile created by hand.**

Compatibility per subscription client (`supported` / `unproven` / `unsupported`) is in
[`docs/COMPATIBILITY.md`](../COMPATIBILITY.md): for `trusttunnel` mihomo is `supported` (verified on core v1.19.32);
Karing, Shadowrocket, NekoBox, Throne, v2rayN and Hiddify (its core was run only as built from source) are
`unproven`; sing-box, Mieru CLI and Telegram are `unsupported`.

## Routing

TrustTunnel is a first-class service in «Routing» (steps, presets, direct exit, WARP, your own exits, chains
through other nodes). A rule applies to **the whole service**: all TrustTunnel clients follow one policy.

- **There are no lanes for individual clients** (error `lanes_unsupported`): the endpoint talks plain SOCKS5
  without credentials to the router, so the router cannot tell which client came (`extended_auth` stays off:
  Xray does not understand SOCKS5 method 0x80).
- The built-in exit (`trusttunnel_native`) is `direct` only. Any other policy requires attaching the service to
  the Xray-router («Node capabilities» -> attach); attaching and detaching restart the endpoint.
- The router's ingress is a SOCKS5 inbound **without a password** on `127.0.0.1:45104` (enabled by
  `XRAY_ROUTER_PORT_TRUSTTUNNEL`). It listens on loopback only, but any local process or host-network container
  can use that port as a proxy into the TrustTunnel service's policy. It is not reachable from outside the
  server.
- Refusals: `router_lacks_trusttunnel` (an Xray-router older than 1.6 — rebuild it),
  `node_lacks_trusttunnel_egress` (a node without the `egress.trusttunnel.v1` capability — update the node),
  `lanes_unsupported`.

Details: [`docs/ROUTING.en.md`](../ROUTING.en.md).

## What it does not do

- No QUIC/HTTP3 and no UDP: HTTP/2 over TCP only.
- Capture («accept the access» without rotation) is not supported: the only copy of the password is the
  panel's store. Existing runtime users cannot be imported either.
- No per-access traffic quota (traffic is counted and shown).
- No lanes for individual clients (above). The sing-box feed does not carry it for official sing-box and unrecognised clients (see «Clients»).

## Backup

Keep `/var/lib/trusttunnel-manager` (`state.json` holds the accesses' passwords and the counters; the directory
is 0700), `.env.trusttunnel` and `secrets/trusttunnel-manager-token`. The passwords are also in the panel's
encrypted store, but without the state directory the counters reset. The certificate is restored by ordinary
issuance.

## Diagnostics

- **The app does not connect, an SNI refusal**: the connection goes by IP address or with a foreign name. The
  profile must carry the TrustTunnel domain itself.
- **The domain is behind a CDN**: a proxied name breaks TLS and SNI; it must be DNS-only.
- **The manager is `degraded` / `certificate_missing`**: there is no certificate for the domain; issue it
  (the installer's `certificates` step) and the manager picks it up by itself.
- **Port collision**: `4453` and `1987` must be free on loopback; check `ss -ltnp`.
- **Clients «twitch» when an access is issued**: that is expected — every credential change restarts the
  endpoint (changes within ~2 s are coalesced) and the apps reconnect by themselves.
- **407 on connect**: a wrong name or password, a disabled access, or a rotation already replaced the password.
