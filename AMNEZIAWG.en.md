# AmneziaWG

[Русский](AMNEZIAWG.ru.md) · **English**

AmneziaWG is WireGuard with traffic obfuscation: the same fast tunnel, but the packets no longer
carry the fixed signature that deep packet inspection recognises. Proxy Control runs it as one more
protocol next to MTProxy, NaiveProxy and Mieru. Unlike them it is a **VPN over UDP**, so it is given
out as a **config file and a QR code**, not through a subscription link.

## Versions

Four versions of the protocol exist; Proxy Control serves the three newest. They are **not
compatible with one another** (their server-side parameters differ), so each version runs on its own
interface, UDP port and tunnel subnet of the node, and one access is always exactly one version. A
client can hold several accesses and choose in the app which to use.

| Version | What it adds | Interface · subnet | Needs in the app |
|---|---|---|---|
| **1.5** | junk packets and signature packets `I1`–`I5` that imitate other UDP protocols (QUIC, DNS…) at the start of a session | `awg15` · 10.66.15.0/24 | an app that supports AmneziaWG 1.5 |
| **2.0** | random padding on every packet type (`S3`, `S4`), header values from ranges instead of fixed numbers | `awg20` · 10.66.20.0/24 | AmneziaVPN 4.8.12.9 or later |
| **3.1** | header protection with a key and padding of the payload; designed against statistical and behavioural analysis | `awg31` · 10.66.31.0/24 | AmneziaVPN 5.0.1.5 or later |

Amnezia describes 3.1 as the newest and most block-resistant version and recommends trying a
different version (and, for 3.1, adjusting `I1` and lowering the MTU) if a connection is unstable
in a given network. Giving a person several versions is exactly for that.

**The UDP port is chosen per server.** The well-known 51820–51822 are fingerprinted by censors, so each
version gets its own free pseudo-random port (10240–32000), picked once when AmneziaWG is enabled and kept
across updates. You see the ports in the installer plan and report, on the AmneziaWG screen and in every
client config. To choose your own, see below.

The server is [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go), built in the node's
container from a pinned commit; the obfuscation parameters of each version are generated once per
node and stay fixed.

## How it works

- The node runs one container, `awg-manager` (host network, only `NET_ADMIN`/`NET_RAW`, a
  read-only file system). It starts one `amneziawg-go` per enabled version, sets the interface address
  and a NAT rule, and keeps the peers of each interface in step with the panel.
- **The client's private key is created by the panel and stays in its encrypted store.** The node
  receives only the client's public key and a preshared key, so a lost or copied node does not leak a
  client's key. The server keys and the obfuscation parameters live in the node's state directory
  (`/var/lib/awg-manager`) and survive restarts and updates.
- Everything a client needs in its config — its tunnel address, the port of its version, the server
  key and the obfuscation values — is learned from the node when the access is issued, so the config
  can be shown later without asking the node.
- On a central panel with linked nodes, an access is issued on a chosen node like any other; the node
  must run a panel version with AmneziaWG and serve the chosen version, otherwise the panel refuses
  the request instead of leaving it waiting.

## Enabling it on a server

Requirements: a DNS name (or the address) that **reaches the server directly over UDP** — it must not
be behind a proxying CDN — and an Ubuntu 24.04 host with `/dev/net/tun`. No new domain is needed:
the panel's own name works if it points straight at the server.

In the installer wizard answer «Enable AmneziaWG» and pick the versions, or add a section to the
TOML (see the [installer reference](docs/INSTALLER_REFERENCE.en.md) for every key):

```toml
[amneziawg]
enabled  = true
versions = ["1.5", "2.0", "3.1"]
host     = "vpn.example.com"   # defaults to the panel domain
# ports  = { "1.5" = 23456, "2.0" = 24567, "3.1" = 25678 }   # optional: your own UDP ports (any subset)
```

The ports are random and free unless you name them: in the TOML `ports` (above), in the wizard (it shows
the random ones; press Enter to accept or type a comma list in version order), or with `--ports` of the
script below. The installer turns on IPv4 forwarding, opens the UDP ports and allows forwarding for the tunnel
interfaces in the firewall it manages (on a server whose firewall it does not manage, open the ports
and allow forwarding yourself), builds the container and checks that every version answers.
On a server whose firewall the installer does not manage (no `ufw`, Docker's forwarding policy is `DROP`), open the UDP ports and install `deploy/awg-forward.service` as a systemd unit: it lets the tunnel interfaces through Docker's forwarding chain after every start of Docker.
Restarting `awg-manager` (an update) briefly drops the tunnels; clients reconnect on their own.

### A server the installer did not set up

For a host that was installed by hand (no installer state), run the supported script from the unpacked
release; it does what the installer's AmneziaWG step does and is safe to repeat:

```bash
sudo scripts/enable-amneziawg.sh --host vpn.example.com
```

It copies the manager and its Compose overlay, creates the token and the state directory (the server keys
are never touched), writes `.env.amneziawg`, turns on IPv4 forwarding, opens the UDP ports and the forwarding
rules in `ufw` (or installs `awg-forward.service` when there is no `ufw`), adds the overlay to the version
agent's list, rebuilds the manager and the panel and checks that every version answers. `--versions`,
`--mtu` and `--dns` narrow the defaults. The ports are random and free like the installer's, kept on a re-run, and
printed at the end («clients dial HOST on UDP …»); `--ports 1.5=23456,2.0=24567` sets some or all of them (the
rest are picked, the `ufw` rules of changed ports are removed). A host behind a home router also needs the
chosen UDP ports forwarded to it.

## The AmneziaWG screen

The left menu has an «AmneziaWG» item on a server that runs the protocol. It shows the version cards (port, subnet, state, number of accesses), the manager's state and every access of this server with the client that holds it, the last connection and the traffic; «Open access» opens the access window. The screen only reads: accesses are given to clients, below.

## Giving access

1. Open the client → **Nodes and accesses**. The matrix has an «AmneziaWG 1.5 / 2.0 / 3.1» column for
   every version a node serves; tick the cells you want.
2. Open the access and press **Show config**: the panel builds it from its store, shows the text and
   the QR, and offers **Download .conf**. The config contains the client's private key, so it is shown
   once per request and recorded in the audit log.
3. The person imports the file (or scans the QR) in the AmneziaWG or AmneziaVPN app.

Through the API an access is `protocol: "amneziawg"` with `options: {"version": "2.0"}`; the account
is named `<name>-awg<ver>` by the panel and MCP tools. **Rotate** issues a new key pair: the old
config stops working. **Disable** removes the peer from the live interface and keeps its address;
**Delete** frees the address.

## What it does not do

- It is not part of any subscription (no client consumes it there) and appears in no feed.
- Accesses already existing on a node cannot be imported: the node holds no client private key, so
  such a config cannot be rebuilt.
- No traffic quota, no routing policy and no egress: the tunnel leaves through the server's own
  route. Expiry (`valid_until`) works, as for the other protocols, by disabling the access.
- IPv4 inside the tunnel only (`::/0` is routed into the tunnel and dropped, so IPv6 does not leak).

## Troubleshooting

- **No handshake**: check that the UDP port of that version is open end to end and that the config's
  `Endpoint` name resolves to the server; the dashboard card shows the peers per version and the
  traffic.
- **Handshake works, no traffic**: forwarding is off (`sysctl net.ipv4.ip_forward`) or the host
  firewall drops forwarded packets; the `awg-manager` health reports `ip_forward`.
- **Connects but stalls**: lower the MTU (1280 is the default) or try another version.
- **Wrong version in the app**: a config of one version does not work against the port of another.
