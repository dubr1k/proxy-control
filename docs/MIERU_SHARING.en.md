# Sharing Mieru configurations

**English** · [Русский](MIERU_SHARING.ru.md)

Proxy Control discloses Mieru credentials only after **create** or **controlled rotation**. List APIs, UI tables, and audit never contain passwords, `mierus://` URLs, QR payloads, or reveal tokens.

## Create access

1. Open **Mieru**.
2. Select **Add**.
3. Enter username and optional rolling quota/expiry.
4. A one-time dialog opens after creation.
5. Select the target client:
   - **Native**: copy the official `mierus://` URL or shell-safe `mieru import config 'mierus://…'` command; its QR contains that exact URL.
   - **Karing**: open or scan a `karing://install-config` deep link containing a complete Mieru sing-box profile, or download that JSON profile. This variant is offered only when every binding is a single exact port.
   - **Shadowrocket**: not offered. There is no verified Mieru import format, and Proxy Control does not fabricate one.
6. Confirm import, then close the dialog.

The reveal response carries `Cache-Control: no-store`. URL and QR exist in frontend only inside the ephemeral dialog and are cleared on close.

## Reissue for an existing user

Mita stores only `hashedPassword`, but the panel keeps every key it issues itself (create and **New key**) in its encrypted secret store (master key `PANEL_MASTER_KEY_FILE`). Therefore:

- **Configuration** shows the current key again — no rotation, nothing changes on the node, the old link keeps working (`POST /api/mieru/users/{username}/access`, audit `mieru.access`). The link follows the shape mita serves now: a user in its own lane gets the slot's port.
- The client's subscription serves the same key and switches to the new one right after **New key**.
- A user issued before the panel kept keys shows «Key not kept» («Ключ не сохранён»): its password exists only as a hash. Press **New key** once; from then on it is kept.

**New key** is a rotation. The panel:

1. generates a new credential;
2. performs controlled restart/reload under Mieru transaction policy;
3. invalidates the previous client configuration;
4. keeps the new key and displays the new URL and QR.

Warn the user that the old config stops working as soon as rotation succeeds.

## Client matrix

| Client | Exact-port Mieru access | Port-range access | QR payload |
| --- | --- | --- | --- |
| Official Mieru | `mierus://`, import command | Supported | The displayed `mierus://` URL |
| Karing | Full Mieru sing-box profile, download, and `karing://install-config` | Not offered | The Karing deep link containing the full profile |
| Shadowrocket | Not offered; no verified format | Not offered | None |
| NekoBox+ | Not offered; no verified format | Not offered | None |
| Throne (formerly Nekoray) | The «sing-box JSON for Karing and Throne» subscription (`?format=singbox`); Throne does not import Clash YAML. In Throne 1.3.1 a UDP binding connects only when the server is an IP address | Not offered | None |

Use an official Mieru client compatible with server `mita` 3.35.x, 3.36.x or 3.37.x, or a current Karing build. The [official Mieru client guide](https://github.com/enfein/mieru/blob/main/docs/client-install.md) defines `mierus://`, `mieru import config`, and the sing-box Mieru outbound fields. Karing documents configuration-content import and its [URL scheme](https://karing.app/en/cooperation/scheme); its current source lists the Mieru outbound type.

After import verify expected hostname/port, declared TCP/UDP listener reachability, end-to-end transport, and rejection of the old config after rotation. Never paste any credential payload into a broadly visible ticket/chat or screenshot.

## QR security contract

The QR is client-specific. On **Native**, it encodes the exact displayed `mierus://` URL. On **Karing**, it encodes the exact displayed `karing://install-config` deep link whose `url` parameter is the full Mieru profile. A QR never substitutes a raw HTTP endpoint or an unsupported-client format. Backend creates each SVG from the declared payload, and frontend rejects QR metadata that does not match the selected payload.

Never:

- store URL/QR in localStorage or sessionStorage;
- return them from list APIs;
- write them to audit/application logs;
- reveal them to a viewer;
- include them in backups, screenshots, or issues;
- attempt to recover password from a hash.

Create, rotate, and reveal require authorized mutation roles and CSRF where applicable.

## Dialog closed too early

Do not search the DB or logs. Press **Configuration** — the panel shows the same key again. Rotate only when the key is compromised or the user predates kept keys («Key not kept»).

## Mobile UI

Client tabs scroll horizontally, while QR, payload, import command, unsupported-client notice, and actions stack inside the dialog on narrow screens. Responsive gates cover widths from 320 px and require zero horizontal document overflow. The selected client controls both the visible payload and QR; closing the dialog clears every variant and revokes generated download URLs.

## Troubleshooting

- **No QR:** use the create/rotate one-time dialog, not list view.
- **Old link fails:** expected after rotation.
- **New link imports but cannot connect:** check server status, TCP/UDP listener, DNS/firewall, and real protocol probe.
- **Client created both TCP and UDP entries, only TCP works:** `mierus://` advertises each declared server port binding. Compare the imported entries with the current manager configuration first; an undeclared transport is not supported. When UDP is declared, prove it with an official-client UDP-only profile before blaming the server. If that probe succeeds, use TCP on the affected path and treat the failure as client- or network-specific. Do not add or retain a UDP listener solely because a third-party client generated one.
- **Traffic unavailable:** this is an honest adapter limitation, not a credential problem.
- **Viewer sees no QR:** expected RBAC behavior.

See [Mieru deployment](../MIERU.en.md), [operations](OPERATIONS.en.md), and [troubleshooting](TROUBLESHOOTING.en.md).
