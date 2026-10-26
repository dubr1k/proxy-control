# Host-side golden fixtures (Python → Rust port, WP0)

Recorded from the **Python** installer and version-agent by `scripts/dev/record-host-goldens.py`.
Every Rust host package (`pc_host`, `installer`, `version_agent`) loads these files and must
reproduce them byte for byte, or read them and write them back unchanged. Do not edit them by hand:
regenerate them on ams-test.

    # as root on ams-test, from a checkout (never against the stand's own installation)
    python3 scripts/dev/record-host-goldens.py
    python3 scripts/dev/record-host-goldens.py --output /tmp/again --check-against tests/fixtures/host-golden

The recorder re-executes itself in a private mount namespace and covers every live state directory
(`/var/lib/proxy-control`, `/opt/mtproxy-shared443`, `/etc/proxy-control`, …) with an empty tmpfs,
then drives the real CLI (`installer.cli.run`) and the real adapters against a throwaway root under
`/tmp/proxy-control-host-golden`. Commands are answered by a simulated host (`SimHost`) and by the
unit tests' fake runners. `INDEX.json` lists every file with its SHA-256.

## Determinism

- Clock: `time.time()` is fixed at 1767225600 (2026-01-01T00:00:00Z); `time.sleep` is a no-op.
- Entropy: `secrets.token_bytes/hex/urlsafe`, `uuid.uuid4` and tempfile names come from
  `sha256("host-golden:<scenario>:<n>")`, reset per scenario. **No value here is a real secret**:
  every token, password, key and certificate is a seeded or labelled stand-in.
- Host: IPv4 203.0.113.10, IPv6 2001:db8::10, machine-id `0123456789abcdef0123456789abcdef`,
  Ubuntu-like package versions, `nginx-full` installed with the stock `nginx.conf`, UFW inactive
  (IPV6=yes), sshd on 22.
- Release tree: real compose files, `deploy/`, `probe/`, `docker/`, `scripts/` and release pins;
  the panel, manager, installer and pc_common sources are one `GOLDEN-STAND-IN` file each and the
  `version_agent/*.py` files are one-line stand-ins, so ownership hashes do not move with every commit.
  `release/release.json` is stamped by `release/build.py` for version 3.3.0, commit `000…0`.
- Running the recorder twice gives byte-identical output (`--check-against`).

## Layout

| Path | What | Python source |
|---|---|---|
| `config/errors.json` | 150-odd TOML inputs: `parse_config` result, exact `ConfigError` text, canonical dict and `render_config` for the valid ones | `installer/config.py` |
| `config/cli-blocked.json` | the same failures through `plan --config`: `BLOCKED: …` on stderr, exit 2 (plus a missing file and invalid UTF-8) | `installer/cli.py` |
| `config/render/` | `render_config` of every example and the round-trip result | `config.py:139` |
| `vectors/` | Python semantics the digest and validators rely on: `isdigit`/`isdecimal`/`\d`, `strip`, `lower`, `ipaddress`, `str()` of scalars and keys, `round()`, float `repr`, JSON escaping and key order; validator outcomes (domains, version regexes) and `compare_versions` | stdlib, `audit.py`, `config.py`, `wizard.py`, `version_agent/{catalog,upstream}.py` |
| `plans/<name>/` | for every `examples/installer/*.toml` and two extra configs (`kitchen-sink`, `coexist-ingress`): canonical `plan.json` bytes, `digest`, `digests.json` (plan + intent digest), `plan --json` and text output, the audit commands, and `audit-transcript.json` (every audit command with its output, the resolver answer, the facts built from them); **real release pins** | `planner.py`, `audit.py` |
| `plans/index.json`, `plans/release.json` | the host facts and release identity the plans were made with | |
| `installs/<name>/journal/` | `state.json`, `plan.json`, `ownership.json`, `report.json` (+ modes) after `install --accept-plan` | `transaction.py` |
| `installs/<name>/root/tree.json` | every path the install left: kind, mode, uid/gid, size, sha256 (copies of release files are marked `copy_of_source`) | all adapters |
| `installs/<name>/root/files/…` | the bytes of every text file the install wrote (rendered vhosts, stream router, ACME vhosts, `.env*`, master key, `users.conf`, markers, WARP owner marker, version-agent env/state/catalog, units, …) | all adapters |
| `installs/<name>/commands.json` | every command the install ran, in order (`<root>`/`<work>`/`<tmp>` replace the throwaway paths) | |
| `installs/<name>/audit-transcript.json` | the audit `install` ran: every command with its output, the resolver answer and the facts (= the journal plan's `audit_facts`) | `audit.py` |
| `installs/<name>/{status.json,status.txt,install-stdout.json,report/}` | CLI `status`, `install --json` output, `report` (public report + root-only handoff, modes) | `cli.py`, `report.py` |
| `journals/handoff/{before,after}` | a panel update's `PanelOwnershipHandoff` prepare/commit on the kitchen-sink host (`report.json` stays stale: Python bug) | `transaction.py:483` |
| `journals/home-like/` | shaped like the `home` host (see below) | |
| `journals/rolled-back` | a failed verification rolled the whole install back (`error: "AcceptanceError"`) | |
| `journals/interrupted/{applying,resumed}` | a crash inside `mieru.runtime` (`applying` checkpoint), then `resume` | |
| `journals/{repaired,uninstalled,uninstalled-purged}` | `repair`, `uninstall`, `uninstall --purge-data` | |
| `journals/lock.json` | the lock file mode and the busy message | `transaction.py:187` |
| `renders/<config>/` | render functions called directly: stream router (current and pre-client-IP forms), ACME vhosts, Core compose/env/panel vhost, Naive Caddyfile template/env/unit/pin/deploy hook, Mieru env and bootstrap input, TrustTunnel/AmneziaWG/Xray-router env, version-agent env merge against several existing files (`env.operator-keys` keeps operator keys), managed 3x-ui add-inbound bodies and WARP routing | adapters |
| `renders/nginx/` | `ensure_stream_context` and `patch_owned_map`/`remove_owned_map_block` edge cases | `nginx.py` |
| `renders/ingress-upgrade/` | the old panel/stream forms, what `ingress_upgrade` turns them into, its result and backup metadata | `ingress_upgrade.py` |
| `renders/core-vhosts/` | panel, subscription and MCP vhost texts with non-default ports | `core.py:2771` |
| `agent/seed/` | the installer's agent `state.json` (indent 2, sorted, trailing newline) and catalog seed | `adapters/version_agent.py:460` |
| `agent/updates/NN-step/` | agent `state.json` (indent 2, sorted, ASCII, **no** trailing newline) and the `/v1/versions` body after: upstream check, telemt image update, mita upstream update, xray update, a naive update rolled back; plus the override file, overlays, every command and (`downloads/`) the artifacts the steps download | `version_agent/service.py` |
| `metrics/` | nft rulesets, the discovered port map (with override variants), `parse_counters`, and two sampler ticks over a fake `/proc` (Python `round`) | `version_agent/{hostmetrics,metrics_ports}.py` |
| `wizard/{en,ru}/<scenario>.json` | stdin, stdout, stderr, exit code and the saved TOML/credentials of wizard runs (`--lang` given or the language asked); `core-apply-install` goes on to a full install; `<scenario>.plan.json` is the canonical plan a scenario printed | `wizard.py`, `i18n.py`, `cli.py` |
| `wizard/i18n-catalogue.json` | the message catalogue in both languages | `i18n.py` |

## Stand-ins that differ from a real host

- **Installs use stand-in artifacts.** Xray, mita/mieru `.deb`, the 3x-ui archive and the WARP key and
  package are small stand-ins; the adapters' compiled-in pins and the tree's
  `release/external-artifacts.json` are patched to their digests. So the plan digests under
  `installs/` and `journals/` differ from `plans/` for profiles with Mieru, the router or 3x-ui;
  `plans/` uses the real pins.
- Fake runners stand in for Docker, systemd, the panel acceptance and the 3x-ui API (see
  `install_runners`). Their answers are the "healthy" ones; the journal shapes are the code's own.
- `journals/home-like` is inferred from the code, never read from that host: a fresh `full` install
  (NaiveProxy, Mieru, AmneziaWG; no router, no WARP; UFW managed) at 3.2.0 rebased by two panel
  updates (3.2.1, 3.3.0). The real `home` journal may have been written by an older installer, so
  adapter `data` keys can differ; treat checkpoint `data` as opaque JSON.
