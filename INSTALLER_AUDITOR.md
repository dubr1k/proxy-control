# Complete Proxy Control installer and auditor

**English** · [Русский](INSTALLER_AUDITOR.ru.md)

`scripts/proxyctl.py` is a thin delegation to `installer.cli`, whose
subcommands are `wizard`, `plan`, `install`, `status`, `resume`, `repair`,
`report`, and `uninstall`, and which is driven by a configuration file rather
than by hostname flags: there is no separate `audit` subcommand (the audit runs
inside `plan`) and no `--proxy-domain` / `--panel-domain` flags.

The installer has no separate manual here. The accurate and complete
description lives in one place:

- **[Installer reference](docs/INSTALLER_REFERENCE.en.md)** — every command,
  every configuration field, profiles, ownership boundaries, per-protocol
  acceptance, WARP, hard stops, recovery, reports, and limits.
- **[README](README.en.md)** — what the project is, how it shares port 443,
  domains and certificates, and the install path end to end.
- **[INSTALL.en.md](INSTALL.en.md)** — the installation walkthrough.

The installer's behaviour is verified against a real release archive in two
labs, described in [tests/lab/README.md](tests/lab/README.md).
