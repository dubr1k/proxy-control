"""The Compose project — the stack — Proxy Control runs in.

3.0 named it `proxy_panel_by_dubr1k`. A host installed earlier runs `mtproxy` until
`scripts/migrate-compose-project.sh` moves it (`scripts/update-host.sh` runs it at its end), so a
check for Proxy Control's own containers and volumes looks in both.
"""
COMPOSE_PROJECT = "proxy_panel_by_dubr1k"
LEGACY_COMPOSE_PROJECT = "mtproxy"
COMPOSE_PROJECTS = (COMPOSE_PROJECT, LEGACY_COMPOSE_PROJECT)

# The version-agent's pins (Telemt's image, 3.2: the AmneziaWG and TrustTunnel managers' build
# args) live in this file under the project. Every Compose call that may rebuild or recreate a
# service carries it, or a repair would quietly put the installer's own pin back.
VERSION_OVERRIDE = "version-overrides/compose.versions.yaml"


def without_override_service(text: str, service: str) -> str:
    """The version override without one service's block: a block for a service whose overlay is
    gone would make every Compose call over the file fail (a service with no image or build)."""
    kept: list[str] = []
    skipping = False
    for line in text.splitlines(keepends=True):
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            skipping = line.strip()[:-1] == service
        elif not line.startswith("    "):
            skipping = False
        if not skipping:
            kept.append(line)
    return "".join(kept)
