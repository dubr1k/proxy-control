"""The Compose project — the stack — Proxy Control runs in.

3.0 named it `proxy_panel_by_dubr1k`. A host installed earlier runs `mtproxy` until
`scripts/migrate-compose-project.sh` moves it (`scripts/update-host.sh` runs it at its end), so a
check for Proxy Control's own containers and volumes looks in both.
"""
COMPOSE_PROJECT = "proxy_panel_by_dubr1k"
LEGACY_COMPOSE_PROJECT = "mtproxy"
COMPOSE_PROJECTS = (COMPOSE_PROJECT, LEGACY_COMPOSE_PROJECT)
