#!/usr/bin/env bash
# Update an installed Proxy Control host to one verified release (v1.1).
#
# Run by `install-release.sh --update` from the release tree it has just verified, as root:
#
#   bash install-release.sh --update        # the copy published beside a release
#
# The host's version-agent updates the panel (its tree, image and database, with its own backups and
# rollback); then the managers the agent names in `pending_rebuild` are rebuilt with exactly the
# Compose call the agent uses, and on a host with the Xray-router its MTProxy bridge is started.
# The owned Nginx ingress templates then migrate transactionally to preserve client IP.
# Telemt, mask, certificates, `.env*` and `secrets/` are never touched. The digest the agent is
# about to install must be the one this release's script verified, or nothing happens.
set -Eeuo pipefail

VERSION=
EXPECTED=
LANGUAGE=en
SOCK=${UPDATE_HOST_AGENT_SOCKET:-/run/proxy-control/version-agent.sock}
ENV_FILE=${UPDATE_HOST_AGENT_ENV:-/etc/proxy-control/version-agent.env}
POLL=${UPDATE_HOST_POLL_SECONDS:-5}
RELEASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

say() { if [[ $LANGUAGE == ru ]]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }
fail() { printf 'update-host: %s\n' "$(say "$1" "$2")" >&2; exit 1; }

while (($#)); do
    case $1 in
        --version) VERSION=${2:?}; shift 2 ;;
        --sha256) EXPECTED=${2:?}; shift 2 ;;
        --lang) LANGUAGE=${2:?}; shift 2 ;;
        *) printf 'usage: update-host.sh --version X.Y.Z --sha256 DIGEST [--lang ru|en]\n' >&2; exit 2 ;;
    esac
done
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || fail "неверная версия" "malformed version"
[[ $EXPECTED =~ ^[0-9a-f]{64}$ ]] || fail "нужен проверенный --sha256" "a verified --sha256 is required"
[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "нужен root (запускается через sudo из install-release.sh)" "root is required (started through sudo by install-release.sh)"
[[ -S $SOCK ]] || fail "version-agent не найден ($SOCK): хост установлен до v0.11 или агент выключен — обновите по docs/UPGRADING.ru.md" \
    "version-agent not found ($SOCK): the host predates v0.11 or the agent is off — update per docs/UPGRADING.md"

agent() { curl -fsS --max-time 60 --unix-socket "$SOCK" "$@"; }
json() { python3 -c "$1" "${@:2}"; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || true; }

versions=$(agent http://agent/v1/versions) || fail "version-agent не отвечает" "the version-agent does not answer"
current=$(json 'import json,sys; print(json.loads(sys.argv[1])["components"]["panel"].get("current") or "")' "$versions")
say "панель сейчас: ${current:-?}; цель: $VERSION" "panel now: ${current:-?}; target: $VERSION"

if [[ $current != "$VERSION" ]]; then
    checked=$(agent -X POST http://agent/v1/upstream/check) || fail "проверка обновлений не удалась" "the update check failed"
    # The agent installs from the release's own SHA256SUMS; it must name the bytes verified here.
    json '
import json, sys
panel = json.loads(sys.argv[1])["components"]["panel"]
entry = next((e for e in panel.get("available", []) if e.get("version") == sys.argv[2]), None)
if entry is None:
    raise SystemExit("the version-agent does not offer " + sys.argv[2])
if entry.get("sha256") != sys.argv[3]:
    raise SystemExit("the version-agent would install other bytes than the ones verified")
' "$checked" "$VERSION" "$EXPECTED" || fail "агент не предлагает ровно этот проверенный выпуск" "the agent does not offer exactly this verified release"
    body=$(json 'import json,sys; print(json.dumps({"component": "panel", "version": sys.argv[1], "expected_current": sys.argv[2] or None}))' "$VERSION" "$current")
    agent -X POST -H 'Content-Type: application/json' -d "$body" http://agent/v1/update >/dev/null \
        || fail "агент отказал в обновлении" "the agent refused the update"
    say "панель обновляется (резервные копии и откат — у агента)…" "the panel is updating (backups and rollback are the agent's)…"
    status=
    for _ in $(seq 1 180); do
        sleep "$POLL"
        status=$(agent http://agent/v1/versions 2>/dev/null \
            | python3 -c 'import json,sys; p=json.load(sys.stdin)["components"]["panel"]; print(p.get("status"), p.get("current"), p.get("last_error") or "")' 2>/dev/null) || continue
        [[ $status == updating* ]] || break
    done
    [[ $status == "ready $VERSION"* ]] || fail "панель не обновилась: $status" "the panel did not update: $status"
    # The agent restarts itself a few seconds after an update that changed its own code.
    for _ in $(seq 1 30); do sleep "$POLL"; agent http://agent/v1/health >/dev/null 2>&1 && break; done
fi
[[ $(docker exec proxy-control-panel cat /app/VERSION 2>/dev/null) == "$VERSION" ]] \
    || fail "контейнер панели не сообщает $VERSION" "the panel container does not report $VERSION"
say "панель: $VERSION" "panel: $VERSION"

# --- the managers the agent does not rebuild --------------------------------------------
pending=$(agent http://agent/v1/versions | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["components"]["panel"].get("pending_rebuild") or []))')
DIR=$(sed -n 's/^PROXY_CONTROL_COMPOSE_DIR=//p' "$ENV_FILE" 2>/dev/null | tail -n1)
FILES=$(sed -n 's/^PROXY_CONTROL_COMPOSE_FILES=//p' "$ENV_FILE" 2>/dev/null | tail -n1)
DIR=${DIR:-/opt/mtproxy-shared443}
FILES=${FILES:-compose.yaml}
cd -- "$DIR" || fail "нет каталога проекта $DIR" "no project directory $DIR"
compose=(docker compose --project-name mtproxy --env-file .env)
[[ -f .optional.env ]] && compose+=(--env-file .optional.env)
for sibling in naive mieru xray-router mcp; do [[ -f .env.$sibling ]] && compose+=(--env-file ".env.$sibling"); done
IFS=: read -r -a overlays <<< "$FILES"
for file in "${overlays[@]}"; do compose+=(-f "$DIR/$file"); done
[[ -f version-overrides/compose.versions.yaml ]] && compose+=(-f "$DIR/version-overrides/compose.versions.yaml")
has() { case ":$FILES:" in *":$1:"*) return 0 ;; esac; return 1; }

services=()
for manager in $pending; do
    case $manager in
        mieru_manager) has compose.mieru.yaml && services+=(mieru-manager) ;;
        naive_manager) has compose.naive.yaml && services+=(naive-manager) ;;
        xray_router_manager) has compose.xray-router.yaml && services+=(xray-router) ;;
        mcp_server) has compose.mcp.yaml && services+=(mcp) ;;
    esac
done
# Agents predating this fix omitted mcp_server from their sync set. Complete that
# boundary from the release tree whose digest install-release.sh already verified.
mcp_backup=
if has compose.mcp.yaml; then
    mcp_backup=$(python3 - "$RELEASE_DIR/mcp_server" "$DIR" <<'PY'
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

source, project = Path(sys.argv[1]), Path(sys.argv[2])
target = project / "mcp_server"
def digest(path):
    if not path.is_dir():
        return None
    result = hashlib.sha256()
    for file in sorted(path.rglob("*")):
        if "__pycache__" in file.parts:
            continue
        if file.is_symlink():
            raise SystemExit("refusing a symlink in MCP sources")
        if file.is_file():
            result.update(str(file.relative_to(path)).encode() + b"\0" + file.read_bytes())
    return result.digest()
if source.is_symlink() or target.is_symlink() or not source.is_dir():
    raise SystemExit("verified MCP source tree is missing or unsafe")
if digest(source) != digest(target):
    backups = project / "version-overrides"
    backups.mkdir(exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".mcp-update-", dir=project))
    try:
        shutil.copytree(source, staging / "mcp_server", ignore=shutil.ignore_patterns("__pycache__"))
        if target.exists():
            previous = backups / f"mcp-source-previous-{time.time_ns()}"
            os.replace(target, previous)
            print(previous)
        os.replace(staging / "mcp_server", target)
    finally:
        shutil.rmtree(staging)
PY
    ) || fail "не удалось обновить исходники MCP" "could not update MCP sources"
    # Always reconcile an enabled MCP, including agents that did not report it.
    [[ " ${services[*]} " == *" mcp "* ]] || services+=(mcp)
fi
# v1.1: the router's MTProxy bridge comes with the router (a new service on an updated host).
if has compose.xray-router.yaml && grep -q '^  xray-router-ingress:' compose.xray-router.yaml; then
    services+=(xray-router-ingress)  # idempotent where it already runs the same image
fi
if ((${#services[@]})); then
    "${compose[@]}" config -q || fail "модель Compose не собирается" "the Compose model does not render"
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    rollback_services=()
    for service in "${services[@]}"; do
        if docker image inspect "mtproxy-$service:latest" >/dev/null 2>&1; then
            docker tag "mtproxy-$service:latest" "mtproxy-$service:rollback-$stamp" \
                || fail "не удалось сохранить образ $service" "could not save the $service image"
            rollback_services+=("$service")
            say "точка отката: mtproxy-$service:rollback-$stamp" "rollback image: mtproxy-$service:rollback-$stamp"
        fi
    done
    say "пересобираю: ${services[*]}" "rebuilding: ${services[*]}"
    if ! "${compose[@]}" up -d --build --no-deps --wait "${services[@]}"; then
        if [[ -n $mcp_backup ]]; then
            python3 - "$DIR/mcp_server" "$mcp_backup" <<'PY' \
                || fail "откат исходников MCP не удался" "MCP source rollback failed"
import os
import shutil
import sys
shutil.rmtree(sys.argv[1])
os.replace(sys.argv[2], sys.argv[1])
PY
        fi
        for service in "${rollback_services[@]}"; do
            docker tag "mtproxy-$service:rollback-$stamp" "mtproxy-$service:latest" \
                || fail "откат образа $service не удался" "the $service image rollback failed"
        done
        if ((${#rollback_services[@]})); then
            "${compose[@]}" up -d --no-build --no-deps --wait "${rollback_services[@]}" \
                || fail "проверка служб после отката не прошла" "the restored services did not become healthy"
        fi
        if ((${#rollback_services[@]} == ${#services[@]})); then
            fail "пересборка не удалась; прежние образы восстановлены" "the rebuild failed; previous images restored"
        fi
        fail "пересборка не удалась; восстановлены доступные образы, новым службам нужна проверка оператора" \
            "the rebuild failed; available images restored, new services need operator recovery"
    fi
else
    say "менеджеры пересобирать не нужно" "no manager needs a rebuild"
fi
[[ " $pending " == *" docker "* ]] && say "изменился каталог docker/: Telemt и mask не перезапускались — сделайте это сами, когда удобно (docs/UPGRADING.ru.md)" \
    "docker/ changed: Telemt and mask were not restarted — do it when convenient (docs/UPGRADING.md)"

(cd -- "$RELEASE_DIR" && python3 -m installer.ingress_upgrade --project-dir "$DIR" --apply) \
    || fail "миграция ingress не прошла; проверьте её отчёт и резервную копию" \
        "ingress migration failed; inspect its report and backup"

bad=$(docker ps -a --format '{{.Names}}' | grep '^proxy-control-' | while read -r name; do
    state=$(health "$name"); case $state in healthy|running) ;; *) echo "$name=$state" ;; esac; done)
[[ -z $bad ]] || fail "не здоровы: $bad" "unhealthy: $bad"
say "готово: Proxy Control $VERSION" "done: Proxy Control $VERSION"
