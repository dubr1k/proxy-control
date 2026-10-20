#!/usr/bin/env bash
# Move an installed host's stack from the Compose project `mtproxy` to `proxy_panel_by_dubr1k` (3.0).
#
# Run by update-host.sh at its end, as root; once a host is moved it does nothing:
#
#   bash scripts/migrate-compose-project.sh [--dir /opt/mtproxy-shared443] [--lang ru|en] [--check]
#
# `--check` runs every check below and stops before anything changes.
# The containers keep their names, the images their bytes: every image a running service was built
# into is tagged with the new project's name (no rebuild), the data volumes (the panel database,
# Telemt's config) are copied into the new project's volumes while the stack is stopped, and the
# same model update-host.sh and the version-agent use — PROXY_CONTROL_COMPOSE_FILES, the version
# overrides and the env files present — comes up under the new name. The old volumes and images
# stay as they are: they are the way back, and a failure here brings the old project up again from
# them. Everything that can be checked is checked before anything stops: the model renders, it
# defines every running service, and every host path it bind-mounts exists. (3.0.0 read the model
# from the containers' labels; a label can name an overlay the host never installed.) The services
# are down for under a minute.
set -Eeuo pipefail

OLD=mtproxy
NEW=proxy_panel_by_dubr1k
DIR=/opt/mtproxy-shared443
LANGUAGE=en
CHECK_ONLY=
ENV_FILE=${MIGRATE_AGENT_ENV:-/etc/proxy-control/version-agent.env}

say() { if [[ $LANGUAGE == ru ]]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }
fail() { printf 'migrate-compose-project: %s\n' "$(say "$1" "$2")" >&2; exit 1; }

while (($#)); do
    case $1 in
        --dir) DIR=${2:?}; shift 2 ;;
        --lang) LANGUAGE=${2:?}; shift 2 ;;
        --check) CHECK_ONLY=1; shift ;;
        *) printf 'usage: migrate-compose-project.sh [--dir DIR] [--lang ru|en] [--check]\n' >&2; exit 2 ;;
    esac
done
[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "нужен root" "root is required"

mapfile -t old_containers < <(docker ps -a -q --filter "label=com.docker.compose.project=$OLD" | sed '/^$/d')
if ((${#old_containers[@]} == 0)); then
    say "стек уже в проекте $NEW" "the stack already runs as $NEW"
    exit 0
fi
cd -- "$DIR" || fail "нет каталога проекта $DIR" "no project directory $DIR"

# The model every other tool of this host uses (update-host.sh, the version-agent): the overlays of
# PROXY_CONTROL_COMPOSE_FILES, the version overrides, the env files present.
FILES=$(sed -n 's/^PROXY_CONTROL_COMPOSE_FILES=//p' "$ENV_FILE" 2>/dev/null | tail -n1)
FILES=${FILES:-compose.yaml}
model=(--project-directory "$DIR" --env-file "$DIR/.env")
[[ -f $DIR/.optional.env ]] && model+=(--env-file "$DIR/.optional.env")
for sibling in naive mieru xray-router amneziawg trusttunnel mcp; do
    [[ -f $DIR/.env.$sibling ]] && model+=(--env-file "$DIR/.env.$sibling")
done
IFS=: read -r -a overlays <<< "$FILES"
for file in "${overlays[@]}"; do
    [[ $file != */* && -f $DIR/$file ]] || fail "файла Compose $file нет" "no Compose file $file"
    model+=(-f "$DIR/$file")
done
[[ -f $DIR/version-overrides/compose.versions.yaml ]] && model+=(-f "$DIR/version-overrides/compose.versions.yaml")
old=(docker compose --project-name "$OLD" "${model[@]}")
new=(docker compose --project-name "$NEW" "${model[@]}")
config=$("${new[@]}" config --format json) || fail "модель Compose не собирается" "the Compose model does not render"

# What runs now, what of it is built here, and which volumes hold data (not the tmpfs sockets).
mapfile -t running < <(docker ps --filter "label=com.docker.compose.project=$OLD" \
    --format '{{.Label "com.docker.compose.service"}}' | sed '/^$/d' | sort -u)
((${#running[@]})) || fail "в проекте $OLD ничего не работает" "nothing runs in the $OLD project"
# Before anything stops: the model defines every running service, and every host path the services
# it will start (with their dependencies) bind-mount exists — a missing one fails `up` mid-way.
problem=$(python3 -c '
import json, os, sys
model = json.loads(sys.argv[1])
services, secrets = model.get("services", {}), model.get("secrets") or {}
running = sys.argv[2:]
missing = [name for name in running if name not in services]
if missing:
    print("not in the model: " + " ".join(missing)); raise SystemExit
start, queue = set(), list(running)
while queue:
    name = queue.pop()
    if name in start or name not in services:
        continue
    start.add(name)
    queue.extend((services[name].get("depends_on") or {}).keys())
# A short-syntax bind has docker create a missing directory; a long-syntax one fails instead.
paths = {volume.get("source", "") for name in start for volume in services[name].get("volumes") or []
         if volume.get("type") == "bind" and not (volume.get("bind") or {}).get("create_host_path")}
paths |= {(secrets.get(used.get("source")) or {}).get("file") or "" for name in start
          for used in services[name].get("secrets") or []}
absent = sorted(path for path in paths if path and not os.path.exists(path))
if absent:
    print("missing host paths: " + " ".join(absent))
' "$config" "${running[@]}")
[[ -z $problem ]] || fail "модель не подходит для перевода, ничего не остановлено: $problem" \
    "the model cannot move this stack, nothing was stopped: $problem"
read -r -a built <<< "$(python3 -c '
import json, sys
services = json.loads(sys.argv[1]).get("services", {})
print(" ".join(sorted(name for name, service in services.items() if "build" in service and name in sys.argv[2:])))
' "$config" "${running[@]}")"
read -r -a data_volumes <<< "$(python3 -c '
import json, sys
volumes = json.loads(sys.argv[1]).get("volumes", {}) or {}
print(" ".join(sorted(key for key, volume in volumes.items()
                      if not (volume or {}).get("external") and ((volume or {}).get("driver_opts") or {}).get("type") != "tmpfs")))
' "$config")"

if [[ -n $CHECK_ONLY ]]; then
    say "проверка пройдена: $OLD → $NEW, службы ${running[*]}, тома ${data_volumes[*]}" \
        "check passed: $OLD → $NEW, services ${running[*]}, volumes ${data_volumes[*]}"
    exit 0
fi
say "перевожу стек $OLD → $NEW: ${running[*]}" "moving the stack $OLD → $NEW: ${running[*]}"
for service in "${built[@]}"; do
    container=$("${old[@]}" ps -q "$service") || fail "не найден контейнер $service" "no $service container"
    image=$(docker inspect --format '{{.Image}}' "$container") || fail "не прочитан образ $service" "could not read the $service image"
    [[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || fail "неверный ID образа $service" "invalid $service image ID"
    docker tag "$image" "$NEW-$service:latest" || fail "не удалось назвать образ $service" "could not tag the $service image"
done

copied=()
restore() {
    say "возвращаю проект $OLD" "bringing the $OLD project back"
    "${new[@]}" down --remove-orphans >/dev/null 2>&1 || true
    for volume in "${copied[@]}"; do docker volume rm "${NEW}_$volume" >/dev/null 2>&1 || true; done
    "${old[@]}" up -d --no-build --wait "${running[@]}" \
        || fail "проект $OLD не поднялся — нужен оператор (тома ${OLD}_* не тронуты)" \
            "the $OLD project did not come up — operator needed (the ${OLD}_* volumes are untouched)"
}

"${old[@]}" stop || { restore; fail "стек не остановился" "the stack did not stop"; }
compose_version=$(docker compose version --short 2>/dev/null || echo unknown)
for volume in "${data_volumes[@]}"; do
    docker volume inspect "${OLD}_$volume" >/dev/null 2>&1 || continue
    if docker volume inspect "${NEW}_$volume" >/dev/null 2>&1; then
        restore; fail "том ${NEW}_$volume уже есть — проверьте его вручную" "volume ${NEW}_$volume already exists — inspect it by hand"
    fi
    docker volume create --label "com.docker.compose.project=$NEW" --label "com.docker.compose.volume=$volume" \
        --label "com.docker.compose.version=$compose_version" "${NEW}_$volume" >/dev/null \
        || { restore; fail "не создан том ${NEW}_$volume" "could not create volume ${NEW}_$volume"; }
    copied+=("$volume")
    # Any image of the stack has cp; the copy keeps owners, modes and times.
    helper=$(docker image inspect --format '{{.Id}}' "$NEW-panel:latest" 2>/dev/null) || helper=$(docker inspect --format '{{.Image}}' "${old_containers[0]}")
    docker run --rm --network none --user 0 --entrypoint sh \
        -v "${OLD}_$volume:/from:ro" -v "${NEW}_$volume:/to" "$helper" -c 'cp -a /from/. /to/' \
        || { restore; fail "не скопирован том $volume" "could not copy volume $volume"; }
    say "том $volume скопирован в ${NEW}_$volume" "volume $volume copied to ${NEW}_$volume"
done
"${old[@]}" down --remove-orphans || { restore; fail "старые контейнеры не удалены" "the old containers were not removed"; }
if ! "${new[@]}" up -d --no-build --wait "${running[@]}"; then
    restore
    fail "стек не поднялся как $NEW; проект $OLD возвращён" "the stack did not come up as $NEW; the $OLD project is back"
fi

# The agent names the panel image and volume after the project; an older installer wrote the old names.
if [[ -f $ENV_FILE ]]; then
    sed -i -e "s/^PROXY_CONTROL_PANEL_IMAGE=$OLD-panel\$/PROXY_CONTROL_PANEL_IMAGE=$NEW-panel/" \
        -e "s/^PROXY_CONTROL_PANEL_VOLUME=${OLD}_panel-data\$/PROXY_CONTROL_PANEL_VOLUME=${NEW}_panel-data/" "$ENV_FILE"
fi
# The socket volumes are tmpfs: nothing in them outlives a restart.
for volume in $(docker volume ls -q --filter "label=com.docker.compose.project=$OLD"); do
    driver_type=$(docker volume inspect --format '{{index .Options "type"}}' "$volume" 2>/dev/null || true)
    if [[ $driver_type == tmpfs ]]; then docker volume rm "$volume" >/dev/null 2>&1 || true; fi
done
say "стек работает как $NEW. Прежние тома ${OLD}_* оставлены как точка отката; удалить: docker volume rm $(printf "${OLD}_%s " "${copied[@]}")" \
    "the stack runs as $NEW. The previous ${OLD}_* volumes are kept as the way back; to remove: docker volume rm $(printf "${OLD}_%s " "${copied[@]}")"
