#!/bin/sh
# Rotate the Xray-router ingress credentials (v0.5, spec §5.7). Each named service gets a
# fresh `user:password` in the project's secrets/ and in its manager's state directory;
# the router is recreated with the new keys, then each manager, which re-renders its egress
# block at bootstrap (naive: Caddy reload; mieru: mita restart). Prints service names only.
#
#   rotate-xray-router-ingress [naive] [mieru]      (default: both)
set -eu

PROJECT_DIR=${PROJECT_DIR:-/opt/mtproxy-shared443}
NAIVE_STATE_DIR=${NAIVE_DATA_DIR:-/var/lib/naive-manager}
MIERU_STATE_DIR=${MIERU_MANAGER_STATE_DIR:-/var/lib/mieru-manager}
readonly NAIVE_MANAGER_UID=10002
readonly NAIVE_MANAGER_GID=101
readonly MIERU_MANAGER_UID=10005
readonly ROUTER_GID=10006

fail() {
    printf 'rotate-xray-router-ingress: %s\n' "$1" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -f "$PROJECT_DIR/.env.xray-router" ] || fail "the Xray-router is not installed in $PROJECT_DIR"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"

if [ "$#" -eq 0 ]; then
    set -- naive mieru
fi
for service in "$@"; do
    case $service in
        naive|mieru) ;;
        *) fail "unknown service: $service (naive|mieru)" ;;
    esac
done

random_hex() {
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

random_password() {
    # 32 random bytes as base64url without padding: 43 characters, [A-Za-z0-9_-].
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

write_secret() {
    # $1 destination, $2 content, $3 owner uid:gid, $4 mode — atomic, never world-readable.
    dir=$(dirname -- "$1")
    tmp=$dir/.$(basename -- "$1").$$.tmp
    umask 077
    printf '%s\n' "$2" > "$tmp"
    chown "$3" -- "$tmp"
    chmod "$4" -- "$tmp"
    mv -f -- "$tmp" "$1"
}

compose() {
    env_files="--env-file $PROJECT_DIR/.env"
    files="-f $PROJECT_DIR/compose.yaml"
    for overlay in naive mieru xray-router; do
        if [ -f "$PROJECT_DIR/.env.$overlay" ]; then
            env_files="$env_files --env-file $PROJECT_DIR/.env.$overlay"
            files="$files -f $PROJECT_DIR/compose.$overlay.yaml"
        fi
    done
    # shellcheck disable=SC2086 # the lists are built from fixed words and one directory
    docker compose --project-directory "$PROJECT_DIR" $env_files $files "$@" >/dev/null
}

rotated=""
for service in "$@"; do
    credential="$service-$(random_hex 4):$(random_password)"
    # The router reads it as a Docker file secret (its own owner and mode): root:10006 0440.
    write_secret "$PROJECT_DIR/secrets/xray-router-ingress-$service" "$credential" "0:$ROUTER_GID" 0440
    case $service in
        naive)
            [ -d "$NAIVE_STATE_DIR" ] && write_secret "$NAIVE_STATE_DIR/xray-router-ingress" "$credential" "$NAIVE_MANAGER_UID:$NAIVE_MANAGER_GID" 0400
            ;;
        mieru)
            [ -d "$MIERU_STATE_DIR" ] && write_secret "$MIERU_STATE_DIR/xray-router-ingress" "$credential" "$MIERU_MANAGER_UID:$MIERU_MANAGER_UID" 0400
            ;;
    esac
    rotated="$rotated $service"
done

# Docker file secrets are read when the container is created: recreate, do not restart.
compose up -d --force-recreate --no-deps --wait xray-router
printf 'recreated: xray-router\n'
for service in "$@"; do
    if [ -f "$PROJECT_DIR/.env.$service" ]; then
        compose up -d --force-recreate --no-deps --wait "$service-manager"
        printf 'recreated: %s-manager\n' "$service"
    fi
done
printf 'rotated:%s\n' "$rotated"
