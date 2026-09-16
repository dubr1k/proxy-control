#!/bin/sh
# The Xray-router manager's state directory (v0.5): generations, current.json, journal.json
# and state.json, owned by the manager identity 10006:10006, mode 0700. `prepare` creates
# it empty; `verify` checks a restored one (BACKUP_RESTORE) before the container starts.
set -eu

readonly ROUTER_UID=10006
readonly ROUTER_GID=10006
readonly ROUTER_MODE=0700

fail() {
    printf 'prepare-xray-router-state: %s\n' "$*" >&2
    exit 1
}

verify_regular_file() {
    file=$1
    description=$2
    [ ! -L "$file" ] || fail "$description must not be a symlink: $file"
    [ -f "$file" ] || fail "$description must be a regular file: $file"
    [ "$(stat -c '%u:%g' -- "$file")" = "$ROUTER_UID:$ROUTER_GID" ] || fail "$description must have owner 10006:10006: $file"
    [ "$(stat -c '%a' -- "$file")" = "600" ] || fail "$description must have mode 0600: $file"
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ "$#" -le 2 ] || fail "usage: $0 prepare|verify [absolute-state-directory]"
mode=${1:-}
case "$mode" in
    prepare|verify) ;;
    *) fail "usage: $0 prepare|verify [absolute-state-directory]" ;;
esac
state_dir=${2:-${XRAY_ROUTER_STATE_DIR:-/var/lib/xray-router}}

case "$state_dir" in
    /*) ;;
    *) fail "state directory must be an absolute path" ;;
esac
[ "$state_dir" != "/" ] || fail "refusing filesystem root"
case "$state_dir" in
    *//*|*/./*|*/.|*/../*|*/..|*/) fail "state directory must be a normalized absolute path without traversal" ;;
esac

path_part=$state_dir
while [ "$path_part" != "/" ]; do
    [ ! -L "$path_part" ] || fail "state path must not contain a symlink: $path_part"
    path_part=${path_part%/*}
    [ -n "$path_part" ] || path_part=/
done

if [ -e "$state_dir" ] || [ -L "$state_dir" ]; then
    if [ ! -d "$state_dir" ] || [ -L "$state_dir" ]; then
        fail "state path must be a real directory, not a symlink"
    fi
    if [ "$mode" = "prepare" ]; then
        [ -z "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail "prepare refuses a non-empty state directory; use verify after restoring"
    fi
else
    [ "$mode" = "prepare" ] || fail "verify requires an existing state directory; run prepare for a fresh deployment"
    install -d -m "$ROUTER_MODE" -o "$ROUTER_UID" -g "$ROUTER_GID" -- "$state_dir"
fi
if [ "$mode" = "prepare" ]; then
    chown "$ROUTER_UID:$ROUTER_GID" -- "$state_dir"
    chmod "$ROUTER_MODE" -- "$state_dir"
    install -d -m "$ROUTER_MODE" -o "$ROUTER_UID" -g "$ROUTER_GID" -- "$state_dir/generations"
    printf 'Prepared Xray-router state directory: %s\n' "$state_dir"
else
    [ "$(stat -c '%u:%g' -- "$state_dir")" = "$ROUTER_UID:$ROUTER_GID" ] || fail "state directory must have owner 10006:10006; restore ownership explicitly, then retry verify"
    [ "$(stat -c '%a' -- "$state_dir")" = "700" ] || fail "state directory must have mode 0700; restore its mode explicitly, then retry verify"
    for name in current.json journal.json state.json; do
        candidate=$state_dir/$name
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            verify_regular_file "$candidate" "$name"
        fi
    done
    generations=$state_dir/generations
    if [ -e "$generations" ] || [ -L "$generations" ]; then
        if [ -L "$generations" ] || [ ! -d "$generations" ]; then
            fail "generations must be a real directory, not a symlink"
        fi
        [ "$(stat -c '%u:%g' -- "$generations")" = "$ROUTER_UID:$ROUTER_GID" ] || fail "generations directory must have owner 10006:10006"
        [ "$(stat -c '%a' -- "$generations")" = "700" ] || fail "generations directory must have mode 0700"
        for generation in "$generations"/*; do
            if [ -e "$generation" ] || [ -L "$generation" ]; then
                verify_regular_file "$generation" "generation"
            fi
        done
    fi
    printf 'Verified Xray-router state directory: %s\n' "$state_dir"
fi
