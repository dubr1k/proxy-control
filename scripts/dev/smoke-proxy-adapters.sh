#!/usr/bin/env bash
# Lab-only native protocol/engine + helper CLI smoke; never touches installed host paths.
set -euo pipefail
if [[ ${1:-} == --inside ]]; then
    root=$2 native=$3 testbin=$4 installer=$5
    [[ $(readlink /proc/self/ns/mnt) != $(readlink /proc/1/ns/mnt) ]]
    [[ $(readlink /proc/self/ns/net) != $(readlink /proc/1/ns/net) ]]
    ip link set lo up
    mkdir -p "$native/host-bin"
    touch "$native/docker.sock"
    mount --bind /run/docker.sock "$native/docker.sock"
    export PC_PROXY_SMOKE_DOCKER_HOST="unix://$native/docker.sock"
    mount --bind /usr/bin "$native/host-bin"
    for path in /etc /var/lib /var/log /var/tmp /var/www /opt /run /usr/local/bin /usr/local/libexec /usr/share/doc; do
        [[ -d $path && ! -L $path ]] || { printf 'Missing safe lab mountpoint: %s\n' "$path" >&2; exit 1; }
        mount -t tmpfs -o mode=0755 tmpfs "$path"
    done
    mount -t tmpfs -o mode=0755 tmpfs /usr/bin
    for path in "$native/host-bin/"*; do
        case "${path##*/}" in mita|mieru) continue;; esac
        "$native/host-bin/ln" -s "$path" "/usr/bin/${path##*/}"
    done
    PC_PROXY_SMOKE_TREE="$root" PC_PROXY_SMOKE_NATIVE="$native" PC_PROXY_SMOKE_INSTALLER="$installer" \
        "$testbin" adapters::proxy_smoke::real_proxy_engine_install_repair_and_rollback --ignored --nocapture --test-threads=1
    "$installer" prepare-naive-state prepare --state-dir /var/lib/proxy-helper-smoke --log-dir /var/log/proxy-helper-smoke
    "$installer" prepare-naive-state verify --state-dir /var/lib/proxy-helper-smoke --log-dir /var/log/proxy-helper-smoke
    install -d -m 0700 /etc/proxy-helper-smoke
    printf '%064d\n' 1 > /etc/proxy-helper-smoke/token
    chmod 0600 /etc/proxy-helper-smoke/token
    "$installer" prepare-mieru-token prepare /etc/proxy-helper-smoke/token
    "$installer" prepare-mieru-token verify /etc/proxy-helper-smoke/token
    [[ $(stat -c '%u:%g:%a' /etc/proxy-helper-smoke/token) == 0:10005:440 ]]
    ln /etc/proxy-helper-smoke/token /etc/proxy-helper-smoke/alias
    if "$installer" prepare-mieru-token prepare /etc/proxy-helper-smoke/token; then
        printf 'Hardlink refusal failed\n' >&2; exit 1
    fi
    printf 'NATIVE_PROXY_ENGINE_AND_HELPER_SMOKE_OK\n'
    exit 0
fi
case ${1:-} in --naive) export PC_PROXY_SMOKE_PROTOCOL=naive;; --mieru) export PC_PROXY_SMOKE_PROTOCOL=mieru;; esac
root=$(realpath "$(dirname "$0")/../..")
case "$root" in /root/dev/rust-host-wp5c-*) ;; *) printf 'Use a dedicated ams-test WP5c stand only\n' >&2; exit 1;; esac
native="$root/native"
target=${CARGO_TARGET_DIR:-/root/rust-target-host-wp5c-proxies}
case "$target" in /root/rust-target-host-wp5c-*) ;; *) printf 'Unsafe shared target directory\n' >&2; exit 1;; esac
mkdir -p "$native"
for package in mita mieru; do
    file="${package}_3.38.1_amd64.deb"
    if [[ ! -f $native/$file ]]; then
        curl --fail --silent --show-error --location --max-time 120 \
            "https://github.com/enfein/mieru/releases/download/v3.38.1/$file" --output "$native/$file"
    fi
done
printf '%s  %s\n' \
    2c7c0be33d34cf126187d97c17484a34b5c62b764c96b0a88ec4cbc7660d72c9 "$native/mita_3.38.1_amd64.deb" \
    f758f886039efcceb6aa9e88c6393ad1d7326e533e0e9a01d378e49bedaa5563 "$native/mieru_3.38.1_amd64.deb" | sha256sum --check --status
if [[ ! -f $native/caddy ]]; then
    container="pc-wp5c-caddy-extract-$$"
    docker create --name "$container" --entrypoint /caddy proxy-control-caddy-naive:v2.11.7 version > /dev/null
    trap 'docker rm "$container" > /dev/null 2>&1 || true' EXIT
    docker cp "$container:/caddy" "$native/caddy"
    docker rm "$container" > /dev/null
    trap - EXIT
fi
mkdir -p "$native/client"
if [[ ! -f $native/client/usr/bin/mieru ]]; then
    dpkg-deb -x "$native/mieru_3.38.1_amd64.deb" "$native/client"
fi
printf '%s  %s\n' 3529fc7190e073d89da1ea9bbf08aa481edca59866c466725b8231325b0b6577 "$native/client/usr/bin/mieru" | sha256sum --check --status
if [[ ${1:-} == --prepare ]]; then
    printf 'PINNED_PROXY_NATIVE_ARTIFACTS_READY\n'
    exit 0
fi
export CARGO_TARGET_DIR="$target" CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
cargo build --manifest-path "$root/installer/Cargo.toml" --locked --bin proxy-control-installer
# Lab/dev tools may use Python; the installed host preparers and native client probe do not.
testbin=$(cargo test --manifest-path "$root/installer/Cargo.toml" --locked --lib --no-run --message-format=json | \
    python3 -c 'import json,sys; rows=(json.loads(line) for line in sys.stdin); print(next(r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="installer" and r.get("profile",{}).get("test") and r.get("executable")))')
installer="$target/debug/proxy-control-installer"
# Both the engine and real native probe containers share this owned, otherwise empty network.
# No host network or installed proxy participates in the acceptance dialogue.
keeper="pc-wp5c-network-$$"
export PC_PROXY_SMOKE_NETWORK="$keeper"
export PC_PROXY_SMOKE_IMAGE="pc-wp5c-mieru-client:smoke-$$"
cleanup() {
    docker rm --force "$keeper" > /dev/null 2>&1 || true
    docker image rm "$PC_PROXY_SMOKE_IMAGE" > /dev/null 2>&1 || true
}
trap cleanup EXIT
docker run --detach --name "$keeper" --network none --entrypoint /bin/sh \
    debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 \
    -c 'exec sleep infinity' > /dev/null
network_pid=$(docker inspect --format '{{.State.Pid}}' "$keeper")
nsenter --net="/proc/$network_pid/ns/net" unshare --mount --propagation private \
    bash "$0" --inside "$root" "$native" "$testbin" "$installer"
if [[ ${PC_PROXY_SMOKE_PROTOCOL:-} != naive ]]; then
    docker run --rm --network none --entrypoint /bin/sh "$PC_PROXY_SMOKE_IMAGE" -ec \
        'if command -v python >/dev/null || command -v python3 >/dev/null; then
             printf "Native image unexpectedly has a Python interpreter\n" >&2; exit 1
         fi
         found=$(find /usr /opt -iname "*python*" -print -quit)
         if [ -n "$found" ]; then
             printf "Native image unexpectedly contains Python artifact: %s\n" "$found" >&2; exit 1
         fi
         digest=$(sha256sum /usr/local/bin/mieru | cut -d " " -f 1)
         if [ "$digest" != 3529fc7190e073d89da1ea9bbf08aa481edca59866c466725b8231325b0b6577 ]; then
             printf "Native image official client digest mismatch\n" >&2; exit 1
         fi
         if [ ! -x /usr/local/bin/mieru-probe ]; then
             printf "Native image Rust probe missing\n" >&2; exit 1
         fi
         printf "NATIVE_MIERU_IMAGE_NO_PYTHON_PINNED_CLIENT_OK\n"'
fi
