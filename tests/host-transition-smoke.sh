#!/usr/bin/env bash
# Actual old Python agent -> native agent process, never the lab's systemd or installed paths.
# Usage: bash tests/host-transition-smoke.sh INSTALLER AGENT LEGACY_VERSION_AGENT_DIR VERSION
set -Eeuo pipefail
if [[ ${1:-} != --inside ]]; then
    [[ $# == 4 && $EUID == 0 ]] || { echo 'requires root and isolated-build installer/agent/legacy-dir/version arguments' >&2; exit 2; }
    scratch=$(mktemp -d /tmp/pc-host-transition.XXXXXX)
    trap 'rm -rf -- "$scratch"' EXIT
    exec_args=(--inside "$scratch" "$1" "$2" "$3" "$4")
    unshare --mount --pid --fork --net bash "$0" "${exec_args[@]}"
    exit
fi
shift
scratch=$1 installer=$2 agent=$3 legacy=$4 version=$5
mount --make-rprivate /
root=$scratch/root
mkdir -p "$root"/{usr,proc,dev,etc/systemd/system/version-agent.service.d,etc/tmpfiles.d,etc/proxy-control,opt/proxy-control,opt/mtproxy-shared443,run/proxy-control,run/lock,var/lib/proxy-control,var/log,tmp,lab/bin,release/installer/bin/linux-amd64,release/version_agent/bin/linux-amd64,release/release}
mount --bind /usr "$root/usr"
mount -o remount,bind,ro "$root/usr"
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
[[ ! -d /usr/lib64 ]] || ln -s usr/lib64 "$root/lib64"
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mknod -m 0666 "$root/dev/null" c 1 3
mknod -m 0666 "$root/dev/urandom" c 1 9
mknod -m 0666 "$root/dev/random" c 1 8
printf 'root:x:0:0:root:/root:/bin/bash\n' > "$root/etc/passwd"
printf 'root:x:0:\n' > "$root/etc/group"
printf '127.0.0.1 localhost\n' > "$root/etc/hosts"
cp -a "$legacy" "$root/opt/proxy-control/version_agent"
install -m 0755 "$installer" "$root/release/installer/bin/linux-amd64/proxy-control-installer"
install -m 0755 "$agent" "$root/release/version_agent/bin/linux-amd64/proxy-control-version-agent"
printf '%s\n' "$version" > "$root/release/VERSION"
printf '[Service]\nEnvironmentFile=/etc/proxy-control/version-agent.env\nExecStart=/usr/bin/python3 -m version_agent.server\nMemoryDenyWriteExecute=false\n' > "$root/etc/systemd/system/version-agent.service"
printf '[Service]\nLimitNOFILE=9999\n' > "$root/etc/systemd/system/version-agent.service.d/operator.conf"
printf 'd /run/proxy-control 0770 root 10001 -\n' > "$root/etc/tmpfiles.d/proxy-control-version-agent.conf"
cat > "$root/etc/proxy-control/version-agent.env" <<'ENV'
PROXY_CONTROL_UPSTREAM_CHECK=off
PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL=0
PROXY_CONTROL_VERSION_SOCKET_GID=0
OPERATOR_OVERRIDE=keep
ENV
printf '{"components":{}}\n' > "$root/etc/proxy-control/versions.json"
# A persistent parent owns and reaps the agent, like systemd. Separate systemctl shell
# processes cannot wait for each other's children; polling /proc had an exists/open race
# when a native agent exited between the test and cut. The FIFO reply acknowledges wait,
# not a guessed sleep or a second observation of an already-disappearing process.
cat > "$root/lab/service-manager" <<'MANAGER'
#!/usr/bin/env bash
set -Eeuo pipefail
exec 3<> /run/service-command 4<> /run/service-result
pid=''
while read -r command <&3; do
    printf '%s version-agent\n' "$command" >> /var/log/systemctl.log
    status=0
    case $command in
        stop)
            if [[ -n $pid ]]; then
                kill "$pid" 2>/dev/null || true
                wait "$pid" 2>/dev/null || true
                pid=''
                rm /run/agent.pid
            fi
            ;;
        start)
            if [[ -n $pid ]]; then
                status=1
            else
                set -a
                # shellcheck disable=SC1091
                source /etc/proxy-control/version-agent.env
                set +a
                if grep -q '^ExecStart=/usr/bin/python3 ' /etc/systemd/system/version-agent.service; then
                    PYTHONPATH=/opt/proxy-control /usr/bin/python3 -m version_agent.server > /var/log/agent.log 2>&1 < /dev/null &
                else
                    /opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent > /var/log/agent.log 2>&1 < /dev/null &
                fi
                pid=$!
                printf '%s\n' "$pid" > /run/agent.pid
            fi
            ;;
        *) status=90 ;;
    esac
    printf '%s\n' "$status" >&4
done
MANAGER
cat > "$root/lab/bin/systemctl" <<'SERVICE'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $1 != daemon-reload ]] || exit 0
printf '%s\n' "$1" > /run/service-command
read -r status < /run/service-result
exit "$status"
SERVICE
chmod 0755 "$root/lab/bin/systemctl"
cat > "$root/lab/run" <<'RUN'
#!/usr/bin/env bash
set -Eeuo pipefail
export PATH=/lab/bin:/usr/bin:/bin UPDATE_HOST_POLL_SECONDS=0.02
trap 'status=$?; printf "smoke failed at line %s (exit %s)\n" "$LINENO" "$status" >&2; for file in /var/log/agent.log /var/log/systemctl.log /tmp/old-health.json /tmp/failure.err /tmp/native-health.json; do [[ ! -f $file ]] || { printf "%s:\n" "$file" >&2; cat "$file" >&2; }; done; exit "$status"' ERR
binary=/release/installer/bin/linux-amd64/proxy-control-installer
version=$(cat /release/VERSION)
write_identity() {
    printf '{\n  "binaries": {\n    "version_agent/bin/linux-amd64/proxy-control-version-agent": "%s"\n  },\n  "commit": "%040d",\n  "manifest_sha256": "%064d",\n  "tag": "v%s",\n  "version": "%s"\n}\n' "$(sha256sum /release/version_agent/bin/linux-amd64/proxy-control-version-agent | cut -d' ' -f1)" 0 0 "$1" "$1" > /release/release/release.json
}
health() { curl -fsS --max-time 2 --unix-socket /run/proxy-control/version-agent.sock http://agent/v1/health; }
mkfifo /run/service-command /run/service-result
bash /lab/service-manager &
systemctl start version-agent
for _ in {1..100}; do health > /tmp/old-health.json 2>/dev/null && break; sleep .02; done
grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' /tmp/old-health.json
! grep -q implementation /tmp/old-health.json
cp /etc/systemd/system/version-agent.service /tmp/old-unit
cp /etc/proxy-control/version-agent.env /tmp/old-env
cp /etc/tmpfiles.d/proxy-control-version-agent.conf /tmp/old-tmpfiles
# A genuine native binary with the wrong release version must restore the genuine old Python server.
printf '9.9.9\n' > /release/VERSION
write_identity 9.9.9
if "$binary" --source /release migrate-agent --version 9.9.9 > /tmp/failure.out 2> /tmp/failure.err; then exit 1; fi
grep -q 'previous generation restored and verified' /tmp/failure.err
cmp /tmp/old-unit /etc/systemd/system/version-agent.service
cmp /tmp/old-env /etc/proxy-control/version-agent.env
cmp /tmp/old-tmpfiles /etc/tmpfiles.d/proxy-control-version-agent.conf
[[ ! -e /var/lib/proxy-control/installer/state.json && ! -e /var/lib/proxy-control/installer/ownership.json ]]
health > /tmp/restored-health.json
! grep -q implementation /tmp/restored-health.json
printf '%s\n' "$version" > /release/VERSION
write_identity "$version"
"$binary" --source /release migrate-agent --version "$version"
health > /tmp/native-health.json
grep -Eq '"implementation"[[:space:]]*:[[:space:]]*"rust"' /tmp/native-health.json
grep -Eq "\"version\"[[:space:]]*:[[:space:]]*\"$version\"" /tmp/native-health.json
cmp /tmp/old-env /etc/proxy-control/version-agent.env
cmp /tmp/old-tmpfiles /etc/tmpfiles.d/proxy-control-version-agent.conf
grep -q '^MemoryDenyWriteExecute=false$' /etc/systemd/system/version-agent.service
grep -q '^LimitNOFILE=9999$' /etc/systemd/system/version-agent.service.d/operator.conf
[[ ! -e /opt/proxy-control/version_agent/server.py ]]
[[ $(readlink "/proc/$(cat /run/agent.pid)/exe") == /opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent ]]
# No Python is needed to keep the migrated process healthy or re-run its idempotent migration.
python=$(readlink -f /usr/bin/python3)
mount --bind /dev/null "$python"
"$binary" --source /release migrate-agent --version "$version"
health > /tmp/no-python-health.json
[[ ! -e /var/lib/proxy-control/installer/state.json && ! -e /var/lib/proxy-control/installer/ownership.json ]]
grep -Eq '"implementation"[[:space:]]*:[[:space:]]*"rust"' /tmp/no-python-health.json
printf 'SMOKE PASS: real Python agent rollback, native replacement, strict version/implementation health, preserved overrides, no-Python rerun\n'
systemctl stop version-agent
RUN
chmod 0755 "$root/lab/run"
chroot "$root" /bin/bash /lab/run
