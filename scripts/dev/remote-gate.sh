#!/usr/bin/env bash
# Sync the working tree to the disposable lab host and run one gate level there.
# Never points at a production host: the default is the throwaway ams-test.
set -Eeuo pipefail

LEVEL=${1:-}
shift || true
HOST=${LAB_HOST:-ams-test}
REMOTE=${LAB_DIR:-/root/dev/proxy-control}
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

case $HOST in
  # AMS_Z is the host formerly aliased GER; both names stay refused.
  ams-server|AMS_R|AMS_P|AMS_Z|GER) echo "refusing production host $HOST" >&2; exit 2 ;;
esac

sync_tree() {
  "${SSH[@]}" "mkdir -p $REMOTE && git config --global --add safe.directory $REMOTE >/dev/null 2>&1 || true"
  rsync -a --delete --no-owner --no-group -e "ssh -o BatchMode=yes" \
    --exclude .venv --exclude .lab-state --exclude lab-results --exclude lab-results-container \
    --exclude dist --exclude dist-again --exclude __pycache__ --exclude .pytest_cache \
    --exclude .ruff_cache --exclude node_modules --exclude .DS_Store --exclude .hermes \
    --exclude secrets --exclude .env --exclude graphify-out/cache \
    "$ROOT/" "$HOST:$REMOTE/"
}

remote() {
  "${SSH[@]}" "cd $REMOTE && $1"
}

ensure_venv='test -x .venv/bin/python || python3 -m venv .venv; .venv/bin/pip install -q -r panel/requirements-dev.txt'
build_images='docker build -q -f panel/Dockerfile -t mtproxy-panel:latest panel >/dev/null && docker build -q -f mieru_manager/Dockerfile -t mtproxy-mieru-manager:latest . >/dev/null'

case $LEVEL in
  quick)
    sync_tree
    remote "$ensure_venv && .venv/bin/ruff check . && .venv/bin/python -m pytest -q -p no:cacheprovider $*"
    ;;
  full)
    sync_tree
    remote "$ensure_venv && $build_images && .venv/bin/ruff check . \
      && .venv/bin/python -m pytest -q -p no:cacheprovider \
      && .venv/bin/python -m unittest -q tests/test_deploy.py \
      && python3 scripts/check-doc-links.py \
      && bash scripts/dev/check-js-syntax.sh \
      && git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n \
      && git ls-files -z '*.sh' | xargs -0 -r shellcheck \
      && shellcheck install-bootstrap \
      && for unit in deploy/*.service; do systemd-analyze verify \"\$unit\"; done \
      && git diff --check && echo REMOTE_GATE_FULL_OK"
    ;;
  compose)
    sync_tree
    remote "mkdir -p /tmp/cover /tmp/letsencrypt secrets \
      && printf 'ci=0123456789abcdef0123456789abcdef\n' > secrets/users.conf \
      && printf 'Bearer ci-telemt-token-0123456789abcdef\n' > secrets/telemt-api-token \
      && printf 'ci-naive-manager-token-0123456789abcdef0123456789abcdef\n' > secrets/naive-manager-token \
      && printf 'ci-mieru-manager-token-0123456789abcdef0123456789abcdef\n' > secrets/mieru-manager-token \
      && printf '{\"schema\":1,\"active_key_id\":\"k-ci000000\",\"keys\":[{\"key_id\":\"k-ci000000\",\"state\":\"active\",\"created_at\":1,\"key_material\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}]}\n' > secrets/panel-master-key \
      && export MTPROXY_DOMAIN=proxy.example.com MTPROXY_BACKEND_PORT=18445 MTPROXY_COVER_ROOT=/tmp/cover MTPROXY_LETSENCRYPT_ROOT=/tmp/letsencrypt MIERU_MANAGER_TOKEN_FILE=\$PWD/secrets/mieru-manager-token \
      && docker compose -f compose.yaml config -q \
      && NAIVE_PUBLIC_HOST=naive.example.com docker compose -f compose.yaml -f compose.naive.yaml config -q \
      && MIERU_PUBLIC_HOST=mieru.example.com MIERU_MITA_GID=321 MIERU_MITA_BIN=/bin/true MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 docker compose -f compose.yaml -f compose.mieru.yaml config -q \
      && FLEET_NODE_ID=node-ci FLEET_CENTRAL_URL=https://fleet.example.com:8790 FLEET_CLIENT_CERT=/tmp/client.crt FLEET_CLIENT_KEY=/tmp/client.key docker compose -f compose.yaml -f compose.agent.yaml config -q \
      && FLEET_SERVER_CERT=/tmp/server.crt FLEET_SERVER_KEY=/tmp/server.key FLEET_CLIENT_CA=/tmp/client-ca.crt docker compose -f compose.yaml -f compose.fleet-central.yaml config -q \
      && docker build -q -f deploy/Dockerfile.agent -t proxy-control-agent:test . >/dev/null \
      && docker build -q -f deploy/Dockerfile.ingress -t proxy-control-ingress:test . >/dev/null \
      && test \"\$(docker run --rm --entrypoint id proxy-control-ingress:test -u)\" = 10001 \
      && echo REMOTE_GATE_COMPOSE_OK"
    ;;
  lab-container)
    sync_tree
    remote "python3 release/build.py --source . --output dist --version \"\$(cat VERSION)\" --allow-dirty \
      && sha=\$(awk '/proxy-control-v.*\.tar\.gz\$/ {print \$1}' dist/SHA256SUMS) \
      && python3 scripts/lab/docker_lab.py --release-archive dist/proxy-control-v\$(cat VERSION).tar.gz --release-sha256 \$sha --output lab-results-container \
      && echo REMOTE_GATE_LAB_CONTAINER_OK"
    ;;
  lab-host)
    test "${LAB_RESET:-0}" = 1 || { echo "lab-host reinstalls $HOST entirely; rerun with LAB_RESET=1" >&2; exit 2; }
    sync_tree
    # The runner must be the copy inside the extracted release (it derives its root from
    # its own location and refuses a tree with `.git`), exactly as docker_lab.py stages it.
    remote "python3 release/build.py --source . --output dist --version \"\$(cat VERSION)\" --allow-dirty \
      && sha=\$(awk '/proxy-control-v.*\.tar\.gz\$/ {print \$1}' dist/SHA256SUMS) \
      && cp \"dist/proxy-control-v\$(cat VERSION).tar.gz\" /tmp/proxy-control-release.tar.gz \
      && printf '%s\n' \"\$sha\" > /tmp/proxy-control-release.sha256 \
      && rm -rf /tmp/proxy-control-release && mkdir -p /tmp/proxy-control-release \
      && tar -xzf /tmp/proxy-control-release.tar.gz -C /tmp/proxy-control-release \
      && printf '%s\n' \"\$sha\" > /root/lab-host.sha"
    # The install scenario drops the SSH session (the host's firewall changes reset
    # established connections), so the runner is detached from it: it writes its own log
    # on the host and this side only follows the log until the exit marker appears.
    remote "rm -f /root/lab-host.log; setsid nohup bash -c 'LAB_RESET=1 bash /tmp/proxy-control-release/proxy-control/scripts/lab/guest-runner.sh host \"\$(cat /root/lab-host.sha)\"; echo LAB_HOST_EXIT=\$?' > /root/lab-host.log 2>&1 < /dev/null &"
    shown=0
    while :; do
      sleep 30
      if ! text=$("${SSH[@]}" "cat /root/lab-host.log 2>/dev/null"); then
        continue
      fi
      total=$(printf '%s\n' "$text" | grep -c '^LAB_RESULT\|^LAB_PLAN_DIGEST\|^LAB_HOST_EXIT' || true)
      if ((total > shown)); then
        printf '%s\n' "$text" | grep '^LAB_RESULT\|^LAB_PLAN_DIGEST\|^LAB_HOST_EXIT' | tail -n "$((total - shown))"
        shown=$total
      fi
      if printf '%s\n' "$text" | grep -q '^LAB_HOST_EXIT='; then
        code=$(printf '%s\n' "$text" | sed -n 's/^LAB_HOST_EXIT=//p' | tail -n1)
        test "$code" = 0 && echo REMOTE_GATE_LAB_HOST_OK
        exit "$code"
      fi
    done
    ;;
  *)
    echo "usage: $0 {quick <pytest args…>|full|compose|lab-container|lab-host}" >&2
    exit 2
    ;;
esac
