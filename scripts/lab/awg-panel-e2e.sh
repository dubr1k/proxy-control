#!/usr/bin/env bash
# Live end-to-end of the PANEL with awg_manager on a DISPOSABLE lab host (root, Docker, /dev/net/tun, nft, ufw optional).
#
# Starts the manager through compose.amneziawg.yaml, then lets a REAL panel app (in-process, the
# production adapter and client) issue one access per AmneziaWG version, and proves that the config
# file the panel hands out brings up a working tunnel with a real amneziawg-go client in its own
# network namespace for each of 1.5, 2.0 and 3.1; a disabled access stops working, a rotated one
# needs the new config. Everything it creates is removed on exit.
#
#   AWG_ACCEPTANCE_LAB=1 bash scripts/lab/awg-panel-e2e.sh        # from the repository root
set -euo pipefail

[[ ${AWG_ACCEPTANCE_LAB:-} == 1 ]] || { echo "refusing to run: set AWG_ACCEPTANCE_LAB=1 (lab host only)" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=${AWG_ACCEPTANCE_DIR:-/root/awg-panel-e2e}
PROJECT=awg-panel-e2e
IMAGE=proxy-control-awg-manager:e2e
VERSIONS=(1.5 2.0 3.1)
declare -A PORT=([1.5]=51820 [2.0]=51821 [3.1]=51822)
declare -A CADDR
FAILS=0
CLIENT_PIDS=()
UFW_RULES=()
OLD_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
COMPOSE=(docker compose -p "$PROJECT" --project-directory "$REPO" -f "$WORK/base.yaml" -f "$REPO/compose.amneziawg.yaml")

say() { printf '\n== %s\n' "$*"; }
ok() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
suffix() { echo "${1/./}"; }

api() { # method path [json]
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --unix-socket "$SOCK" -X "$method" -H "X-Awg-Token: $TOKEN" -w '\n%{http_code}')
  [[ -n $body ]] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "http://awg-manager$path"
}
body_of() { sed '$d'; }
code_of() { tail -n1; }
jq_py() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

cleanup() {
  local rc=$?
  set +e
  say "cleanup"
  for pid in "${CLIENT_PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  sleep 1
  for v in "${VERSIONS[@]}"; do
    s=$(suffix "$v")
    ip netns del "awgc$s" 2>/dev/null
    ip netns del "awgw$s" 2>/dev/null
    ip link del "vh$s" 2>/dev/null
    ip link del "vw$s" 2>/dev/null
    rm -f "/var/run/amneziawg/cl$s.sock" "/var/run/amneziawg/cw$s.sock"
  done
  for rule in "${UFW_RULES[@]}"; do
    # shellcheck disable=SC2086
    ufw --force $rule >/dev/null 2>&1
  done
  if [[ -f $WORK/base.yaml ]]; then
    AWG_MANAGER_TOKEN_FILE=$WORK/token AWG_MANAGER_STATE_DIR=$WORK/state "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  fi
  docker rm -f proxy-control-awg-manager >/dev/null 2>&1
  echo "$OLD_FORWARD" >/proc/sys/net/ipv4/ip_forward
  if nft list table inet awg_manager >/dev/null 2>&1; then bad "nft table awg_manager left behind"; fi
  for v in "${VERSIONS[@]}"; do
    if ip link show "awg$(suffix "$v")" >/dev/null 2>&1; then bad "interface awg$(suffix "$v") left behind"; fi
  done
  rmdir /var/run/amneziawg 2>/dev/null
  docker rmi "$IMAGE" >/dev/null 2>&1
  rm -rf "$WORK"
  echo "E2E_RESULT fails=$FAILS rc=$rc"
  [[ $rc -ne 0 || $FAILS -ne 0 ]] && exit 1
  exit 0
}
trap cleanup EXIT

wait_for() { # seconds description command...
  local limit=$1 desc=$2; shift 2
  local i
  for ((i = 0; i < limit * 2; i++)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "timeout waiting for $desc" >&2
  return 1
}

say "prepare"
rm -rf "$WORK"; mkdir -p "$WORK/state"; chmod 700 "$WORK/state"
python3 -c "import secrets; print(secrets.token_urlsafe(48))" >"$WORK/token"; chmod 600 "$WORK/token"
TOKEN=$(cat "$WORK/token")
printf 'services:\n  panel:\n    image: alpine:latest\n' >"$WORK/base.yaml"
export AWG_MANAGER_TOKEN_FILE=$WORK/token AWG_MANAGER_STATE_DIR=$WORK/state
export AMNEZIAWG_PUBLIC_HOST=vpn.lab.example
check "compose file is valid" "${COMPOSE[@]}" config -q
sysctl -qw net.ipv4.ip_forward=1

say "build image"
docker build -q -t "$IMAGE" -f "$REPO/awg_manager/Dockerfile" "$REPO" >/dev/null
docker run --rm --entrypoint cat "$IMAGE" /usr/local/bin/amneziawg-go >"$WORK/amneziawg-go"
chmod +x "$WORK/amneziawg-go"
check "binary is static and runs" "$WORK/amneziawg-go" --version

say "start manager through compose"
"${COMPOSE[@]}" up -d --no-deps --build awg-manager >/dev/null
VOLUME=${PROJECT}_awg-manager-run
SOCK=$(docker volume inspect -f '{{.Mountpoint}}' "$VOLUME")/manager.sock
wait_for 60 "manager socket" test -S "$SOCK"
wait_for 60 "manager health ok" bash -c "curl -sS --unix-socket '$SOCK' -H 'X-Awg-Token: $TOKEN' http://x/v1/health | grep -q '\"status\":\"ok\"'" \
  || { docker logs proxy-control-awg-manager 2>&1 | tail -30; bad "manager did not become healthy"; exit 1; }
out=$(api GET /v1/health); echo "$out" | body_of
check "health is ok with all instances running" test "$(echo "$out" | body_of | jq_py "d['status']")" = ok
check "unauthenticated request is refused" test "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" http://x/v1/health)" = 401
check "container healthcheck is healthy" wait_for 60 "docker health" bash -c "[[ \$(docker inspect -f '{{.State.Health.Status}}' proxy-control-awg-manager) == healthy ]]"
for v in "${VERSIONS[@]}"; do
  s=$(suffix "$v")
  check "interface awg$s is up on the host" ip link show "awg$s"
  check "udp ${PORT[$v]} is bound" bash -c "ss -lun | grep -q ':${PORT[$v]} '"
done

say "firewall for the lab (what the installer must do on a ufw host)"
if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  for v in "${VERSIONS[@]}"; do
    s=$(suffix "$v")
    ufw allow in on "vh$s" to any port "${PORT[$v]}" proto udp >/dev/null
    UFW_RULES+=("delete allow in on vh$s to any port ${PORT[$v]} proto udp")
    ufw route allow in on "awg$s" >/dev/null
    UFW_RULES+=("route delete allow in on awg$s")
  done
fi


VENV_PY=${AWG_E2E_PYTHON:-$REPO/.venv/bin/python}

say "the panel issues one access per version"
OUT=$WORK/out; mkdir -p "$OUT"
"$VENV_PY" "$REPO/scripts/lab/awg_panel_issue.py" issue "$REPO" "$SOCK" "$WORK/token" "$OUT" || { bad "the panel could not issue the accesses"; exit 1; }
for v in "${VERSIONS[@]}"; do
  check "$v: the config has the version's endpoint port" grep -q "^Endpoint = vpn.lab.example:${PORT[$v]}$" "$OUT/$v.conf"
  check "$v: the manager's state never holds the client's private key" bash -c "! grep -q \"\$(sed -n 's/^PrivateKey = //p' '$OUT/$v.conf')\" '$WORK/state/state.json'"
  CADDR[$v]=$(python3 -c "import json;print(json.load(open('$OUT/index.json'))['grants']['$v']['address'])")
  ok "$v: address ${CADDR[$v]}"
done
check "S3/S4 only from 2.0 on" bash -c "! grep -q '^S3 = ' '$OUT/1.5.conf' && grep -q '^S3 = ' '$OUT/2.0.conf' && grep -q '^S3 = ' '$OUT/3.1.conf'"
check "header protection key only in 3.1" bash -c "! grep -q '^HeaderProtectionKey' '$OUT/2.0.conf' && grep -q '^HeaderProtectionKey' '$OUT/3.1.conf'"

run_client() { # ns iface version veth-tag
  local ns=$1 iface=$2 version=$3 tag=$4 ts hv hc
  ts=$(suffix "$version"); hv="v${tag}$ts"; hc="vc${tag}$ts"
  ip netns add "$ns"
  ip link add "$hv" type veth peer name "$hc"
  ip link set "$hc" netns "$ns"
  ip addr add "10.99.${ts}.1/30" dev "$hv" 2>/dev/null || true
  ip link set "$hv" up
  ip -n "$ns" addr add "10.99.${ts}.2/30" dev "$hc"
  ip -n "$ns" link set "$hc" up
  ip -n "$ns" link set lo up
  ip netns exec "$ns" env LOG_LEVEL=error "$WORK/amneziawg-go" -f "$iface" >"$WORK/$iface.log" 2>&1 &
  CLIENT_PIDS+=($!)
  wait_for 10 "client socket $iface" test -S "/var/run/amneziawg/$iface.sock"
  python3 "$REPO/scripts/lab/awg_conf_to_uapi.py" "$REPO" "$OUT/$version.conf" "10.99.${ts}.1:${PORT[$version]}" >"$WORK/$iface.uapi" 2>"$WORK/$iface.meta"
  python3 - "$REPO" "/var/run/amneziawg/$iface.sock" "$WORK/$iface.uapi" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts/lab")
from awg_lab import uapi_exchange
uapi_exchange(sys.argv[2], b"set=1\n" + open(sys.argv[3], "rb").read() + b"\n")
PY
  ip -n "$ns" addr add "${CADDR[$version]}/24" dev "$iface"
  ip -n "$ns" link set "$iface" mtu 1280 up
  ip -n "$ns" route replace default dev "$iface"
}
stop_clients() {
  for pid in "${CLIENT_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  CLIENT_PIDS=(); sleep 1
}
drop_client() { # ns hostveth sock
  ip netns del "$1" 2>/dev/null || true
  ip link del "$2" 2>/dev/null || true
  rm -f "$3"
}
handshake_of() { # username
  api GET /v1/peers | body_of | jq_py "next((p['latest_handshake'] or 0 for p in d['peers'] if p['username']=='$1'), 0)"
}

DEFAULT_GW=$(ip -4 route show default | awk '{print $3; exit}')
for v in "${VERSIONS[@]}"; do
  s=$(suffix "$v"); user="e2e-awg$s"
  say "version $v through the panel's config"
  gw=$(api GET /v1/instances | body_of | jq_py "[i['gateway'] for i in d['instances'] if i['version']=='$v'][0]")
  run_client "e2ec$s" "ec$s" "$v" h
  if ip netns exec "e2ec$s" ping -c3 -W3 "$gw" >/dev/null 2>&1; then ok "$v: ping gateway $gw through the tunnel built from the panel's config"; else bad "$v: ping gateway failed"; fi
  hs=$(handshake_of "$user")
  if [[ $hs -gt 0 ]]; then ok "$v: handshake recorded (latest_handshake=$hs)"; else bad "$v: no handshake"; fi
  if ip netns exec "e2ec$s" ping -c2 -W3 1.1.1.1 >/dev/null 2>&1; then ok "$v: NAT to the internet"
  elif ip netns exec "e2ec$s" ping -c2 -W3 "$DEFAULT_GW" >/dev/null 2>&1; then ok "$v: NAT to the host gateway $DEFAULT_GW"
  else bad "$v: nothing outside is reachable"; fi
  stop_clients; drop_client "e2ec$s" "vh$s" "/var/run/amneziawg/ec$s.sock"
done

say "disable, enable and rotate from the panel"
s=20; v=2.0; user=e2e-awg20; gw=$(api GET /v1/instances | body_of | jq_py "[i['gateway'] for i in d['instances'] if i['version']=='$v'][0]")
if "$VENV_PY" "$REPO/scripts/lab/awg_panel_issue.py" action "$REPO" "$SOCK" "$WORK/token" "$OUT" disable "$v" >/dev/null; then ok "panel disabled $user"; else bad "panel disable failed"; fi
check "manager shows the peer disabled" test "$(api GET /v1/peers | body_of | jq_py "[p['enabled'] for p in d['peers'] if p['username']=='$user'][0]")" = False
run_client "e2ec$s" "ec$s" "$v" h
if ip netns exec "e2ec$s" ping -c2 -W2 "$gw" >/dev/null 2>&1; then bad "$v: a disabled access still reaches the gateway"; else ok "$v: a disabled access does not connect"; fi
stop_clients; drop_client "e2ec$s" "vh$s" "/var/run/amneziawg/ec$s.sock"

if "$VENV_PY" "$REPO/scripts/lab/awg_panel_issue.py" action "$REPO" "$SOCK" "$WORK/token" "$OUT" enable "$v" >/dev/null; then ok "panel enabled $user"; else bad "panel enable failed"; fi
cp "$OUT/$v.conf" "$WORK/old-$v.conf"
if "$VENV_PY" "$REPO/scripts/lab/awg_panel_issue.py" action "$REPO" "$SOCK" "$WORK/token" "$OUT" rotate "$v" >/dev/null; then ok "panel rotated the keys of $user"; else bad "panel rotate failed"; fi
check "the rotated config has a new private key" test "$(sed -n 's/^PrivateKey = //p' "$OUT/$v.conf")" != "$(sed -n 's/^PrivateKey = //p' "$WORK/old-$v.conf")"
cp "$OUT/$v.conf" "$WORK/new-$v.conf"; cp "$WORK/old-$v.conf" "$OUT/$v.conf"
run_client "e2ec$s" "ec$s" "$v" h
if ip netns exec "e2ec$s" ping -c2 -W2 "$gw" >/dev/null 2>&1; then bad "$v: the old config still works after rotation"; else ok "$v: the old config is dead after rotation"; fi
stop_clients; drop_client "e2ec$s" "vh$s" "/var/run/amneziawg/ec$s.sock"
cp "$WORK/new-$v.conf" "$OUT/$v.conf"
run_client "e2ec$s" "ec$s" "$v" h
if ip netns exec "e2ec$s" ping -c3 -W3 "$gw" >/dev/null 2>&1; then ok "$v: the new config works"; else bad "$v: the new config does not work"; fi
stop_clients; drop_client "e2ec$s" "vh$s" "/var/run/amneziawg/ec$s.sock"

echo "SUMMARY fails=$FAILS"
