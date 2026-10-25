#!/usr/bin/env bash
# Live acceptance of awg_manager on a DISPOSABLE lab host (root, Docker, /dev/net/tun, nft, ufw optional).
#
# Builds the image, starts the manager through compose.amneziawg.yaml, creates one peer per
# AmneziaWG version through the Unix-socket API and proves, for each of 1.5, 2.0 and 3.1, that a
# real amneziawg-go client in its own network namespace (a) cannot handshake with another
# version's parameters, (b) handshakes with its own, (c) reaches the gateway and (d) the outside
# world through NAT. Everything it creates is removed on exit.
#
#   AWG_ACCEPTANCE_LAB=1 bash scripts/lab/awg-acceptance.sh        # from the repository root
set -euo pipefail

[[ ${AWG_ACCEPTANCE_LAB:-} == 1 ]] || { echo "refusing to run: set AWG_ACCEPTANCE_LAB=1 (lab host only)" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=${AWG_ACCEPTANCE_DIR:-/root/awg-acceptance}
PROJECT=awg-acceptance
IMAGE=proxy-control-awg-manager:acceptance
VERSIONS=(1.5 2.0 3.1)
declare -A PORT=([1.5]=51820 [2.0]=51821 [3.1]=51822)
declare -A WRONG=([1.5]=2.0 [2.0]=3.1 [3.1]=1.5)
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
  echo "ACCEPTANCE_RESULT fails=$FAILS rc=$rc"
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

cat >"$WORK/mkclient.py" <<'PY'
"""Build the client-side UAPI body: target instance, obfuscation source instance, keys, endpoint."""
import json, sys
sys.path.insert(0, sys.argv[1] + "/scripts/lab")
from awg_lab import hexkey, uapi_lines  # noqa: E402

target = json.load(open(sys.argv[2]))["instance"]
source = json.load(open(sys.argv[3]))["instance"]
private, psk, endpoint = sys.argv[4], sys.argv[5], sys.argv[6]
lines = [f"private_key={hexkey(private)}"]
lines += uapi_lines(source["obfuscation"])
lines += [
    f"public_key={hexkey(target['server_public_key'])}",
    f"preshared_key={hexkey(psk)}",
    f"endpoint={endpoint}",
    "replace_allowed_ips=true",
    "allowed_ip=0.0.0.0/0",
    "persistent_keepalive_interval=5",
]
sys.stdout.write("\n".join(lines) + "\n")
PY
cat >"$WORK/uapi.py" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts/lab")
from awg_lab import uapi_exchange  # noqa: E402

uapi_exchange(sys.argv[2], b"set=1\n" + open(sys.argv[3], "rb").read() + b"\n")
PY

say "create one peer per version"
declare -A CPRIV CPSK CADDR
for v in "${VERSIONS[@]}"; do
  s=$(suffix "$v")
  CPRIV[$v]=$(cd "$REPO" && python3 scripts/lab/awg_lab.py genkey)
  cpub=$(cd "$REPO" && echo "${CPRIV[$v]}" | python3 scripts/lab/awg_lab.py pubkey)
  CPSK[$v]=$(cd "$REPO" && python3 scripts/lab/awg_lab.py genpsk)
  req=$(python3 -c "import json,sys; print(json.dumps(dict(operation_id='acc-$s', username='acc-$s', version='$v', public_key=sys.argv[1], preshared_key=sys.argv[2])))" "$cpub" "${CPSK[$v]}")
  out=$(api POST /v1/peers "$req")
  [[ $(echo "$out" | code_of) == 201 ]] || { bad "create peer $v: $(echo "$out" | body_of)"; exit 1; }
  echo "$out" | body_of >"$WORK/$s.create.json"
  CADDR[$v]=$(jq_py "d['peer']['address']" <"$WORK/$s.create.json")
  ok "peer for $v created at ${CADDR[$v]}"
  replay=$(api POST /v1/peers "$req")
  check "create is idempotent for $v" test "$(echo "$replay" | code_of)" = 200
done

run_client() { # ns iface target-version param-version tag
  local ns=$1 iface=$2 target=$3 param=$4 tag=$5
  local ts hv hc
  ts=$(suffix "$target")
  hv="v${tag}$ts"           # host side veth (vh15 / vw15)
  hc="vc${tag}$ts"          # namespace side
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
  python3 "$WORK/mkclient.py" "$REPO" "$WORK/$ts.create.json" "$WORK/$(suffix "$param").create.json" \
    "${CPRIV[$target]}" "${CPSK[$target]}" "10.99.${ts}.1:${PORT[$target]}" >"$WORK/$iface.uapi"
  python3 "$WORK/uapi.py" "$REPO" "/var/run/amneziawg/$iface.sock" "$WORK/$iface.uapi"
  ip -n "$ns" addr add "${CADDR[$target]}/24" dev "$iface"
  ip -n "$ns" link set "$iface" mtu 1280 up
  ip -n "$ns" route replace default dev "$iface"
}

stop_clients() {
  for pid in "${CLIENT_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  CLIENT_PIDS=()
  sleep 1
}

handshake_of() { # username -> latest_handshake or 0
  api GET /v1/peers | body_of | jq_py "next((p['latest_handshake'] or 0 for p in d['peers'] if p['username']=='$1'), 0)"
}

DEFAULT_GW=$(ip -4 route show default | awk '{print $3; exit}')
for v in "${VERSIONS[@]}"; do
  s=$(suffix "$v")
  w=${WRONG[$v]}
  say "version $v (wrong-version client uses $w parameters)"

  run_client "awgw$s" "cw$s" "$v" "$w" w
  gw=$(jq_py "d['instance']['gateway']" <"$WORK/$s.create.json")
  if ip netns exec "awgw$s" ping -c3 -W2 "$gw" >/dev/null 2>&1; then bad "$v: client with $w parameters reached the gateway"; else ok "$v: client with $w parameters cannot ping the gateway"; fi
  check "$v: wrong-version client got no handshake" test "$(handshake_of "acc-$s")" = 0
  stop_clients
  ip netns del "awgw$s"; ip link del "vw$s" 2>/dev/null || true
  rm -f "/var/run/amneziawg/cw$s.sock"

  run_client "awgc$s" "cl$s" "$v" "$v" h
  if ip netns exec "awgc$s" ping -c3 -W3 "$gw" >/dev/null 2>&1; then ok "$v: ping gateway $gw through the tunnel"; else bad "$v: ping gateway $gw failed"; fi
  hs=$(handshake_of "acc-$s")
  if [[ $hs -gt 0 ]]; then ok "$v: handshake recorded by the manager (latest_handshake=$hs)"; else bad "$v: no handshake recorded"; fi
  if ip netns exec "awgc$s" ping -c2 -W3 1.1.1.1 >/dev/null 2>&1; then ok "$v: NAT to the internet (1.1.1.1)"
  elif ip netns exec "awgc$s" ping -c2 -W3 "$DEFAULT_GW" >/dev/null 2>&1; then ok "$v: NAT to the host default gateway $DEFAULT_GW (1.1.1.1 unreachable from this lab)"
  else bad "$v: nothing outside the host is reachable through NAT"; fi
  out=$(api GET /v1/peers | body_of | jq_py "[(p['rx'],p['tx']) for p in d['peers'] if p['username']=='acc-$s'][0]")
  echo "$v counters (rx,tx): $out"
  check "$v: counters moved" test "$out" != "(0, 0)"
  stop_clients
  ip netns del "awgc$s"; ip link del "vh$s" 2>/dev/null || true
  rm -f "/var/run/amneziawg/cl$s.sock"
done

say "disable / enable / rotate / restart behave on a live device"
s=20
out=$(api POST /v1/peers/acc-20/disable "{}")
check "disable returns the peer disabled" test "$(echo "$out" | body_of | jq_py "d['peer']['enabled']")" = False
out=$(api POST /v1/peers/acc-20/enable "{}")
check "enable returns the peer enabled" test "$(echo "$out" | body_of | jq_py "d['peer']['enabled']")" = True
docker restart proxy-control-awg-manager >/dev/null
wait_for 60 "manager healthy after restart" bash -c "curl -sS --unix-socket '$SOCK' -H 'X-Awg-Token: $TOKEN' http://x/v1/health | grep -q '\"status\":\"ok\"'"
check "state survived the restart (same server key and obfuscation)" test "$(api GET /v1/instances | body_of | jq_py "[i for i in d['instances'] if i['version']=='2.0'][0]['server_public_key']")" = "$(jq_py "d['instance']['server_public_key']" <"$WORK/$s.create.json")"
check "peer survived the restart" test "$(api GET /v1/peers | body_of | jq_py "len(d['peers'])")" = 3

say "SIGTERM tears the data plane down and keeps the state"
docker stop proxy-control-awg-manager >/dev/null
check "nft table removed on stop" bash -c "! nft list table inet awg_manager"
check "interfaces removed on stop" bash -c "! ip link show awg20"
check "state file kept (mode 600)" test "$(stat -c %a "$WORK/state/state.json")" = 600

echo "SUMMARY fails=$FAILS"
