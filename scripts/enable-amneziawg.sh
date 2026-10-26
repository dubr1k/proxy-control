#!/usr/bin/env bash
# Enable AmneziaWG on a host that was NOT set up by the installer (a hand-managed Proxy Control host).
#
# Does what the installer's `amneziawg` adapter does, idempotently, from the unpacked release this
# script lives in: copies awg_manager, the shared Rust crate pc_common its image builds against and
# compose.amneziawg.yaml into the project directory, creates the manager token (kept if it exists)
# and the state directory, writes .env.amneziawg, turns on IPv4 forwarding, opens the UDP ports (ufw)
# or installs the forwarding service (no ufw), adds the overlay to the version agent's compose list,
# brings awg-manager and the panel up and checks the result.
# Server keys in /var/lib/awg-manager are never touched.
#
# UDP ports: the well-known 51820-51822 are fingerprinted, so by default every version gets a free
# pseudo-random port in 10240-32000 derived from /etc/machine-id (stable per host; the same derivation
# as the installer's). --ports names some or all of them (1.5=P,2.0=P,3.1=P; the rest are picked).
# A re-run keeps the ports already in .env.amneziawg unless --ports changes them; the ufw rules of
# ports that changed are removed. The chosen ports are printed at the end.
#
#   sudo scripts/enable-amneziawg.sh --host vpn.example.com [--dir /opt/mtproxy-shared443]
#        [--versions 1.5,2.0,3.1] [--ports 1.5=23456,2.0=24567,3.1=25678]
#        [--mtu 1280] [--dns 1.1.1.1,1.0.0.1]
set -euo pipefail

usage() { awk 'NR >= 2 { if (/^set -euo/) exit; print }' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR=/opt/mtproxy-shared443 HOST="" VERSIONS=1.5,2.0,3.1 MTU=1280 DNS=1.1.1.1,1.0.0.1 PORTS_ARG=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --host) HOST=${2:?}; shift 2 ;;
    --dir) DIR=${2:?}; shift 2 ;;
    --versions) VERSIONS=${2:?}; shift 2 ;;
    --ports) PORTS_ARG=${2:?}; shift 2 ;;
    --mtu) MTU=${2:?}; shift 2 ;;
    --dns) DNS=${2:?}; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 2; }
[[ -n $HOST ]] || { echo "--host is required: the DNS name clients dial (it must reach this server over UDP, not behind a proxying CDN)" >&2; usage; }
[[ $HOST =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || { echo "invalid --host" >&2; exit 2; }
[[ $MTU =~ ^[0-9]{4}$ && $MTU -ge 1280 && $MTU -le 1420 ]] || { echo "--mtu must be 1280-1420" >&2; exit 2; }
[[ -d $DIR && -f $DIR/compose.yaml ]] || { echo "$DIR is not a Proxy Control project directory" >&2; exit 2; }
[[ -d $SRC/awg_manager && -d $SRC/pc_common && -f $SRC/compose.amneziawg.yaml ]] || { echo "run this script from an unpacked release" >&2; exit 2; }
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun is missing on this host" >&2; exit 2; }

declare -A SUBNET=([1.5]=10.66.15.0/24 [2.0]=10.66.20.0/24 [3.1]=10.66.31.0/24)
declare -A PORT=() GIVEN=() OLD=()
IFS=, read -r -a VERS <<< "$VERSIONS"
for v in "${VERS[@]}"; do
  [[ -n ${SUBNET[$v]:-} ]] || { echo "unsupported version: $v (1.5, 2.0, 3.1)" >&2; exit 2; }
done
# --ports: any subset of the selected versions; every number is a UDP port a client can dial
if [[ -n $PORTS_ARG ]]; then
  IFS=, read -r -a ENTRIES <<< "$PORTS_ARG"
  for entry in "${ENTRIES[@]}"; do
    [[ $entry =~ ^(1\.5|2\.0|3\.1)=([0-9]{4,5})$ ]] || { echo "invalid --ports entry: $entry (use 1.5=P,2.0=P,3.1=P)" >&2; exit 2; }
    v=${BASH_REMATCH[1]} p=${BASH_REMATCH[2]}
    [[ -n ${SUBNET[$v]:-} && " ${VERS[*]} " == *" $v "* ]] || { echo "--ports names version $v, which is not in --versions" >&2; exit 2; }
    (( 10#$p >= 1024 && 10#$p <= 65535 )) || { echo "--ports $v: $p is outside 1024-65535" >&2; exit 2; }
    GIVEN[$v]=$((10#$p))
  done
fi
# the ports of an earlier run (kept unless --ports names the version)
if [[ -f $DIR/.env.amneziawg ]]; then
  OLD_LINE=$(sed -n 's/^AWG_PORTS=//p' "$DIR/.env.amneziawg" | tail -n1)
  IFS=, read -r -a OLD_ENTRIES <<< "$OLD_LINE"
  for entry in "${OLD_ENTRIES[@]}"; do
    if [[ $entry =~ ^(1\.5|2\.0|3\.1)=([0-9]{4,5})$ ]]; then OLD[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}; fi
  done
fi
# listeners already bound on the host (UDP and TCP); the ports of an earlier run are ours
BOUND=$( { ss -H -lun 2>/dev/null; ss -H -ltn 2>/dev/null; } | awk '{n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' ')
for v in "${VERS[@]}"; do
  if [[ -n ${GIVEN[$v]:-} ]]; then PORT[$v]=${GIVEN[$v]}
  elif [[ -n ${OLD[$v]:-} ]]; then PORT[$v]=${OLD[$v]}; fi
done
# every other version: a free pseudo-random port, derived exactly like the installer does
NEED=()
for v in "${VERS[@]}"; do [[ -n ${PORT[$v]:-} ]] || NEED+=("$v"); done
if (( ${#NEED[@]} )); then
  PICKED=$(python3 - "$BOUND" "${PORT[@]}" -- "${NEED[@]}" <<'PY'
import hashlib, socket, sys
bound_arg, *rest = sys.argv[1:]
split = rest.index("--")
fixed, need = rest[:split], rest[split + 1:]
taken = {int(p) for p in bound_arg.split()} | {int(p) for p in fixed}
try:
    ident = open("/etc/machine-id").read().strip() or socket.gethostname()
except OSError:
    ident = socket.gethostname()
for version in need:
    for attempt in range(4096):
        port = 10240 + int.from_bytes(hashlib.sha256(f"{ident}:{version}:{attempt}".encode()).digest(), "big") % 21761
        if port not in taken:
            taken.add(port)
            print(f"{version}={port}")
            break
    else:
        sys.exit("no free port found")
PY
  )
  for entry in $PICKED; do PORT[${entry%%=*}]=${entry#*=}; done
fi
PORTS="" SUBNETS=""
declare -A SEEN=()
for v in "${VERS[@]}"; do
  p=${PORT[$v]}
  [[ -z ${SEEN[$p]:-} ]] || { echo "UDP $p is chosen twice; the ports must be distinct" >&2; exit 2; }
  SEEN[$p]=1
  # a port the earlier run holds is ours; anything else bound there belongs to another program
  if [[ " $BOUND " == *" $p "* && ${OLD[$v]:-} != "$p" ]]; then
    echo "port $p (version $v) is already in use by another program" >&2; exit 2
  fi
  PORTS+="${PORTS:+,}$v=$p"; SUBNETS+="${SUBNETS:+,}$v=${SUBNET[$v]}"
done

echo "== files"
cd "$DIR"
# the manager's sources and the shared Rust crate its image builds against
for tree in awg_manager pc_common; do
  rm -rf "$DIR/$tree.new" && cp -a "$SRC/$tree" "$DIR/$tree.new"
  rm -rf "${DIR:?}/${tree:?}" && mv "$DIR/$tree.new" "$DIR/$tree"
  # a release unpacked by an ordinary user must not leave that user as the owner of root-run code
  chown -R root:root "$DIR/$tree"
done
install -m 0644 "$SRC/compose.amneziawg.yaml" "$DIR/compose.amneziawg.yaml"
install -d -m 0700 "$DIR/secrets" /var/lib/awg-manager
if [[ ! -s secrets/awg-manager-token ]]; then
  ( umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > secrets/awg-manager-token )
fi
chmod 600 secrets/awg-manager-token
( umask 077; cat > .env.amneziawg <<E
AWG_MANAGER_TOKEN_FILE=$DIR/secrets/awg-manager-token
AWG_MANAGER_STATE_DIR=/var/lib/awg-manager
AWG_VERSIONS=$VERSIONS
AWG_PORTS=$PORTS
AWG_SUBNETS=$SUBNETS
AWG_MTU=$MTU
AWG_DNS=$DNS
AWG_MANAGER_SOCKET_GID=10007
AMNEZIAWG_PUBLIC_HOST=$HOST
E
)
chmod 600 .env.amneziawg

echo "== host"
printf '# Managed by Proxy Control (AmneziaWG): the tunnels forward clients'"'"' packets to the Internet.\nnet.ipv4.ip_forward = 1\n' \
  > /etc/sysctl.d/99-proxy-control-amneziawg.conf
sysctl -p /etc/sysctl.d/99-proxy-control-amneziawg.conf >/dev/null
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
  # ports of an earlier run that this run no longer uses lose their rules
  for v in "${!OLD[@]}"; do
    if [[ " ${PORT[*]} " != *" ${OLD[$v]} "* ]] && ufw status | grep -q "proxy-control:firewall:udp:${OLD[$v]}\b"; then
      ufw delete allow "${OLD[$v]}/udp" >/dev/null
      echo "ufw: removed the rule for the previous UDP port ${OLD[$v]}"
    fi
  done
  for v in "${VERS[@]}"; do
    ufw allow "${PORT[$v]}/udp" comment "proxy-control:firewall:udp:${PORT[$v]}" >/dev/null
    ufw route allow in on "awg${v/./}" comment "proxy-control:firewall:route:awg${v/./}" >/dev/null
  done
  echo "ufw: UDP ports and forwarding rules are in place"
else
  install -m 0644 "$SRC/deploy/awg-forward.service" /etc/systemd/system/proxy-control-awg-forward.service
  systemctl daemon-reload
  systemctl enable --now proxy-control-awg-forward.service >/dev/null
  echo "no ufw: proxy-control-awg-forward.service allows forwarding past Docker's DROP policy; open UDP $PORTS in your firewall if it filters input"
fi

echo "== compose"
AGENT_ENV=/etc/proxy-control/version-agent.env
if [[ -f $AGENT_ENV ]] && ! grep -q 'compose.amneziawg.yaml' "$AGENT_ENV"; then
  sed -i 's#^\(PROXY_CONTROL_COMPOSE_FILES=.*\)$#\1:compose.amneziawg.yaml#' "$AGENT_ENV"
fi
# The compose set is the host's own list (the version agent's), never "whatever .env files exist".
LIST=$(sed -n 's/^PROXY_CONTROL_COMPOSE_FILES=//p' "$AGENT_ENV" 2>/dev/null | tail -n1)
LIST=${LIST:-compose.yaml:compose.amneziawg.yaml}
args=(--env-file .env) files=()
[[ -f .optional.env ]] && args+=(--env-file .optional.env)
IFS=: read -r -a LISTED <<< "$LIST"
for f in "${LISTED[@]}"; do
  files+=(-f "$f")
  case $f in
    compose.naive.yaml) e=.env.naive ;; compose.mieru.yaml) e=.env.mieru ;; compose.xray-router.yaml) e=.env.xray-router ;;
    compose.mcp.yaml) e=.env.mcp ;; compose.amneziawg.yaml) e=.env.amneziawg ;; *) e="" ;;
  esac
  [[ -n $e && -f $e ]] && args+=(--env-file "$e")
done
[[ -f version-overrides/compose.versions.yaml ]] && files+=(-f version-overrides/compose.versions.yaml)
docker compose "${args[@]}" "${files[@]}" up -d --build --wait --no-deps awg-manager panel
systemctl try-restart version-agent.service 2>/dev/null || true

echo "== check"
docker exec proxy-control-awg-manager /usr/local/bin/awg-manager healthcheck
for v in "${VERS[@]}"; do ip link show "awg${v/./}" >/dev/null; done
echo "AmneziaWG is enabled: versions $VERSIONS, clients dial $HOST on UDP $PORTS"
