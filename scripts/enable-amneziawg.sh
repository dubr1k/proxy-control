#!/usr/bin/env bash
# Enable AmneziaWG on a host that was NOT set up by the installer (a hand-managed Proxy Control host).
#
# Does what the installer's `amneziawg` adapter does, idempotently, from the unpacked release this
# script lives in: copies awg_manager and compose.amneziawg.yaml into the project directory, creates
# the manager token (kept if it exists) and the state directory, writes .env.amneziawg, turns on IPv4
# forwarding, opens the UDP ports (ufw) or installs the forwarding service (no ufw), adds the overlay
# to the version agent's compose list, brings awg-manager and the panel up and checks the result.
# Server keys in /var/lib/awg-manager are never touched.
#
#   sudo scripts/enable-amneziawg.sh --host vpn.example.com [--dir /opt/mtproxy-shared443]
#        [--versions 1.5,2.0,3.1] [--mtu 1280] [--dns 1.1.1.1,1.0.0.1]
set -euo pipefail

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR=/opt/mtproxy-shared443 HOST="" VERSIONS=1.5,2.0,3.1 MTU=1280 DNS=1.1.1.1,1.0.0.1
while [[ $# -gt 0 ]]; do
  case $1 in
    --host) HOST=${2:?}; shift 2 ;;
    --dir) DIR=${2:?}; shift 2 ;;
    --versions) VERSIONS=${2:?}; shift 2 ;;
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
[[ -d $SRC/awg_manager && -f $SRC/compose.amneziawg.yaml ]] || { echo "run this script from an unpacked release" >&2; exit 2; }
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun is missing on this host" >&2; exit 2; }

declare -A PORT=([1.5]=51820 [2.0]=51821 [3.1]=51822) SUBNET=([1.5]=10.66.15.0/24 [2.0]=10.66.20.0/24 [3.1]=10.66.31.0/24)
IFS=, read -r -a VERS <<< "$VERSIONS"
PORTS="" SUBNETS=""
for v in "${VERS[@]}"; do
  [[ -n ${PORT[$v]:-} ]] || { echo "unsupported version: $v (1.5, 2.0, 3.1)" >&2; exit 2; }
  if ss -H -lun 2>/dev/null | grep -qE ":${PORT[$v]}\b" && ! docker ps --format '{{.Names}}' | grep -qx proxy-control-awg-manager; then
    echo "UDP ${PORT[$v]} is already in use by another program" >&2; exit 2
  fi
  PORTS+="${PORTS:+,}$v=${PORT[$v]}"; SUBNETS+="${SUBNETS:+,}$v=${SUBNET[$v]}"
done

echo "== files"
cd "$DIR"
rm -rf "$DIR/awg_manager.new" && cp -a "$SRC/awg_manager" "$DIR/awg_manager.new"
rm -rf "$DIR/awg_manager" && mv "$DIR/awg_manager.new" "$DIR/awg_manager"
# a release unpacked by an ordinary user must not leave that user as the owner of root-run code
chown -R root:root "$DIR/awg_manager"
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
docker exec proxy-control-awg-manager python -m awg_manager.healthcheck
for v in "${VERS[@]}"; do ip link show "awg${v/./}" >/dev/null; done
echo "AmneziaWG is enabled: versions $VERSIONS, clients dial $HOST (UDP $PORTS)"
