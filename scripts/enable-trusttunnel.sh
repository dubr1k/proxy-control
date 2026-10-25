#!/usr/bin/env bash
# Enable TrustTunnel on a host that was NOT set up by the installer (a hand-managed Proxy Control host).
#
# Does what the installer's `trusttunnel` adapter does, idempotently, from the unpacked release this
# script lives in: copies trusttunnel_manager and compose.trusttunnel.yaml into the project directory,
# creates the manager token (kept if it exists) and the state directory, writes .env.trusttunnel
# with the endpoint pin from release/external-artifacts.json (the manager reads the host name's Let's
# Encrypt lineage through a read-only mount of /etc/letsencrypt), adds the overlay to the version agent's compose list, brings trusttunnel-manager and the panel up and checks it.
# The state directory /var/lib/trusttunnel-manager (credentials, counters) is never touched.
#
# TrustTunnel is TCP only and shares TCP/443: no firewall rule and no UDP port is added. The endpoint
# listens on 127.0.0.1:LISTEN_PORT; YOUR Nginx stream router must send the host name there
# (`<host> 127.0.0.1:<port>;` in the $ssl_preread_server_name map). The host name needs an A record to this
# server (DNS only, no CDN proxy) and a certificate issued beforehand (certbot lineage named after it).
#
#   sudo scripts/enable-trusttunnel.sh --host gate.example.org [--dir /opt/mtproxy-shared443]
#        [--listen-port 4453]
set -euo pipefail

usage() { awk 'NR >= 2 { if (/^set -euo/) exit; print }' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR=/opt/mtproxy-shared443 HOST="" LISTEN_PORT=4453 METRICS_PORT=1987
while [[ $# -gt 0 ]]; do
  case $1 in
    --host) HOST=${2:?}; shift 2 ;;
    --dir) DIR=${2:?}; shift 2 ;;
    --listen-port) LISTEN_PORT=${2:?}; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 2; }
[[ -n $HOST ]] || { echo "--host is required: the DNS name clients dial (an A record to this server, not behind a proxying CDN)" >&2; usage; }
[[ $HOST =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid --host (a lower-case DNS name)" >&2; exit 2; }
[[ $LISTEN_PORT =~ ^[0-9]{4,5}$ && $LISTEN_PORT -ge 1024 && $LISTEN_PORT -le 65535 && $LISTEN_PORT -ne $METRICS_PORT ]] \
  || { echo "--listen-port must be 1024-65535 and not $METRICS_PORT (the manager's metrics port)" >&2; exit 2; }
[[ -d $DIR && -f $DIR/compose.yaml ]] || { echo "$DIR is not a Proxy Control project directory" >&2; exit 2; }
[[ -d $SRC/trusttunnel_manager && -d $SRC/pc_common && -f $SRC/compose.trusttunnel.yaml ]] || { echo "run this script from an unpacked release" >&2; exit 2; }
LINEAGE=/etc/letsencrypt/live/$HOST
[[ -r $LINEAGE/fullchain.pem && -r $LINEAGE/privkey.pem ]] \
  || { echo "no certificate for $HOST in $LINEAGE: issue it first (certbot certonly --cert-name $HOST -d $HOST)" >&2; exit 2; }
# the port must be free (a port held by the earlier run of this very endpoint is ours)
if ss -H -ltn "sport = :$LISTEN_PORT" 2>/dev/null | grep -q . && ! ss -H -ltnp "sport = :$LISTEN_PORT" 2>/dev/null | grep -q 'trusttunnel_end'; then
  echo "TCP port $LISTEN_PORT is already in use by another program" >&2; exit 2
fi
TT_SHA256_AARCH64=c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686
read -r TT_VERSION TT_SHA256 < <(python3 - "$SRC/release/external-artifacts.json" <<'PY'
import json, sys
entry = next(item for item in json.load(open(sys.argv[1]))["artifacts"] if item["name"] == "trusttunnel")
print(entry["version"], entry["platforms"]["amd64"]["sha256"])
PY
)

echo "== files"
cd "$DIR"
# the manager's sources and the shared Rust crate its image builds against
for tree in trusttunnel_manager pc_common; do
  rm -rf "$DIR/$tree.new" && cp -a "$SRC/$tree" "$DIR/$tree.new"
  rm -rf "$DIR/$tree" && mv "$DIR/$tree.new" "$DIR/$tree"
  # a release unpacked by an ordinary user must not leave that user as the owner of root-run code
  chown -R root:root "$DIR/$tree"
done
install -m 0644 "$SRC/compose.trusttunnel.yaml" "$DIR/compose.trusttunnel.yaml"
install -d -m 0700 "$DIR/secrets" /var/lib/trusttunnel-manager
if [[ ! -s secrets/trusttunnel-manager-token ]]; then
  ( umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > secrets/trusttunnel-manager-token )
fi
chmod 600 secrets/trusttunnel-manager-token

( umask 077; cat > .env.trusttunnel <<E
TRUSTTUNNEL_MANAGER_TOKEN_FILE=$DIR/secrets/trusttunnel-manager-token
TT_MANAGER_STATE_DIR=/var/lib/trusttunnel-manager
TT_CERT_DIR=/etc/letsencrypt
TT_HOSTNAME=$HOST
TT_LISTEN=127.0.0.1:$LISTEN_PORT
TT_VERSION=v$TT_VERSION
TT_SHA256_X86_64=$TT_SHA256
TT_SHA256_AARCH64=$TT_SHA256_AARCH64
TRUSTTUNNEL_MANAGER_SOCKET_GID=10008
TRUSTTUNNEL_PUBLIC_HOST=$HOST
E
)
chmod 600 .env.trusttunnel

echo "== compose"
AGENT_ENV=/etc/proxy-control/version-agent.env
if [[ -f $AGENT_ENV ]] && ! grep -q 'compose.trusttunnel.yaml' "$AGENT_ENV"; then
  sed -i 's#^\(PROXY_CONTROL_COMPOSE_FILES=.*\)$#\1:compose.trusttunnel.yaml#' "$AGENT_ENV"
fi
# The compose set is the host's own list (the version agent's), never "whatever .env files exist".
LIST=$(sed -n 's/^PROXY_CONTROL_COMPOSE_FILES=//p' "$AGENT_ENV" 2>/dev/null | tail -n1)
LIST=${LIST:-compose.yaml:compose.trusttunnel.yaml}
args=(--env-file .env) files=()
[[ -f .optional.env ]] && args+=(--env-file .optional.env)
IFS=: read -r -a LISTED <<< "$LIST"
for f in "${LISTED[@]}"; do
  files+=(-f "$f")
  case $f in
    compose.naive.yaml) e=.env.naive ;; compose.mieru.yaml) e=.env.mieru ;; compose.xray-router.yaml) e=.env.xray-router ;;
    compose.mcp.yaml) e=.env.mcp ;; compose.amneziawg.yaml) e=.env.amneziawg ;; compose.trusttunnel.yaml) e=.env.trusttunnel ;; *) e="" ;;
  esac
  [[ -n $e && -f $e ]] && args+=(--env-file "$e")
done
[[ -f version-overrides/compose.versions.yaml ]] && files+=(-f version-overrides/compose.versions.yaml)
docker compose "${args[@]}" "${files[@]}" up -d --build --wait --no-deps trusttunnel-manager panel
systemctl try-restart version-agent.service 2>/dev/null || true

echo "== check"
docker exec proxy-control-trusttunnel-manager /usr/local/bin/trusttunnel-manager healthcheck
echo "TrustTunnel is enabled: clients dial $HOST on TCP/443; the endpoint listens on 127.0.0.1:$LISTEN_PORT"
echo "Nginx: add '$HOST 127.0.0.1:$LISTEN_PORT;' to your stream SNI map if the installer does not manage it; nothing UDP, no firewall rule needed."
