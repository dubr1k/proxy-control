#!/usr/bin/env bash
# Prove the managed 3x-ui path against a real 3x-ui, not a fixture.
#
# The container and host labs build a coexistence topology, so they cannot
# exercise `three_xui.mode = "managed-new"`, which owns the whole host. This
# runs that path end to end on a disposable server: it installs the pinned
# 3x-ui, drives the installer's own provisioning, and requires every promised
# inbound to be listening afterwards. A row 3x-ui stores but Xray refuses to
# serve fails here, which is exactly the failure this path had.
#
# It refuses to run where a 3x-ui already exists, and removes what it created.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
PREFIX=${PREFIX:-/}
XUI_ROOT=/usr/local/x-ui
XUI_DB=/etc/x-ui
UNIT=/etc/systemd/system/x-ui.service
PANEL_PORT=8451
VLESS_TCP_PORT=8449
VLESS_XHTTP_PORT=8450
HYSTERIA_PORT=443

fail() { printf 'managed-xui-acceptance: %s\n' "$1" >&2; exit 1; }

require_clean_host() {
  [[ $EUID -eq 0 ]] || fail "run as root on a disposable server"
  [[ ! -e $XUI_ROOT ]] || fail "$XUI_ROOT exists; this runs on a host with no 3x-ui"
  [[ ! -e $XUI_DB ]] || fail "$XUI_DB exists; this runs on a host with no 3x-ui"
  command -v python3 >/dev/null || fail "python3 is required"
}

architecture() {
  case "$(dpkg --print-architecture)" in
    amd64) printf 'amd64' ;;
    arm64) printf 'arm64' ;;
    *) fail "unsupported architecture" ;;
  esac
}

stage_three_xui() {
  local arch url digest archive
  arch=$(architecture)
  url=$(python3 -c "
import json,sys
d=json.load(open('$ROOT/release/external-artifacts.json'))
for a in d['artifacts']:
    if a['name']=='three_xui':
        print(a['platforms']['$arch']['url']); break
")
  digest=$(python3 -c "
import json
d=json.load(open('$ROOT/release/external-artifacts.json'))
for a in d['artifacts']:
    if a['name']=='three_xui':
        print(a['platforms']['$arch']['sha256']); break
")
  archive=$(mktemp)
  curl -fsSL -o "$archive" "$url"
  printf '%s  %s\n' "$digest" "$archive" | sha256sum -c - >/dev/null \
    || fail "the pinned 3x-ui digest does not match"
  local staging
  staging=$(mktemp -d)
  tar -xzf "$archive" -C "$staging"
  install -d -m 0755 "$XUI_ROOT" "$XUI_DB"
  cp -a "$staging/x-ui/." "$XUI_ROOT/"
  chmod 0755 "$XUI_ROOT/x-ui" "$XUI_ROOT/bin/xray-linux-$arch"
  rm -rf "$staging" "$archive"

  cat > "$UNIT" <<'UNITFILE'
[Unit]
Description=3x-ui staged by the managed acceptance run
After=network.target
[Service]
Type=simple
# x-ui launches Xray by a relative path, so it only works from its own tree.
WorkingDirectory=/usr/local/x-ui
ExecStart=/usr/local/x-ui/x-ui run
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNITFILE
  systemctl daemon-reload
  systemctl enable --now x-ui >/dev/null
}

wait_for_port() {
  local port=$1 protocol=${2:-tcp} deadline
  deadline=$(( $(date +%s) + 60 ))
  while (( $(date +%s) < deadline )); do
    if [[ $protocol == udp ]]; then
      ss -lnuH | grep -q ":$port " && return 0
    else
      ss -lntH | grep -q ":$port " && return 0
    fi
    sleep 1
  done
  return 1
}

provision() {
  PYTHONPATH="$ROOT" python3 - <<'PY'
import sys
from pathlib import Path

from installer.adapters.three_xui import ThreeXuiAdapter
from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)

config = InstallerConfig(
    schema=1,
    host_mode=HostMode.FRESH,
    profile=Profile.CORE,
    acme_email="lab@example.invalid",
    initial_user="owner",
    domains=DomainConfig(panel="panel.lab.test", mtproxy="proxy.lab.test"),
    mieru=None,
    three_xui=ThreeXuiConfig(
        mode=ThreeXuiMode.MANAGED_NEW,
        panel_domain="xui.lab.test",
        vless_tcp_domain="vless.lab.test",
        vless_xhttp_domain="xhttp.lab.test",
        hysteria_domain="hy2.lab.test",
    ),
    firewall=FirewallConfig(manage_ufw=False),
)

adapter = ThreeXuiAdapter(source_dir=Path("."), panel_username="labowner")
action = adapter._managed_action(config)
report = adapter.provision(action, password="acceptance-panel-password")
print(f"provisioned inbounds={report['inbounds']}")
PY
}

cleanup() {
  # KEEP=1 leaves the staged 3x-ui in place so a failure can be inspected on
  # the disposable server it ran on.
  if [[ ${KEEP:-0} == 1 ]]; then
    printf 'managed-xui-acceptance: KEEP=1, leaving the staged 3x-ui in place\n'
    return 0
  fi
  systemctl disable --now x-ui >/dev/null 2>&1 || true
  rm -f "$UNIT"
  systemctl daemon-reload || true
  rm -rf "$XUI_ROOT" "$XUI_DB"
}

main() {
  require_clean_host
  trap cleanup EXIT
  stage_three_xui
  wait_for_port 2053 || fail "the staged 3x-ui never answered on its default port"

  # Hysteria2 needs a certificate that exists; the panel's own is enough here.
  install -d -m 0755 "/etc/letsencrypt/live/hy2.lab.test"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=hy2.lab.test" \
    -keyout /etc/letsencrypt/live/hy2.lab.test/privkey.pem \
    -out /etc/letsencrypt/live/hy2.lab.test/fullchain.pem 2>/dev/null

  cd "$ROOT"
  provision

  wait_for_port "$PANEL_PORT" || fail "the panel did not move onto its private port"
  ss -lntH | grep -q ':2053 ' && fail "the panel still answers on its default public port"
  wait_for_port "$VLESS_TCP_PORT" || fail "the VLESS Reality TCP inbound is not listening"
  wait_for_port "$VLESS_XHTTP_PORT" || fail "the VLESS Reality XHTTP inbound is not listening"
  wait_for_port "$HYSTERIA_PORT" udp || fail "the Hysteria2 inbound is not listening"

  printf 'managed-xui-acceptance: every promised inbound is listening\n'
}

main "$@"
