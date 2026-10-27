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
  [[ ${PC_MANAGED_XUI_LIVE:-} == ams-test ]] || fail "explicit lab acknowledgement required: PC_MANAGED_XUI_LIVE=ams-test"
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
  if [[ -n ${PC_MANAGED_XUI_TEST_BIN:-} ]]; then
    "$PC_MANAGED_XUI_TEST_BIN" --ignored --exact real_managed_three_xui_native_provision --nocapture
  else
    cargo test --manifest-path "$ROOT/installer/Cargo.toml" --locked --test managed_three_xui_live \
      -- --ignored --exact real_managed_three_xui_native_provision --nocapture
  fi
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
  rm -f /etc/proxy-control/three-xui-owned
  rm -rf /var/lib/proxy-control/three-xui
  rm -rf /etc/letsencrypt/live/xui.lab.test /etc/letsencrypt/live/hy2.lab.test
}

main() {
  require_clean_host
  trap cleanup EXIT

  # The panel and Hysteria2 need certificates that exist: 3x-ui refuses a settings form
  # whose certificate path is absent. In a real install Core issues them before this
  # adapter runs; here two throw-away self-signed pairs stand in.
  for domain in xui.lab.test hy2.lab.test; do
    install -d -m 0755 "/etc/letsencrypt/live/$domain"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$domain" \
      -keyout "/etc/letsencrypt/live/$domain/privkey.pem" \
      -out "/etc/letsencrypt/live/$domain/fullchain.pem" 2>/dev/null
  done

  cd "$ROOT"
  provision

  wait_for_port "$PANEL_PORT" || fail "the panel did not move onto its private port"
  ss -lntH | grep -q ':2053 ' && fail "the panel still answers on its default public port"
  wait_for_port "$VLESS_TCP_PORT" || fail "the VLESS Reality TCP inbound is not listening"
  wait_for_port "$VLESS_XHTTP_PORT" || fail "the VLESS Reality XHTTP inbound is not listening"
  wait_for_port "$HYSTERIA_PORT" udp || fail "the Hysteria2 inbound is not listening"

  printf 'managed-xui-acceptance: every promised inbound is listening (not a client proof)\n'
}

main "$@"
