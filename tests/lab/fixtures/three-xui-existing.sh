#!/usr/bin/env bash
# Materialize a foreign 3x-ui installation the installer must never touch.
# The caller hashes the tree before and after the run to prove byte identity.
set -Eeuo pipefail

VERSION=${1:-3.7.0}
ROOT=/usr/local/x-ui
DATABASE=/etc/x-ui/x-ui.db

install -d -m 0755 "$ROOT/bin" /etc/x-ui
cat > "$ROOT/bin/config.json" <<JSON
{
  "inbounds": [
    {
      "tag": "foreign-vless-tcp",
      "protocol": "vless",
      "listen": "127.0.0.1",
      "port": 9443,
      "settings": {"clients": [{"id": "11111111-2222-4333-8444-555555555555"}]},
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverNames": ["old-xray.lab.test"],
          "target": "old-xray.lab.test:443",
          "privateKey": "FOREIGN-PRIVATE-KEY-NEVER-READ",
          "shortIds": ["abcdef0123456789"]
        }
      },
      "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}
    }
  ],
  "outbounds": [{"tag": "direct"}, {"tag": "blocked"}],
  "routing": {"rules": [{"protocol": ["bittorrent"], "outboundTag": "blocked"}]}
}
JSON
printf 'foreign-sqlite-%s\n' "$VERSION" > "$DATABASE"
printf '#!/bin/sh\necho "x-ui %s"\n' "$VERSION" > "$ROOT/x-ui"
chmod 0755 "$ROOT/x-ui"
cat > /etc/systemd/system/x-ui.service <<'UNIT'
[Unit]
Description=foreign 3x-ui
[Service]
ExecStart=/usr/bin/sleep infinity
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
printf 'materialized foreign 3x-ui %s\n' "$VERSION"
