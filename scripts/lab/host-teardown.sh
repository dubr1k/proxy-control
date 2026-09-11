#!/usr/bin/env bash
# Return the disposable lab host to a pristine state after `guest-runner.sh host`.
#
# The host scenario leaves the coexistence topology behind on purpose — a foreign
# shared-443 router, a fake certbot, a lab resolver, a foreign 3x-ui and `*.lab.test`
# certificates — because its last scenario asserts that the installer touched none of
# it. A real `host_mode = "fresh"` install afterwards is refused against that router,
# so the residue has to go. Nothing here is subtle: every path below is one the lab
# runner wrote, and `LAB_RESET=1` is the same opt-in the runner itself requires.
set -Eeuo pipefail

if [[ ${LAB_RESET:-0} != 1 ]]; then
  printf 'host-teardown removes lab state from this host; rerun with LAB_RESET=1 on a disposable host\n' >&2
  exit 2
fi
RELEASE_ROOT=${RELEASE_ROOT:-/tmp/proxy-control-release/proxy-control}

# 1. The installer's own generation, purged the way the runner purges it.
if [[ -d $RELEASE_ROOT ]]; then
  ( cd "$RELEASE_ROOT" && PYTHONPATH="$RELEASE_ROOT" python3 -m installer.cli --root / uninstall --purge-data >/dev/null 2>&1 ) || true
fi
label=label=com.docker.compose.project=mtproxy
docker container ls -aq --filter "$label" | xargs -r docker rm -f >/dev/null 2>&1 || true
docker network ls -q --filter "$label" | xargs -r docker network rm >/dev/null 2>&1 || true
docker volume ls -q --filter "$label" | xargs -r docker volume rm -f >/dev/null 2>&1 || true

# 2. Lab-only services and units.
systemctl disable --now caddy-naive mita lab-xray x-ui >/dev/null 2>&1 || true
rm -f /etc/systemd/system/lab-xray.service /etc/systemd/system/x-ui.service \
  /etc/systemd/system/caddy-naive.service /etc/systemd/system/mita.service /etc/tmpfiles.d/mita.conf
systemctl daemon-reload

# 3. Files the runner and the installer wrote.
rm -rf /var/lib/proxy-control /opt/mtproxy-shared443 /etc/letsencrypt /etc/proxy-control \
  /var/lib/naive-manager /var/log/naive-proxy /var/lib/mieru-manager /etc/mieru-manager /var/lib/mita \
  /usr/local/x-ui /etc/x-ui /var/lib/lab-status /tmp/proxyctl-host /tmp/lab-credentials /tmp/lab-client-results
# The fake certbot shadows the packaged one on PATH; a real install must never see it.
rm -f /usr/local/bin/certbot /usr/local/bin/caddy /usr/bin/mita \
  /usr/local/libexec/check-naive-caddy-build /usr/local/libexec/caddy-naive-adapt \
  /usr/local/libexec/prepare-naive-state /usr/local/libexec/prepare-mieru-state /usr/local/libexec/prepare-mieru-token
rm -f /etc/nginx/conf.d/lab-adjacent.conf /etc/nginx/conf.d/proxy-control-*.conf /etc/nginx/stream.d/*.conf
rm -f /tmp/plan*.json /tmp/status.json /tmp/resume-*.json /tmp/*.out /tmp/lab-*.sha256 /tmp/lab-install.toml
for user in naive-caddy mita; do
  pkill -KILL -u "$user" >/dev/null 2>&1 || true
  userdel "$user" >/dev/null 2>&1 || true
done
for group in naive-accounting mita foreign-accounting; do
  groupdel "$group" >/dev/null 2>&1 || true
done

# 4. Name resolution: the lab zone and the local resolver go, the stub resolver returns.
sed -i '/lab\.test/d' /etc/hosts
rm -f /etc/dnsmasq.d/lab.conf
systemctl disable --now dnsmasq >/dev/null 2>&1 || true
if [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
  ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
fi

# 5. Nginx goes back to the packaged configuration: the lab rewrote nginx.conf wholesale.
rm -f /etc/nginx/nginx.conf
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall -o Dpkg::Options::=--force-confmiss nginx-common >/dev/null
nginx -t
systemctl restart nginx

printf 'LAB_HOST_TEARDOWN_OK\n'
