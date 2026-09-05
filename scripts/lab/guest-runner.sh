#!/usr/bin/env bash
# shellcheck disable=SC2317 # scenario functions are dispatched by name through case_run.
set -Eeuo pipefail

MODE=${1:-smoke}
EXPECTED_ARCHIVE_SHA=${2:-}
shift 2 2>/dev/null || true
SCENARIO_FILTER=("$@")
ROOT=/tmp/mtproxy-source
if [[ ${MODE:-} == container || ${MODE:-} == host ]]; then
  ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
fi
FIXTURE=/tmp/proxyctl-host
PROXY=proxy.lab.test
PANEL=panel.lab.test
ROUTE=/etc/nginx/stream.d/routes.conf
RESULTS_FAILED=0
BASELINE=/tmp/lab-baseline.sha256
RELEASE=/tmp/proxy-control-release.tar.gz
RELEASE_SHA=/tmp/proxy-control-release.sha256
# The archive carries a "proxy-control/" prefix, so the tree the installer runs
# from is one level below where it is unpacked.
RELEASE_STAGE=/tmp/proxy-control-release
RELEASE_ROOT=$RELEASE_STAGE/proxy-control
INSTALLER_STATE=/var/lib/proxy-control/installer/state.json
if [[ ${MODE:-} == container || ${MODE:-} == host ]]; then
  RELEASE_ROOT=$ROOT
fi
CONFIG=/tmp/lab-install.toml
CREDENTIALS=/tmp/lab-credentials
CLIENT_RESULTS=/tmp/lab-client-results
FOREIGN_BASELINE=/tmp/lab-foreign.sha256
declare -A CASE_STATUS=()

selected() {
  local name=$1 candidate
  ((${#SCENARIO_FILTER[@]})) || return 0
  for candidate in "${SCENARIO_FILTER[@]}"; do
    [[ $candidate == "$name" ]] && return 0
  done
  return 1
}

emit() {
  local name=$1 status=$2 started=$3 message=${4:-}
  local elapsed
  elapsed=$(python3 - "$started" <<'PY'
import sys,time
print(f"{time.time()-float(sys.argv[1]):.3f}")
PY
)
  message=${message//$'\t'/ }
  message=${message//$'\n'/ }
  message=${message:0:4000}
  printf 'LAB_RESULT\t%s\t%s\t%s\t%s\n' "$name" "$status" "$elapsed" "$message"
  [[ $status == passed ]] || RESULTS_FAILED=1
}

case_run() {
  local name=$1 function=$2 started log rc message prerequisite
  shift 2
  selected "$name" || return 0
  started=$(python3 -c 'import time; print(time.time())')
  for prerequisite in "$@"; do
    if [[ ${CASE_STATUS[$prerequisite]:-missing} != passed ]]; then
      CASE_STATUS[$name]=skipped
      emit "$name" skipped "$started" "prerequisite failed: $prerequisite"
      return 0
    fi
  done
  log=$(mktemp)
  set +e
  ( set -Eeuo pipefail; "$function" ) >"$log" 2>&1
  rc=$?
  set -e
  if ((rc == 0)); then
    CASE_STATUS[$name]=passed
    emit "$name" passed "$started"
  else
    CASE_STATUS[$name]=failed
    message=$(tr '\n' ' ' <"$log")
    emit "$name" failed "$started" "$message"
  fi
  rm -f "$log"
}

run_captured() {
  local log=$1 rc
  shift
  set +e
  ( set -Eeuo pipefail; "$@" ) >"$log" 2>&1
  rc=$?
  set -e
  if ((rc == 0)); then
    return 0
  fi
  cat "$log" >&2
  return "$rc"
}

add_hosts() {
  local address
  address=$(host_ip)
  [[ -n $address ]] || address=127.0.0.1
  if ! grep -q "$PROXY" /etc/hosts; then
    printf '%s %s %s\n' "$address" "$PROXY" "$PANEL" >> /etc/hosts
  fi
}

make_fixture() {
  rm -rf "$FIXTURE"
  mkdir -p "$FIXTURE/etc/nginx/stream.d" "$FIXTURE/etc/nginx/sites-enabled" \
    "$FIXTURE/usr/local/x-ui/bin" "$FIXTURE/etc/letsencrypt/live/$PROXY" \
    "$FIXTURE/etc/letsencrypt/live/$PANEL" "$FIXTURE/var/lib/lab-status"
  cat > "$FIXTURE/etc/nginx/nginx.conf" <<'EOF'
stream { include /etc/nginx/stream.d/*.conf; }
EOF
  cat > "$FIXTURE$ROUTE" <<'EOF'
map $ssl_preread_server_name $shared_backend {
    old-xray.lab.test 127.0.0.1:9443;
    default 127.0.0.1:8443;
}
server { listen 443; proxy_pass $shared_backend; ssl_preread on; }
EOF
  cat > "$FIXTURE/usr/local/x-ui/bin/config.json" <<'EOF'
{"inbounds":[{"tag":"xray-reality","protocol":"vless","listen":"127.0.0.1","port":9443,"streamSettings":{"security":"reality","realitySettings":{"serverNames":["old-xray.lab.test"]}}}],"outbounds":[{"tag":"warp"}]}
EOF
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/nginx"
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/xray"
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/3x-ui"
  printf 'active\n' > "$FIXTURE/var/lib/lab-status/warp"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$PROXY" \
    -addext "subjectAltName=DNS:$PROXY,DNS:$PANEL" \
    -keyout /tmp/lab.key -out /tmp/lab.crt >/dev/null 2>&1
  for domain in "$PROXY" "$PANEL"; do
    cp /tmp/lab.crt "$FIXTURE/etc/letsencrypt/live/$domain/fullchain.pem"
    cp /tmp/lab.key "$FIXTURE/etc/letsencrypt/live/$domain/privkey.pem"
  done
  find "$FIXTURE" -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/fixture.before
}

proxy_args() {
  printf '%s\n' --proxy-domain "$PROXY" --panel-domain "$PANEL" --email lab@example.invalid \
    --route-file "$ROUTE" --users owner,phone --protocol-probe /usr/local/bin/lab-probe \
    --source-dir "$ROOT"
}

archive_integrity() {
  [[ -n $EXPECTED_ARCHIVE_SHA ]]
  [[ $(sha256sum /tmp/mtproxy-source.tar | cut -d' ' -f1) == "$EXPECTED_ARCHIVE_SHA" ]]
  [[ $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true) == "" ]] # archive is intentionally metadata-free
  test -f "$ROOT/scripts/proxyctl.py"
}

audit_fixture() {
  python3 "$ROOT/scripts/proxyctl.py" --root "$FIXTURE" audit \
    --proxy-domain "$PROXY" --panel-domain "$PANEL" --json >/tmp/audit.json
  python3 - <<'PY'
import json
r=json.load(open('/tmp/audit.json'))
assert r['nginx']['sni_map_count'] == 1
assert r['xray']['installed'] and r['xray']['outbound_tags'] == ['warp']
assert all(d['dns_matches_host'] and d['tls_certificate_present'] for d in r['domains'])
PY
}

plan_fixture() {
  mapfile -t args < <(proxy_args)
  python3 "$ROOT/scripts/proxyctl.py" --root "$FIXTURE" plan "${args[@]}" --json >/tmp/plan.json
  python3 -m json.tool /tmp/plan.json >/dev/null
}

coexist_fixture() {
  find "$FIXTURE" -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/fixture.after
  cmp /tmp/fixture.before /tmp/fixture.after
  grep -qx active "$FIXTURE"/var/lib/lab-status/{nginx,xray,3x-ui,warp}
}

dns_tls_fixture() {
  python3 - <<'PY'
import json
r=json.load(open('/tmp/audit.json'))
assert {d['domain'] for d in r['domains']} == {'proxy.lab.test','panel.lab.test'}
assert all(d['a_records'] == ['10.0.2.15'] for d in r['domains'])
assert all(not d['unhandled_aaaa'] for d in r['domains'])
assert all(d['tls_certificate_present'] for d in r['domains'])
PY
}

secrets_scan() {
  ! grep -ERi '(panel-bootstrap-password|telemt-api-token)[=:][^[:space:]]+|tg://proxy\?.*secret=' \
    /tmp/audit.json /tmp/plan.json 2>/dev/null
}

write_fake_certbot() {
  local destination=$1
  # A deterministic, offline Certbot-compatible generator. The lab never talks
  # to ACME, but it must produce a complete lineage the installer accepts: a
  # locally trusted CA, a leaf with the exact SANs, cert/chain/fullchain, a
  # 0600 private key, an archive, and a renewal configuration.
  cat > "$destination" <<'CERTBOT'
#!/bin/bash
set -eu

name=
domains=()
subcommand=
while (($#)); do
  case $1 in
    certonly|renew) subcommand=$1; shift ;;
    --cert-name) name=$2; shift 2 ;;
    -d) domains+=("$2"); shift 2 ;;
    *) shift ;;
  esac
done
test -n "$name"

letsencrypt_root=${LETSENCRYPT_ROOT:-/etc/letsencrypt}
live_root=${LETSENCRYPT_LIVE_ROOT:-$letsencrypt_root/live}
archive_root=${LETSENCRYPT_ARCHIVE_ROOT:-$letsencrypt_root/archive}
renewal_root=${LETSENCRYPT_RENEWAL_ROOT:-$letsencrypt_root/renewal}
ca_dir=${LETSENCRYPT_LAB_CA_DIR:-$letsencrypt_root/lab-ca}

if [[ $subcommand == renew ]]; then
  # A dry run only proves the lineage is renewable; it issues nothing.
  test -f "$renewal_root/$name.conf"
  test -e "$live_root/$name/cert.pem"
  test -e "$live_root/$name/privkey.pem"
  exit 0
fi
test "${#domains[@]}" -ge 1

umask 077
mkdir -p "$ca_dir"
if [[ ! -f $ca_dir/ca.crt ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30     -subj "/CN=Proxy Control lab CA"     -addext "basicConstraints=critical,CA:TRUE,pathlen:0"     -addext "keyUsage=critical,keyCertSign,cRLSign"     -keyout "$ca_dir/ca.key" -out "$ca_dir/ca.crt" >/dev/null 2>&1
  if [[ $(id -u) -eq 0 && -d /usr/local/share/ca-certificates ]]; then
    install -m 0644 "$ca_dir/ca.crt" /usr/local/share/ca-certificates/proxy-control-lab-ca.crt
    update-ca-certificates >/dev/null 2>&1
  fi
fi

san=""
for domain in "${domains[@]}"; do
  if [[ -z $san ]]; then san="DNS:$domain"; else san="$san,DNS:$domain"; fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
openssl req -newkey rsa:2048 -nodes -subj "/CN=${domains[0]}"   -keyout "$work/privkey.pem" -out "$work/leaf.csr" >/dev/null 2>&1
{
  printf 'subjectAltName=%s
' "$san"
  printf 'basicConstraints=critical,CA:FALSE
'
  printf 'keyUsage=critical,digitalSignature,keyEncipherment
'
  printf 'extendedKeyUsage=serverAuth
'
} > "$work/leaf.ext"
openssl x509 -req -in "$work/leaf.csr" -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key"   -CAcreateserial -days 2 -extfile "$work/leaf.ext" -out "$work/cert.pem" >/dev/null 2>&1

version=1
mkdir -p "$archive_root/$name"
while [[ -f $archive_root/$name/cert$version.pem ]]; do
  version=$((version + 1))
done
install -m 0644 "$work/cert.pem" "$archive_root/$name/cert$version.pem"
install -m 0644 "$ca_dir/ca.crt" "$archive_root/$name/chain$version.pem"
cat "$work/cert.pem" "$ca_dir/ca.crt" > "$archive_root/$name/fullchain$version.pem"
chmod 0644 "$archive_root/$name/fullchain$version.pem"
install -m 0600 "$work/privkey.pem" "$archive_root/$name/privkey$version.pem"

publish() {
  local target=$1
  mkdir -p "$target"
  ln -sfn "$archive_root/$name/cert$version.pem" "$target/cert.pem"
  ln -sfn "$archive_root/$name/chain$version.pem" "$target/chain.pem"
  ln -sfn "$archive_root/$name/fullchain$version.pem" "$target/fullchain.pem"
  ln -sfn "$archive_root/$name/privkey$version.pem" "$target/privkey.pem"
}
publish "$live_root/$name"
for domain in "${domains[@]}"; do
  if [[ $domain != "$name" ]]; then
    publish "$live_root/$domain"
  fi
done

mkdir -p "$renewal_root"
{
  printf 'version = 2.11.0
'
  printf 'archive_dir = %s/%s
' "$archive_root" "$name"
  printf 'cert = %s/%s/cert.pem
' "$live_root" "$name"
  printf 'privkey = %s/%s/privkey.pem
' "$live_root" "$name"
  printf 'chain = %s/%s/chain.pem
' "$live_root" "$name"
  printf 'fullchain = %s/%s/fullchain.pem
' "$live_root" "$name"
} > "$renewal_root/$name.conf"
CERTBOT
  chmod 755 "$destination"
}

setup_full_host() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx-full libnginx-mod-stream docker.io docker-compose-v2 certbot openssl socat jq >/dev/null
  add_hosts
  mkdir -p /etc/nginx/stream.d /usr/local/x-ui/bin /var/lib/lab-status
  cat > /etc/nginx/nginx.conf <<'EOF'
load_module modules/ngx_stream_module.so;
user www-data;
pid /run/nginx.pid;
events { worker_connections 256; }
stream { include /etc/nginx/stream.d/*.conf; }
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
  cat > "$ROUTE" <<'EOF'
map $ssl_preread_server_name $shared_backend {
    old-xray.lab.test 127.0.0.1:9443;
    default 127.0.0.1:9443;
}
server { listen 443; proxy_pass $shared_backend; ssl_preread on; }
EOF
  cat > /usr/local/x-ui/bin/config.json <<'EOF'
{"inbounds":[{"tag":"xray-reality","protocol":"vless","listen":"127.0.0.1","port":9443,"streamSettings":{"security":"reality","realitySettings":{"serverNames":["old-xray.lab.test"]}}}],"outbounds":[{"tag":"warp"}]}
EOF
  cat > /etc/systemd/system/lab-xray.service <<'EOF'
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:9443,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/cat
EOF
  cat > /etc/systemd/system/lab-warp.service <<'EOF'
[Service]
ExecStart=/usr/bin/sleep infinity
EOF
  cat > /etc/systemd/system/lab-3x-ui.service <<'EOF'
[Service]
ExecStart=/usr/bin/sleep infinity
EOF
  systemctl daemon-reload
  systemctl enable --now lab-xray lab-warp lab-3x-ui docker nginx >/dev/null
  cat > /usr/local/bin/lab-probe <<'EOF'
#!/bin/sh
set -eu
test "$1" = --domain
test "$3" = --secrets-file
test -s "$4"
EOF
  chmod 755 /usr/local/bin/lab-probe
  write_fake_certbot /usr/local/bin/certbot
  sha256sum "$ROUTE" /usr/local/x-ui/bin/config.json > "$BASELINE"
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui > /tmp/status.before
}

full_environment_preflight() {
  local started log script
  started=$(python3 -c 'import time; print(time.time())')
  log=$(mktemp)
  script="$(declare -p PROXY PANEL ROUTE BASELINE); $(declare -f host_ip add_hosts write_fake_certbot setup_full_host); setup_full_host"
  # `set -e` kills the composed script silently when a `test` or a `read` fails,
  # and the report then carries whatever apt printed last. Name the command.
  script="trap 'printf \"PREFLIGHT FAILED: %s\\n\" \"\$BASH_COMMAND\" >&2' ERR; $script"
  if bash -Eeuo pipefail -c "$script" >"$log" 2>&1; then
    emit environment-preflight passed "$started"
    rm -f "$log"
    return 0
  fi
  emit environment-preflight failed "$started" "$(tail -n 5 "$log" | tr '\n' ' ')"
  sed 's/^/environment-preflight: /' "$log" >&2
  rm -f "$log"
  return 1
}

runtime_cmd() {
  mapfile -t args < <(proxy_args)
  python3 "$ROOT/scripts/proxyctl.py" "$1" "${args[@]}"
}

full_audit() { python3 "$ROOT/scripts/proxyctl.py" audit --proxy-domain "$PROXY" --panel-domain "$PANEL" --json >/tmp/audit.json; }
full_plan() { runtime_cmd plan >/tmp/plan.json; }
full_install() {
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
  test ! -e /opt/mtproxy-shared443
  run_captured /tmp/install.out runtime_cmd install
  systemctl is-active docker nginx >/dev/null
  curl --insecure --fail --silent --show-error \
    --resolve "$PANEL:443:127.0.0.1" "https://$PANEL/healthz" | jq -e '.status == "ok"' >/dev/null
  test "$(stat -c %a /var/lib/proxy-control/runtime.json)" = 600
  jq -e '.status == "active" and (.owned_packages == [])' /var/lib/proxy-control/runtime.json >/dev/null
  test "$(stat -c %a /var/lib/proxy-control/ownership.json)" = 600
}
full_repair() { python3 "$ROOT/scripts/proxyctl.py" repair; test "$(jq -r .status /var/lib/proxy-control/runtime.json)" = active; }
full_idempotence() {
  local before after
  before=$(sha256sum /var/lib/proxy-control/runtime.json | cut -d' ' -f1)
  run_captured /tmp/idempotent.out runtime_cmd install
  after=$(sha256sum /var/lib/proxy-control/runtime.json | cut -d' ' -f1)
  [[ $before == "$after" ]]
}
full_uninstall() {
  python3 "$ROOT/scripts/proxyctl.py" uninstall
  python3 "$ROOT/scripts/proxyctl.py" uninstall
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
  sha256sum -c "$BASELINE" >/dev/null
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui > /tmp/status.after
  cmp /tmp/status.before /tmp/status.after
  dpkg-query -W nginx-full docker.io docker-compose-v2 certbot >/dev/null
  rm -rf /opt/mtproxy-shared443
}

interrupt_install_recovery() {
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
  test ! -e /opt/mtproxy-shared443
  mapfile -t args < <(proxy_args)
  set +e
  PROXYCTL_TEST_CRASH_AFTER_PHASE=project_rendered \
    python3 "$ROOT/scripts/proxyctl.py" install "${args[@]}" >/tmp/interrupted-install.log 2>&1
  local interrupted_rc=$?
  set -e
  test "$interrupted_rc" -eq 137
  test -f /var/lib/proxy-control/runtime.json
  test "$(jq -r .phase /var/lib/proxy-control/runtime.json)" = project_rendered
  run_captured /tmp/recovered-install.out runtime_cmd install
  test "$(jq -r .status /var/lib/proxy-control/runtime.json)" = active
  test -f /var/lib/proxy-control/ownership.json
}

interrupt_uninstall_recovery() {
  test "$(jq -r .status /var/lib/proxy-control/runtime.json)" = active
  test -f /var/lib/proxy-control/ownership.json
  set +e
  PROXYCTL_TEST_CRASH_AFTER_PHASE=compose_down \
    python3 "$ROOT/scripts/proxyctl.py" uninstall >/tmp/interrupted-uninstall.log 2>&1
  local interrupted_rc=$?
  set -e
  test "$interrupted_rc" -eq 137
  test "$(jq -r .phase /var/lib/proxy-control/runtime.json)" = compose_down
  python3 "$ROOT/scripts/proxyctl.py" uninstall
  test ! -e /var/lib/proxy-control/runtime.json
  test ! -e /var/lib/proxy-control/ownership.json
}

docker_build_check() {
  docker image inspect mtproxy-panel >/dev/null 2>&1 || docker image ls --format '{{.Repository}}' | grep -qx mtproxy-panel
}

full_coexist() {
  sha256sum -c "$BASELINE" >/dev/null
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui >/dev/null
  ss -lnt | grep -q ':443 '
  ss -lnt | grep -q ':9443 '
}

full_dns_tls() {
  full_audit
  dns_tls_fixture
}

full_secrets_scan() {
  if grep -ERi 'tg://proxy\?.*secret=|telemt-api-token[=:][^[:space:]]+|panel-bootstrap-password[=:][^[:space:]]+' \
    /tmp/*.out /tmp/*.log /tmp/audit.json /tmp/plan.json 2>/dev/null; then
    return 1
  fi
  test "$(stat -c %a /opt/mtproxy-shared443/secrets 2>/dev/null || echo 700)" = 700
}


# ----------------------------------------------------------------------
# release mode: drive the typed installer from an exact release archive
# ----------------------------------------------------------------------

installer_cmd() {
  python3 -m installer.cli --root / "$@"
}

stage_mita_package() {
  # The installer deliberately never downloads the mita server or the official
  # client, so the operator stages both pinned packages by hand. The lab
  # performs exactly that documented step and reads the pins from the release
  # under test instead of keeping a second copy of them.
  local architecture name cache url digest
  architecture=$(dpkg --print-architecture)
  install -d -m 0755 /root/lab-artifacts /var/lib/proxy-control
  while read -r url digest; do
    name=${url##*/}
    cache=/root/lab-artifacts/$name
    if ! printf '%s  %s\n' "$digest" "$cache" | sha256sum -c --status 2>/dev/null; then
      curl --fail --silent --show-error --location --output "$cache" "$url"
      printf '%s  %s\n' "$digest" "$cache" | sha256sum -c --status
    fi
    install -m 0644 "$cache" "/var/lib/proxy-control/$name"
  done < <(PYTHONPATH="$RELEASE_ROOT" python3 -c '
import sys
from installer.adapters.mieru import _MIERU_CLIENT_PINS, _MITA_PINS
for pins in (_MITA_PINS, _MIERU_CLIENT_PINS):
    url, package_digest, _executable_digest = pins[sys.argv[1]]
    print(url, package_digest)
' "$architecture")
}

release_setup() {
  setup_full_host
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq dpkg-dev iproute2 >/dev/null
  install -d -m 0700 "$CREDENTIALS"
  install -d -m 0755 "$CLIENT_RESULTS"
  rm -rf "$RELEASE_STAGE"
  install -d -m 0755 "$RELEASE_STAGE"
  tar -xf "$RELEASE" -C "$RELEASE_STAGE"
  test -f "$RELEASE_ROOT/release/release.json"
  # setup_full_host builds the coexistence topology - an existing shared-443
  # stream router and a foreign 3x-ui - so the configuration has to describe
  # that host. `fresh` is refused against an active stream router, and
  # `managed-new` requires `fresh`, which is why this combination could never
  # have planned.
  cat > "$CONFIG" <<TOML
schema = 1
host_mode = "coexist"
profile = "full"
acme_email = "lab@example.invalid"
initial_user = "owner"

[domains]
panel = "$PANEL"
mtproxy = "$PROXY"
naive = "naive.lab.test"
mieru = "mieru.lab.test"

[mieru]
tcp_ports = [46001]
udp_ports = [46002]

[three_xui]
mode = "existing"
vless_tcp_domain = "vless.lab.test"
warp = false
warp_domains = []

[firewall]
manage_ufw = false
TOML
  printf '%s naive.lab.test mieru.lab.test xui.lab.test vless.lab.test xhttp.lab.test hy2.lab.test\n' "$(host_ip)" >> /etc/hosts
  stage_mita_package
}

release_environment_preflight() {
  local started log script
  started=$(python3 -c 'import time; print(time.time())')
  log=$(mktemp)
  script="$(declare -p PROXY PANEL ROUTE BASELINE RELEASE RELEASE_STAGE RELEASE_ROOT CONFIG CREDENTIALS CLIENT_RESULTS); $(declare -f host_ip add_hosts write_fake_certbot setup_full_host stage_mita_package release_setup); release_setup"
  # `set -e` kills the composed script silently when a `test` or a `read` fails,
  # and the report then carries whatever apt printed last. Name the command.
  script="trap 'printf \"PREFLIGHT FAILED: %s\\n\" \"\$BASH_COMMAND\" >&2' ERR; $script"
  if bash -Eeuo pipefail -c "$script" >"$log" 2>&1; then
    emit environment-preflight passed "$started"
    rm -f "$log"
    return 0
  fi
  emit environment-preflight failed "$started" "$(tail -n 5 "$log" | tr '\n' ' ')"
  sed 's/^/environment-preflight: /' "$log" >&2
  rm -f "$log"
  return 1
}

release_artifact_integrity() {
  # The release archive is the only source of the installer under test.
  test -s "$RELEASE_SHA"
  [[ $(sha256sum "$RELEASE" | cut -d' ' -f1) == "$(cat "$RELEASE_SHA")" ]]
  test -f "$RELEASE_ROOT/install.sh"
  test -f "$RELEASE_ROOT/installer/cli.py"
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['tag'] and d['commit'] and len(d['manifest_sha256'])==64" "$RELEASE_ROOT/release/release.json"
}

release_audit() {
  cd "$RELEASE_ROOT"
  installer_cmd plan --config "$CONFIG" --json >/tmp/plan.json
  python3 - <<'AUDITPY'
import json
plan = json.load(open('/tmp/plan.json'))
facts = plan['audit_facts']
assert facts['topology']['nginx']['observation'] == 'observed'
assert 'three_xui' in facts['topology']
assert facts['prerequisites']['hard_stops'] == []
AUDITPY
}

release_plan() {
  cd "$RELEASE_ROOT"
  python3 - <<'PLANPY'
import json
plan = json.load(open('/tmp/plan.json'))
order = plan['adapter_order']
assert order[:3] == ['packages', 'nginx', 'certificates'], order
assert order[-1] == 'three_xui', order
PLANPY
}

release_install() {
  cd "$RELEASE_ROOT"
  # An earlier uninstall scenario purges /var/lib/proxy-control, so re-stage the
  # operator-supplied package the same way before every install.
  stage_mita_package
  local digest
  digest=$(python3 -c "import json;print(json.load(open('/tmp/plan.json'))['digest'])")
  run_captured /tmp/install.out installer_cmd install --config "$CONFIG" --accept-plan "$digest"
  installer_cmd status --json >/tmp/status.json
  python3 -c "import json;assert json.load(open('/tmp/status.json'))['status']=='active'"
}

release_install_full_xui() {
  release_install
  systemctl is-active nginx docker >/dev/null
  test -d /opt/mtproxy-shared443
  test "$(stat -c %a /opt/mtproxy-shared443/secrets)" = 700
  ss -lnt | grep -q ':443 '
}

release_coexist_existing_xui() {
  # A foreign 3x-ui must survive an installer run byte-for-byte.
  bash "$ROOT/tests/lab/fixtures/three-xui-existing.sh" 3.7.0 >/dev/null
  find /usr/local/x-ui /etc/x-ui -type f -print0 | sort -z | xargs -0 sha256sum > "$FOREIGN_BASELINE"
  cd "$RELEASE_ROOT"
  installer_cmd plan --config "$CONFIG" --json >/tmp/plan-coexist.json
  python3 - <<'COEXISTPY'
import json
plan = json.load(open('/tmp/plan-coexist.json'))
owners = {a['owner'] for a in plan['actions'] if a['adapter'] == 'three_xui'}
assert owners <= {'nginx.routes.three_xui', 'proxy-control:three-xui'}, owners
COEXISTPY
  sha256sum -c "$FOREIGN_BASELINE" >/dev/null
}

release_nginx_multi_map() {
  # An ambiguous multi-map topology must be resolved or refused, never guessed.
  cp "$ROOT/tests/lab/fixtures/nginx-multi-map.conf" /etc/nginx/stream.d/multi-map.conf
  nginx -t
  systemctl restart nginx
  cd "$RELEASE_ROOT"
  if installer_cmd plan --config "$CONFIG" --json >/tmp/plan-multi.json 2>/tmp/plan-multi.err; then
    python3 -c "import json;json.load(open('/tmp/plan-multi.json'))"
  else
    grep -q 'BLOCKED' /tmp/plan-multi.err
  fi
  rm -f /etc/nginx/stream.d/multi-map.conf
  nginx -t
  systemctl restart nginx
}

client_probe() {
  local service=$1
  LAB_CREDENTIALS=$CREDENTIALS LAB_RESULTS=$CLIENT_RESULTS docker compose -f "$ROOT/tests/lab/clients/compose.yaml" run --rm "$service"
}

release_telemt_client() { client_probe telemt; }
release_naive_client() { client_probe naive; }
release_mieru_client() { client_probe mieru; }
release_vless_tcp_client() { client_probe vless-tcp; }
release_vless_xhttp_client() { client_probe vless-xhttp; }
release_hysteria_client() { client_probe hysteria2; }

release_repair() {
  cd "$RELEASE_ROOT"
  installer_cmd repair --json >/tmp/repair.json
  python3 -c "import json;assert json.load(open('/tmp/repair.json'))['status']=='active'"
}

release_idempotence() {
  cd "$RELEASE_ROOT"
  local before after digest
  before=$(sha256sum "$INSTALLER_STATE" | cut -d' ' -f1)
  digest=$(python3 -c "import json;print(json.load(open('/tmp/plan.json'))['digest'])")
  run_captured /tmp/idempotent.out installer_cmd install --config "$CONFIG" --accept-plan "$digest"
  after=$(sha256sum "$INSTALLER_STATE" | cut -d' ' -f1)
  [[ $before == "$after" ]]
}

release_reboot_recovery() {
  # A restart of every owned runtime must recover without a second mutation.
  systemctl restart nginx docker
  sleep 5
  release_repair
}

release_crash_every_phase() {
  # Interrupt each durable phase, then require resume to finish it exactly once.
  cd "$RELEASE_ROOT"
  local phase
  for phase in prepared applied verified; do
    python3 - "$phase" <<'CRASHPY'
import json, sys
from pathlib import Path

phase = sys.argv[1]
state = Path('/var/lib/proxy-control/installer/state.json')
document = json.loads(state.read_text())
document['status'] = 'applying'
# A crash interrupts exactly one action: every earlier one stays verified.
# Rewinding all of them at once would forge a journal the engine can never
# produce, and the installer is right to refuse that.
checkpoint = document['checkpoints'][-1]
checkpoint['phase'] = phase
if phase == 'prepared' and isinstance(checkpoint['data'].get('ownership'), dict):
    # A checkpoint that has not applied yet claims nothing.
    checkpoint['data']['ownership'] = {}
state.write_text(json.dumps(document))
CRASHPY
    installer_cmd resume --json >/tmp/resume-"$phase".json
    python3 -c "import json,sys;assert json.load(open(sys.argv[1]))['status']=='active'" /tmp/resume-"$phase".json
  done
}

release_secrets_scan() {
  # `! cmd` skips errexit, so a match becomes an explicit failure instead.
  if grep -ERi '(panel-bootstrap-password|telemt-api-token|naive-manager-token|mieru-manager-token)[=:][^[:space:]]+|tg://proxy\?.*secret=|privateKey' /tmp/*.json /tmp/*.out /tmp/*.log 2>/dev/null; then
    return 1
  fi
  test "$(stat -c %a /opt/mtproxy-shared443/secrets)" = 700
  test "$(stat -c %a /etc/mieru-manager/token 2>/dev/null || echo 440)" = 440
}

release_dns_tls() {
  python3 - <<'DNSPY'
import json
plan = json.load(open('/tmp/plan.json'))
dns = plan['audit_facts']['topology']['dns']
assert dns, 'no DNS facts were audited'
for domain, fact in dns.items():
    assert fact['a_matches_local'], domain
    assert fact['aaaa_handled'], domain
    assert fact['caa_compatible'], domain
DNSPY
}

release_uninstall() {
  cd "$RELEASE_ROOT"
  installer_cmd uninstall --json >/tmp/uninstall.json
  installer_cmd uninstall --json >/tmp/uninstall-again.json
  test ! -e /opt/mtproxy-shared443/compose.yaml
  sha256sum -c "$BASELINE" >/dev/null
  dpkg-query -W nginx-full docker.io docker-compose-v2 certbot >/dev/null
}

release_uninstall_foreign_identity() {
  # A foreign holder of a fixed identity blocks the install instead of being
  # taken over, and the uninstall never removes an identity it did not create.
  groupadd --system --gid 10004 foreign-accounting 2>/dev/null || true
  cd "$RELEASE_ROOT"
  if installer_cmd plan --config "$CONFIG" --json >/tmp/plan-foreign.json 2>/tmp/plan-foreign.err; then
    if grep -q '"adapter": "naive"' /tmp/plan-foreign.json; then
      return 1
    fi
  else
    grep -qi 'collision' /tmp/plan-foreign.err
  fi
  getent group 10004 | grep -q foreign-accounting
  groupdel foreign-accounting
}

release_coexistence() {
  sha256sum -c "$BASELINE" >/dev/null
  sha256sum -c "$FOREIGN_BASELINE" >/dev/null
  systemctl is-active nginx lab-xray lab-warp lab-3x-ui >/dev/null
}


# ----------------------------------------------------------------------
# container mode: the part of release acceptance a systemd container proves
# ----------------------------------------------------------------------

host_ip() {
  ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n 1
}

container_setup() {
  local address
  address=$(host_ip)
  [[ -n $address ]]
  printf '%s %s %s naive.lab.test mieru.lab.test xui.lab.test vless.lab.test xhttp.lab.test hy2.lab.test\n' \
    "$address" "$PROXY" "$PANEL" >> /etc/hosts

  # A local resolver so the audit's mandatory CAA query answers instead of
  # failing closed: the lab zone publishes no CAA, exactly like a fresh host.
  # Everything outside the lab zone keeps going to the upstream resolvers this
  # host already used, so image pulls and package downloads still work.
  local upstreams
  upstreams=$(awk '/^nameserver/ && $2 !~ /^127\./ {print "server=" $2}' /etc/resolv.conf | sort -u)
  {
    printf 'no-resolv\nno-hosts\nlisten-address=127.0.0.1\nbind-interfaces\n'
    printf 'address=/lab.test/%s\n' "$address"
    if [[ -n $upstreams ]]; then
      printf '%s\n' "$upstreams"
    else
      printf 'server=1.1.1.1\nserver=8.8.8.8\n'
    fi
  } > /etc/dnsmasq.d/lab.conf
  systemctl restart dnsmasq
  printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
  dig +short CAA "$PANEL" >/dev/null

  mkdir -p /etc/nginx/stream.d /var/lib/lab-status
  cat > /etc/nginx/nginx.conf <<'NGINX'
load_module modules/ngx_stream_module.so;
user www-data;
pid /run/nginx.pid;
events { worker_connections 256; }
stream { include /etc/nginx/stream.d/*.conf; }
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGINX
  cat > "$ROUTE" <<'ROUTES'
map $ssl_preread_server_name $shared_backend {
    old-xray.lab.test 127.0.0.1:9443;
    default 127.0.0.1:9443;
}
server { listen 443; proxy_pass $shared_backend; ssl_preread on; }
ROUTES
  # The adjacent site must be a real TLS server: acceptance performs a verified
  # handshake through the shared router, not a bare TCP probe. Nginx presents
  # exactly the leaf it is given, which is what a real adjacent site does.
  write_fake_certbot /usr/local/bin/certbot
  /usr/local/bin/certbot certonly --cert-name old-xray.lab.test -d old-xray.lab.test
  cat > /etc/nginx/conf.d/lab-adjacent.conf <<'ADJACENT'
server {
    listen 127.0.0.1:9443 ssl;
    server_name old-xray.lab.test;
    ssl_certificate /etc/letsencrypt/live/old-xray.lab.test/cert.pem;
    ssl_certificate_key /etc/letsencrypt/live/old-xray.lab.test/privkey.pem;
    location / { return 200 "adjacent\n"; }
}
ADJACENT
  cat > /etc/systemd/system/lab-xray.service <<'UNIT'
[Unit]
Description=foreign adjacent service marker
[Service]
ExecStart=/usr/bin/sleep infinity
UNIT
  systemctl daemon-reload
  systemctl enable lab-xray nginx >/dev/null
  systemctl restart lab-xray
  nginx -t
  systemctl restart nginx
  ss -lnt | grep -q ':9443 '
  sha256sum "$ROUTE" > "$BASELINE"

  # The controller already extracted the archive; this runner is the copy
  # inside it, so the release root is simply its own parent.
  test -f "$RELEASE_ROOT/release/release.json"

  # A foreign 3x-ui is part of the coexistence topology, so it is present
  # before the very first audit and is hashed straight away.
  bash "$ROOT/tests/lab/fixtures/three-xui-existing.sh" 3.7.0 >/dev/null
  find /usr/local/x-ui /etc/x-ui -type f -print0 | sort -z | xargs -0 sha256sum > "$FOREIGN_BASELINE"

  container_write_configs
}

container_write_configs() {
  # The container hosts the coexistence topology: an existing shared-443
  # stream router and a foreign 3x-ui the installer must never touch.
  cat > "$CONFIG" <<TOML
schema = 1
host_mode = "coexist"
profile = "full"
acme_email = "lab@example.invalid"
initial_user = "owner"

[domains]
panel = "$PANEL"
mtproxy = "$PROXY"
naive = "naive.lab.test"
mieru = "mieru.lab.test"

[mieru]
tcp_ports = [46001]
udp_ports = [46002]

[three_xui]
mode = "existing"
vless_tcp_domain = "vless.lab.test"

[firewall]
manage_ufw = false
TOML
}

container_environment_preflight() {
  local started log script
  started=$(python3 -c 'import time; print(time.time())')
  log=$(mktemp)
  script="$(declare -p PROXY PANEL ROOT ROUTE BASELINE FOREIGN_BASELINE RELEASE RELEASE_ROOT CONFIG); $(declare -f host_ip write_fake_certbot container_write_configs container_setup); container_setup"
  # `set -e` kills the composed script silently when a `test` or a `read` fails,
  # and the report then carries whatever apt printed last. Name the command.
  script="trap 'printf \"PREFLIGHT FAILED: %s\\n\" \"\$BASH_COMMAND\" >&2' ERR; $script"
  if bash -Eeuo pipefail -c "$script" >"$log" 2>&1; then
    emit environment-preflight passed "$started"
    rm -f "$log"
    return 0
  fi
  emit environment-preflight failed "$started" "$(tail -n 5 "$log" | tr '\n' ' ')"
  sed 's/^/environment-preflight: /' "$log" >&2
  rm -f "$log"
  return 1
}

container_cmd() {
  ( cd "$RELEASE_ROOT" && PYTHONPATH="$RELEASE_ROOT" python3 -m installer.cli --root / "$@" )
}

container_artifact_integrity() {
  test -s "$RELEASE_SHA"
  [[ $(sha256sum "$RELEASE" | cut -d' ' -f1) == "$(cat "$RELEASE_SHA")" ]]
  test -f "$RELEASE_ROOT/install.sh"
  test -f "$RELEASE_ROOT/installer/cli.py"
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['tag'] and d['commit'] and len(d['manifest_sha256'])==64" \
    "$RELEASE_ROOT/release/release.json"
  # The release is the only installer under test: nothing here comes from the
  # working tree that produced it.
  ! test -e "$RELEASE_ROOT/.git"
}

container_audit() {
  container_cmd plan --config "$CONFIG" --json >/tmp/plan.json
  python3 - <<'AUDITPY'
import json
plan = json.load(open('/tmp/plan.json'))
facts = plan['audit_facts']
assert facts['topology']['nginx']['observation'] == 'observed', facts['topology']['nginx']
assert 'three_xui' in facts['topology']
assert facts['prerequisites']['hard_stops'] == [], facts['prerequisites']['hard_stops']
AUDITPY
}

container_plan() {
  python3 - <<'PLANPY'
import json
plan = json.load(open('/tmp/plan.json'))
order = plan['adapter_order']
assert order[:3] == ['packages', 'nginx', 'certificates'], order
assert order[-1] == 'three_xui', order
assert 'naive' in order and 'mieru' in order, order
PLANPY
}

container_nginx_multi_map() {
  cp "$ROOT/tests/lab/fixtures/nginx-multi-map.conf" /etc/nginx/stream.d/multi-map.conf
  nginx -t
  systemctl restart nginx
  ss -lnt | grep -q ':8443 '""
  # An ambiguous topology is resolved or refused, never guessed.
  if container_cmd plan --config "$CONFIG" --json >/tmp/plan-multi.json 2>/tmp/plan-multi.err; then
    python3 -c "import json;json.load(open('/tmp/plan-multi.json'))"
  else
    grep -q 'BLOCKED' /tmp/plan-multi.err
  fi
  rm -f /etc/nginx/stream.d/multi-map.conf
  nginx -t
  systemctl restart nginx
  ! ss -lnt | grep -q ':8443 '
}

container_coexist_existing_xui() {
  # Existing mode plans only the owned shared-443 route for 3x-ui, and the
  # foreign tree is byte-identical afterwards.
  python3 - <<'COEXISTPY'
import json
plan = json.load(open('/tmp/plan.json'))
owners = {a['owner'] for a in plan['actions'] if a['adapter'] == 'three_xui'}
assert owners == {'nginx.routes.three_xui'}, owners
mutations = [m for a in plan['actions'] if a['adapter'] == 'three_xui' for m in a['mutations']]
assert any(m == 'route=vless.lab.test 127.0.0.1:9443' for m in mutations), mutations
assert any(m == 'mode=existing' for m in mutations), mutations
COEXISTPY
  sha256sum -c "$FOREIGN_BASELINE" >/dev/null
  sha256sum -c "$BASELINE" >/dev/null
}

container_uninstall_foreign_identity() {
  groupadd --system --gid 10004 foreign-accounting
  if container_cmd plan --config "$CONFIG" --json >/tmp/plan-foreign.json 2>/tmp/plan-foreign.err; then
    if grep -q '"adapter": "naive"' /tmp/plan-foreign.json; then
      return 1
    fi
  else
    grep -qi 'collision' /tmp/plan-foreign.err
  fi
  # The foreign identity is still there: nothing took it over or removed it.
  getent group 10004 | grep -q foreign-accounting
  groupdel foreign-accounting
}

container_dns_tls() {
  python3 - <<'DNSPY'
import json
plan = json.load(open('/tmp/plan.json'))
dns = plan['audit_facts']['topology']['dns']
assert dns, 'no DNS facts were audited'
for domain, fact in dns.items():
    assert fact['a_matches_local'], (domain, fact)
    assert fact['aaaa_handled'], (domain, fact)
    assert fact['caa_compatible'], (domain, fact)
DNSPY
}

container_secrets_scan() {
  if grep -ERi '(panel-bootstrap-password|telemt-api-token|naive-manager-token|mieru-manager-token)[=:][^[:space:]]+|tg://proxy\?.*secret=|privateKey' \
      /tmp/plan*.json /tmp/plan*.err 2>/dev/null; then
    return 1
  fi
  ! grep -q 'FOREIGN-PRIVATE-KEY-NEVER-READ' /tmp/plan.json
}

emit_plan_digest() {
  [[ -f /tmp/plan.json ]] || return 0
  local digest
  digest=$(python3 -c "import json;print(json.load(open('/tmp/plan.json'))['digest'])" 2>/dev/null || true)
  [[ -n $digest ]] || return 0
  printf 'LAB_PLAN_DIGEST\t%s\n' "$digest"
}


# ----------------------------------------------------------------------
# host mode: the same acceptance on a disposable bare-metal host, with
# stub domains and a deterministic certificate generator instead of ACME
# ----------------------------------------------------------------------

host_setup() {
  # A host acceptance run starts from a pristine host. An existing installer
  # transaction is refused rather than silently adopted; LAB_RESET=1 is the
  # explicit opt-in that clears installer-owned state on a disposable host.
  local residue=0 candidate
  for candidate in "$INSTALLER_STATE" /opt/mtproxy-shared443 /etc/proxy-control \
      /etc/letsencrypt/live; do
    [[ -e $candidate ]] && residue=1
  done
  compgen -G '/etc/nginx/conf.d/proxy-control-*.conf' >/dev/null && residue=1
  if [[ ${LAB_RESET:-0} == 1 ]]; then
    # Disposable host only: return it to a pristine state so a rerun measures
    # the installer, not the residue of the previous attempt.
    ( cd "$RELEASE_ROOT" && PYTHONPATH="$RELEASE_ROOT" python3 -m installer.cli --root / \
        uninstall --purge-data >/dev/null 2>&1 ) || true
    # Remove the Compose project the same way the installer detects it: by
    # label, not by container name.
    local label=label=com.docker.compose.project=mtproxy
    docker container ls -aq --filter "$label" | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network ls -q --filter "$label" | xargs -r docker network rm >/dev/null 2>&1 || true
    docker volume ls -q --filter "$label" | xargs -r docker volume rm -f >/dev/null 2>&1 || true
    systemctl disable --now caddy-naive mita >/dev/null 2>&1 || true
    rm -rf /var/lib/proxy-control /opt/mtproxy-shared443 /etc/letsencrypt \
      /etc/proxy-control /var/lib/naive-manager /var/log/naive-proxy \
      /var/lib/mieru-manager /etc/mieru-manager /var/lib/mita
    rm -f /etc/systemd/system/caddy-naive.service /etc/systemd/system/mita.service \
      /etc/tmpfiles.d/mita.conf /usr/local/bin/caddy /usr/bin/mita \
      /usr/local/libexec/check-naive-caddy-build /usr/local/libexec/caddy-naive-adapt \
      /usr/local/libexec/prepare-naive-state /usr/local/libexec/prepare-mieru-state \
      /usr/local/libexec/prepare-mieru-token \
      /etc/letsencrypt/renewal-hooks/deploy/proxy-control-naive-caddy
    # A stray process keeps its identity alive, and userdel then refuses.
    pkill -KILL -u naive-caddy >/dev/null 2>&1 || true
    pkill -KILL -u mita >/dev/null 2>&1 || true
    sleep 1
    userdel naive-caddy >/dev/null 2>&1 || true
    groupdel naive-accounting >/dev/null 2>&1 || true
    userdel mita >/dev/null 2>&1 || true
    groupdel mita >/dev/null 2>&1 || true
    systemctl daemon-reload
    rm -f /etc/nginx/conf.d/proxy-control-*.conf
    # The identity-collision scenario creates this group; a previous run that
    # stopped early can leave it behind and block the next audit.
    groupdel foreign-accounting >/dev/null 2>&1 || true
    rm -f /tmp/plan*.json /tmp/status.json /tmp/resume-*.json /tmp/*.out
  elif ((residue)); then
    printf 'installer state already exists; run uninstall or set LAB_RESET=1\n' >&2
    return 1
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx-full libnginx-mod-stream docker.io docker-compose-v2 \
    certbot openssl socat jq dnsmasq dnsutils dpkg-dev iproute2 >/dev/null
  container_setup
  install -d -m 0700 "$CREDENTIALS"
  install -d -m 0755 "$CLIENT_RESULTS"
  systemctl enable --now docker >/dev/null 2>&1 || true
}

host_environment_preflight() {
  local started log script
  started=$(python3 -c 'import time; print(time.time())')
  log=$(mktemp)
  script="export LAB_RESET=${LAB_RESET:-0}; $(declare -p PROXY PANEL ROOT ROUTE BASELINE FOREIGN_BASELINE RELEASE RELEASE_ROOT CONFIG CREDENTIALS CLIENT_RESULTS INSTALLER_STATE); $(declare -f host_ip write_fake_certbot container_write_configs container_setup host_setup); host_setup"
  # `set -e` kills the composed script silently when a `test` or a `read` fails,
  # and the report then carries whatever apt printed last. Name the command.
  script="trap 'printf \"PREFLIGHT FAILED: %s\\n\" \"\$BASH_COMMAND\" >&2' ERR; $script"
  if bash -Eeuo pipefail -c "$script" >"$log" 2>&1; then
    emit environment-preflight passed "$started"
    rm -f "$log"
    return 0
  fi
  emit environment-preflight failed "$started" "$(tail -n 5 "$log" | tr '\n' ' ')"
  sed 's/^/environment-preflight: /' "$log" >&2
  rm -f "$log"
  return 1
}

host_install() {
  local digest
  # An earlier uninstall scenario purges /var/lib/proxy-control, so re-stage the
  # operator-supplied package the same way before every install.
  stage_mita_package
  # Derive the plan immediately before applying it: an approved digest is only
  # meaningful for the host as it is right now.
  container_cmd plan --config "$CONFIG" --json >/tmp/plan-install.json
  digest=$(python3 -c "import json;print(json.load(open('/tmp/plan-install.json'))['digest'])")
  run_captured /tmp/install.out container_cmd install --config "$CONFIG" --accept-plan "$digest"
  container_cmd status --json >/tmp/status.json
  python3 -c "import json;assert json.load(open('/tmp/status.json'))['status']=='active'"
  test -d /opt/mtproxy-shared443
  test "$(stat -c %a /opt/mtproxy-shared443/secrets)" = 700
}

host_docker_build() {
  docker image inspect mtproxy-panel >/dev/null 2>&1 \
    || docker image ls --format '{{.Repository}}' | grep -qx mtproxy-panel
}

host_repair() {
  container_cmd repair --json >/tmp/repair.json
  python3 -c "import json;assert json.load(open('/tmp/repair.json'))['status']=='active'"
}

host_idempotence() {
  local before after digest
  before=$(sha256sum "$INSTALLER_STATE" | cut -d' ' -f1)
  container_cmd plan --config "$CONFIG" --json >/tmp/plan-idempotent.json
  digest=$(python3 -c "import json;print(json.load(open('/tmp/plan-idempotent.json'))['digest'])")
  run_captured /tmp/idempotent.out container_cmd install --config "$CONFIG" --accept-plan "$digest"
  after=$(sha256sum "$INSTALLER_STATE" | cut -d' ' -f1)
  [[ $before == "$after" ]]
}

host_reboot_recovery() {
  systemctl restart nginx docker
  sleep 5
  host_repair
}

host_crash_every_phase() {
  local phase
  for phase in prepared applied verified; do
    python3 - "$phase" <<'CRASHPY'
import json, sys
from pathlib import Path

phase = sys.argv[1]
state = Path('/var/lib/proxy-control/installer/state.json')
document = json.loads(state.read_text())
document['status'] = 'applying'
# A crash interrupts exactly one action: every earlier one stays verified.
# Rewinding all of them at once would forge a journal the engine can never
# produce, and the installer is right to refuse that.
checkpoint = document['checkpoints'][-1]
checkpoint['phase'] = phase
if phase == 'prepared' and isinstance(checkpoint['data'].get('ownership'), dict):
    # A checkpoint that has not applied yet claims nothing.
    checkpoint['data']['ownership'] = {}
state.write_text(json.dumps(document))
CRASHPY
    container_cmd resume --json >/tmp/resume-"$phase".json
    python3 -c "import json,sys;assert json.load(open(sys.argv[1]))['status']=='active'" /tmp/resume-"$phase".json
  done
}

host_report() {
  container_cmd report --config "$CONFIG" --output /var/lib/proxy-control/reports --json >/tmp/report.out
  test -f /var/lib/proxy-control/reports/report.json
  test "$(stat -c %a /var/lib/proxy-control/reports/report.json)" = 644
  # The public report must never name or carry a credential.
  ! grep -Eiq '(password|token|secret|privateKey)' /var/lib/proxy-control/reports/report.json
}

host_uninstall() {
  container_cmd uninstall --json >/tmp/uninstall.json
  container_cmd uninstall --json >/tmp/uninstall-again.json
  test ! -e /opt/mtproxy-shared443/compose.yaml
  # The foreign topology and the foreign 3x-ui are byte-identical afterwards.
  sha256sum -c "$BASELINE" >/dev/null
  sha256sum -c "$FOREIGN_BASELINE" >/dev/null
  dpkg-query -W nginx-full docker.io docker-compose-v2 certbot >/dev/null
}

host_secrets_scan() {
  if grep -ERi '(panel-bootstrap-password|telemt-api-token|naive-manager-token|mieru-manager-token)[=:][^[:space:]]+|tg://proxy\?.*secret=|privateKey' \
      /tmp/plan*.json /tmp/*.out /var/lib/proxy-control/reports/report.json 2>/dev/null; then
    return 1
  fi
  test "$(stat -c %a /opt/mtproxy-shared443/secrets 2>/dev/null || echo 700)" = 700
}

host_coexistence() {
  sha256sum -c "$BASELINE" >/dev/null
  sha256sum -c "$FOREIGN_BASELINE" >/dev/null
  systemctl is-active nginx lab-xray >/dev/null
}

if [[ ${GUEST_RUNNER_LIB_ONLY:-0} == 1 ]]; then
  return 0 2>/dev/null || exit 0
fi

add_hosts
make_fixture
if [[ $MODE == smoke ]]; then
  case_run archive-integrity archive_integrity
  case_run audit audit_fixture
  case_run plan plan_fixture
  case_run coexistence coexist_fixture
  case_run dns-tls-preflight dns_tls_fixture
  case_run secrets-scan secrets_scan
elif [[ $MODE == full ]]; then
  if ! full_environment_preflight; then
    exit "$RESULTS_FAILED"
  fi
  CASE_STATUS[environment-preflight]=passed
  case_run audit full_audit environment-preflight
  case_run plan full_plan audit
  case_run install full_install plan
  case_run docker-build docker_build_check install
  case_run repair full_repair install
  case_run idempotence full_idempotence repair
  case_run secrets-scan full_secrets_scan idempotence
  case_run dns-tls-preflight full_dns_tls idempotence
  case_run uninstall full_uninstall idempotence
  case_run interrupted-install-recovery interrupt_install_recovery uninstall
  case_run interrupted-uninstall-recovery interrupt_uninstall_recovery interrupted-install-recovery
  case_run coexistence full_coexist interrupted-uninstall-recovery
elif [[ $MODE == release-amd64 || $MODE == release-arm64 ]]; then
  if ! release_environment_preflight; then
    exit "$RESULTS_FAILED"
  fi
  CASE_STATUS[environment-preflight]=passed
  case_run release-artifact-integrity release_artifact_integrity environment-preflight
  case_run audit release_audit release-artifact-integrity
  case_run plan release_plan audit
  emit_plan_digest
  case_run install-full-xui release_install_full_xui plan
  case_run coexist-existing-xui release_coexist_existing_xui install-full-xui
  case_run nginx-multi-map release_nginx_multi_map install-full-xui
  case_run telemt-official-client release_telemt_client install-full-xui
  case_run naive-official-client release_naive_client install-full-xui
  case_run mieru-official-client release_mieru_client install-full-xui
  case_run vless-tcp-client release_vless_tcp_client install-full-xui
  case_run vless-xhttp-client release_vless_xhttp_client install-full-xui
  case_run hysteria2-client release_hysteria_client install-full-xui
  case_run docker-build docker_build_check install-full-xui
  case_run repair release_repair install-full-xui
  case_run idempotence release_idempotence repair
  case_run reboot-recovery release_reboot_recovery idempotence
  case_run crash-every-phase release_crash_every_phase reboot-recovery
  case_run secrets-scan release_secrets_scan crash-every-phase
  case_run dns-tls-preflight release_dns_tls plan
  case_run uninstall release_uninstall crash-every-phase
  case_run uninstall-foreign-identity release_uninstall_foreign_identity uninstall
  case_run interrupted-install-recovery interrupt_install_recovery uninstall
  case_run interrupted-uninstall-recovery interrupt_uninstall_recovery interrupted-install-recovery
  case_run coexistence release_coexistence interrupted-uninstall-recovery
elif [[ $MODE == container ]]; then
  if ! container_environment_preflight; then
    exit "$RESULTS_FAILED"
  fi
  CASE_STATUS[environment-preflight]=passed
  case_run release-artifact-integrity container_artifact_integrity environment-preflight
  case_run audit container_audit release-artifact-integrity
  case_run plan container_plan audit
  emit_plan_digest
  case_run nginx-multi-map container_nginx_multi_map plan
  case_run coexist-existing-xui container_coexist_existing_xui plan
  case_run uninstall-foreign-identity container_uninstall_foreign_identity plan
  case_run dns-tls-preflight container_dns_tls plan
  case_run secrets-scan container_secrets_scan coexist-existing-xui
elif [[ $MODE == host ]]; then
  if ! host_environment_preflight; then
    exit "$RESULTS_FAILED"
  fi
  CASE_STATUS[environment-preflight]=passed
  case_run release-artifact-integrity container_artifact_integrity environment-preflight
  case_run audit container_audit release-artifact-integrity
  case_run plan container_plan audit
  emit_plan_digest
  # Everything that asserts the untouched host runs before the install.
  case_run nginx-multi-map container_nginx_multi_map plan
  case_run coexist-existing-xui container_coexist_existing_xui plan
  case_run uninstall-foreign-identity container_uninstall_foreign_identity plan
  case_run dns-tls-preflight container_dns_tls plan
  case_run install host_install dns-tls-preflight
  case_run docker-build host_docker_build install
  case_run repair host_repair install
  case_run idempotence host_idempotence repair
  case_run reboot-recovery host_reboot_recovery idempotence
  case_run crash-every-phase host_crash_every_phase reboot-recovery
  case_run report host_report crash-every-phase
  case_run secrets-scan host_secrets_scan report
  case_run uninstall host_uninstall secrets-scan
  case_run coexistence host_coexistence uninstall
else
  printf 'unknown mode: %s\n' "$MODE" >&2
  exit 2
fi
exit "$RESULTS_FAILED"
