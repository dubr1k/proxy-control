#!/usr/bin/env bash
# Fetch, verify and unpack one Proxy Control release, then hand it to the installer.
#
# `install-bootstrap` (inside every archive) refuses a pre-release suffix (`-rc.N`), so a
# pre-release is installed by the same steps without it: download the four release files,
# `sha256sum --check SHA256SUMS`, extract, and run `sudo bash install.sh wizard`
# from the extracted tree. This script performs
# exactly those steps for any tag and stops at the first failed check. It never pipes a
# download into a shell: the files land on disk, the payload is checked against
# SHA256SUMS, the manifest must name the same archive and digest, the digest may be pinned
# (`--sha256`, the `lab-sha256` of the tag annotation) and, when `gh` is present, the
# GitHub build-provenance attestation is verified too. Everything before the installer
# runs unprivileged; `sudo` is asked once, for the installer itself — the same rule
# `install-bootstrap` follows.
#
#   scripts/install-release.sh --requirements            # what is needed and what gets installed
#   bash install-release.sh                              # the copy published beside a release:
#                                                        # that release, its digest pinned
#   scripts/install-release.sh --version 1.1.2 --sha256 <lab-sha256>
#   scripts/install-release.sh --version 1.1.2 --no-wizard
#   scripts/install-release.sh --version 1.1.2 -- plan --config install.toml --json
#   bash install-release.sh --update                     # v1.1: update an installed host to that
#                                                        # release (scripts/update-host.sh, as root)
set -Eeuo pipefail

REPO=${PROXY_CONTROL_REPO:-dubr1k/proxy-control}
VERSION=
EXPECTED=
DESTINATION=
LANGUAGE=
LANGUAGE_GIVEN=0   # --lang was typed: the wizard does not ask the language again
MODE=install   # install | update | check | unpack | requirements
REQUIRE_ATTESTATION=0
SOURCE_DIR=
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# The copy published beside a release (`install-release.sh` on the release page) carries
# that release's version and archive digest, stamped by release/build.py: run without
# arguments it installs exactly those bytes. In the repository both stay empty.
STAMPED_VERSION=""
STAMPED_SHA256=""

usage() {
    cat >&2 <<'USAGE'
usage: scripts/install-release.sh [--version X.Y.Z[-rc.N]] [--sha256 DIGEST] [--dir DIR]
                                  [--from-dir VERIFIED_DIST] [--lang ru|en] [--requirements | --check-only | --no-wizard]
                                  [--attest] [--update] [-- INSTALLER ARGS...]

  --version       release to fetch (default: the release this copy was published with,
                  or the VERSION file beside this script's tree)
  --sha256        pin the archive digest — the `lab-sha256` of the tag annotation
                  or the digest in the release note; a different archive is refused
                  (the copy published with a release pins its own digest already)
  --dir           where to download and extract (default: ./proxy-control-vX.Y.Z; must be new)
  --from-dir      use four already-downloaded release files from this directory;
                  they are copied, then verified exactly like downloaded files
  --lang          language of the messages (default: from $LANG, ru or en)
  --requirements  print what the host needs and what the installer sets up, then exit
  --check-only    download and verify only; extract nothing, install nothing
  --no-wizard     download, verify and extract; print the next command instead of running it
  --attest        require `gh attestation verify` to pass (default: verify when gh exists)
  --update        update this already installed host to the release instead of installing:
                  the same verification, then (as root) the host's version-agent updates the
                  panel and changed managers plus enabled MCP are rebuilt (scripts/update-host.sh)
  --              everything after it goes to the native installer (default: wizard)
USAGE
    exit 2
}

say() {
    # say <ru text> <en text>
    if [[ $LANGUAGE == ru ]]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi
}

fail() {
    # fail <ru text> <en text>
    printf 'install-release: %s\n' "$(say "$1" "$2")" >&2
    exit 1
}

while (($#)); do
    case $1 in
        --version) VERSION=${2:?}; shift 2 ;;
        --sha256) EXPECTED=${2:?}; shift 2 ;;
        --dir) DESTINATION=${2:?}; shift 2 ;;
        --from-dir) SOURCE_DIR=${2:?}; shift 2 ;;
        --lang) LANGUAGE=${2:?}; LANGUAGE_GIVEN=1; shift 2 ;;
        --requirements) MODE=requirements; shift ;;
        --check-only) MODE=check; shift ;;
        --no-wizard) MODE=unpack; shift ;;
        --attest) REQUIRE_ATTESTATION=1; shift ;;
        --update) MODE=update; shift ;;
        -h|--help) usage ;;
        --) shift; break ;;
        *) usage ;;
    esac
done

if [[ -z $LANGUAGE ]]; then
    case ${LC_ALL:-${LC_MESSAGES:-${LANG:-}}} in
        ru*) LANGUAGE=ru ;;
        *) LANGUAGE=en ;;
    esac
fi
[[ $LANGUAGE == ru || $LANGUAGE == en ]] || usage

requirements() {
    if [[ $LANGUAGE == ru ]]; then
        cat <<'TEXT'
Proxy Control — что нужно для установки

Сервер
  • x86-64 (amd64): другие архитектуры установщик отвергает при аудите — релиз
    собирается и проверяется на стенде только под x86-64.
  • Ubuntu 24.04 LTS с systemd; вход обычным пользователем с `sudo` (проверка
    архива идёт без привилегий, root нужен только самому установщику).
  • Bash, awk, curl, tar, sha256sum и sudo для проверки и запуска; Python и Rust
    на хосте не нужны: релиз содержит проверяемые статические исполняемые файлы.
  • Свободные TCP/443 и TCP/80 в режиме `fresh`; в режиме `coexist` — ваш Nginx
  со `stream` уже владеет 443 и имеет ровно одну карту `$ssl_preread_server_name`.
  fresh сохраняет IP клиентов панели через приватные Unix-сокеты Nginx; новых
  TCP-портов нет. В coexist сохранение IP требует настройки операторского PROXY bridge.
  • Публичный IPv4 без NAT; для домена MTProxy проксирование CDN выключено (DNS-only).

Домены и DNS
  • Домен панели и домен MTProxy — всегда; домен NaiveProxy — в профилях с Naive;
    домен Mieru — в профилях с Mieru (сертификат ему не нужен); необязательный
    домен подписки; необязательный отдельный домен TrustTunnel;
    в режиме 3x-ui — ещё четыре домена.
  • Записи A ведут на этот сервер, AAAA либо нет, либо тоже на него; CAA не
    запрещает Let's Encrypt. Сертификаты выпускаются через HTTP-01 на порту 80.

Закреплённые внешние артефакты класть не нужно — установщик скачивает их сам по
  закреплённым HTTPS-URL и сверяет SHA-256 до любого использования (несовпадение —
  отказ, файл выбрасывается); файл, положенный вручную в /var/lib/proxy-control/
  (хост без интернета), используется как есть и никогда не заменяется:
  • профили с Mieru: mita_3.38.1_amd64.deb и mieru_3.38.1_amd64.deb;
  • управляемый 3x-ui 3.10.2: x-ui-linux-amd64.tar.gz;
  • Xray-router: Xray-linux-64.zip (Xray-core 26.10.17);
  • TrustTunnel: trusttunnel-v1.1.0-linux-x86_64.tar.gz (TrustTunnel endpoint 1.1.0) —
    его скачивает и сверяет при сборке образа менеджера Docker, не установщик.
  URL и SHA-256 — в release/external-artifacts.json распакованного релиза.

WARP (необязательно): секция [egress] в install.toml или вопросы мастера —
  установщик ставит закреплённый клиент Cloudflare WARP в proxy-режиме на
  127.0.0.1:40000 и задаёт начальный egress NaiveProxy/Mieru; дальше им владеет
  экран «Маршрутизация» панели.

Xray-router (необязательно): [egress] router = true — выделенный Xray для
  политик с geosite/geoip/портами и блокировками рядом с WARP; мастер предлагает его
  каждому профилю с NaiveProxy или Mieru (и узлу с TrustTunnel), архив приезжает сам (см. выше). Через него
  же можно направить MTProxy (WARP, свой выход, другой узел): рядом встаёт мост
  xray-router-ingress в сети Compose, новых портов хоста нет.

AmneziaWG (необязательно): секция [amneziawg] в install.toml или вопрос мастера —
  обфусцированный WireGuard версий 1.5, 2.0 и 3.1 в контейнере awg-manager (сеть
  хоста, /dev/net/tun, права NET_ADMIN и NET_RAW). Образ собирается на хосте из
  закреплённого коммита amneziawg-go (лицензия MIT, проект Amnezia VPN; нужен доступ
  к GitHub и Docker Hub на время сборки). Новый домен не нужен: клиенты подключаются
  по UDP напрямую к серверу по имени (по умолчанию — домен панели; он должен указывать
  на сервер и не проксироваться) или по IPv4. Установщик создаёт каталог
  /var/lib/awg-manager (ключи сервера), файл /etc/sysctl.d/99-proxy-control-amneziawg.conf
  (net.ipv4.ip_forward = 1) и открывает в UFW UDP-порты версий (случайные свободные,
  свои на каждый сервер; можно задать свои) и маршрутизацию на интерфейсах awg15, awg20, awg31; без управляемого UFW
  откройте эти порты и разрешите пересылку сами. Нужен /dev/net/tun на хосте.

TrustTunnel (необязательно): секция [trusttunnel] и ключ domains.trusttunnel в install.toml
  или вопросы мастера — VPN AdGuard (HTTP/2 поверх TLS, только TCP) в контейнере
  trusttunnel-manager, который запускает закреплённый trusttunnel_endpoint (Apache-2.0,
  проект TrustTunnel; образ собирается на хосте, нужен доступ к GitHub на время сборки).
  Нужен отдельный домен: A-запись на этот сервер, только DNS (прокси CDN выключен), имя
  не совпадает с другими доменами; сертификат Let's Encrypt для него выпускается
  установщиком (HTTP-01, порт 80). Новых портов и UDP нет: общий TCP/443 делит SNI-маршрут
  Nginx, endpoint слушает только 127.0.0.1:4453 (listen_port; рядом 127.0.0.1:1987 для
  метрик менеджера), правила UFW не добавляются. Установщик создаёт /var/lib/trusttunnel-manager
  (учётные данные, счётчики), secrets/trusttunnel-manager-token и .env.trusttunnel; менеджер
  читает сертификат домена из /etc/letsencrypt (только чтение).

Обновление уже установленного хоста (с v1.1): скачайте install-release.sh и .sha256
  нового выпуска так же, как для установки, сверьте сумму и запустите
  `bash install-release.sh --update` — та же проверка выпуска, затем version-agent
  хоста обновляет панель (с резервными копиями и откатом), изменившиеся менеджеры
  и включённый MCP пересобираются с точками отката образов.
  Telemt, сертификаты, .env и secrets/ не трогаются. Если на хосте AmneziaWG и его
  исходники изменились, awg-manager пересобирается: туннели на секунды рвутся,
  клиенты переподключаются сами, /var/lib/awg-manager с ключами не трогается.
  Так же пересобирается trusttunnel-manager: перезапуск endpoint рвёт сессии на секунды.
  Переход 3.3.0 → 4.0 выполняется только этой командой: сначала заменяется Python-
  агент, проверяются Rust-реализация и точная версия, затем обновляется панель.
  При отказе миграции агент и его журнал откатываются; данные и настройки сохраняются.

Что делает установщик (мастер → план → подтверждение digest → применение):
  • Пакеты Ubuntu, которых нет на хосте: ca-certificates certbot curl
    docker-compose-v2 docker.io nginx-full openssl — и только они
    попадают под его владение (Python установщику не нужен).
  • Сертификаты Let's Encrypt (certbot, webroot) и проверка продления сразу.
  • Nginx: свой блок SNI-маршрутов на общем 443 и TLS-vhost панели; чужие
    маршруты не трогает, при неоднозначной конфигурации останавливается.
  • Compose-проект `proxy_panel_by_dubr1k` в /opt/mtproxy-shared443: контейнеры
    proxy-control-panel, -mtproxy (Telemt), -mask, а по профилю -naive-manager и
    -mieru-manager; тома, секреты (secrets/), мастер-ключ панели.
  • Host-службы по профилю: caddy-naive.service (NaiveProxy) и mita.service (Mieru).
  • AmneziaWG (если включён): контейнер proxy-control-awg-manager, секрет
    secrets/awg-manager-token, .env.amneziawg, /var/lib/awg-manager и sysctl-файл
    пересылки IPv4.
  • TrustTunnel (если включён): контейнер proxy-control-trusttunnel-manager, секрет
    secrets/trusttunnel-manager-token, .env.trusttunnel, /var/lib/trusttunnel-manager,
    и подключение /etc/letsencrypt только для чтения; ничего UDP.
  • Правила UFW — только если вы это разрешили и только на свежем хосте
    (порты 80 и 443, порты профиля, UDP-порты и маршрутизация AmneziaWG;
    для TrustTunnel правил нет: он использует уже открытый TCP/443).
  • 3x-ui — в режиме `existing` только маршрут, в `managed-new` — свой экземпляр.
    `managed-new` требует отсутствия прежней базы и её каталога /etc/x-ui.
  • Журнал транзакции, владение и отчёты — /var/lib/proxy-control/.
Каждый шаг журналируется и откатывается; прерванную установку продолжает
`sudo bash install.sh resume`. Ничего не меняется до подтверждения digest плана.
TEXT
    else
        cat <<'TEXT'
Proxy Control — what an install needs

Server
  • x86-64 (amd64): the installer rejects any other architecture at audit time —
    the release is built and lab-tested for x86-64 only.
  • Ubuntu 24.04 LTS with systemd; log in as a regular user with `sudo` (the archive
    is verified unprivileged; root is needed by the installer alone).
  • Bash, awk, curl, tar, sha256sum and sudo for verification and hand-off; neither
    Python nor Rust is required on the host: verified static binaries ship in the release.
  • Free TCP/443 and TCP/80 in `fresh` mode; in `coexist` mode your Nginx `stream`
  already owns 443 and has exactly one `$ssl_preread_server_name` map.
  fresh preserves panel client IPs through private Nginx Unix sockets, with no new
  TCP ports. In coexist mode, preserving IPs requires an operator-configured PROXY bridge.
  • A public IPv4 without NAT; CDN proxying switched off for the MTProxy domain.

Domains and DNS
  • The panel domain and the MTProxy domain — always; a NaiveProxy domain in the
    Naive profiles; a Mieru domain in the Mieru profiles (no certificate needed);
    an optional subscription domain; an optional domain of its own for TrustTunnel;
    four more domains in the 3x-ui modes.
  • A records point at this server, AAAA either absent or also this server; CAA
    does not forbid Let's Encrypt. Certificates are issued over HTTP-01 on port 80.

Nothing to stage for the pinned external artifacts — the installer fetches them from
  their pinned HTTPS URLs and proves the SHA-256 before anything uses them (a mismatch
  is a refusal, the file is discarded); a file staged by hand in
  /var/lib/proxy-control/ (an offline host) is used as it is and never replaced:
  • the Mieru profiles: mita_3.38.1_amd64.deb and mieru_3.38.1_amd64.deb;
  • managed 3x-ui 3.10.2: x-ui-linux-amd64.tar.gz;
  • the Xray-router: Xray-linux-64.zip (Xray-core 26.10.17);
  • TrustTunnel: trusttunnel-v1.1.0-linux-x86_64.tar.gz (TrustTunnel endpoint 1.1.0) —
    Docker downloads and checks it while building the manager image, not the installer.
  URLs and SHA-256 in release/external-artifacts.json of the extracted release.

WARP (optional): the [egress] section of install.toml or the wizard's questions —
  the installer sets up the pinned Cloudflare WARP client in proxy mode on
  127.0.0.1:40000 and seeds the initial egress of NaiveProxy/Mieru; from then on
  the panel's «Routing» screen owns it.

Xray-router (optional): [egress] router = true — a dedicated Xray for
  policies with geosite/geoip/ports and blocks beside WARP; the wizard offers it to
  every profile with NaiveProxy or Mieru (and a node with TrustTunnel), the archive arrives by itself (see above).
  MTProxy can be sent through it too (WARP, your own exit, another node):
  the xray-router-ingress bridge runs beside it on the Compose network, no new host ports.

AmneziaWG (optional): the [amneziawg] section of install.toml or the wizard's question —
  obfuscated WireGuard versions 1.5, 2.0 and 3.1 in the awg-manager container (host
  network, /dev/net/tun, NET_ADMIN and NET_RAW). The image is built on the host from
  the pinned amneziawg-go commit (MIT licence, the Amnezia VPN project; GitHub and Docker
  Hub must be reachable during the build). No new domain is needed: clients connect over
  UDP straight to the server by name (the panel domain by default; it must point at the
  server and not be proxied) or by IPv4. The installer creates /var/lib/awg-manager (the
  server keys), /etc/sysctl.d/99-proxy-control-amneziawg.conf (net.ipv4.ip_forward = 1) and
  opens one random free UDP port per version (chosen per server; you can set your own) plus forwarding on the awg15, awg20 and
  awg31 interfaces in UFW; without a UFW the installer manages, open the ports and allow
  forwarding yourself. /dev/net/tun must exist on the host.

TrustTunnel (optional): the [trusttunnel] section and the domains.trusttunnel key of install.toml
  or the wizard's questions — AdGuard's VPN (HTTP/2 over TLS, TCP only) in the
  trusttunnel-manager container, which runs the pinned trusttunnel_endpoint (Apache-2.0,
  the TrustTunnel project; the image is built on the host, GitHub must be reachable during the
  build). It needs a domain of its own: an A record to this server, DNS only (no CDN proxy),
  different from every other domain; its Let's Encrypt certificate is issued by the
  installer (HTTP-01, port 80). No new ports and nothing UDP: the shared TCP/443 is divided
  by the Nginx SNI route, the endpoint listens on 127.0.0.1:4453 only (listen_port; beside it
  127.0.0.1:1987 for the manager's metrics), no UFW rule is added. The installer creates
  /var/lib/trusttunnel-manager (credentials, counters), secrets/trusttunnel-manager-token and
  .env.trusttunnel; the manager reads the name's certificate from /etc/letsencrypt (read-only).

Updating an installed host (since v1.1): download the new release's install-release.sh
  and .sha256 as for an install, check the sum and run `bash install-release.sh --update`
  — the same release verification, then the host's version-agent updates the panel (with
  its backups and rollback); changed managers and enabled MCP are rebuilt with image backups. Telemt, certificates,
  .env and secrets/ are not touched. On a host with AmneziaWG whose sources changed,
  awg-manager is rebuilt: the tunnels drop for a few seconds and the clients reconnect
  by themselves; /var/lib/awg-manager with the keys is not touched.
  trusttunnel-manager is rebuilt the same way: restarting the endpoint drops sessions for seconds.
  The 3.3.0 → 4.0 transition is supported only through this command: replace the Python
  agent, verify its Rust implementation and exact version, then update the panel.
  A migration failure restores the agent and journal; operator settings and data stay intact.

What the installer does (wizard → plan → digest confirmation → apply):
  • Ubuntu packages missing on the host: ca-certificates certbot curl
    docker-compose-v2 docker.io nginx-full openssl — only those come
    under its ownership (the installer does not require Python).
  • Let's Encrypt certificates (certbot, webroot) with a renewal dry-run right away.
  • Nginx: its own SNI-route block on the shared 443 and the panel's TLS vhost;
    foreign routes stay untouched, an ambiguous configuration is a hard stop.
  • The Compose project `proxy_panel_by_dubr1k` in /opt/mtproxy-shared443: the containers
    proxy-control-panel, -mtproxy (Telemt), -mask and, per profile, -naive-manager
    and -mieru-manager; volumes, secrets (secrets/), the panel's master key.
  • Host services per profile: caddy-naive.service (NaiveProxy), mita.service (Mieru).
  • AmneziaWG (when enabled): the proxy-control-awg-manager container, the
    secrets/awg-manager-token secret, .env.amneziawg, /var/lib/awg-manager and the
    IPv4 forwarding sysctl file.
  • TrustTunnel (when enabled): the proxy-control-trusttunnel-manager container, the
    secrets/trusttunnel-manager-token secret, .env.trusttunnel, /var/lib/trusttunnel-manager,
    and a read-only mount of /etc/letsencrypt; nothing UDP.
  • UFW rules — only when you allow it and only on a fresh host
    (ports 80 and 443, the profile's ports, AmneziaWG's UDP ports and forwarding;
    none for TrustTunnel: it uses the TCP/443 that is already open).
  • 3x-ui — a route only in `existing` mode, its own instance in `managed-new`.
    `managed-new` requires the old database and its /etc/x-ui directory to be absent.
  • The transaction journal, ownership and reports — /var/lib/proxy-control/.
Every step is journaled and reversible; an interrupted install continues with
`sudo bash install.sh resume`. Nothing changes before the plan digest is confirmed.
TEXT
    fi
}

if [[ $MODE == requirements ]]; then
    requirements
    exit 0
fi

if [[ -z $VERSION && -n $STAMPED_VERSION ]]; then
    VERSION=$STAMPED_VERSION
elif [[ -z $VERSION && -f $SCRIPT_DIR/../VERSION ]]; then
    VERSION=$(tr -d '[:space:]' < "$SCRIPT_DIR/../VERSION")
fi
# The stamped digest belongs to the stamped release only: another --version is fetched
# unpinned (or with its own --sha256), never checked against this release's bytes.
if [[ -z $EXPECTED && -n $STAMPED_SHA256 && $VERSION == "$STAMPED_VERSION" ]]; then
    EXPECTED=$STAMPED_SHA256
fi
[[ -n $VERSION ]] || fail "укажите --version" "pass --version"
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
    || fail "неверный формат версии: $VERSION" "malformed version: $VERSION"
[[ -z $EXPECTED || $EXPECTED =~ ^[0-9a-f]{64}$ ]] \
    || fail "--sha256 ожидает 64 шестнадцатеричных символа" "--sha256 expects 64 hex characters"

# --- preflight: unprivileged, x86-64, the tools this script itself needs ---------------
[[ ${EUID:-$(id -u)} -ne 0 ]] || fail \
    "запускайте проверку обычным пользователем: скачанные, ещё не проверенные байты не должны обрабатываться от root; sudo будет запрошен один раз — для установщика" \
    "run the verification as an unprivileged user: downloaded, not yet verified bytes must not be handled as root; sudo is asked once, for the installer"

case $(uname -m) in
    x86_64|amd64) ;;
    *) fail "поддерживается только x86-64, здесь $(uname -m)" "x86-64 only, this host is $(uname -m)" ;;
esac

for tool in curl tar awk; do
    command -v "$tool" >/dev/null 2>&1 || fail "нужен $tool" "$tool is required"
done
if command -v sha256sum >/dev/null 2>&1; then
    SHA256SUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256SUM=(shasum -a 256)
else
    fail "нужен sha256sum" "sha256sum is required"
fi

os_id=; os_version=
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release && printf '%s' "${ID:-}")
    # shellcheck disable=SC1091
    os_version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")
fi
if [[ $os_id != ubuntu || $os_version != 24.04 ]]; then
    say "предупреждение: релиз проверен на Ubuntu 24.04, здесь ${os_id:-?} ${os_version:-?} — аудит установщика решит сам" \
        "warning: the release is verified on Ubuntu 24.04, this host is ${os_id:-?} ${os_version:-?} — the installer's audit decides" >&2
fi
if [[ $MODE == install || $MODE == update ]] && ! command -v sudo >/dev/null 2>&1; then
    fail "нужен sudo для запуска установщика (или --no-wizard)" "sudo is required to start the installer (or use --no-wizard)"
fi

# --- download the four release files ---------------------------------------------------
# `--from-dir` is for a locally reconstructed or separately transferred release
# bundle. It is deliberately not an execution bypass: copied files receive the
# same checksum, manifest, archive-member and optional attestation checks below.
if [[ -n $SOURCE_DIR ]]; then
    [[ -d $SOURCE_DIR ]] || fail "--from-dir не является каталогом" "--from-dir is not a directory"
    SOURCE_DIR=$(cd -- "$SOURCE_DIR" && pwd)
fi
archive_name="proxy-control-v$VERSION.tar.gz"
base="https://github.com/$REPO/releases/download/v$VERSION"
if [[ -z $DESTINATION ]]; then
    DESTINATION=$PWD/proxy-control-v$VERSION
fi
[[ ! -e $DESTINATION ]] || fail "каталог уже существует: $DESTINATION (укажите --dir)" "the directory exists: $DESTINATION (pass --dir)"
mkdir -p -- "$DESTINATION"
chmod 0700 -- "$DESTINATION"
DESTINATION=$(cd -- "$DESTINATION" && pwd)
cd -- "$DESTINATION"

if [[ -n $SOURCE_DIR ]]; then
    say "копирую v$VERSION из проверенного локального каталога" \
        "copying v$VERSION from the verified local directory"
else
    say "скачиваю v$VERSION из https://github.com/$REPO/releases/tag/v$VERSION" \
        "downloading v$VERSION from https://github.com/$REPO/releases/tag/v$VERSION"
fi
for name in "$archive_name" SHA256SUMS release-manifest.json sbom.spdx.json; do
    if [[ -n $SOURCE_DIR ]]; then
        [[ -f $SOURCE_DIR/$name && ! -L $SOURCE_DIR/$name ]] \
            || fail "в --from-dir нет обычного файла $name" "--from-dir lacks a regular $name"
        cp -- "$SOURCE_DIR/$name" "$name" \
            || fail "не удалось скопировать $name из --from-dir" "could not copy $name from --from-dir"
    else
        curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$name" -- "$base/$name" \
            || fail "не удалось скачать $name" "could not download $name"
    fi
    chmod 0600 -- "$name"
done

# --- verify: SHA256SUMS, the manifest, the pinned digest, the attestation --------------
"${SHA256SUM[@]}" --check --strict SHA256SUMS \
    || fail "SHA256SUMS не сходится — не устанавливайте эти файлы" "SHA256SUMS does not match — do not install these files"
actual=$("${SHA256SUM[@]}" -- "$archive_name" | cut -d' ' -f1)
if [[ -n $EXPECTED && $actual != "$EXPECTED" ]]; then
    fail "digest архива $actual ≠ ожидаемому $EXPECTED" "archive digest $actual ≠ expected $EXPECTED"
fi
if [[ -n $EXPECTED ]]; then
    say "digest архива совпал с закреплённым" "the archive digest matches the pinned one"
fi
check_manifest() {
    LC_ALL=C awk -v archive="$archive_name" -v digest="$actual" -v version="$VERSION" '
        NR == 1 { if ($0 != "{") exit 1; next }
        $0 == "}" { if (comma) exit 1; closed=1; next }
        closed { exit 1 }
        { if (count && !comma) exit 1
          if ($0 !~ /^  "[a-z_]+": ("[^"\\]*"|[0-9]+),?$/) exit 1
          comma=($0 ~ /,$/); count++
          line=$0; sub(/^  "/,"",line); key=line; sub(/".*/,"",key)
          if (seen[key]++) exit 1
          sub(/^[^"]*": /,"",line); sub(/,$/,"",line)
          if (line ~ /^"/) { sub(/^"/,"",line); sub(/"$/,"",line) }
          value[key]=line }
        END { if (!closed || value["archive"]!=archive || value["archive_sha256"]!=digest || value["version"]!=version || value["tag"]!="v"version) exit 1 }
    ' release-manifest.json
}
check_manifest \
    || fail "release-manifest.json не описывает этот архив" "release-manifest.json does not describe this archive"

if command -v gh >/dev/null 2>&1; then
    if gh attestation verify "$archive_name" --repo "$REPO" >/dev/null 2>&1; then
        say "attestation GitHub подтверждена" "GitHub attestation verified"
    elif ((REQUIRE_ATTESTATION)); then
        fail "attestation GitHub не подтверждена" "GitHub attestation not verified"
    else
        say "предупреждение: gh не смог подтвердить attestation (нет входа в gh или сети?); архив всё равно совпадает с SHA256SUMS" \
            "warning: gh could not verify the attestation (gh not logged in, no network?); the archive still matches SHA256SUMS" >&2
    fi
elif ((REQUIRE_ATTESTATION)); then
    fail "--attest требует установленного gh" "--attest needs gh installed"
fi

# Do not let tar create a link, device or special file, even from a checksum-valid archive.
tar -tvzf "$archive_name" | LC_ALL=C awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" { bad=1 } END { exit bad }' \
    || fail "архив содержит не обычный файл/каталог" "the archive contains a link or special member"
tar -tzf "$archive_name" | LC_ALL=C awk '
    { if ($0 !~ /^proxy-control\// || $0 ~ /(^|\/)\.\.(\/|$)/ || $0 ~ /[[:cntrl:]]/) bad=1; count++ }
    END { exit bad || !count }
' || fail "архив не прошёл проверку перед распаковкой" "the archive failed its extraction preflight"

say "проверено: $archive_name ($actual)" "verified: $archive_name ($actual)"
if [[ $MODE == check ]]; then
    say "файлы лежат в $DESTINATION; распаковка и установка не выполнялись" \
        "the files are in $DESTINATION; nothing was extracted or installed"
    exit 0
fi

# --- extract and hand over -------------------------------------------------------------
tar -xzf "$archive_name"
root=$DESTINATION/proxy-control
[[ -f $root/install.sh && -f $root/release/release.json ]] \
    || fail "распакованный релиз неполон" "the extracted release is incomplete"

# Canonical release.json records both host binaries. Verify them without running archive code.
rows=$(LC_ALL=C awk '
    /^  "binaries": \{$/ { if (seen++) exit 1; inside=1; next }
    inside && /^  },?$/ { inside=0; done=1; next }
    inside { if ($0 !~ /^    "[a-zA-Z0-9_./-]+": "[0-9a-f]+",?$/) exit 1
             line=$0; sub(/^    "/,"",line); path=line; sub(/".*/,"",path)
             sub(/^[^"]*": "/,"",line); sub(/",?$/,"",line)
             if (length(line)!=64 || paths[path]++) exit 1
             if (path!="installer/bin/linux-amd64/proxy-control-installer" && path!="version_agent/bin/linux-amd64/proxy-control-version-agent") exit 1
             print path " " line; count++ }
    END { if (!done || inside || count!=2) exit 1 }
' "$root/release/release.json") \
    || fail "неверная запись binaries в release.json" "invalid release.json binaries"
count=0
while read -r path expected; do
    [[ -f $root/$path && ! -L $root/$path ]] \
        || fail "нет обычного файла $path" "missing regular binary $path"
    mode=$(stat -c '%a' -- "$root/$path" 2>/dev/null || stat -f '%Lp' -- "$root/$path")
    binary_digest=$("${SHA256SUM[@]}" -- "$root/$path" | cut -d' ' -f1)
    [[ $mode == 755 && $binary_digest == "$expected" ]] \
        || fail "неверные права или digest $path" "binary mode or digest mismatch: $path"
    count=$((count + 1))
done <<< "$rows"
((count == 2)) || fail "неполный набор бинарников" "incomplete host binaries"
say "распаковано в $root" "extracted to $root"

if [[ $MODE == unpack ]]; then
    say "дальше: cd $root && sudo bash install.sh wizard   (или plan --config ... --json без изменений)" \
        "next: cd $root && sudo bash install.sh wizard   (or plan --config ... --json, which changes nothing)"
    exit 0
fi

if [[ $MODE == update ]]; then
    [[ -f $root/scripts/update-host.sh ]] \
        || fail "в этом выпуске нет scripts/update-host.sh (обновление через curl — с v1.1.0)" "this release has no scripts/update-host.sh (curl updates start with v1.1.0)"
    say "обновляю этот хост до v$VERSION от root (sudo): панель через version-agent, затем изменившиеся менеджеры" \
        "updating this host to v$VERSION as root (sudo): the panel through the version-agent, then the changed managers"
    cd -- "$root"
    exec sudo -- bash "$root/scripts/update-host.sh" --version "$VERSION" --sha256 "$actual" --lang "$LANGUAGE"
fi

if (($#)); then
    say "запускаю от root (sudo): proxy-control-installer $*" "starting as root (sudo): proxy-control-installer $*"
else
    say "запускаю мастер установщика от root (sudo); он спросит, покажет план и ничего не применит без подтверждения digest" \
        "starting the installer's wizard as root (sudo); it asks, shows the plan and applies nothing without the digest confirmation"
fi
cd -- "$root"
if (($# == 0)) && ((LANGUAGE_GIVEN)); then
    set -- wizard --lang "$LANGUAGE"
fi
exec sudo -- bash "$root/install.sh" "$@"
