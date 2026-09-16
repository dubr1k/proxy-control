#!/usr/bin/env bash
# Fetch, verify and unpack one Proxy Control release, then hand it to the installer.
#
# `install-bootstrap` (inside every archive) refuses a pre-release suffix, so a beta is
# installed by the four documented steps (README, «Бета-выпуски» / «Beta releases»):
# download the four release files, `sha256sum --check SHA256SUMS`, extract, and run
# `sudo python3 -m installer.cli wizard` from the extracted tree. This script performs
# exactly those steps for any tag and stops at the first failed check. It never pipes a
# download into a shell: the files land on disk, the payload is checked against
# SHA256SUMS, the manifest must name the same archive and digest, the digest may be pinned
# (`--sha256`, the `lab-sha256` of the tag annotation) and, when `gh` is present, the
# GitHub build-provenance attestation is verified too. Everything before the installer
# runs unprivileged; `sudo` is asked once, for the installer itself — the same rule
# `install-bootstrap` follows.
#
#   scripts/install-release.sh --requirements            # what is needed and what gets installed
#   scripts/install-release.sh --version 0.4.0-beta.1 --sha256 <lab-sha256>
#   scripts/install-release.sh --version 0.4.0-beta.1 --no-wizard
#   scripts/install-release.sh --version 0.4.0-beta.1 -- plan --config install.toml --json
set -Eeuo pipefail

REPO=${PROXY_CONTROL_REPO:-dubr1k/proxy-control}
VERSION=
EXPECTED=
DESTINATION=
LANGUAGE=
MODE=install   # install | check | unpack | requirements
REQUIRE_ATTESTATION=0
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

usage() {
    cat >&2 <<'USAGE'
usage: scripts/install-release.sh [--version X.Y.Z[-beta.N]] [--sha256 DIGEST] [--dir DIR]
                                  [--lang ru|en] [--requirements | --check-only | --no-wizard]
                                  [--attest] [-- INSTALLER ARGS...]

  --version       release to fetch (default: the VERSION file beside this script's tree)
  --sha256        pin the archive digest — the `lab-sha256` of the tag annotation
                  or the digest in the release note; a different archive is refused
  --dir           where to download and extract (default: ./proxy-control-vX.Y.Z; must be new)
  --lang          language of the messages (default: from $LANG, ru or en)
  --requirements  print what the host needs and what the installer sets up, then exit
  --check-only    download and verify only; extract nothing, install nothing
  --no-wizard     download, verify and extract; print the next command instead of running it
  --attest        require `gh attestation verify` to pass (default: verify when gh exists)
  --              everything after it goes to `python3 -m installer.cli` (default: wizard)
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
        --lang) LANGUAGE=${2:?}; shift 2 ;;
        --requirements) MODE=requirements; shift ;;
        --check-only) MODE=check; shift ;;
        --no-wizard) MODE=unpack; shift ;;
        --attest) REQUIRE_ATTESTATION=1; shift ;;
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
  • Python 3.11+ (в Ubuntu 24.04 — 3.12) для установщика; curl, tar, sha256sum — для
    этого скрипта.
  • Свободные TCP/443 и TCP/80 в режиме `fresh`; в режиме `coexist` — ваш Nginx
    со `stream` уже владеет 443 и имеет ровно одну карту `$ssl_preread_server_name`.
  • Публичный IPv4 без NAT; для домена MTProxy проксирование CDN выключено (DNS-only).

Домены и DNS
  • Домен панели и домен MTProxy — всегда; домен NaiveProxy — в профилях с Naive;
    домен Mieru — в профилях с Mieru (сертификат ему не нужен); необязательный
    домен подписки; в режиме 3x-ui — ещё четыре домена.
  • Записи A ведут на этот сервер, AAAA либо нет, либо тоже на него; CAA не
    запрещает Let's Encrypt. Сертификаты выпускаются через HTTP-01 на порту 80.

Для профилей с Mieru — заранее, установщик ничего не скачивает сам:
  • /var/lib/proxy-control/mita_3.36.0_amd64.deb и mieru_3.36.0_amd64.deb
    (URL и SHA-256 — в release/external-artifacts.json распакованного релиза).

WARP (необязательно): секция [egress] в install.toml или вопросы мастера —
  установщик ставит закреплённый клиент Cloudflare WARP в proxy-режиме на
  127.0.0.1:40000 и задаёт начальный egress NaiveProxy/Mieru; дальше им владеет
  экран «Маршрутизация» панели (v0.4).

Xray-router (необязательно, v0.5): [egress] router = true — выделенный Xray для
  политик с geosite/geoip/портами и блокировками рядом с WARP. Заранее положите
  • /var/lib/proxy-control/Xray-linux-64.zip (Xray-core 26.3.27; URL и SHA-256 — в
    release/external-artifacts.json). Мастер спрашивает про роутер, только если архив есть.

Что делает установщик (мастер → план → подтверждение digest → применение):
  • Пакеты Ubuntu, которых нет на хосте: ca-certificates certbot curl
    docker-compose-v2 docker.io nginx-full openssl python3 — и только они
    попадают под его владение.
  • Сертификаты Let's Encrypt (certbot, webroot) и проверка продления сразу.
  • Nginx: свой блок SNI-маршрутов на общем 443 и TLS-vhost панели; чужие
    маршруты не трогает, при неоднозначной конфигурации останавливается.
  • Compose-проект `mtproxy` в /opt/mtproxy-shared443: контейнеры
    proxy-control-panel, -mtproxy (Telemt), -mask, а по профилю -naive-manager и
    -mieru-manager; тома, секреты (secrets/), мастер-ключ панели.
  • Host-службы по профилю: caddy-naive.service (NaiveProxy) и mita.service (Mieru).
  • Правила UFW — только если вы это разрешили и только на свежем хосте.
  • 3x-ui — в режиме `existing` только маршрут, в `managed-new` — свой экземпляр.
  • Журнал транзакции, владение и отчёты — /var/lib/proxy-control/.
Каждый шаг журналируется и откатывается; прерванную установку продолжает
`python3 -m installer.cli resume`. Ничего не меняется до подтверждения digest плана.
TEXT
    else
        cat <<'TEXT'
Proxy Control — what an install needs

Server
  • x86-64 (amd64): the installer rejects any other architecture at audit time —
    the release is built and lab-tested for x86-64 only.
  • Ubuntu 24.04 LTS with systemd; log in as a regular user with `sudo` (the archive
    is verified unprivileged; root is needed by the installer alone).
  • Python 3.11+ (Ubuntu 24.04 ships 3.12) for the installer; curl, tar, sha256sum —
    for this script.
  • Free TCP/443 and TCP/80 in `fresh` mode; in `coexist` mode your Nginx `stream`
    already owns 443 and has exactly one `$ssl_preread_server_name` map.
  • A public IPv4 without NAT; CDN proxying switched off for the MTProxy domain.

Domains and DNS
  • The panel domain and the MTProxy domain — always; a NaiveProxy domain in the
    Naive profiles; a Mieru domain in the Mieru profiles (no certificate needed);
    an optional subscription domain; four more domains in the 3x-ui modes.
  • A records point at this server, AAAA either absent or also this server; CAA
    does not forbid Let's Encrypt. Certificates are issued over HTTP-01 on port 80.

For the Mieru profiles — in advance, the installer never downloads on your behalf:
  • /var/lib/proxy-control/mita_3.36.0_amd64.deb and mieru_3.36.0_amd64.deb
    (URLs and SHA-256 in release/external-artifacts.json of the extracted release).

WARP (optional): the [egress] section of install.toml or the wizard's questions —
  the installer sets up the pinned Cloudflare WARP client in proxy mode on
  127.0.0.1:40000 and seeds the initial egress of NaiveProxy/Mieru; from then on
  the panel's «Routing» screen owns it (v0.4).

Xray-router (optional, v0.5): [egress] router = true — a dedicated Xray for
  policies with geosite/geoip/ports and blocks beside WARP. Stage in advance
  • /var/lib/proxy-control/Xray-linux-64.zip (Xray-core 26.3.27; URL and SHA-256 in
    release/external-artifacts.json). The wizard asks about the router only when it is there.

What the installer does (wizard → plan → digest confirmation → apply):
  • Ubuntu packages missing on the host: ca-certificates certbot curl
    docker-compose-v2 docker.io nginx-full openssl python3 — only those come
    under its ownership.
  • Let's Encrypt certificates (certbot, webroot) with a renewal dry-run right away.
  • Nginx: its own SNI-route block on the shared 443 and the panel's TLS vhost;
    foreign routes stay untouched, an ambiguous configuration is a hard stop.
  • The Compose project `mtproxy` in /opt/mtproxy-shared443: the containers
    proxy-control-panel, -mtproxy (Telemt), -mask and, per profile, -naive-manager
    and -mieru-manager; volumes, secrets (secrets/), the panel's master key.
  • Host services per profile: caddy-naive.service (NaiveProxy), mita.service (Mieru).
  • UFW rules — only when you allow it and only on a fresh host.
  • 3x-ui — a route only in `existing` mode, its own instance in `managed-new`.
  • The transaction journal, ownership and reports — /var/lib/proxy-control/.
Every step is journaled and reversible; an interrupted install continues with
`python3 -m installer.cli resume`. Nothing changes before the plan digest is confirmed.
TEXT
    fi
}

if [[ $MODE == requirements ]]; then
    requirements
    exit 0
fi

if [[ -z $VERSION && -f $SCRIPT_DIR/../VERSION ]]; then
    VERSION=$(tr -d '[:space:]' < "$SCRIPT_DIR/../VERSION")
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

for tool in curl tar python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "нужен $tool" "$tool is required"
done
if command -v sha256sum >/dev/null 2>&1; then
    SHA256SUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256SUM=(shasum -a 256)
else
    fail "нужен sha256sum" "sha256sum is required"
fi
python3 -c 'import tomllib' 2>/dev/null \
    || fail "установщику нужен Python 3.11 или новее (tomllib)" "the installer needs Python 3.11 or newer (tomllib)"

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
if [[ $MODE == install ]] && ! command -v sudo >/dev/null 2>&1; then
    fail "нужен sudo для запуска установщика (или --no-wizard)" "sudo is required to start the installer (or use --no-wizard)"
fi

# --- download the four release files ---------------------------------------------------
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

say "скачиваю v$VERSION из https://github.com/$REPO/releases/tag/v$VERSION" \
    "downloading v$VERSION from https://github.com/$REPO/releases/tag/v$VERSION"
for name in "$archive_name" SHA256SUMS release-manifest.json sbom.spdx.json; do
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$name" -- "$base/$name" \
        || fail "не удалось скачать $name" "could not download $name"
    chmod 0600 -- "$name"
done

# --- verify: SHA256SUMS, the manifest, the pinned digest, the attestation --------------
"${SHA256SUM[@]}" --check --strict SHA256SUMS \
    || fail "SHA256SUMS не сходится — не устанавливайте эти файлы" "SHA256SUMS does not match — do not install these files"
actual=$("${SHA256SUM[@]}" -- "$archive_name" | cut -d' ' -f1)
if [[ -n $EXPECTED && $actual != "$EXPECTED" ]]; then
    fail "digest архива $actual ≠ ожидаемому $EXPECTED" "archive digest $actual ≠ expected $EXPECTED"
fi
check_manifest() {
    python3 - release-manifest.json "$archive_name" "$actual" "$VERSION" <<'PYEOF'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
if manifest.get("archive") != sys.argv[2]:
    raise SystemExit("the manifest names a different archive")
if manifest.get("archive_sha256") != sys.argv[3]:
    raise SystemExit("the manifest records a different archive digest")
if str(manifest.get("version", "")) != sys.argv[4] or manifest.get("tag") != f"v{sys.argv[4]}":
    raise SystemExit("the manifest version or tag disagrees with the requested release")
PYEOF
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

tar -tzf "$archive_name" | python3 -c '
import sys
for line in sys.stdin:
    name = line.rstrip("\n")
    if name.startswith("/") or ".." in name.split("/"):
        raise SystemExit(f"unsafe member in the release archive: {name}")
    if not name.startswith("proxy-control/"):
        raise SystemExit(f"member outside the release prefix: {name}")
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
say "распаковано в $root" "extracted to $root"

if [[ $MODE == unpack ]]; then
    say "дальше: cd $root && sudo python3 -m installer.cli wizard   (или plan --config ... --json без изменений)" \
        "next: cd $root && sudo python3 -m installer.cli wizard   (or plan --config ... --json, which changes nothing)"
    exit 0
fi

if (($#)); then
    say "запускаю от root (sudo): python3 -m installer.cli $*" "starting as root (sudo): python3 -m installer.cli $*"
else
    say "запускаю мастер установщика от root (sudo); он спросит, покажет план и ничего не применит без подтверждения digest" \
        "starting the installer's wizard as root (sudo); it asks, shows the plan and applies nothing without the digest confirmation"
fi
cd -- "$root"
exec sudo -- bash "$root/install.sh" "$@"
