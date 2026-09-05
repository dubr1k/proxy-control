# Автоматическая установка Proxy Control на Ubuntu 24.04

[English](INSTALL.en.md) · **Русский**

Root-only `install.sh` вызывает транзакционный `scripts/proxyctl.py install`. Поддерживаются команды:

```text
audit → plan → install → repair → uninstall
```

Полный installer разворачивает Telemt/MTProxy и panel. NaiveProxy, Mieru и fleet подключаются отдельно после successful core acceptance.

## Основной путь установки: проверенный релиз

Это поддерживаемый способ установки Proxy Control. Он заменяет ручную
последовательность `scripts/proxyctl.py` ниже, которая остаётся в документации
для уже развёрнутых систем и для разбора того, что делает установщик.

Скачайте архив, его `SHA256SUMS` и `release-manifest.json` со страницы релиза,
затем проверьте provenance **до** того, как что-либо получит привилегии:

```bash installer-check
gh attestation verify proxy-control-v0.1.0.tar.gz --repo dubr1k/proxy-control
sha256sum --check --ignore-missing SHA256SUMS
./install-bootstrap --archive proxy-control-v0.1.0.tar.gz --checksum SHA256SUMS --manifest release-manifest.json
```

Порядок важен: сначала проверяется аттестация, и только потом что-либо
передаётся `sudo`. `install-bootstrap` отказывается работать от root, проверяет,
что каждый вход — обычный файл, принадлежащий вам и не доступный на запись
группе или остальным, сверяет архив с опубликованной контрольной суммой,
требует, чтобы манифест называл тот же архив и тот же digest, отклоняет
prerelease-версию и проверяет архив на абсолютные и выходящие за пределы члены
перед единственным `exec sudo`. Ничто никогда не скачивается и не исполняется
одной командой.

Без дальнейших аргументов установщик запускает двуязычный мастер: он пишет файл
конфигурации, показывает план и ничего не применяет, пока вы не подтвердите
digest плана. Полная поверхность — профили, все поля конфигурации, границы
владения, приёмка по протоколам, WARP и egress, восстановление и отчёты — в
[справочнике установщика](docs/INSTALLER_REFERENCE.ru.md).

Перед установкой профиля с Mieru разместите оба пинованных upstream-пакета для
вашей архитектуры в `/var/lib/proxy-control/`: `mita_3.36.0_<arch>.deb` (сервер)
и `mieru_3.36.0_<arch>.deb` (официальный клиент, который запускает приёмка).
Установщик никогда не скачивает их сам и отказывается продолжать, если digest не
совпадает с пином; URL и digest — в
[`release/external-artifacts.json`](release/external-artifacts.json).

## Требования

- Ubuntu 24.04 + systemd;
- root/sudo;
- DNS A/AAAA для proxy и panel names указывает напрямую на host;
- TCP/80 доступен для ACME HTTP-01;
- public TCP/443 принадлежит существующему Nginx `stream` listener;
- в выбранном route file есть ровно одна понятная `$ssl_preread_server_name` map;
- loopback ports свободны;
- подготовлен внешний executable protocol probe, проверяющий real Fake-TLS/Obfuscated2 `req_pq_multi → resPQ`;
- создан host-level backup Nginx, services и соседних routes.

Cloud/CDN proxy для raw MTProto hostname должен быть отключён (DNS-only). Unhandled AAAA, NAT mismatch, ambiguous Nginx maps и port collisions — hard stops.

Restrictive `umask 077` используйте только внутри secret/backup subshell. До Git clone, Docker build context и APT верните `022`; public ACME roots и `.well-known/acme-challenge` должны иметь mode `0755`. Если сертификат proxy/panel был выпущен до installer, его renewal `webroot_map` должен сразу использовать `/var/www/<proxy-domain>` и `/var/www/<panel-domain>`.

## Внешняя проба MTProto

Приёмка MTProxy выполняется настоящей пробой на TDLib. Собирать и ставить её
руками не нужно: установщик берёт её из каталога `probe/` внутри релиза,
проверяет digest и сам ставит по фиксированному пути
`/usr/local/libexec/mtproxy-respq-probe` с режимом `0750`.

Проба принимает ровно `--domain DOMAIN --secrets-file PATH`, монтирует файл
секретов read-only в `/run/mtproxy/users.conf` и для каждого секрета вызывает
в TDLib `addProxy`, затем `pingProxy`. Отдельные секреты не попадают ни в argv
установщика, ни в argv Docker, ни в историю shell, ни в вывод пробы. У
контейнера read-only корень, отдельный tmpfs под состояние TDLib, сброшенные
capabilities и `no-new-privileges`. Ошибка любого секрета останавливает
установку.

## 1. Аудит и план

Отдельной команды `audit` нет: аудит выполняется внутри `plan`, который ничего
не меняет и печатает и наблюдаемые факты, и полный список предстоящих действий.

Все команды ниже выполняются из распакованного релиза — того каталога, который
напечатал `install-bootstrap`. Из клона Git они не работают: там нет
`release/release.json`, и установщик отказывается работать без идентичности
релиза.

```bash installer-check
python3 -m installer.cli plan --config examples/installer/core.toml --json
```

Вместо примера укажите путь к своему файлу — тому, который написал мастер.

Проверьте в выводе: владельца TCP/443 и топологию Nginx, DNS и CAA по каждому
домену, свободные локальные порты, коллизии идентификаторов, пути проекта,
список пакетов, имена сертификатов и маршруты, которые будут добавлены.

Паролей, токенов, секретов пользователей и ссылок доступа в плане нет и быть не
может.

## 2. Готовность к откату

До установки сохраните:

- выбранный файл маршрутов Nginx и включаемые конфиги с владельцем и режимом;
- `nginx -T` в приватный артефакт;
- активные слушатели и unit-файлы;
- текущее состояние Docker/Compose;
- результаты проверки соседних SNI.

Установщик ведёт собственный журнал владения и точные резервные копии, но это
не замена независимой резервной копии хоста.

## 3. Установка

У плана есть digest, и установка не начнётся, пока вы не подтвердите именно его:

```bash installer-check
sudo python3 -m installer.cli install --config examples/installer/core.toml --accept-plan DIGEST
```

Установщик:

1. ставит только отсутствующие пакеты Ubuntu;
2. выпускает сертификаты по группам служб и сразу проверяет продление
   `certbot renew --dry-run`;
3. создаёт секреты с ограниченным режимом;
4. разворачивает проект Compose `mtproxy`;
5. создаёт первого владельца панели через stdin, не печатая пароль;
6. добавляет только свои маршруты Nginx проверенной транзакцией;
7. дожидается готовности служб и выполняет приёмку каждого протокола.

Он не трогает DNS, WARP, Fleet, чужие контейнеры и чужие маршруты Nginx.
Правилами UFW и 3x-ui он управляет только если вы это выбрали в конфигурации.

## 4. Приёмка

```bash
docker compose -f /opt/mtproxy-shared443/compose.yaml ps
curl -fsS -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
```

Обязательно выполните:

- реальный тест клиентом Telegram;
- вход в панель по HTTPS;
- проверку соседних SNI;
- проверку целостности SQLite и контрольной суммы резервной копии;
- проверку, что Telemt API не опубликован на хосте.

## 5. Состояние, продолжение и repair

```bash installer-check
sudo python3 -m installer.cli status --json
sudo python3 -m installer.cli resume --json
sudo python3 -m installer.cli repair --json
```

`resume` продолжает прерванную установку с сохранённой фазы. `repair` читает
приватный журнал владения `/var/lib/proxy-control/installer/state.json`,
завершает прерванное восстановление, проверяет чужие изменения и перезапускает
только зарегистрированные службы. Обе команды не принимают произвольных путей.

## 6. Удаление

```bash installer-check
sudo python3 -m installer.cli uninstall --json
sudo python3 -m installer.cli uninstall --purge-data --json
```

Удаление фиксирует фазы в журнале, убирает только принадлежащие установщику
маршруты, файлы и пакеты и по умолчанию сохраняет тома Compose, резервную копию
учётных данных, сертификаты и каталоги сайтов-прикрытий до отдельной проверки
владельца. Повторный запуск безопасен; прерванную очистку данных нужно
продолжать тем же `--purge-data`. Используйте этот флаг только после проверки
независимой копии томов.

После удаления снова проверьте `nginx -t`, публичные слушатели и соседние SNI.

## Отказ и прерванный SSH

Код выхода SSH `255` доказывает только обрыв связи. На целевом хосте проверьте
`sudo python3 -m installer.cli status --json`, фазу, принадлежащие установщику
файлы, службы и результат приёмки. Не запускайте установку повторно вслепую.

## Следующие интеграции

После core acceptance:

- [Panel и NaiveProxy](PANEL.ru.md)
- [Mieru/mita](MIERU.ru.md)
- [Fleet mTLS](FLEET.ru.md)

Подробности transactions и hard stops: [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md). Эксплуатация: [docs/OPERATIONS.ru.md](docs/OPERATIONS.ru.md), [backup](docs/BACKUP_RESTORE.ru.md), [validation](docs/VALIDATION.md).
