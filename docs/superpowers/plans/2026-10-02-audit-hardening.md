# Исправления по аудиту v1.1.0

**Goal:** устранить подтверждённые дефекты аудита 2026-10-02 и проверить поведение на ams-test и AMS_Z.
**Architecture:** сохранить существующие адаптеры и журналирование; единое effective state для доступа; остановка писателей перед восстановлением SQLite; проверка адреса Fleet при соединении; ограниченные ресурсы запросов.
**Tech stack:** Python, FastAPI/Starlette, SQLite, Docker Compose, Nginx, pytest.
**Spec:** аудит исходного 046b60b, сохранённый в `/tmp/proxy-control-audit-2026-10-02/AUDIT.txt`.
**Global constraints:** тесты только на ams-test; перед изменением работающей установки — backup; секреты не выводить; свежая установка и обновление должны совпадать; публикация выпуска не запрошена.
**Review focus:** реальные изменения runtime, переход времени без запроса UI, недоступный узел, остановка писателей при rollback, DNS rebinding, сохранение TLS hostname и транзакций.

## Последовательность

- [ ] Доступы: регрессионные тесты suspension и временного окна в `panel/tests`; исправления `clients/service.py`, `provisioning.py`, lifecycle, `fleet_v2/generations.py`, `reconcile.py`, `pusher.py`. Проверить disable/readback, resume отдельно отключённых grants, наступление deadline и restart/offline.
- [ ] Обновление: тесты `tests/test_version_agent_panel.py`, реальный SQLite writer; остановить писателей до восстановления в `version_agent/service.py`; включить MCP в sync/rebuild/rollback и `scripts/update-host.sh`, обновить документацию.
- [ ] Сеть: регрессии Fleet DNS и ingress; исправить `fleet_v2/client.py`, `links.py`, `installer/adapters/{core,nginx}.py`, связанные примеры и документацию. Проверить доверенную передачу IP без изменения чужих SNI.
- [ ] Ресурсы: проверить close/commit/rollback соединений в `panel/database.py`; ограничить чтение body до накопления сверх лимита в `panel/web_context.py`; проверить chunked и Content-Length.
- [ ] Зависимости: подобрать совместимые исправленные FastAPI/Starlette по официальным advisories, обновить все применимые pins; проверить разрешение зависимостей и сканирование.
- [ ] Масштабирование: устранить N+1 списка клиентов, ограничить выборку и согласовать UI/API; ограничить конкурентность Fleet без нарушения жизненного цикла соединений.
- [ ] CI и документы: добавить недостающие Compose/JS/dependency проверки; исправить устаревшие утверждения и пример master-key-verify.
- [ ] Интеграция: targeted red/green для каждого изменения, независимое ревью, полный remote-gate, сборка образов и воспроизводимого архива, актуальный lab-host.
- [ ] Живые проверки: backup, обновление одной границы, проверки health/DB/runtime/rollback на ams-test, затем AMS_Z; фиксировать точные результаты и ограничения.

## Исходные доказательства

046b60b: 2656 passed, 2 skipped; ruff, unittest (35), docs, JS, bash, shellcheck прошли. Systemd verify неполон из-за отсутствующих путей отдельных unit-файлов. Девять Compose-моделей валидны. Оба стенда v1.1.0, контейнеры healthy, SQLite integrity ok. Эти результаты не заменяют проверки изменённого кода.
