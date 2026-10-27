# Матрица негативных проверок безопасности

Исполняемые привязки «функция → проверка → маршрут» ведутся в
[единой матрице проверок](VERIFICATION_MATRIX.md). Здесь перечислены границы угроз,
а не второй список имён тестов: удалённые unit-тесты Python и Fleet v1 не являются
доказательством работы нативного выпуска. Python HTTP-, CLI- и лабораторные
контроллеры остаются внешними клиентами Rust runtime.

| Граница | Что должно отказываться безопасно | Где искать актуальные доказательства в единой матрице |
| --- | --- | --- |
| HTTP, сессии и API-ключи | Анонимный запрос, неверная роль, CSRF, неверный scope, отключённый или истёкший ключ | Панель, RBAC, аудит и API-ключи; нативный route-gate проверяет зарегистрированные маршруты |
| Секреты и подписки | Отсутствующий мастер-ключ, чужой SecretRef, отозванный токен, раскрытие секрета в БД, логах, ошибках или аудите | Secret store, выдача/ротация/отзыв подписки, renderers и одноразовый reveal |
| Владение ресурсом | Локальная запись в ресурс центра, скрытое присвоение foreign-ресурса, гонка двух писателей | Clients, импорт, жизненный цикл grants, Fleet node и routing |
| Fleet v2 | Чужой master GUID, replay/downgrade, конфликт дайджеста, слишком большой документ, получение чужого credential | Fleet node/central, generations, reconcile и native ↔ archived 3.3 delivery |
| Удалённые источники | Непроверенный TLS, неверный pin, SSRF, запрещённый URL, слишком большой ответ | Fleet linking/client и проверка release artifacts |
| Транзакции и восстановление | Crash между prepare/apply/commit, повтор операции с другим intent, drift при resume, неудачный rollback | Installer transaction, менеджеры и Fleet reconcile |
| Политика маршрутизации | Неизвестный backend, raw Xray JSON вместо intent, неподдерживаемое правило, изменение без attach, stale revision | Routing IR/compiler/service и router policies |
| Xray artifacts и процессы | Несовпадение дайджеста, битые geodata, SIGKILL при swap, смерть дочернего процесса | Router runtime, installer-router, watchdog и last-known-good recovery |
| Ingress, lanes и relay | Неаутентифицированный или кросс-сервисный SOCKS, неверный ключ, неподдерживаемая полоса, обход private-address запрета | Router attach/detach, lanes, chains и relay |
| Недоступный egress | Молчаливый переход на direct, обход management bypass, блокировка доступа оператора | Routing policies и fail-closed проверки менеджеров; `approved_direct` должен быть явным |
| Соседние службы | Изменение чужих путей, Nginx-маршрутов, firewall или Xray 3x-ui | Installer coexistence и router isolation; Xray 3x-ui не является backend панели |
| TrustTunnel и AmneziaWG | Утечка credential, небезопасный сокет, чужое состояние, вход отключённого клиента, конфликт порта/домена | Протокольные адаптеры, native managers и installer adapters |

Fleet v1 agent/ingress и runtime-v2 выведены из эксплуатации. Их прежние проверки
не заявляют активную защиту нативного runtime. Обнаружение установленного состояния,
резервное копирование и явный перенос остаются обязательными:
[контракты совместимости](COMPATIBILITY.md), [обновление](UPGRADING.ru.md),
[резервное копирование](BACKUP_RESTORE.ru.md).

Проверки выполняются на выделенном Ubuntu-стенде `ams-test`, не на рабочем Mac.
Команды и требования к свежим отчётам приведены в [VALIDATION](VALIDATION.md).
Наличие сценария или старая успешная проверка не доказывают текущую ревизию.
Это не защита от компрометации живого процесса центральной панели, которому
по конструкции доступны база и мастер-ключ.
