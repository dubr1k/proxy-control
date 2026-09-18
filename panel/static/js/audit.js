import { date, esc, query, serialise } from "./common.js";
import { isCurrent } from "./state.js";

const ACTION_NAMES = {
  "auth.login": "Вход в панель",
  "auth.logout": "Выход",
  "user.create": "Создан доступ",
  "user.access": "Открыта ссылка",
  "user.enable": "Доступ включён",
  "user.disable": "Доступ заблокирован",
  "user.rotate": "Ключ обновлён",
  "user.delete": "Доступ удалён",
  "user.limits": "Изменены лимиты",
  "user.reset_quota": "Сброшен счётчик квоты",
  "naive.create": "Создан Naive-доступ",
  "naive.access": "Открыта Naive-конфигурация",
  "naive.enable": "Naive-доступ включён",
  "naive.disable": "Naive-доступ отключён",
  "naive.rotate": "Naive-пароль обновлён",
  "naive.delete": "Naive-доступ удалён",
  "naive.quota": "Изменена Naive-квота",
  "naive.traffic.reset": "Сброшен Naive-счётчик",
  "mieru.create": "Создан Mieru-доступ",
  "mieru.quotas": "Изменена квота Mieru",
  "mieru.enable": "Mieru-доступ включён",
  "mieru.disable": "Mieru-доступ отключён",
  "mieru.rotate": "Mieru-ссылка обновлена",
  "mieru.delete": "Mieru-доступ удалён",
  "mieru.metrics.baseline": "Сброшен Mieru-счётчик",
  "fleet.node.create": "Добавлен Fleet-узел",
  "fleet.command.queue": "Команда Fleet поставлена в очередь",
  "runtime.version.update": "Обновлена версия компонента",
  "admin.create": "Создан администратор",
  "admin.update": "Изменён администратор",
  "admin.delete": "Удалён администратор",
  // v0.3+: every name from docs/AUDIT_EVENTS.md has a label here (a test keeps the two in step),
  // so the journal never falls back to a raw code for an action the panel itself performs.
  "api_key.create": "Создан API-ключ",
  "api_key.enable": "API-ключ включён",
  "api_key.disable": "API-ключ выключен",
  "api_key.delete": "API-ключ удалён",
  "client.create": "Создан клиент",
  "client.active": "Клиент активен",
  "client.suspended": "Клиент приостановлен",
  "client.archived": "Клиент в архиве",
  "client.import": "Импорт существующих пользователей",
  "grant.provision.start": "Выдача доступов начата",
  "grant.provision.succeeded": "Доступы выданы",
  "grant.provision.compensated": "Выдача доступов откачена",
  "grant.provision.manual_intervention_required": "Выдача доступов требует вмешательства",
  "grant.enable": "Доступ клиента включён",
  "grant.disable": "Доступ клиента выключен",
  "grant.rotate": "Доступ клиента ротирован",
  "grant.delete": "Доступ клиента удалён",
  "grant.adopt_on_write": "Доступ подхвачен из runtime",
  "grant.credential.capture": "Доступ принят",
  "grant.credential.adopt": "Доступ принят с ротацией",
  "subscription.create": "Создана подписка",
  "subscription.rotate": "Подписка ротирована",
  "subscription.revoke": "Подписка отозвана",
  "subscription.fetched": "Подписка загружена клиентом",
  "subscription.revoked": "Подписка перестала отвечать",
  "subscription.generation.changed": "Состав подписки изменён",
  "node.up": "Узел на связи",
  "node.down": "Узел не отвечает",
  "node.register": "Зарегистрирован узел v1",
  "node.rename": "Узел переименован",
  "node.enable": "Узел включён",
  "node.disable": "Узел отключён",
  "node.certificates.revoke_all": "Отозваны сертификаты узла",
  "node.link": "Панель подключена",
  "node.link.update": "Связь с панелью изменена",
  "node.pause": "Связь с панелью на паузе",
  "node.resume": "Связь с панелью возобновлена",
  "node.import": "Импорт пользователей с панели",
  "node.version.update": "Обновление версии на панели",
  "node.unlink": "Панель удалена",
  "routing.policy.update": "Политика маршрутизации сохранена",
  "routing.policy.apply": "Применение политики маршрутизации",
  "routing.policy.rollback": "Откат политики маршрутизации",
  "routing.policy.delete": "Политика маршрутизации удалена",
  "routing.target.attach": "Сервис подключён к Xray-router",
  "routing.target.detach": "Сервис отключён от Xray-router",
  "grant.lane.enable": "Клиенту выдана своя полоса",
  "grant.lane.disable": "Клиент возвращён в полосу сервиса",
  "routing.relay.enable": "Relay узла включён",
  "routing.relay.rotate": "Учётки relay перевыпущены",
  "routing.geodata.settings": "Настройки geodata роутера изменены",
  "routing.geodata.update": "Списки geodata роутера обновлены",
  "routing.geodata.restore": "Списки geodata роутера возвращены к пину",
  "fleet.geodata.settings": "Центр изменил настройки geodata",
  "fleet.geodata.update": "Центр обновил списки geodata",
  "fleet.geodata.restore": "Центр вернул списки geodata к пину",
  "fleet.generation.accept": "Принято поколение центра",
  "fleet.credentials.capture": "Центр запросил учётные данные",
  "fleet.unlink": "Связь с центром разорвана",
};

function auditQuery(audit, beforeId = null) {
  const parameters = new URLSearchParams({ limit: "50" });
  if (audit.actor) parameters.set("actor", audit.actor);
  if (audit.action) parameters.set("action", audit.action);
  if (audit.target) parameters.set("target", audit.target);
  if (beforeId != null) parameters.set("before_id", String(beforeId));
  return parameters;
}

function auditBody(item) {
  const ip = item.ip ?? item.ip_address ?? item.remote_ip;
  const detail = item.detail ?? {};
  const hasDetail = detail && typeof detail === "object" && Object.keys(detail).length > 0;
  if (!ip && !hasDetail) return "";
  return `<div class="audit-body"><dl><dt>IP</dt><dd>${esc(ip || "не зафиксирован")}</dd></dl>${hasDetail ? `<pre>${esc(serialise(detail))}</pre>` : ""}</div>`;
}

// One line per entry. The whole line is the <summary> of a <details>, so «Детали и IP» sits
// at the end of the same line and the body opens underneath at full width; an entry with
// nothing to disclose renders the same line without a toggle.
function auditRow(item) {
  const body = auditBody(item);
  const cells = `<time datetime="${esc(item.happened_at || "")}">${date(item.happened_at)}</time><b>${esc(item.actor_username || "system")}</b><span class="audit-action">${esc(ACTION_NAMES[item.action] || item.action || "—")}</span><span class="audit-target">${esc(item.target || "—")}</span>`;
  if (!body) return `<article class="audit-row"><div class="audit-main">${cells}<span class="audit-toggle audit-toggle-none"></span></div></article>`;
  return `<details class="audit-row"><summary class="audit-main">${cells}<span class="audit-toggle">Детали и IP</span></summary>${body}</details>`;
}

function auditMarkup(context) {
  const { audit } = context.state;
  const hasMore = audit.nextCursor !== null && audit.nextCursor !== undefined && audit.nextCursor !== "";
  return `<section class="audit-view">
    <form id="audit-filter-form" class="audit-filters">
      <label>Исполнитель<input id="audit-actor" name="actor" value="${esc(audit.actor)}" maxlength="64" autocomplete="off" placeholder="например, owner"></label>
      <label>Действие<input id="audit-action" name="action" value="${esc(audit.action)}" maxlength="128" autocomplete="off" placeholder="например, user.create"></label>
      <label>Цель<input id="audit-target" name="target" value="${esc(audit.target)}" maxlength="128" autocomplete="off" placeholder="например, alice"></label>
      <div class="audit-filter-actions"><button class="secondary" type="button" data-audit-action="clear">Очистить</button><button class="primary" type="submit">Применить</button></div>
    </form>
    <section class="data-panel"><div class="panel-head"><h2>Журнал действий</h2><span>${audit.items.length ? `Показано ${audit.items.length}` : "Нет записей"}</span></div><div class="audit-list">${audit.items.length ? audit.items.map(auditRow).join("") : '<div class="empty-state"><span>≡</span><h3>Журнал пока пуст</h3><p>Здесь появятся действия администраторов.</p></div>'}</div>${hasMore ? '<footer class="audit-load-more"><button class="secondary" type="button" data-audit-action="more">Загрузить ещё</button></footer>' : ""}</section>
  </section>`;
}

async function loadAudit(context, generation, { append = false } = {}) {
  const audit = context.state.audit;
  const beforeId = append ? audit.nextCursor : null;
  const data = await context.api(`/api/audit?${auditQuery(audit, beforeId)}`);
  if (!isCurrent(context.state, generation, "audit")) return false;
  const items = data.items || [];
  audit.items = append ? [...audit.items, ...items] : items;
  audit.nextCursor = data.next_cursor ?? null;
  return true;
}

export async function renderAudit(context, generation) {
  await loadAudit(context, generation);
  if (!isCurrent(context.state, generation, "audit")) return;
  context.ui.view.innerHTML = auditMarkup(context);
}

async function applyFilters(context, form) {
  const { audit } = context.state;
  audit.actor = query("#audit-actor", form).value.trim();
  audit.action = query("#audit-action", form).value.trim();
  audit.target = query("#audit-target", form).value.trim();
  audit.items = [];
  audit.nextCursor = null;
  await context.navigate("audit");
}

export function handleAuditSubmit(context, form) {
  if (form.id !== "audit-filter-form") return false;
  void applyFilters(context, form).catch((error) => context.ui.toast(error.message, "error"));
  return true;
}

export function handleAuditClick(context, button) {
  if (button.dataset.auditAction === "clear") {
    context.state.audit = { items: [], nextCursor: null, actor: "", action: "", target: "" };
    void context.navigate("audit");
    return true;
  }
  if (button.dataset.auditAction === "more") {
    void (async () => {
      try {
        context.ui.setBusy(button, true, "Загружаем…");
        const generation = context.state.navigationGeneration;
        if (await loadAudit(context, generation, { append: true })) context.ui.view.innerHTML = auditMarkup(context);
      } catch (error) {
        context.ui.toast(error.message, "error");
      } finally {
        context.ui.setBusy(button, false);
      }
    })();
    return true;
  }
  return false;
}
