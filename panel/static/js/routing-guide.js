// «Как это работает» (v0.17, owner: «удобная маршрутизация… прям на сайте детальная
// инструкция»): the words the routing screen speaks instead of capability codes, and the
// built-in guide with step-by-step scenarios. Each scenario's «Начать» button changes the
// draft or opens the rule editor; nothing reaches a node before «Сохранить» and «Применить».
import { esc } from "./common.js";

// What a backend capability means for the operator, in the order an operator thinks of it.
export const CAPABILITY_TEXT = {
  whole_direct: "весь трафик напрямую",
  whole_warp: "весь трафик через WARP",
  block_domain: "блокировать домены",
  block_cidr: "блокировать IP и сети",
  selective_domain: "отдельные домены — в другой выход",
  selective_cidr: "отдельные IP и сети — в другой выход",
  block_geosite: "блокировать списки сайтов (geosite)",
  selective_geosite: "списки сайтов (geosite) — в другой выход",
  block_geoip: "блокировать страны и сети (geoip)",
  selective_geoip: "страны и сети (geoip) — в другой выход",
  block_port: "блокировать порты",
  selective_port: "порты — в другой выход",
  block_protocol: "блокировать протоколы (например, торренты)",
  selective_protocol: "протоколы — в другой выход",
  chains: "выход через другой узел (цепь)",
  custom_exits: "свои выходы: VLESS, Trojan, Shadowsocks, SOCKS5, HTTP",
  lanes: "свой маршрут для отдельного клиента",
  relay: "принимать цепи от других узлов",
  geodata: "обновляемые списки geosite и geoip",
};

export function capabilityList(codes) {
  const known = (codes || []).filter((code) => CAPABILITY_TEXT[code]);
  const order = Object.keys(CAPABILITY_TEXT);
  known.sort((left, right) => order.indexOf(left) - order.indexOf(right));
  const unknown = (codes || []).filter((code) => !CAPABILITY_TEXT[code]);
  return [...known.map((code) => CAPABILITY_TEXT[code]), ...unknown];
}

// Scenario ids the screen knows how to start; `needs` is the capability without which the
// scenario is offered with a note instead of a button.
export const SCENARIOS = [
  {
    id: "warp-all",
    title: "Весь трафик сервиса через WARP",
    why: "Сайты видят IP Cloudflare, а не IP сервера. Полезно, если адрес сервера где-то заблокирован или помечен.",
    needs: "whole_warp",
    steps: ["«По умолчанию» → «Через выход», «Куда» → WARP.", "«При недоступности WARP»: «отказать» — трафик не утечёт напрямую; «напрямую» — клиенты не останутся без связи.", "«Сохранить», посмотреть проверку, «Применить»."],
  },
  {
    id: "sites-warp",
    title: "Отдельные сайты через WARP, остальное напрямую",
    why: "Например, ChatGPT, Claude, YouTube или сайты, которые не открываются с IP сервера.",
    needs: "selective_domain",
    steps: ["«Добавить правило» → «Действие»: «Через выход», «Куда»: WARP.", "В «Домены» — адреса через запятую: openai.com, chatgpt.com, claude.ai. Поддомены входят сами.", "На Xray-router можно взять готовый список: geosite `openai`, `youtube`, `google`.", "«Готово» → «Сохранить» → «Применить»."],
  },
  {
    id: "block-ads",
    title: "Заблокировать рекламу и трекеры",
    why: "Меньше трафика и рекламы у всех клиентов сервиса сразу.",
    needs: "block_geosite",
    steps: ["В «Быстрых настройках» включить «Реклама → блок» (список geosite `category-ads-all`).", "«Сохранить» → «Применить»."],
  },
  {
    id: "block-torrent",
    title: "Заблокировать торренты",
    why: "Жалобы правообладателей приходят на IP сервера — торренты лучше не пускать.",
    needs: "block_protocol",
    steps: ["В «Быстрых настройках» включить «Торренты → блок».", "«Сохранить» → «Применить»."],
  },
  {
    id: "ru-direct",
    title: "Российские сайты напрямую",
    why: "Если по умолчанию трафик идёт через WARP или другой узел, российские сайты откроются быстрее и без капчи.",
    needs: "selective_geosite",
    steps: ["В «Быстрых настройках» включить «Российские домены и IP → напрямую».", "«Сохранить» → «Применить»."],
  },
  {
    id: "chain",
    title: "Выход через другой узел",
    why: "Клиент подключается к этому серверу, а в интернет выходит с IP другого узла парка.",
    needs: "chains",
    steps: ["На узле-выходе в «Возможностях узла» включить relay.", "Здесь: «По умолчанию» (или правило) → «Через выход» → «→ имя узла».", "«Сохранить» → «Применить». Проверка покажет, если relay ещё не готов."],
  },
  {
    id: "custom-exit",
    title: "Свой выход: VPN или прокси",
    why: "Чужой VLESS/Trojan/Shadowsocks/SOCKS5/HTTP-сервер как выход для всего сервиса или отдельных сайтов.",
    needs: "custom_exits",
    steps: ["«Возможности узла» → «Свои выходы» → «+ Выход»: форма или ссылка vless://, trojan://, ss://.", "«Проверить» у выхода — панель пустит через него пробный запрос.", "Выход появится в «Куда» у правил и «По умолчанию»."],
  },
  {
    id: "lane",
    title: "Отдельный маршрут одному клиенту",
    why: "Например, одному клиенту — весь трафик через WARP, остальным — напрямую.",
    needs: "lanes",
    steps: ["Шаг 1 → «Добавить полосу для клиента…» и выбрать его доступ.", "Настроить полосу так же, как сервис: «По умолчанию» и правила.", "«Сохранить» → «Применить». Ссылка Mieru клиента при этом изменится — выдайте её заново."],
  },
];

function scenarioBlock(scenario, capabilities, available) {
  const can = capabilities.includes(scenario.needs);
  const button = can && available
    ? `<button type="button" class="secondary" data-routing-action="scenario" data-scenario="${esc(scenario.id)}">Начать</button>`
    : `<small class="routing-guide-na">${can ? "откройте экран на сервисе, где это доступно" : "этот сервис так не умеет — нужен Xray-router узла (шаг «Возможности узла»)"}</small>`;
  return `<article class="routing-guide-scenario" data-scenario-id="${esc(scenario.id)}">
    <header><b>${esc(scenario.title)}</b>${button}</header>
    <p>${esc(scenario.why)}</p>
    <ol>${scenario.steps.map((step) => `<li>${esc(step).replace(/\x60([^\x60]+)\x60/g, "<code>$1</code>")}</li>`).join("")}</ol>
  </article>`;
}

// The guide itself: what the screen is, its words, what each service can do, scenarios,
// saving versus applying, and what to do when the check refuses.
export function guideHtml(target) {
  const capabilities = target?.capabilities || [];
  const service = target ? `${esc(target.protocolName || target.protocol)} на узле «${esc(target.node_name || target.node_id)}»` : "выбранный сервис";
  return `
  <section><h3>Что это за экран</h3>
    <p>Здесь решается, <b>куда сервис выпускает трафик клиентов</b>: напрямую с IP сервера, через WARP (Cloudflare), через другой узел парка, через ваш собственный выход — или блокирует его. Настройка делается отдельно для каждого сервиса (MTProxy, NaiveProxy, Mieru) на каждом узле.</p>
    <p>У сервиса одна <b>политика</b>: выход <b>по умолчанию</b> и список <b>правил-исключений</b>. Правила читаются сверху вниз, срабатывает первое подходящее; всё, что не попало ни в одно правило, идёт «по умолчанию».</p>
    <p>Сейчас открыт ${service}. Он умеет: ${esc(capabilityList(capabilities).join(", ") || "—")}.</p>
  </section>
  <section><h3>Слова на экране</h3>
    <dl class="routing-guide-terms">
      <dt>Выход</dt><dd>Куда уходит трафик: «Напрямую» (IP сервера), «WARP», «→ другой узел» (цепь), свой выход или «Блок».</dd>
      <dt>По умолчанию</dt><dd>Выход для всего, что не описано правилами.</dd>
      <dt>При недоступности WARP</dt><dd>«отказать» — соединение не пройдёт, но и не утечёт напрямую; «напрямую» — клиент останется со связью, но с IP сервера.</dd>
      <dt>Правило</dt><dd>«Что» (домены, IP и сети, списки geosite/geoip, порты, протоколы) и «Куда». Поддомены входят в домен сами.</dd>
      <dt>geosite / geoip</dt><dd>Готовые списки: geosite — сайты по теме (youtube, openai, category-ads-all), geoip — адреса стран и сетей (ru, cloudflare). Работают только через Xray-router узла.</dd>
      <dt>Быстрые настройки</dt><dd>Готовые правила одним переключателем: реклама, торренты, российские сайты напрямую.</dd>
      <dt>Полоса</dt><dd>Свой маршрут для отдельного доступа клиента: его трафик живёт по своей политике, остальные — по политике сервиса.</dd>
      <dt>Xray-router</dt><dd>Маршрутизатор узла. Сервис, подключённый к нему, умеет всё: списки, порты, протоколы, цепи, свои выходы и полосы.</dd>
      <dt>Relay</dt><dd>Вход для цепей: узел с включённым relay может быть выходом для других узлов парка.</dd>
    </dl>
  </section>
  <section><h3>Что умеет каждый сервис</h3>
    <div class="import-table-wrap"><table class="import-table routing-guide-table">
      <thead><tr><th>Сервис</th><th>Умеет</th><th>Не умеет</th></tr></thead>
      <tbody>
        <tr><td>NaiveProxy без Xray-router</td><td>весь трафик напрямую или через WARP; блокировать домены и IP</td><td>выборочно пускать сайты в другой выход</td></tr>
        <tr><td>Mieru без Xray-router</td><td>всё, что Naive, и выборочно пускать домены и IP в другой выход</td><td>списки geosite/geoip, порты, протоколы, цепи</td></tr>
        <tr><td>Любой сервис через Xray-router</td><td>всё: списки, порты, протоколы, цепи, свои выходы, полосы для клиентов</td><td>—</td></tr>
        <tr><td>MTProxy</td><td colspan="2">вне маршрутизации: Telegram-трафик идёт напрямую</td></tr>
      </tbody>
    </table></div>
    <p>Подключить сервис к Xray-router — в разделе «Возможности узла» кнопкой «Подключить к Xray-router». Если на узле его нет, он ставится установщиком.</p>
  </section>
  <section><h3>Как сделать</h3>
    ${SCENARIOS.map((scenario) => scenarioBlock(scenario, capabilities, Boolean(target?.backend))).join("")}
  </section>
  <section><h3>«Сохранить» и «Применить»</h3>
    <ol>
      <li><b>Сохранить</b> — записывает черновик политики в панель. На узле ничего не меняется; проверка справа показывает, что именно узел сделает и можно ли это применить.</li>
      <li><b>Применить</b> — отправляет сохранённую политику на узел. Панель запоминает прежнюю конфигурацию узла.</li>
      <li><b>Откатить</b> — возвращает узел к предыдущей применённой версии.</li>
      <li><b>История</b> — когда, кем и с каким результатом применялась политика.</li>
      <li><b>Куда пойдёт…</b> — впишите домен или IP и увидите, каким правилом и куда уйдёт трафик по сохранённой политике.</li>
    </ol>
  </section>
  <section><h3>Если проверка говорит «не применимо»</h3>
    <ul>
      <li><b>«backend узла не умеет этого»</b> — правило требует Xray-router: подключите сервис к нему или упростите правило.</li>
      <li><b>«на узле нет WARP» / «WARP не отвечает»</b> — WARP на узле не установлен или не запущен; выберите «напрямую» или другой выход.</li>
      <li><b>«Xray не знает такого кода geosite»</b> — в списках узла нет такого кода; обновите списки или выберите источник Loyalsoldier в «Возможностях узла» → Geodata.</li>
      <li><b>«узел не на связи»</b> — дождитесь, пока связанная панель выйдет на связь; сохранять можно и сейчас.</li>
    </ul>
  </section>`;
}
