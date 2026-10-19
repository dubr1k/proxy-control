import { query } from "./common.js";
import { formatRate } from "./charts.js";

// The protocol pages list a user with the volumes they have moved; this adds what they move now.
// A page puts `<small class="live-rate" data-live-rate="<username>"></small>` in the user's cell and
// calls `startLiveRates` once after painting. The rates are the monitor's own numbers, asked for the
// current page only while its tab is in front; a user without a fresh rate shows nothing, never a zero
// the monitor did not measure.
const EVERY_MS = 5_000;

const part = (arrow, value) => (typeof value === "number" ? `${arrow} ${formatRate(value)}` : null);

function paint(root, data) {
  const live = data.live !== false;
  for (const cell of root.querySelectorAll("[data-live-rate]")) {
    const rate = data.clients?.[cell.dataset.liveRate];
    // An averaged row at zero cannot tell an idle user from one in the middle of a long transfer
    // (the volume is written when the connection closes): it says nothing rather than «0».
    if (!rate || (!live && !(rate.total_bps > 0))) {
      cell.textContent = "";
      continue;
    }
    const split = [part("↓", rate.down_bps), part("↑", rate.up_bps)].filter(Boolean);
    const text = split.length ? split.join(" · ") : formatRate(rate.total_bps);
    cell.textContent = live ? `Сейчас ${text}` : `За минуту ${text}`;
    cell.title = live ? "" : "Объём записывается, когда соединение закрывается";
  }
}

// A page that repaints its list (search, filter, an action) calls this to put the last numbers back at once.
export function repaintLiveRates(context) {
  const data = context.state.liveRatesLast;
  if (data && context.ui.view) paint(context.ui.view, data);
}

export function startLiveRates(context, generation, view, protocol) {
  const state = context.state;
  window.clearInterval(state.liveRatesTimer);
  state.liveRatesLast = null; // another page's numbers must never land on this page's users
  const current = () => state.navigationGeneration === generation && state.view === view;
  const tick = async () => {
    if (!current() || document.hidden) return;
    try {
      const data = await context.api(`/api/metrics/clients?protocol=${encodeURIComponent(protocol)}`);
      const root = query("[data-live-rate]", context.ui.view) ? context.ui.view : null;
      if (current() && root) {
        state.liveRatesLast = data;
        paint(root, data);
      }
    } catch {
      // monitoring is optional (disabled, warming up): the page simply has no live line
    }
  };
  void tick();
  state.liveRatesTimer = window.setInterval(() => {
    if (!current()) window.clearInterval(state.liveRatesTimer);
    else void tick();
  }, EVERY_MS);
}
