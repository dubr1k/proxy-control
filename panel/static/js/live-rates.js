import { query } from "./common.js";
import { formatRate } from "./charts.js";

// The protocol pages list a user with the volumes they have moved; this adds what they move now.
// A page puts `<small class="live-rate" data-live-rate="<username>"></small>` in the user's cell and
// calls `startLiveRates` once after painting. The rates are the monitor's own numbers, asked for the
// current page only while its tab is in front; a user without a fresh rate shows nothing, never a zero
// the monitor did not measure.
const EVERY_MS = 5_000;
const TIMEOUT_MS = 3_000;
const FRESH_MS = 10_000;

const part = (arrow, value) => (typeof value === "number" ? `${arrow} ${formatRate(value)}` : null);

function paint(root, data) {
  const live = data.live !== false;
  for (const cell of root.querySelectorAll("[data-live-rate]")) {
    const rate = data.clients?.[cell.dataset.liveRate];
    // An averaged row at zero cannot tell an idle user from one in the middle of a long transfer
    // (the volume is written when the connection closes): it says nothing rather than «0».
    if (!rate || (!live && !(rate.total_bps > 0))) {
      cell.textContent = "";
      cell.title = "";
      continue;
    }
    const split = [part("↓", rate.down_bps), part("↑", rate.up_bps)].filter(Boolean);
    const text = split.length ? split.join(" · ") : formatRate(rate.total_bps);
    cell.textContent = live ? `Сейчас ${text}` : `За минуту ${text}`;
    cell.title = live ? "" : "Объём записывается, когда соединение закрывается";
  }
}

function clearRates(context) {
  context.state.liveRatesLast = null;
  context.state.liveRatesAt = null;
  for (const cell of context.ui.view?.querySelectorAll("[data-live-rate]") || []) {
    cell.textContent = "";
    cell.title = "";
  }
}

// Filtering/repainting cannot give an expired sample a second life.
export function repaintLiveRates(context) {
  const { liveRatesLast: data, liveRatesAt: at } = context.state;
  if (data && typeof at === "number" && performance.now() - at <= FRESH_MS) {
    if (context.ui.view) paint(context.ui.view, data);
  } else clearRates(context);
}

export function startLiveRates(context, generation, view, protocol) {
  const state = context.state;
  window.clearInterval(state.liveRatesTimer);
  window.clearTimeout(state.liveRatesExpiry);
  state.liveRatesAbort?.abort();
  const run = Symbol("live-rates");
  state.liveRatesRun = run;
  clearRates(context);
  const current = () => state.liveRatesRun === run && state.navigationGeneration === generation && state.view === view;
  let busy = false;
  const tick = async () => {
    if (!current()) return;
    if (state.liveRatesLast && performance.now() - state.liveRatesAt > FRESH_MS) clearRates(context);
    if (busy || document.hidden) return;
    busy = true;
    const controller = new AbortController();
    state.liveRatesAbort = controller;
    let timer;
    try {
      const expired = new Promise((_, reject) => {
        timer = window.setTimeout(() => {
          controller.abort();
          reject(new Error("live rate timeout"));
        }, TIMEOUT_MS);
      });
      // The race also bounds a test/client transport that ignores AbortSignal. A late
      // result cannot repaint after timeout or after another page started its poller.
      const data = await Promise.race([
        context.api(`/api/metrics/clients?protocol=${encodeURIComponent(protocol)}`, { signal: controller.signal }),
        expired,
      ]);
      const root = query("[data-live-rate]", context.ui.view) ? context.ui.view : null;
      if (current() && root && !controller.signal.aborted) {
        state.liveRatesLast = data;
        state.liveRatesAt = performance.now();
        paint(root, data);
        window.clearTimeout(state.liveRatesExpiry);
        state.liveRatesExpiry = window.setTimeout(() => { if (current()) clearRates(context); }, FRESH_MS);
      }
    } catch {
      if (current()) clearRates(context);
    } finally {
      window.clearTimeout(timer);
      if (state.liveRatesAbort === controller) state.liveRatesAbort = null;
      busy = false;
    }
  };
  void tick();
  state.liveRatesTimer = window.setInterval(() => {
    if (!current()) window.clearInterval(state.liveRatesTimer);
    else void tick();
  }, EVERY_MS);
}
