// The live feed of the monitoring screen (and, since 3.1, of the overview's resource card):
// Server-Sent Events first, polling when the stream does not hold, a paused/resumed connection
// when the tab is hidden. One connection per screen; it closes itself when the operator leaves
// the screen (the navigation generation moves on).
//
// States passed to `onState(state, detail)`:
//   live         the SSE stream delivers a snapshot every interval
//   polling      SSE failed twice; `/api/metrics/live` is polled every POLL_MS
//   reconnecting the last attempt failed; the next one is `detail.retryInMs` away
//   paused       the operator paused it, or the tab stayed hidden for more than HIDDEN_PAUSE_MS
const POLL_MS = 3000;
const BACKOFF_FIRST_MS = 1000;
const BACKOFF_MAX_MS = 15_000;
const HIDDEN_PAUSE_MS = 60_000;
const SILENCE_MS = 12_000; // the server pings every 15 s but sends a snapshot every 2 s
const SSE_RETRY_MS = 60_000; // after the fallback to polling, SSE is tried again this often

export function backoffDelay(attempt) {
  return Math.min(BACKOFF_MAX_MS, BACKOFF_FIRST_MS * 2 ** Math.max(0, attempt));
}

export function connectLive(context, node, onSnapshot, onState, { view = "monitoring" } = {}) {
  context.live?.close();
  const generation = context.state.navigationGeneration;
  const target = encodeURIComponent(node || "local");
  let source = null;
  let pollTimer = 0;
  let retryTimer = 0;
  let watchdog = 0;
  let hiddenTimer = 0;
  let sseUpgrade = 0;
  let closed = false;
  let paused = false; // by the operator
  let suspended = false; // by a hidden tab
  let mode = "sse";
  let errors = 0;
  let attempt = 0;
  let lastMessage = 0;
  let pending = null;
  let frame = 0;
  let state = "";

  const alive = () => !closed && context.state.navigationGeneration === generation && context.state.view === view;

  function report(next, detail = {}) {
    if (state === next && next !== "reconnecting") return;
    state = next;
    onState?.(next, detail);
  }

  // Only the newest snapshot is painted, once per animation frame; a hidden tab keeps the
  // latest one and paints it when it comes back.
  function deliver(snapshot) {
    pending = snapshot;
    if (frame) return;
    frame = window.requestAnimationFrame(() => {
      frame = 0;
      const value = pending;
      pending = null;
      if (value && alive()) onSnapshot(value);
    });
  }

  function clearTimers() {
    window.clearTimeout(pollTimer);
    window.clearTimeout(retryTimer);
    window.clearInterval(watchdog);
    window.clearTimeout(sseUpgrade);
    pollTimer = retryTimer = watchdog = sseUpgrade = 0;
  }

  function shutSource() {
    if (!source) return;
    source.close();
    source = null;
  }

  function stopAll() {
    clearTimers();
    shutSource();
  }

  function guard() {
    if (alive()) return true;
    handle.close();
    return false;
  }

  function scheduleReconnect() {
    if (!guard() || paused || suspended) return;
    const delay = backoffDelay(attempt);
    attempt += 1;
    report("reconnecting", { retryInMs: delay });
    retryTimer = window.setTimeout(start, delay);
  }

  function openStream() {
    mode = "sse";
    shutSource();
    try {
      source = new EventSource(`/api/metrics/stream?node=${target}`);
    } catch {
      fallToPolling();
      return;
    }
    lastMessage = Date.now();
    source.addEventListener("open", () => {
      errors = 0;
      attempt = 0;
      lastMessage = Date.now();
      report("live");
    });
    source.addEventListener("snapshot", (event) => {
      if (!guard()) return;
      try {
        deliver(JSON.parse(event.data));
      } catch {
        return; // a malformed frame is skipped, never painted
      }
      errors = 0;
      attempt = 0;
      lastMessage = Date.now();
      report("live");
    });
    // The server closes after 55 minutes so that the session is re-validated.
    source.addEventListener("bye", () => {
      shutSource();
      retryTimer = window.setTimeout(start, 300);
    });
    source.addEventListener("error", () => {
      if (!guard()) return;
      errors += 1;
      shutSource();
      if (errors >= 2) fallToPolling();
      else scheduleReconnect();
    });
    window.clearInterval(watchdog);
    watchdog = window.setInterval(() => {
      if (!guard() || mode !== "sse" || !source) return;
      if (Date.now() - lastMessage > SILENCE_MS) {
        errors += 1;
        shutSource();
        if (errors >= 2) fallToPolling();
        else scheduleReconnect();
      }
    }, 4000);
  }

  async function poll() {
    pollTimer = 0;
    if (!guard() || paused || suspended || mode !== "poll") return;
    try {
      const snapshot = await context.api(`/api/metrics/live?node=${target}`);
      if (!guard() || paused || suspended) return;
      attempt = 0;
      deliver(snapshot);
      report("polling");
      pollTimer = window.setTimeout(poll, POLL_MS);
    } catch {
      if (!guard() || paused || suspended) return;
      const delay = backoffDelay(attempt);
      attempt += 1;
      report("reconnecting", { retryInMs: delay });
      pollTimer = window.setTimeout(poll, delay);
    }
  }

  function fallToPolling() {
    mode = "poll";
    window.clearInterval(watchdog);
    watchdog = 0;
    report("polling");
    void poll();
    // Polling is the fallback, not the home: the stream is tried again now and then.
    sseUpgrade = window.setTimeout(() => {
      if (!guard() || paused || suspended) return;
      window.clearTimeout(pollTimer);
      errors = 1; // one more failure sends it straight back to polling
      openStream();
    }, SSE_RETRY_MS);
  }

  function start() {
    retryTimer = 0;
    if (!guard() || paused || suspended) return;
    if (mode === "poll") void poll();
    else openStream();
  }

  function onVisibility() {
    if (!alive()) {
      handle.close();
      return;
    }
    if (document.hidden) {
      window.clearTimeout(hiddenTimer);
      hiddenTimer = window.setTimeout(() => {
        if (!document.hidden || paused) return;
        suspended = true;
        stopAll();
        report("paused", { reason: "hidden" });
      }, HIDDEN_PAUSE_MS);
      return;
    }
    window.clearTimeout(hiddenTimer);
    if (suspended) {
      suspended = false;
      errors = 0;
      attempt = 0;
      mode = "sse";
      if (!paused) start();
    } else if (pending && alive()) {
      deliver(pending);
    }
  }

  document.addEventListener("visibilitychange", onVisibility);

  const handle = {
    close() {
      if (closed) return;
      closed = true;
      stopAll();
      window.clearTimeout(hiddenTimer);
      document.removeEventListener("visibilitychange", onVisibility);
      if (frame) window.cancelAnimationFrame(frame);
      frame = 0;
      if (context.live === handle) context.live = null;
      handle.onClose?.();
    },
    pause() {
      if (closed || paused) return;
      paused = true;
      stopAll();
      report("paused", { reason: "operator" });
    },
    resume() {
      if (closed || !paused) return;
      paused = false;
      errors = 0;
      attempt = 0;
      mode = "sse";
      state = "";
      start();
    },
    get paused() {
      return paused;
    },
  };
  context.live = handle;
  start();
  return handle;
}
