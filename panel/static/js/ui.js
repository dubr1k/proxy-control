import { esc, query } from "./common.js";

export function createUi(root) {
  const view = query("#view", root);
  const modalEntries = [];
  let modalSequence = 0;
  let historyBack = null;
  let rebasingHistory = false;
  let baseState = window.history.state;

  function liveModals() { return modalEntries.filter((entry) => entry.dialog.open); }

  function pruneClosed(restoreFocus = false) {
    const removed = modalEntries.filter((entry) => !entry.dialog.open);
    for (const entry of removed) modalEntries.splice(modalEntries.indexOf(entry), 1);
    if (restoreFocus) {
      const entry = [...removed].reverse().find((item) => item.trigger?.isConnected
        && (!item.trigger.closest?.("dialog") || item.trigger.closest("dialog").open));
      if (entry && window.location.hash === entry.hash) entry.trigger.focus({ preventScroll: true });
    }
  }

  function consumeHistoryEntry() {
    if (historyBack || !window.history.state?.panelModal) return;
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    historyBack = { promise, resolve };
    window.history.back();
  }

  // The entire modal stack owns one transient entry. Nested/replacement windows
  // replace its token; Back consumes it and restores one for the remaining parent.
  function syncModalHistory() {
    if (historyBack || rebasingHistory) return;
    const top = liveModals().at(-1);
    if (!top) { consumeHistoryEntry(); return; }
    const state = { ...baseState, panelModal: top.token };
    if (window.history.state?.panelModal) window.history.replaceState(state, "");
    else {
      baseState = window.history.state;
      window.history.pushState({ ...baseState, panelModal: top.token }, "");
    }
  }

  window.addEventListener("popstate", () => {
    if (historyBack) {
      const { resolve } = historyBack;
      historyBack = null;
      syncModalHistory();
      resolve();
      return;
    }
    const top = liveModals().at(-1);
    if (!top || window.history.state?.panelModal === top.token) return;
    // Preserve each dialog's existing cancel/confirmation policy.
    if (top.dialog.requestClose) top.dialog.requestClose("history");
    else if (top.dialog.dispatchEvent(new Event("cancel", { cancelable: true }))) top.dialog.close("history");
    pruneClosed(true);
    syncModalHistory();
  });
  root.addEventListener("close", (event) => {
    if (event.target.open) return;
    pruneClosed(true);
    syncModalHistory();
  }, true);

  async function prepareNavigation(changingView) {
    pruneClosed();
    if (changingView && liveModals().length) {
      rebasingHistory = true;
      consumeHistoryEntry();
    } else syncModalHistory();
    if (historyBack) await historyBack.promise;
  }

  function finishNavigation() {
    if (!rebasingHistory) return;
    rebasingHistory = false;
    baseState = window.history.state;
    syncModalHistory();
  }

  function toast(message, type = "ok") {
    const node = root.createElement("div");
    node.className = `toast ${type === "error" ? "error" : ""}`;
    node.textContent = message;
    const region = query("#toast-region", root);
    region?.append(node);
    // Modal dialogs live in the top layer, so a plain z-index leaves the toast
    // behind the blurred backdrop. Re-showing the popover puts the region back
    // on top of whichever dialog was opened last.
    // hidePopover() throws when the popover is already hidden, so the two calls
    // are guarded separately; either one failing must not skip the other.
    try {
      region?.hidePopover?.();
    } catch { /* not shown yet */ }
    try {
      region?.showPopover?.();
    } catch { /* popover unsupported: the static region still renders */ }
    window.setTimeout(() => node.remove(), 3200);
  }

  function setBusy(button, busy, label = "Подождите…") {
    if (!button) return;
    if (busy) {
      // A second busy call (a new label for the next step) must not take the first busy
      // label for the original one: that is what the button would be restored to.
      if (button.getAttribute("aria-busy") !== "true") button.dataset.label = button.textContent;
      button.textContent = label;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      return;
    }
    button.textContent = button.dataset.label || button.textContent;
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }

  // The overview's placeholder has the overview's own shape (resources across, three
  // protocols under it); a generic row of tiles made it jump between 3, 4 and 1 + 3.
  function renderSkeleton(name = "") {
    view.innerHTML = name === "dashboard"
      ? '<div class="protocol-overview skeleton-overview"><i class="host-row"></i><i></i><i></i><i></i></div>'
      : '<div class="skeleton-grid"><i></i><i></i><i></i><i></i></div>';
  }

  function renderError(error) {
    view.innerHTML = `<div class="empty-state"><span>!</span><h3>Не удалось загрузить данные</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`;
  }

  // Disclosure menus are in-flow: no clipped popups on the last row or on a phone.
  root.addEventListener("click", (event) => {
    root.querySelectorAll(".actions-menu[open]").forEach((menu) => {
      if (!menu.contains(event.target) || event.target.closest("button")) menu.open = false;
    });
  });
  root.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const menu = event.target.closest?.(".actions-menu[open]") || root.querySelector(".actions-menu[open]");
    if (!menu) return;
    event.preventDefault();
    event.stopPropagation();
    menu.open = false;
    menu.querySelector("summary")?.focus();
  });

  function openModal(selector, focusSelector = "") {
    const dialog = query(selector, root);
    if (!dialog) return;
    if (!dialog.open) {
      pruneClosed();
      modalEntries.push({ dialog, token: `panel-modal-${++modalSequence}`, hash: window.location.hash, trigger: root.activeElement });
      dialog.showModal();
      syncModalHistory();
    }
    if (focusSelector) window.setTimeout(() => query(focusSelector, root)?.focus(), 50);
  }

  // Every «×» and «Отмена» is a `value="cancel"` submit button of a `method="dialog"` form,
  // which the browser turns into `dialog.close()`. Where that submission does not happen
  // (an extension swallowing `submit`, a browser quirk), the dialog would be stuck with no
  // way out — so the close is also done explicitly, without depending on form semantics.
  root.addEventListener("click", (event) => {
    const button = event.target.closest?.('dialog[open] form[method="dialog"] button[value="cancel"]');
    if (!button) return;
    event.preventDefault();
    button.closest("dialog").close("cancel");
  });

  function confirmed(title, text, button = "Продолжить") {
    const dialog = query("#confirm", root);
    query("#confirm-title", root).textContent = title;
    query("#confirm-text", root).textContent = text;
    query("#confirm-ok", root).textContent = button;
    openModal("#confirm");
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "default"), { once: true });
    });
  }

  // One choice among a few named things (a grant for a lane): the value of the chosen
  // option, or null when dismissed. The labels are set as text, never as markup.
  function choose(title, text, options, button = "Выбрать") {
    const dialog = query("#choose", root);
    query("#choose-title", root).textContent = title;
    query("#choose-text", root).textContent = text;
    query("#choose-ok", root).textContent = button;
    const select = query("#choose-select", root);
    select.replaceChildren(...options.map((option) => {
      const element = document.createElement("option");
      element.value = option.id;
      element.textContent = option.label;
      return element;
    }));
    openModal("#choose");
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "default" ? select.value : null), { once: true });
    });
  }

  async function copyText(input, container = null) {
    if (!input || typeof input.value !== "string") return false;
    try {
      await navigator.clipboard.writeText(input.value);
      return true;
    } catch {
      // The fallback must work even when the source is in a collapsed disclosure.
      const active = root.activeElement;
      const area = root.createElement("textarea");
      area.className = "clipboard-helper";
      area.readOnly = true;
      area.value = input.value;
      (container || input.closest?.("dialog") || root.body).append(area);
      area.focus({ preventScroll: true });
      area.select();
      try { return root.execCommand("copy") === true; }
      catch { return false; }
      finally {
        area.value = "";
        area.remove();
        active?.focus?.({ preventScroll: true });
      }
    }
  }

  // One line of text (a new name): the trimmed value, or null when dismissed. `required`
  // keeps an empty value out; without it an empty answer means «put the default back».
  function askText(title, text, { label = "Название", value = "", maxLength = 128, required = true, button = "Сохранить" } = {}) {
    const dialog = query("#ask-text", root);
    const input = query("#ask-text-input", root);
    query("#ask-text-title", root).textContent = title;
    query("#ask-text-text", root).textContent = text;
    query("#ask-text-label", root).textContent = label;
    query("#ask-text-ok", root).textContent = button;
    query("#ask-text-error", root).textContent = "";
    input.maxLength = maxLength;
    input.required = required;
    input.value = value;
    openModal("#ask-text");
    input.select();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "default" ? input.value.trim() : null), { once: true });
    });
  }

  return { view, toast, setBusy, renderSkeleton, renderError, openModal, confirmed, choose, askText, copyText, prepareNavigation, finishNavigation };
}
