import { esc, query } from "./common.js";

export function createUi(root) {
  const view = query("#view", root);

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
      button.dataset.label = button.textContent;
      button.textContent = label;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      return;
    }
    button.textContent = button.dataset.label || button.textContent;
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }

  function renderSkeleton() {
    view.innerHTML = '<div class="skeleton-grid"><i></i><i></i><i></i><i></i></div>';
  }

  function renderError(error) {
    view.innerHTML = `<div class="empty-state"><span>!</span><h3>Не удалось загрузить данные</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`;
  }

  function openModal(selector, focusSelector = "") {
    const dialog = query(selector, root);
    dialog?.showModal();
    if (focusSelector) window.setTimeout(() => query(focusSelector, root)?.focus(), 50);
  }

  function confirmed(title, text, button = "Продолжить") {
    const dialog = query("#confirm", root);
    query("#confirm-title", root).textContent = title;
    query("#confirm-text", root).textContent = text;
    query("#confirm-ok", root).textContent = button;
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "default"), { once: true });
    });
  }

  async function copyText(input) {
    try {
      await navigator.clipboard.writeText(input.value);
    } catch {
      input.select();
      document.execCommand("copy");
    }
  }

  return { view, toast, setBusy, renderSkeleton, renderError, openModal, confirmed, copyText };
}
