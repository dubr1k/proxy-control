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
    dialog.showModal();
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
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "default" ? select.value : null), { once: true });
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

  return { view, toast, setBusy, renderSkeleton, renderError, openModal, confirmed, choose, copyText };
}
