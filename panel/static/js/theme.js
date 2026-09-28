import { query } from "./common.js";

// The accent is a per-browser preference: it lives in localStorage and never reaches the
// panel, so a colour choice is not an operator action and needs no audit row.
export const ACCENTS = [
  ["indigo", "Индиго"],
  ["blue", "Синий"],
  ["cyan", "Бирюза"],
  ["emerald", "Изумруд"],
  ["violet", "Фиолет"],
  ["rose", "Роза"],
  ["orange", "Оранж"],
];
const KEY = "proxy-control.accent";
const DEFAULT = "indigo";

function stored() {
  try {
    const value = window.localStorage.getItem(KEY);
    return ACCENTS.some(([name]) => name === value) ? value : DEFAULT;
  } catch {
    return DEFAULT; // storage blocked: the panel keeps its default colour
  }
}

export function applyAccent(name = stored()) {
  if (name === DEFAULT) document.documentElement.removeAttribute("data-accent");
  else document.documentElement.dataset.accent = name;
  return name;
}

function remember(name) {
  try {
    window.localStorage.setItem(KEY, name);
  } catch {
    // a private window: the choice lasts until the tab closes
  }
}

export function bindAccentPicker(root) {
  const button = query("#accent-button", root);
  const menu = query("#accent-menu", root);
  if (!button || !menu) return;
  const swatches = query(".accent-swatches", menu);
  swatches.innerHTML = ACCENTS.map(([name, label]) => `<button type="button" role="menuitemradio" class="accent-swatch" data-accent="${name}" aria-checked="false"><i></i>${label}</button>`).join("");
  const mark = (current) => {
    for (const item of swatches.children) item.setAttribute("aria-checked", String(item.dataset.accent === current));
  };
  const setOpen = (open) => {
    menu.hidden = !open;
    button.setAttribute("aria-expanded", String(open));
    if (open) query('[aria-checked="true"]', swatches)?.focus();
  };
  mark(applyAccent());
  button.addEventListener("click", () => setOpen(menu.hidden));
  swatches.addEventListener("click", (event) => {
    const item = event.target.closest("[data-accent]");
    if (!item) return;
    remember(item.dataset.accent);
    mark(applyAccent(item.dataset.accent));
  });
  document.addEventListener("click", (event) => {
    if (!menu.hidden && !menu.contains(event.target) && !button.contains(event.target)) setOpen(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !menu.hidden) { setOpen(false); button.focus(); }
  });
}
