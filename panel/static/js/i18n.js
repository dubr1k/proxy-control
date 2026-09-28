// The English panel (v0.17, owner: «проверь, вся ли панель переведена на английский»).
//
// The UI is written in Russian; English is a dictionary laid over the rendered page. Every
// Russian fragment of the sources (scripts/dev/i18n-strings.py lists them, a test keeps
// `/static/i18n/en.json` complete) is replaced where it appears — a whole text node, or a
// whole-word piece of one around a dynamic value — in text and in the placeholder, title,
// aria-label and alt attributes, including everything painted later (a MutationObserver).
// The choice lives in localStorage: a per-browser preference, never sent to the panel.
import { query } from "./common.js";

const KEY = "proxy-control.lang";
const LANGS = ["ru", "en"];
const CYRILLIC = /[А-Яа-яЁё]/;
const ATTRIBUTES = ["placeholder", "title", "aria-label", "alt"];
// Text the operator typed (client and account names) and code-like blocks stay as they are.
const SKIP = "script,style,pre,code,textarea,[data-no-i18n],.client-identity b,.grant-account,.identity b";

let dictionary = null;
let pattern = null;

export function currentLang() {
  try {
    const value = window.localStorage.getItem(KEY);
    return LANGS.includes(value) ? value : "ru";
  } catch {
    return "ru";
  }
}

function remember(lang) {
  try {
    window.localStorage.setItem(KEY, lang);
  } catch {
    // a private window: the choice lasts until the tab closes
  }
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Longest fragments first, and only whole words: «из» never bites into «изменить».
function compile(entries) {
  const keys = Object.keys(entries).sort((left, right) => right.length - left.length).map(escapeRegExp);
  return keys.length ? new RegExp(`(?<![\\p{L}\\p{N}])(?:${keys.join("|")})(?![\\p{L}\\p{N}])`, "gu") : null;
}

export function translate(text) {
  if (!dictionary || !text || !CYRILLIC.test(text)) return text;
  const lead = /^\s/.test(text) ? " " : "";
  const tail = /\s$/.test(text) ? " " : "";
  const body = text.replace(/\s+/g, " ").trim();
  if (Object.hasOwn(dictionary, body)) return lead + dictionary[body] + tail;
  return lead + (pattern ? body.replace(pattern, (match) => dictionary[match] ?? match) : body) + tail;
}

function skipped(element) {
  return Boolean(element?.closest?.(SKIP));
}

function translateElement(element) {
  if (skipped(element)) return;
  for (const name of ATTRIBUTES) {
    const value = element.getAttribute?.(name);
    if (value && CYRILLIC.test(value)) {
      const next = translate(value);
      if (next !== value) element.setAttribute(name, next);
    }
  }
}

function translateNode(node) {
  if (node.nodeType === Node.TEXT_NODE) {
    if (!CYRILLIC.test(node.nodeValue) || skipped(node.parentElement)) return;
    const next = translate(node.nodeValue);
    if (next !== node.nodeValue) node.nodeValue = next;
    return;
  }
  if (node.nodeType !== Node.ELEMENT_NODE || skipped(node)) return;
  translateElement(node);
  const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
  for (let current = walker.nextNode(); current; current = walker.nextNode()) {
    if (current.nodeType === Node.ELEMENT_NODE) translateElement(current);
    else translateNode(current);
  }
}

function observe(root) {
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === "characterData") translateNode(record.target);
      else if (record.type === "attributes") translateElement(record.target);
      else for (const node of record.addedNodes) translateNode(node);
    }
  });
  observer.observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRIBUTES });
}

// Paints the chosen language: nothing for Russian; for English the dictionary is fetched
// once, the page translated and every later change followed.
export async function applyLanguage(lang = currentLang()) {
  document.documentElement.lang = lang;
  paintSwitch(lang);
  if (lang !== "en") return;
  try {
    const response = await fetch("/static/i18n/en.json", { credentials: "same-origin" });
    if (!response.ok) return;
    dictionary = await response.json();
  } catch {
    return; // the panel stays Russian rather than half-translated
  }
  pattern = compile(dictionary);
  document.title = translate(document.title);
  translateNode(document.body);
  observe(document.body);
}

function paintSwitch(lang) {
  const button = query("#lang-button", document);
  if (!button) return;
  const other = lang === "en" ? "ru" : "en";
  button.textContent = other.toUpperCase();
  button.dataset.lang = other;
  button.setAttribute("aria-label", other === "en" ? "Switch to English" : "Переключить на русский");
  button.title = button.getAttribute("aria-label");
  button.setAttribute("data-no-i18n", "");
}

export function bindLanguageSwitch(root = document) {
  query("#lang-button", root)?.addEventListener("click", ({ currentTarget }) => {
    remember(currentTarget.dataset.lang);
    // A reload repaints every screen from its own templates in the new language.
    window.location.reload();
  });
}
