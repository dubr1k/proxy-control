"""Text inside coloured buttons and the phone bottom bar sits in the middle of its box.

Real Chromium against the development stub: for every visible button-like element with a
background or border (and every item of the phone bar) the box around its text and icon must
be centred inside the element's padding box within one pixel, on both axes. A second part
renders every button class inside the stretching containers the screens use (wrapping action
rows, equal-height grids) so the shared rule is checked even where the stub has no data."""

from __future__ import annotations

import json
import time

import pytest

from test_monitoring_layout import _eval, _open, browser, stub  # noqa: F401  (pytest fixtures)

MEASURE = r"""
((scope) => {
  const sel = 'button, .button, [role=button], .nav-count, .pill, .filter-pill, .mobile-nav button';
  const bad = [];
  let checked = 0;
  for (const el of document.querySelectorAll(sel)) {
    if (scope && !el.closest(scope)) continue;
    if (el.closest('.sidebar, .profile-menu, [hidden]')) continue;
    const cs = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4 || cs.visibility === 'hidden' || cs.display === 'none') continue;
    const filled = !/rgba\(0, 0, 0, 0\)/.test(cs.backgroundColor) || cs.backgroundImage !== 'none';
    const bordered = parseFloat(cs.borderLeftWidth) > 0 && cs.borderLeftStyle !== 'none';
    if (!filled && !bordered && !el.closest('.mobile-nav')) continue;
    if (cs.textAlign === 'left' && !el.closest('.mobile-nav') && cs.display !== 'inline-flex') continue; // list rows, not buttons
    let L = Infinity, T = Infinity, R = -Infinity, B = -Infinity;
    const add = (b) => { if (!b.width && !b.height) return; L = Math.min(L, b.left); T = Math.min(T, b.top); R = Math.max(R, b.right); B = Math.max(B, b.bottom); };
    const walk = (n) => {
      for (const c of n.childNodes) {
        if (c.nodeType === 3) { if (!c.textContent.trim()) continue; const g = document.createRange(); g.selectNodeContents(c); for (const b of g.getClientRects()) add(b); }
        else if (c.nodeType === 1) { const k = getComputedStyle(c); if (k.display === 'none' || k.visibility === 'hidden') continue; if (c.tagName.toLowerCase() === 'svg') add(c.getBoundingClientRect()); else walk(c); }
      }
    };
    walk(el);
    if (L === Infinity) continue;
    checked++;
    const bl = parseFloat(cs.borderLeftWidth), br = parseFloat(cs.borderRightWidth), bt = parseFloat(cs.borderTopWidth), bb = parseFloat(cs.borderBottomWidth);
    const dx = (L + R) / 2 - ((r.left + bl) + (r.right - br)) / 2;
    const dy = (T + B) / 2 - ((r.top + bt) + (r.bottom - bb)) / 2;
    if (Math.abs(dx) > 1 || Math.abs(dy) > 1) bad.push(el.tagName.toLowerCase() + '.' + String(el.className).trim().replace(/\s+/g, '.') + ' "' + el.textContent.trim().slice(0, 20) + '" dx=' + dx.toFixed(1) + ' dy=' + dy.toFixed(1));
  }
  return JSON.stringify({checked, bad});
})
"""

# Every button class of style.css in the containers that stretch or wrap them.
FIXTURE = r"""
(() => {
  document.getElementById('centering-fixture')?.remove();
  const host = document.createElement('div');
  host.id = 'centering-fixture';
  const classes = ['primary', 'secondary', 'danger', 'ghost', 'danger ghost', 'action-button', 'action-button share', 'action-button danger-text', 'icon-button', 'filter-pill', 'filter-pill active'];
  const labels = ['Ссылка', 'Конфигурация', 'Заблокировать', 'Открыть', 'Удалить', 'Создать'];
  const row = (cls, wrapper) => {
    const w = document.createElement('div');
    w.className = wrapper;
    classes.forEach((c, i) => { const b = document.createElement('button'); b.className = c; b.textContent = c === 'icon-button' ? '+' : labels[i % labels.length]; w.appendChild(b); });
    return w;
  };
  host.append(row('', 'row-actions'), row('', 'client-actions'), row('', 'modal-actions'), row('', 'filter-pills'));
  host.firstChild.style.width = '420px';
  host.lastChild.style.width = '420px';
  document.body.appendChild(host);
  return 1;
})()
"""

SIZES = [(390, 844), (1440, 900)]


def _report(devtools, scope=None):
    return json.loads(_eval(devtools, f"({MEASURE})({json.dumps(scope)})"))


@pytest.mark.parametrize(("width", "height"), SIZES)
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_screen_buttons_and_the_phone_bar_are_centred(stub, browser, width, height, theme):  # noqa: F811
    _open(browser, stub, "now", width, height, theme)
    time.sleep(0.3)
    report = _report(browser)
    assert report["checked"] > 5, report
    assert report["bad"] == [], report["bad"]


@pytest.mark.parametrize(("width", "height"), SIZES)
def test_every_button_class_is_centred_in_stretching_containers(stub, browser, width, height):  # noqa: F811
    _open(browser, stub, "now", width, height)
    _eval(browser, FIXTURE)
    time.sleep(0.2)
    report = _report(browser, "#centering-fixture")
    assert report["checked"] >= 30, report
    assert report["bad"] == [], report["bad"]


def test_the_phone_bar_items_are_equal_and_centred_in_both_languages(stub, browser):  # noqa: F811
    _open(browser, stub, "now", 390, 844)
    for lang in ("ru", "en"):
        _eval(browser, f"localStorage.setItem('proxy-control.lang','{lang}');0")
        browser.call("Page.reload")
        time.sleep(1.5)
        report = _report(browser, ".mobile-nav")
        assert report["checked"] >= 8, report
        assert report["bad"] == [], (lang, report["bad"])
        assert _eval(browser, "document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")
