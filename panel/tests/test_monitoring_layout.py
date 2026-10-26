"""The monitoring screen in a real browser, against the development stub (synthetic metrics):
no horizontal scroll at 390 px, nothing escaping the screen, no overlapping cards, the CSP
raises no violation, and the live numbers actually move."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

from test_mobile_layout import DevTools, _browser

ROOT = Path(__file__).resolve().parents[2]
STUB = ROOT / "scripts" / "dev" / "monitoring-stub-server.py"

# Run inside the page: what escapes the viewport or collides, outside the scroll containers
# that are allowed to scroll on their own (tables, the range selector).
CHECK = r"""
(() => {
  const vw = document.documentElement.clientWidth;
  const problems = [];
  const root = document.querySelector('[data-mon]');
  if (!root) return JSON.stringify({problems: ['no monitoring root']});
  if (document.documentElement.scrollWidth > vw + 1) problems.push('page scrolls sideways: ' + document.documentElement.scrollWidth + ' > ' + vw);
  const scroller = (el) => el.closest('.mon-table-wrap, .mon-seg, .chart-sr');
  for (const el of root.querySelectorAll('*')) {
    if (scroller(el) && !el.matches('.mon-table-wrap, .mon-seg')) continue;
    if (el.ownerSVGElement) continue; // the drawing inside a chart is clipped by its own svg
    const box = el.getBoundingClientRect();
    if (!box.width || !box.height) continue;
    if (el.closest('[hidden]')) continue;
    if (box.right > vw + 1 || box.left < -1) problems.push('escapes: ' + el.tagName + '.' + String(el.className.baseVal ?? el.className).slice(0, 40) + ' [' + Math.round(box.left) + ',' + Math.round(box.right) + ']');
  }
  const cards = [...root.querySelectorAll('.mon-tile, .mon-proto, .mon-card, .mon-strip-node')].filter((el) => el.offsetParent !== null);
  for (let i = 0; i < cards.length; i++) for (let j = i + 1; j < cards.length; j++) {
    const a = cards[i].getBoundingClientRect(), b = cards[j].getBoundingClientRect();
    if (cards[i].contains(cards[j]) || cards[j].contains(cards[i])) continue;
    const x = Math.min(a.right, b.right) - Math.max(a.left, b.left), y = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
    if (x > 2 && y > 2) problems.push('overlap: ' + cards[i].className + ' / ' + cards[j].className);
  }
  for (const text of root.querySelectorAll('.tile-figures b, .proto-rates b, .net-pair b')) {
    if (text.scrollWidth > text.parentElement.clientWidth + 2 && text.parentElement.clientWidth) problems.push('text clipped: ' + text.textContent);
  }
  return JSON.stringify({problems, csp: window.__csp || [], errors: window.__errs || [], iw: innerWidth});
})()
"""

INSTRUMENT = (
    "window.__csp=[];window.__errs=[];"
    "document.addEventListener('securitypolicyviolation',e=>__csp.push(e.violatedDirective+' '+e.blockedURI));"
    "addEventListener('error',e=>{if(!String(e.message).includes('ResizeObserver'))__errs.push(e.message)});"
    "addEventListener('unhandledrejection',e=>__errs.push(String(e.reason)));"
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def stub():
    port = _free_port()
    process = subprocess.Popen([sys.executable, str(STUB), "--port", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/auth/me", timeout=1).read()
            break
        except OSError:
            time.sleep(0.1)
    else:
        process.kill()
        pytest.fail("the monitoring stub did not start")
    yield port
    process.terminate()
    process.wait(timeout=5)


@pytest.fixture(scope="module")
def browser():
    profile = Path(tempfile.mkdtemp())
    process = subprocess.Popen(
        [_browser(), "--headless", "--no-sandbox", "--disable-gpu", "--remote-allow-origins=*", "--remote-debugging-port=0",
         f"--user-data-dir={profile}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    port = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and port is None:
        try:
            lines = (profile / "DevToolsActivePort").read_text().splitlines()
            if len(lines) >= 2:
                port = int(lines[0])
        except (FileNotFoundError, IndexError, ValueError, OSError):
            time.sleep(0.05)
    assert port, "Chromium DevTools did not start"
    target = None
    while target is None and time.monotonic() < deadline:
        # A busy CI runner may leave the DevTools endpoint silent for a while: retry until the deadline.
        try:
            listing = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5))
        except OSError:
            time.sleep(0.5)
            continue
        pages = [t for t in listing if t.get("type") == "page"]
        target = pages[0]["webSocketDebuggerUrl"] if pages else None
        time.sleep(0.1)
    assert target, "Chromium DevTools has no page"
    devtools = DevTools(target)
    devtools.call("Page.enable")
    devtools.call("Page.addScriptToEvaluateOnNewDocument", {"source": INSTRUMENT})
    yield devtools
    devtools.close()
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _eval(devtools: DevTools, expression: str):
    result = devtools.call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
    return result["result"].get("value")


def _open(devtools: DevTools, port: int, tab: str, width: int, height: int, theme: str = "dark") -> dict:
    mobile = width < 700
    devtools.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": mobile})
    base = f"http://127.0.0.1:{port}/"
    devtools.call("Page.navigate", {"url": base + "?seed#monitoring"})
    time.sleep(0.6)
    _eval(devtools, f"localStorage.setItem('proxy-control.monitoring', JSON.stringify({{tab:'{tab}',node:'local',range:'24h',nodesRange:'7d',dir:'sum'}}));0")
    devtools.call("Page.navigate", {"url": base + f"?run={time.time()}#monitoring"})
    _eval(devtools, f"document.documentElement.dataset.theme='{theme}';0")
    ready = {
        "now": "!!document.querySelector('[data-proto=mtproxy] .proto-rates') && !!document.querySelector('[data-chart-now] .chart')",
        "traffic": "!!document.querySelector('[data-chart-traffic] .chart') && !!document.querySelector('.mon-table')",
        "nodes": "!!document.querySelector('.mon-compare tbody tr')",
    }[tab]
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if _eval(devtools, ready):
            break
        time.sleep(0.2)
    else:
        detail = _eval(devtools, "JSON.stringify({errors: window.__errs, csp: window.__csp, body: (document.querySelector('#view')||document.body).innerText.slice(0, 300), badge: document.querySelector('[data-live-badge]')?.className})")
        pytest.fail(f"the {tab} tab never rendered: {detail}")
    time.sleep(1.0)  # charts redraw once the ResizeObserver delivers the final width
    return json.loads(_eval(devtools, CHECK))


@pytest.mark.parametrize("tab", ["now", "traffic", "nodes"])
@pytest.mark.parametrize(("width", "height"), [(390, 844), (1440, 900)])
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_every_tab_fits_the_screen_without_collisions(stub, browser, tab, width, height, theme):
    report = _open(browser, stub, tab, width, height, theme)
    assert report["problems"] == [], report["problems"]
    assert report["csp"] == [], f"the CSP blocked something: {report['csp']}"
    assert report["errors"] == [], report["errors"]


def test_the_drill_down_opens_and_still_fits_on_a_phone(stub, browser):
    _open(browser, stub, "nodes", 390, 844)
    _eval(browser, "document.querySelector('[data-mon-drill=\"fra-1\"]').click();0")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not _eval(browser, "document.querySelectorAll('.drill-chart .chart').length >= 5"):
        time.sleep(0.2)
    report = json.loads(_eval(browser, CHECK))
    assert report["problems"] == [], report["problems"]
    assert _eval(browser, "document.querySelectorAll('.drill-chart .chart').length") == 5


def test_the_live_numbers_move_and_the_badge_says_live(stub, browser):
    _open(browser, stub, "now", 1440, 900)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not _eval(browser, "document.querySelector('[data-live-badge]').classList.contains('live')"):
        time.sleep(0.2)
    assert _eval(browser, "document.querySelector('[data-live-badge]').classList.contains('live')")
    seen = set()
    for _ in range(4):
        seen.add(_eval(browser, "document.querySelector('[data-proto=amneziawg] .proto-rates').textContent + document.querySelector('[data-tile=net] .net-pair').textContent"))
        time.sleep(2.2)
    assert len(seen) >= 2, "the displayed rates did not change in 9 seconds"
    # pausing freezes the feed and says so
    _eval(browser, "document.querySelector('[data-mon-pause]').click();0")
    time.sleep(0.5)
    assert _eval(browser, "document.querySelector('[data-live-badge]').classList.contains('paused')")
    frozen = _eval(browser, "document.querySelector('[data-tile=net] .net-pair').textContent")
    time.sleep(4.5)
    assert _eval(browser, "document.querySelector('[data-tile=net] .net-pair').textContent") == frozen


def test_the_chart_tooltip_follows_the_keyboard(stub, browser):
    _open(browser, stub, "traffic", 1440, 900)
    key = "document.querySelector('[data-chart-traffic] svg').dispatchEvent(new KeyboardEvent('keydown',{key:'%s',bubbles:true,shiftKey:%s}));0"
    _eval(browser, key % ("End", "false"))
    time.sleep(0.2)
    assert not _eval(browser, "document.querySelector('[data-chart-traffic] .chart-tip').hidden")
    before = _eval(browser, "document.querySelector('[data-chart-traffic] .chart-tip-head').textContent")
    _eval(browser, key % ("ArrowLeft", "true"))
    time.sleep(0.2)
    after = _eval(browser, "document.querySelector('[data-chart-traffic] .chart-tip-head').textContent")
    assert before != after
