"""The stylesheet and the one small script of the subscription page, and the CSP that lets them run.

The page is served on the subscription host, which answers only `/s/...`, so nothing can be fetched
from `/static`: both are inlined, and the policy admits exactly these bytes by hash — no
`'unsafe-inline'`, no external source. Change a byte and the hash follows; the policy is built from
the constants below, never typed twice.
"""
from __future__ import annotations

import base64
import hashlib

STYLE = """
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--text:#1a1d21;--muted:#5d6672;--line:#d9dde3;--accent:#1f6feb;--on-accent:#fff;--soft:#eef3fd;--code:#f0f2f5}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--card:#1d2127;--text:#e8eaed;--muted:#a0a8b3;--line:#333a43;--accent:#6aa3ff;--on-accent:#0b1220;--soft:#1b2638;--code:#13161a}}
*{box-sizing:border-box}
body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;background:var(--bg);color:var(--text)}
main{max-width:40rem;margin:0 auto;padding:1rem 1rem 2rem}
h1{font-size:1.4rem;line-height:1.25;margin:.5rem 0 1rem}h2{font-size:1.1rem;margin:0 0 .5rem}h3{font-size:1rem;margin:1rem 0 .5rem}
h1,h2,h3,p,li{overflow-wrap:anywhere}
p{margin:.5rem 0}.muted{color:var(--muted)}.small{font-size:.875rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:.75rem;padding:1rem;margin:0 0 1rem}
.warn{background:var(--soft);border-radius:.5rem;padding:.6rem .75rem;margin:0 0 1rem;font-size:.9rem}
.btn{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;min-height:3rem;margin:.5rem 0 0;padding:.6rem 1rem;border:1px solid var(--accent);border-radius:.6rem;background:transparent;color:var(--accent);font:inherit;font-weight:600;text-align:center;text-decoration:none;cursor:pointer}
.btn.primary{background:var(--accent);color:var(--on-accent)}
.btn.small{min-height:2.75rem;width:auto;margin:.25rem 0 0;padding:.4rem .9rem;font-size:.9rem}
.btn:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.app{border-top:1px solid var(--line);padding:.75rem 0 .25rem;margin-top:.75rem}
.app:first-of-type{border-top:0;margin-top:0;padding-top:0}
.app p{margin:.25rem 0}.app-name{font-weight:600}
details{border-radius:.5rem}
details.card>summary{font-weight:600;font-size:1.05rem;list-style:none;cursor:pointer;display:flex;justify-content:space-between;gap:.75rem;align-items:center;min-height:2.5rem}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary::after{content:"+";font-size:1.4rem;color:var(--muted)}
details.card[open]>summary::after{content:"\2212"}
details.qr{margin:.75rem 0 0}details.qr>summary{color:var(--accent);font-weight:600;cursor:pointer;min-height:2.5rem;display:flex;align-items:center}
details.qr img{display:block;width:12rem;height:12rem;max-width:100%;margin:.5rem auto;background:#fff;padding:.5rem;border-radius:.5rem}
code{display:block;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--code);padding:.5rem .6rem;border-radius:.4rem;font:.85rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
table{border-collapse:collapse;width:100%}th,td{padding:.4rem .25rem;text-align:left;vertical-align:top;border-top:1px solid var(--line)}
td{overflow-wrap:anywhere}th{white-space:nowrap;font-weight:600;padding-right:.75rem}
ul{padding-left:1.25rem;margin:.25rem 0}li{margin:.25rem 0}
a{color:var(--accent)}
footer{margin-top:1.5rem;color:var(--muted);font-size:.8rem}
.offscreen{position:fixed;left:-9999px;top:0}
"""

SCRIPT = """
(function () {
  function fallback(text) {
    var box = document.createElement("textarea");
    box.value = text;
    box.setAttribute("readonly", "");
    box.className = "offscreen";
    document.body.appendChild(box);
    box.select();
    var done = false;
    try { done = document.execCommand("copy"); } catch (error) { done = false; }
    document.body.removeChild(box);
    return done;
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-copy]") : null;
    if (!button || button.getAttribute("data-busy")) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source) return;
    var text = source.textContent;
    var label = button.textContent;
    function finish(ok) {
      button.setAttribute("data-busy", "1");
      button.textContent = button.getAttribute(ok ? "data-done" : "data-fail");
      setTimeout(function () { button.textContent = label; button.removeAttribute("data-busy"); }, 2000);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { finish(true); }, function () { finish(fallback(text)); });
    } else {
      finish(fallback(text));
    }
  });
})();
"""


def _hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


# What the browser compares is the exact text between the tags, so the page embeds these strings as they are.
CSP = (
    f"default-src 'none'; style-src {_hash(STYLE)}; script-src {_hash(SCRIPT)}; img-src data:; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
