"""Screenshot regressions: semantic card icons and aligned routing presets."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from test_mobile_layout import ROOT, _render_at_phone_viewport


def _cards_from_real_renderers(tmp_path: Path) -> str:
    # Node 18 does not infer ESM for .js without package metadata. Run copies of
    # the actual modules in an explicitly ESM fixture, not a transformed mock.
    shutil.copytree(ROOT / "static" / "js", tmp_path / "js")
    (tmp_path / "package.json").write_text('{"type":"module"}')
    script = """
      import { renderClients } from './js/clients.js';
      import { renderNodes } from './js/nodes.js';
      globalThis.window = { location: { origin: 'https://example.test' } };
      const view = { innerHTML: '' };
      const state = { view: 'clients', navigationGeneration: 1, me: { role: 'owner', panel_version: '0.12' }, nodes: [], fleet: [], fleetSelection: '', nodeTab: {}, routingTargets: [], versions: { enabled: false, components: {} } };
      const api = async (path) => ({ items: path === '/api/clients' ? [
        { client: { id: 'c1', display_name: 'iphone-my', state: 'active' }, grants: [
          { id: 'g1', protocol: 'naive', runtime_username: 'iphone-my', desired_state: 'enabled', observed_state: 'enabled', node_id: 'remote', routing_lane: 'service', secret_ref: 'stored' },
        ] },
        { client: { id: 'c2', display_name: 'test', state: 'active' }, grants: [] },
      ] : path === '/api/nodes' ? [
        { node_id: 'local', kind: 'local', display_name: 'Этот сервер', enrollment_state: 'active', connectivity_state: 'online', pending_commands: 0, inventory: {}, identity: {guid:'test-guid'} },
        { node_id: 'linked', kind: 'remote', transport: 'panel', display_name: 'Связанный узел', link: { panel_url: 'https://node.example.test', panel_version: '0.12', status: 'online', enabled: true, status_json: {}, desired_generation: 0, acknowledged_generation: 0 } },
      ] : [] });
      const context = { state, ui: { view }, root: {querySelector: () => null}, api };
      await renderClients(context, 1);
      const clients = view.innerHTML;
      state.view = 'fleet';
      await renderNodes(context, 1);
      console.log(JSON.stringify({ clients, nodes: view.innerHTML }));
    """
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    cards = json.loads(result.stdout)
    return cards["clients"] + cards["nodes"]


def test_mobile_cards_have_semantic_icons_and_quick_settings_align(tmp_path: Path) -> None:
    """Client/node icons, grant corners, and routing presets remain usable at 390px."""
    css = (ROOT / "static" / "style.css").read_text()
    cards = _cards_from_real_renderers(tmp_path)
    presets = '''<div class="routing-layout"><form class="routing-editor">
      <div class="routing-presets"><b>Быстрые настройки</b>
        <label class="routing-preset"><input type="checkbox"> Торренты → блок</label>
        <label class="routing-preset"><input type="checkbox"> Реклама → блок</label>
        <label class="routing-preset"><input type="checkbox"> Российские домены и IP → напрямую</label>
      </div></form></div>'''
    script = """
      addEventListener('load', () => {
        const errors = [];
        if (innerWidth !== 390) errors.push(`viewport is ${innerWidth}px instead of 390px`);
        for (const [selector, expected] of [['.client-card', 2], ['.local-node', 1], ['.linked-node', 1]]) {
          const cards = [...document.querySelectorAll(selector)];
          if (cards.length !== expected) errors.push(`${selector}: expected ${expected}, got ${cards.length}`);
          for (const card of cards) {
            const glyph = card.querySelector(':scope > .user-glyph');
            const icon = glyph?.querySelector('svg[aria-hidden="true"]');
            if (!icon || !icon.querySelector('path, circle, rect')) errors.push(`${selector}: badge shows initials, not a semantic icon`);
            if (glyph?.textContent.trim()) errors.push(`${selector}: initials remain visible`);
            const box = glyph?.getBoundingClientRect();
            if (!box || box.width < 32 || box.height < 32) errors.push(`${selector}: icon badge too small`);
          }
        }
        const grant = document.querySelector('.client-card .grant-chip[data-grant-id="g1"]');
        if (!grant) errors.push('grant card missing');
        else {
          const box = grant.getBoundingClientRect();
          const radius = parseFloat(getComputedStyle(grant).borderTopLeftRadius);
          if (radius > 12) errors.push(`grant card has pill/oval corners: ${radius}px`);
          if (grant.scrollWidth > grant.clientWidth + 1 || box.right > innerWidth + 1) errors.push('grant content escapes card');
        }
        const group = document.querySelector('.routing-presets');
        const title = group.querySelector('b').getBoundingClientRect();
        const labels = [...group.querySelectorAll('.routing-preset')];
        const bounds = group.getBoundingClientRect();
        let bottom = title.bottom;
        for (const label of labels) {
          const box = label.getBoundingClientRect();
          const checkbox = label.querySelector('input').getBoundingClientRect();
          if (box.top < bottom + 3) errors.push('quick settings title or previous toggle shares a row');
          if (box.height < 36 || box.left < bounds.left - 1 || box.right > bounds.right + 1) errors.push('quick setting escapes group or has a short target');
          if (Math.abs(box.left - bounds.left) > 1 || Math.abs(box.right - bounds.right) > 1) errors.push('quick setting does not fill its row');
          if (Math.abs(checkbox.top + checkbox.height / 2 - box.top - box.height / 2) > 2) errors.push('quick setting checkbox is off-center');
          bottom = box.bottom;
        }
        if (document.documentElement.scrollWidth > innerWidth + 1) errors.push('page scrolls horizontally');
        document.body.dataset.result = errors.length ? 'fail' : 'pass';
        document.body.dataset.errors = JSON.stringify(errors);
      });
    """
    page = tmp_path / "mobile-badges-presets.html"
    page.write_text(
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<style>{css}</style></head><body><main style='padding:10px'>{cards}{presets}</main>"
        f"<script>{script}</script></body></html>"
    )
    screenshot = Path(os.environ["MOBILE_UI_SCREENSHOT"]) if os.environ.get("MOBILE_UI_SCREENSHOT") else None
    rendered = _render_at_phone_viewport(page, tmp_path / "chromium-profile", screenshot)
    assert rendered["innerWidth"] == 390
    assert rendered["result"] == "pass", json.loads(rendered["errors"])
