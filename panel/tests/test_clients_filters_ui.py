"""«Клиенты» (v1.0.2): search and filters, and the grant rows that open the grant window.

The real modules run in Node (as in test_mobile_badges_presets): the filter is the code the
screen uses, not a re-implementation of it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"

CLIENTS = [
    {"client": {"id": "c1", "display_name": "Ноутбук Сергея", "state": "active"}, "grants": [
        {"id": "g1", "protocol": "mtproxy", "runtime_username": "laptop", "node_id": "local", "desired_state": "enabled", "observed_state": "enabled", "secret_ref": {"id": "s"}, "routing_lane": None},
        {"id": "g2", "protocol": "mieru", "runtime_username": "laptop", "node_id": "fra", "desired_state": "disabled", "observed_state": "disabled", "secret_ref": {"id": "s"}, "routing_lane": "own"},
    ]},
    {"client": {"id": "c2", "display_name": "home-iphone", "state": "suspended"}, "grants": [
        {"id": "g3", "protocol": "naive", "runtime_username": "phone", "node_id": "fra", "desired_state": "enabled", "observed_state": "pending", "secret_ref": None, "routing_lane": None},
    ]},
    {"client": {"id": "c3", "display_name": "Старый <b>телефон</b>", "state": "archived"}, "grants": [
        {"id": "g4", "protocol": "naive", "runtime_username": "old", "node_id": "local", "desired_state": "deleted", "observed_state": "missing", "secret_ref": None, "routing_lane": None},
    ]},
]
NODES = [
    {"node_id": "local", "display_name": "Этот сервер"},
    {"node_id": "fra", "display_name": "Frankfurt", "transport": "panel", "link": {"enabled": True}},
]


def _node(tmp_path: Path, body: str) -> dict:
    shutil.copytree(STATIC / "js", tmp_path / "js")
    (tmp_path / "package.json").write_text('{"type":"module"}')
    script = f"""
      import {{ matchesClient, CLIENT_FILTER_DEFAULT, renderClients, handleClientsClick, handleClientsInput, openImportModal }} from './js/clients.js';
      globalThis.window = {{ location: {{ origin: 'https://example.test' }} }};
      const clients = {json.dumps(CLIENTS)};
      const nodes = {json.dumps(NODES)};
      const view = {{ innerHTML: '' }};
      const state = {{ view: 'clients', navigationGeneration: 1, me: {{ role: 'owner' }}, clients, nodes,
        clientFilter: {{ query: '', state: 'all', protocol: '', node: '', issue: '' }} }};
      const context = {{ state, ui: {{ view }}, root: {{ querySelector: () => null }},
        api: async (path) => ({{ items: path.startsWith('/api/clients') ? clients : nodes }}) }};
      const pick = (filter) => clients.filter((entry) => matchesClient(context, entry, {{ ...state.clientFilter, ...filter }})).map((entry) => entry.client.id);
      {body}
    """
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=tmp_path, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def test_search_and_filters_select_the_right_clients(tmp_path: Path) -> None:
    found = _node(tmp_path, """
      console.log(JSON.stringify({
        all: pick({}),
        byName: pick({ query: 'НОУТБУК' }),
        byAccount: pick({ query: 'phone' }),
        byNode: pick({ query: 'frankfurt' }),
        twoWords: pick({ query: 'сергея laptop' }),
        suspended: pick({ state: 'suspended' }),
        mieru: pick({ protocol: 'mieru' }),
        mieruOnLocal: pick({ protocol: 'mieru', node: 'local' }),
        onFra: pick({ node: 'fra' }),
        pending: pick({ issue: 'pending' }),
        orphan: pick({ issue: 'orphan' }),
        disabled: pick({ issue: 'disabled' }),
        lane: pick({ issue: 'lane' }),
        problem: pick({ issue: 'problem' }),
        empty: pick({ issue: 'empty' }),
        noNaive: pick({ issue: 'empty', protocol: 'naive' }),
        deletedIsNotOrphan: pick({ issue: 'orphan', state: 'archived' }),
      }));
    """)
    assert found["all"] == ["c1", "c2", "c3"]
    assert found["byName"] == ["c1"]
    assert found["byAccount"] == ["c2"]
    assert found["byNode"] == ["c1", "c2"]
    assert found["twoWords"] == ["c1"]
    assert found["suspended"] == ["c2"]
    assert found["mieru"] == ["c1"]
    # protocol and node hold on one and the same grant
    assert found["mieruOnLocal"] == []
    assert found["onFra"] == ["c1", "c2"]
    assert found["pending"] == ["c2"]
    assert found["orphan"] == ["c2"]
    assert found["disabled"] == ["c1"]
    assert found["lane"] == ["c1"]
    assert found["problem"] == ["c2"]
    # a deleted grant does not count: the archived client has no access at all
    assert found["empty"] == ["c3"]
    assert found["noNaive"] == ["c1", "c3"]
    assert found["deletedIsNotOrphan"] == []


def test_the_screen_opens_on_active_clients_and_the_card_keeps_two_buttons_and_a_menu(tmp_path: Path) -> None:
    result = _node(tmp_path, """
      await renderClients(context, 1);
      const cards = view.innerHTML.split('<article').slice(1);
      const buttons = (html) => (html.match(/<button[^>]*data-client-action="[a-z]+"/g) || []).length;
      state.clientFilter = { ...CLIENT_FILTER_DEFAULT, query: 'нет такого' };
      context.api = async (path) => path.startsWith('/api/clients') ? { items: [], total: 3, matched: 0, counts: {} } : { items: nodes };
      await renderClients(context, 1);
      console.log(JSON.stringify({ initial: CLIENT_FILTER_DEFAULT.state, cards, empty: view.innerHTML }));
    """)
    assert result["initial"] == "active"
    # the state the panel starts with and the one «Сбросить» restores are the same
    assert 'clientFilter: { query: "", state: "active"' in (STATIC / "js" / "state.js").read_text()
    active, suspended, archived = result["cards"]
    for card in (active, suspended):
        menu = card[card.index('class="client-menu"'):]
        assert 'aria-label="Ещё действия"' in menu and 'aria-expanded="false"' in menu and 'aria-haspopup="menu"' in menu
        assert 'role="menu" hidden' in menu
        # the three rarer actions sit inside the menu, not beside «Открыть»
        outside = card[:card.index('class="client-menu"')]
        for action in ("rename", "suspend", "resume", "archive"):
            assert f'data-client-action="{action}"' not in outside
        assert 'data-client-action="rename"' in menu and 'data-client-action="archive"' in menu
    assert 'data-client-action="resume"' in suspended and 'data-client-action="suspend"' in active
    # an archived card's menu holds only the permanent delete
    archived_menu = archived[archived.index('class="client-menu"'):]
    assert 'data-client-action="delete"' in archived_menu and 'data-client-action="rename"' not in archived
    # an empty list under a narrowed state offers the whole list
    assert 'data-client-action="show-all"' in result["empty"]


def test_the_card_lists_clickable_grant_rows_and_escapes_names(tmp_path: Path) -> None:
    rendered = _node(tmp_path, """
      await renderClients(context, 1);
      console.log(JSON.stringify({ html: view.innerHTML }));
    """)["html"]
    # every live grant is a row that opens its own window; the deleted one is not listed
    for grant_id in ("g1", "g2", "g3"):
        assert f'data-grant-open="{grant_id}"' in rendered
    assert 'data-grant-open="g4"' not in rendered
    # the per-row buttons moved into the grant window
    assert 'data-client-action="grant-' not in rendered
    # the toolbar: search, state pills with counts, the three selects, the counter
    for fragment in ('id="client-search"', 'data-client-filter-state="suspended"', "Приостановленные · 1",
                     'id="client-filter-protocol"', 'id="client-filter-node"', 'id="client-filter-issue"', "Клиентов: 3"):
        assert fragment in rendered, fragment
    assert ">Frankfurt<" in rendered
    assert "<b>телефон</b>" not in rendered and "&lt;b&gt;телефон&lt;/b&gt;" in rendered





def test_paging_and_server_search_keep_the_dom_bounded_and_discard_stale_responses(tmp_path):
    result = _node(tmp_path, """
      const rows = Array.from({length: 123}, (_, i) => ({client: {id: `id-${i}`, display_name: `Person ${i}`, state:'active'}, grants: []}));
      const calls = [];
      const list = {innerHTML:''}, counter = {textContent:''};
      const badge = {textContent:''};
      context.root.querySelector = selector => selector === '#clients-count' ? badge : null;
      view.querySelector = (selector) => selector === '.client-list' ? list : selector === '#client-count' ? counter : null;
      view.querySelectorAll = () => [];
      context.ui.toast = () => {};
      context.api = async (path) => {
        calls.push(path);
        if (path === '/api/nodes') return {items:nodes};
        const url = new URL(path, 'https://example.test');
        const start = Number(url.searchParams.get('cursor') || 0);
        const selected = url.searchParams.get('query') ? rows.filter(row => row.client.display_name.includes(url.searchParams.get('query'))) : rows;
        const limit = Number(url.searchParams.get('limit') || selected.length);
        return {items:selected.slice(start,start+limit), next_cursor: start+limit < selected.length ? String(start+limit) : null,
          matched:selected.length,total:rows.length,counts:{active:rows.length,suspended:0,archived:0},node_ids:['local','fra']};
      };
      await renderClients(context,1);
      const first = state.clients.map(row=>row.client.id);
      const firstBadge = badge.textContent;
      handleClientsClick(context,{dataset:{clientAction:'next-page'}});
      await new Promise(setImmediate);
      const second = state.clients.map(row=>row.client.id);
      const secondCards = (list.innerHTML.match(/data-client-id=/g)||[]).length;
      handleClientsClick(context,{dataset:{clientAction:'previous-page'}});
      await new Promise(setImmediate);
      const back = state.clients.map(row=>row.client.id);
      handleClientsInput(context,{id:'client-search',value:'Person 122'});
      await new Promise(resolve=>setTimeout(resolve,350));
      const found = state.clients.map(row=>row.client.id);
      const pending = [];
      context.api = path => new Promise(resolve=>pending.push({path,resolve}));
      handleClientsInput(context,{id:'client-filter-protocol',value:'mieru'});
      handleClientsInput(context,{id:'client-filter-protocol',value:'naive'});
      pending[1].resolve({items:[rows[2]],next_cursor:null,total:123,matched:1,counts:{active:123}});
      await new Promise(setImmediate);
      pending[0].resolve({items:[rows[1]],next_cursor:null,total:123,matched:1,counts:{active:123}});
      await new Promise(setImmediate);
      console.log(JSON.stringify({first,second,back,found,secondCards,calls,firstBadge,lastBadge:badge.textContent,last:state.clients[0].client.id}));
    """)
    assert result["first"] == [f"id-{i}" for i in range(50)]
    assert result["firstBadge"] == result["lastBadge"] == "123"
    assert result["second"] == [f"id-{i}" for i in range(50, 100)]
    assert result["secondCards"] == 50 and result["back"] == result["first"]
    assert result["found"] == ["id-122"] and result["last"] == "id-2"
    assert all("limit=50" in path for path in result["calls"] if path.startswith("/api/clients"))


def test_import_still_offers_clients_outside_the_current_page(tmp_path):
    result = _node(tmp_path, """
      const rows = Array.from({length:123},(_,i)=>({client:{id:`id-${i}`,display_name:`Person ${i}`},grants:[]}));
      state.clients = rows.slice(0,50);
      const elements = new Map();
      context.root.querySelector = selector => {
        if (!elements.has(selector)) elements.set(selector,{innerHTML:'',textContent:''});
        return elements.get(selector);
      };
      context.ui.openModal = () => {};
      const calls = [];
      context.api = async path => {
        calls.push(path);
        if (path === '/api/clients') return {items:rows};
        return {already_imported:0,proposals:[{same_username_hint:false,items:[{protocol:'naive',runtime_username:'imported',enabled:true,imported_grant_id:null}]}]};
      };
      await openImportModal(context);
      console.log(JSON.stringify({html:elements.get('#client-import-rows').innerHTML,calls,error:elements.get('#client-import-error').textContent}));
    """)
    assert not result["error"] and "/api/clients" in result["calls"]
    assert result["html"].count('<option value="id-') == 123
    assert '<option value="id-122">Person 122</option>' in result["html"]
