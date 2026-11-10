import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const closes = [];
class Dialog extends EventTarget {
  open = false;
  returnValue = '';
  showModal() { assert.equal(this.open, false); this.open = true; }
  close(value) {
    assert.equal(this.open, true);
    this.open = false;
    if (value !== undefined) this.returnValue = value;
    // HTML queues `close`; `open` changes synchronously before that event.
    closes.push(() => this.dispatchEvent(new Event('close')));
  }
}
const nodes = new Map();
for (const name of ['confirm', 'choose', 'ask-text']) nodes.set(`#${name}`, new Dialog());
const root = {
  activeElement: null,
  addEventListener() {},
  createElement: () => ({}),
  querySelectorAll: () => [],
  querySelector(selector) {
    if (!nodes.has(selector)) nodes.set(selector, {
      textContent: '', value: '', select() {},
      replaceChildren(...options) { this.value = options[0]?.value || ''; },
    });
    return nodes.get(selector);
  },
};
const window = {
  location: { hash: '#versions' }, addEventListener() {}, setTimeout() {},
  history: { state: null,
    pushState(state) { this.state = state; }, replaceState(state) { this.state = state; }, back() {} },
};
const qrSource = readFileSync(new URL('../static/js/qr.js', import.meta.url), 'utf8')
  .replace(/^import .*;\n/gm, '').replace(/^export /gm, '');
const source = readFileSync(new URL('../static/js/ui.js', import.meta.url), 'utf8')
  .replace(/^import .*;\n/gm, '').replace(/^export /gm, '');
const box = { window, document: root, query: (selector, scope) => selector === '#qr-modal' ? null : scope.querySelector(selector) };
vm.createContext(box);
vm.runInContext(qrSource, box);
vm.runInContext(source, box);
const ui = box.createUi(root);
const flush = async () => { for (let n = 0; n < 8; n++) await Promise.resolve(); };
const deliverClose = async () => { assert.ok(closes.length); closes.shift()(); await flush(); };

for (const [selector, invoke, accepted, cancelled] of [
  ['#confirm', () => ui.confirmed('Update', 'Build'), true, false],
  ['#choose', () => ui.choose('Lane', 'Choose', [{ id: 'lane-one', label: 'One' }]), 'lane-one', null],
  ['#ask-text', () => ui.askText('Rename', 'Name', { value: ' Alice ' }), 'Alice', null],
]) {
  const dialog = nodes.get(selector);
  const first = invoke();
  await flush();
  if (!dialog.open) await first; // Surface a controller failure instead of hiding it behind geometry.
  assert.equal(dialog.open, true, `${selector}: first opening is ready`);
  dialog.close('cancel');
  const second = invoke();
  await flush();
  assert.equal(dialog.open, false, `${selector}: reopen waits for the old close event`);
  await deliverClose();
  assert.equal(await first, cancelled, `${selector}: cancel cannot become approval`);
  assert.equal(dialog.open, true);
  let settled = false;
  second.then(() => { settled = true; });
  await flush();
  assert.equal(settled, false, `${selector}: old close cannot settle the new request`);
  dialog.close('default');
  await deliverClose();
  assert.equal(await second, accepted);
  // Escape/programmatic dismissal does not necessarily replace returnValue.
  const third = invoke();
  await flush();
  dialog.close();
  await deliverClose();
  assert.equal(await third, cancelled, `${selector}: prior approval never survives a new opening`);
}
assert.equal(closes.length, 0);
console.log('PASS queued close/reopen isolation and stale-returnValue dismissal for confirmation, choice and text');
