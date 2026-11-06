import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const strip = source => source.replace(/^import [\s\S]*?from "[^\"]+";\n/gm,'').replace(/^export /gm,'');
let now = 1, next = 0, interval;
const timers = new Map();
const box = {console,AbortController,performance:{now:()=>now},document:{hidden:false},formatRate:String,
  window:{clearInterval(){},setInterval(fn){interval=fn;return 1},
    setTimeout(fn,ms){const id=++next;timers.set(id,{at:now+ms,fn});return id},clearTimeout(id){timers.delete(id)}}};
vm.createContext(box);
for(const file of ['common','live-rates']) vm.runInContext(strip(readFileSync(new URL(`../static/js/${file}.js`,import.meta.url),'utf8')),box);
const flush = ()=>new Promise(setImmediate);
const advance = async ms => {now+=ms;for(const [id,timer] of [...timers])if(timer.at<=now){timers.delete(id);timer.fn()}await flush()};
const cell={dataset:{liveRate:'alice'},textContent:'',title:''};
const root={querySelector:()=>cell,querySelectorAll:()=>[cell]};
const measured=()=>({live:true,clients:{alice:{up_bps:12,down_bps:24,total_bps:36}}});
let calls=0, late;
const context={state:{view:'users',navigationGeneration:1},ui:{view:root},api:async()=>{calls++;return measured()}};
box.startLiveRates(context,1,'users','mtproxy');await flush();
assert.match(cell.textContent,/Сейчас/);
context.api=()=>{calls++;return new Promise(resolve=>{late=resolve})};
interval();interval();await flush();
assert.equal(calls,2,'single in-flight request per page');
await advance(4000);
assert.equal(cell.textContent,'','hung request expires instead of leaving current rate');
late(measured());await flush();
assert.equal(cell.textContent,'','late success must not resurrect an expired poll');
context.api=async()=>measured();interval();await flush();
assert.match(cell.textContent,/Сейчас/);
// Even if browser timers are throttled, repaint must enforce monotonic sample age.
now+=11000;box.repaintLiveRates(context);
assert.equal(cell.textContent,'','stale repaint never restores old current rate');
context.api=async()=>({live:true,clients:{alice:{up_bps:0,down_bps:0,total_bps:0}}});
interval();await flush();
assert.match(cell.textContent,/Сейчас/,'a freshly measured zero is not unavailable');
console.log('PASS hung polls, single-flight, late replies, monotonic repaint expiry and measured zero');
