// Run with node on ams-test; no panel service or proxy requests are needed.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../static/js/monitoring.js', import.meta.url), 'utf8')
  .replace(/^import [\s\S]*?from "[^\"]+";\n/gm, '')
  .replace(/^export /gm, '');
const box = { console, number: String, esc: String, formatRate: String, formatBytes: String,
  alignSeries(series) {
    const x = [...new Set(Object.values(series).flatMap(a => a.map(p => p[0])))].sort((a,b) => a-b);
    return { x, series: Object.fromEntries(Object.entries(series).map(([k,a]) => [k, x.map(t => a.find(p => p[0] === t)?.[1] ?? null)])) };
  } };
vm.createContext(box);
vm.runInContext(source, box);
const node = (naive, status='ok') => ({status, protocols:{naive}});
const client = {available:true, live:true, source:'naive_connect', semantics:'authenticated_connect_payload', up_bps:12, down_bps:24, up_bytes:120, down_bytes:240, connections:2};
const legacy = {available:true, live:true, source:'kernel', up_bps:900, down_bps:800, connections:8};
const unavailable = {available:false, source:'naive_connect', semantics:'authenticated_connect_payload', reason:'live_meter_unavailable'};
const merged = box.mergeProtocols([node(client), node(legacy), node(unavailable), node({available:false,reason:'disabled'})]).naive;
assert.equal(merged.up_bps, 12, 'legacy port counters must not enter CONNECT sum');
assert.equal(merged.source, 'naive_connect');
assert.equal(merged.semantics, client.semantics);
assert.equal(merged.coverage.compatible, 1);
assert.equal(merged.coverage.enabled, 3);
assert.equal(merged.partial, true);
assert.equal(box.mergeProtocols([node(unavailable),node(legacy)]).naive.available, false);
assert.equal(box.mergeProtocols([node({...client,up_bps:null,down_bps:null,connections:null})]).naive.up_bps, null, 'unknown is not zero');
assert.equal(box.mergeProtocols([node({...client,up_bps:999},'stale'),node(client)]).naive.up_bps,12);
assert.equal(box.sampleValues(node(legacy))['naive_connect.up_bps'], null);
assert.equal(box.sampleValues(node(client))['naive_connect.up_bps'], 12);
assert.equal(box.sampleValues(node(unavailable))['naive_connect.up_bps'], null);
assert.match(box.protoMeta(client), /Активных туннелей/);
assert.match(box.protoMeta({...client,connections:null}), /—/);
assert.match(box.protoMeta({connections:5}), /Соединений/);
const chart = box.trafficSeries({series:{'naive_connect.up_bps':[[1,12],[2,null],[3,4]],'naive_connect.down_bps':[[1,24],[2,null],[3,2]],'naive.up_bps':[[1,900]],'naive.down_bps':[[1,800]]}},'sum');
assert.equal(chart.series.find(s => s.id === 'naive_connect').values[0],36);
assert.equal(chart.series.find(s => s.id === 'naive_connect').values[1],null);
assert.match(chart.series.find(s => s.id === 'naive').label,/прежний/);
assert.match(chart.series.find(s => s.id === 'naive_connect').label,/CONNECT/);
console.log('PASS Naive CONNECT fleet, nullable live rates, active tunnels and separate history semantics');
const pending = {...client,up_bps:null,down_bps:null};
assert.equal(box.sumNodes([node(client),node(pending)])['naive_connect.up_bps'],null,'fleet chart and card agree when a source has no fresh rate');
assert.equal(box.trafficSeries({series:{'naive_connect.up_bps':[[1,12]],'naive_connect.down_bps':[[1,null]]}},'sum').series.length,0,'unknown direction is not a fabricated combined rate');
assert.equal(box.sumNodes([node(legacy),node(unavailable)])['naive_connect.up_bps'],null);
