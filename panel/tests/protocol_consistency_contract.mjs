import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const root = new URL('../static/',import.meta.url);
const strip = s => s.replace(/^import [\s\S]*?from "[^\"]+";\n/gm,'').replace(/^export /gm,'');
const load = file => strip(readFileSync(new URL(`js/${file}.js`,root),'utf8'));
const shared = ['common','protocol-users','grant-row-actions'].map(file => {try{return load(file)}catch{return ''}}).join('\n');
const ctx = (role='owner') => ({state:{me:{role}},ui:{},root:{}});
const item = {username:'runtime-account',client_name:'Анна <test>',client_id:'c1',grant_id:'g1',enabled:true,traffic_available:true,credential_kept:true,rx:0,tx:10,upload_bytes:0,download_bytes:10,upload_bytes_decimal:'0',download_bytes_decimal:'10',total_bytes_decimal:'10'};
for (const [file,row] of [['users','userRow'],['naive','naiveRow'],['mieru','mieruRow'],['amneziawg','accessRow'],['trusttunnel','accessRow']]) {
 const box={console};vm.createContext(box);vm.runInContext(shared+'\n'+load(file),box);
 const html=box[row](ctx(),item);
 assert.match(html,/<b>Анна &lt;test&gt;<\/b>/,`${file}: client must be primary identity`);
 assert.match(html,/>Настроить<\//,`${file}: settings must be visible`);
 assert.match(html,/>Удалить доступ<\//,`${file}: delete must be visible`);
 const settings=html.indexOf('<details'),end=html.indexOf('</details>');
 const del=html.indexOf('>Удалить доступ</');
 assert.ok(del < settings || del > end,`${file}: deletion must not be hidden in settings`);
 const viewer=box[row](ctx('viewer'),item);
 assert.doesNotMatch(viewer,/>Настроить<|>Удалить доступ</,`${file}: viewer must not mutate`);
 const unknown=box[row](ctx(),{username:'unmapped',enabled:false,traffic_available:false});
 assert.match(unknown,/Не привязан к клиенту/,`${file}: unmapped identity explicit`);
 assert.match(unknown,/Недоступно|—/,`${file}: missing traffic is not measured zero`);
 if(file==='users') assert.match(box[row](ctx(),{...item,runtime_total_octets:1234}),/1.2 КБ/, 'runtime traffic not replaced by no quota');
}
console.log('PASS five protocol client identities, settings/delete, role guards and truthful traffic');
const limits = {console};vm.createContext(limits);vm.runInContext(shared+'\n'+load('access-limits'),limits);
assert.equal(limits.gbToBytes('1.25'),1250000000);
assert.equal(limits.gbToBytes('0.000000001'),1);
assert.equal(limits.bytesToGb('1250000001'),'1.250000001');
assert.throws(()=>limits.gbToBytes('9007199254740993'));
const elements = {};
const rootEl={querySelector:s=>elements[s]||null};
const fields=(prefix,bytesOn=false,daysOn=false)=>{
 elements[`#${prefix}-traffic-enabled`]={checked:bytesOn};elements[`#${prefix}-traffic-gb`]={value:'1.25'};
 elements[`#${prefix}-validity-enabled`]={checked:daysOn};elements[`#${prefix}-validity-days`]={value:'7',dataset:{}};
 elements[`#${prefix}-rolling-days`]={value:'30'};
};
fields('test');
for(const protocol of ['mtproxy','naive','mieru','amneziawg','trusttunnel']){
 const grant=limits.applyManualLimits([{protocol,options:{}}],rootEl,'test')[0];
 assert.deepEqual(Object.keys(grant.options),[],'default no quota');assert.equal(grant.valid_until,undefined,'default no expiry');
}
fields('test',true,true);
assert.equal(limits.applyManualLimits([{protocol:'mtproxy'}],rootEl,'test')[0].options.data_quota_bytes,1250000000);
assert.equal(limits.applyManualLimits([{protocol:'naive'}],rootEl,'test')[0].options.quota_bytes,1250000000);
assert.equal(limits.applyManualLimits([{protocol:'mieru'}],rootEl,'test')[0].options.quotas[0].megabytes,1193);
assert.throws(()=>limits.applyManualLimits([{protocol:'amneziawg'}],rootEl,'test'));
assert.equal(limits.validityLimit(rootEl,'test',1000000),1000+7*86400);
elements['#test-validity-days'].dataset={original:'123456',initial:'7'};
assert.equal(limits.validityLimit(rootEl,'test',1000000),123456,'untouched original expiry preserved exactly');
fields('test',false,false);
assert.equal(limits.trafficLimit(rootEl,'test'),null);
assert.equal(limits.validityLimit(rootEl,'test'),null);
const html=readFileSync(new URL('index.html',root),'utf8');
assert.doesNotMatch(html,/id="mieru-(?:days|mib)"[^>]*value="(?:30|1024)"/,'Mieru must not inject finite defaults');
for(const prefix of ['new-user','new-naive','new-mieru','new-awg','new-tt','new-client']){
 assert.match(html,new RegExp(`id="${prefix}-validity-enabled"[^>]*type="checkbox"`));
 assert.doesNotMatch(html,new RegExp(`id="${prefix}-(?:traffic|validity)-enabled"[^>]*checked`));
}
console.log('PASS unlimited defaults, opt-in GB/day payloads, Mieru rounding and exact unchanged expiry');
let scheduled;
const rateCell={dataset:{liveRate:'alice'},textContent:'',title:''};
const rateRoot={querySelector:()=>rateCell,querySelectorAll:()=>[rateCell]};
const rates={console,AbortController,performance:{now:()=>1},document:{hidden:false},window:{setTimeout(){return 1;},clearTimeout(){},clearInterval(){},setInterval(fn){scheduled=fn;return 1;}},formatRate:String};
vm.createContext(rates);vm.runInContext(load('common')+'\n'+load('live-rates'),rates);
const rateContext={state:{view:'users',navigationGeneration:1},ui:{view:rateRoot},api:async()=>({live:true,clients:{alice:{up_bps:12,down_bps:24,total_bps:36}}})};
rates.startLiveRates(rateContext,1,'users','mtproxy');
await new Promise(setImmediate);
assert.match(rateCell.textContent,/Сейчас/);
rateContext.api=async()=>{throw new Error('unavailable')};scheduled();
await new Promise(setImmediate);
assert.equal(rateCell.textContent,'','failed poll clears stale current rate');
assert.equal(rateContext.state.liveRatesLast,null);
console.log('PASS unavailable live-rate poll clears stale current data');
