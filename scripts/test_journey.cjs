'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../public/journey.js'), 'utf8');
function fixture(reduced = false) {
  let focus = null, next = 0;
  const pending = new Map();
  const els = Object.fromEntries(['journey','invite','consent','reset','announcer'].map(id => [id, {
    dataset: { phase:'ready' }, disabled: true, textContent:'', listeners:{},
    addEventListener(type, fn) { this.listeners[type] = fn; },
    focus() { focus = id; },
    click() { if (!this.disabled) this.listeners.click(); }
  }]));
  const delays = [];
  const window = { matchMedia: () => ({matches:reduced}),
    setTimeout(fn, ms) { const id = ++next; pending.set(id,fn); delays.push(ms); return id; },
    clearTimeout(id) { pending.delete(id); }
  };
  vm.runInNewContext(source, { document:{getElementById:id=>els[id]}, window });
  return {els, pending, delays, focused:()=>focus, run:()=>{for (const [id,fn] of pending){pending.delete(id);fn();}}};
}
let checks = 0;
function test(name, fn){fn();checks++;console.log('PASS '+name);}
test('initial state waits for an explicit local request',()=>{
 const {els}=fixture();assert.equal(els.journey.dataset.phase,'ready');assert.equal(els.invite.disabled,false);assert.equal(els.consent.disabled,true);assert.equal(els.reset.disabled,true);
});
test('sending requires separate receiving consent',()=>{
 const {els,focused}=fixture();els.invite.click();assert.equal(els.journey.dataset.phase,'invited');assert.equal(els.invite.disabled,true);assert.equal(els.consent.disabled,false);assert.equal(focused(),'consent');assert.match(els.announcer.textContent,/No access has been granted/);
});
test('duplicate source clicks never approve the request',()=>{
 const {els}=fixture();els.invite.click();els.invite.listeners.click();assert.equal(els.journey.dataset.phase,'invited');
});
test('completion reports only a fictional local receipt',()=>{
 const {els,run,focused}=fixture();els.invite.click();els.consent.click();assert.equal(els.journey.dataset.phase,'crossing');assert.equal(focused(),'reset');run();assert.equal(els.journey.dataset.phase,'complete');assert.match(els.announcer.textContent,/not a real delivery/);
});
test('duplicate consent cannot schedule duplicate completion',()=>{
 const {els,pending}=fixture();els.invite.click();els.consent.click();els.consent.listeners.click();assert.equal(pending.size,1);
});
test('reset while crossing cancels the pending completion',()=>{
 const {els,run,pending,focused}=fixture();els.invite.click();els.consent.click();els.reset.click();assert.equal(pending.size,0);run();assert.equal(els.journey.dataset.phase,'ready');assert.equal(focused(),'invite');
});
test('reset declines a waiting fictional invitation',()=>{
 const {els}=fixture();els.invite.click();els.reset.click();assert.equal(els.journey.dataset.phase,'ready');assert.equal(els.consent.disabled,true);
});
test('repeated complete reset cycles retain no previous state',()=>{
 const {els,run}=fixture();for(let i=0;i<4;i++){els.invite.click();els.consent.click();run();els.reset.click();}assert.equal(els.journey.dataset.phase,'ready');
});
test('reduced motion uses immediate completion',()=>{
 const {els,delays,run}=fixture(true);els.invite.click();els.consent.click();assert.deepEqual(delays,[0]);run();assert.equal(els.journey.dataset.phase,'complete');
});
test('incomplete markup fails harmlessly',()=>{
 vm.runInNewContext(source,{document:{getElementById:()=>null}});
});
console.log(`${checks} local journey checks passed.`);
