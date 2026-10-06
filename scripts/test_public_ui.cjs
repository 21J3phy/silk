'use strict';

// Dependency-free state and mock-DOM verification. This is not a browser-rendering test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const publicDir = path.resolve(__dirname, '../public');
const model = require(path.join(publicDir, 'app.js'));
let checks = 0;
function check(name, fn) { fn(); console.log(`PASS ${name}`); checks++; }
function flow(actions, now = 100) { return actions.reduce((state, action) => model.transition(state, action, now), model.initial()); }

check('happy path and one-proposal budget', () => {
  let state = flow(['invite', 'consent', 'propose']);
  assert.equal(state.remaining, 0);
  assert.strictEqual(model.transition(state, 'propose', 101), state);
  state = model.transition(state, 'approve', 102);
  assert.equal(state.receipt, true);
  assert.equal(state.phase, 'approved');
  assert.equal(state.events.length, 4);
  assert.strictEqual(model.transition(state, 'approve', 103), state);
});
check('no proposal or approval before consent', () => {
  for (const phase of ['ready', 'invited', 'consented']) {
    const state = { ...model.initial(), phase };
    assert.strictEqual(model.transition(state, 'approve', 0), state);
  }
  for (const phase of ['ready', 'invited']) {
    const state = { ...model.initial(), phase };
    assert.strictEqual(model.transition(state, 'propose', 0), state);
  }
});
check('decline is terminal until reset', () => {
  const state = flow(['invite', 'decline']);
  assert.equal(state.phase, 'declined');
  assert.strictEqual(model.transition(state, 'consent', 101), state);
});
check('revocation blocks unapproved work', () => {
  const state = flow(['invite', 'consent', 'propose', 'revoke']);
  assert.equal(state.phase, 'revoked');
  assert.equal(state.receipt, false);
  assert.strictEqual(model.transition(state, 'approve', 101), state);
});
check('revocation retains completed receipt', () => {
  const state = flow(['invite', 'consent', 'propose', 'approve', 'revoke']);
  assert.equal(state.phase, 'revoked');
  assert.equal(state.receipt, true);
});
check('exact expiry boundary blocks submission', () => {
  let state = model.transition(model.initial(), 'duration', 0, 60);
  state = model.transition(state, 'invite', 0);
  state = model.transition(state, 'consent', 1000);
  assert.equal(state.expiresAt, 61000);
  assert.equal(model.transition(state, 'propose', 60999).phase, 'proposed');
  state = model.transition(state, 'propose', 61000);
  assert.equal(state.phase, 'expired');
  assert.equal(state.remaining, 1);
  assert.strictEqual(model.transition(state, 'approve', 62000), state);
});
check('expiry preserves completed receipt', () => {
  let state = flow(['invite', 'consent', 'propose', 'approve'], 0);
  state = model.transition(state, 'tick', 300000);
  assert.equal(state.phase, 'expired');
  assert.equal(state.receipt, true);
});
check('reset discards all temporary data', () => {
  const state = flow(['invite', 'consent', 'propose', 'approve']);
  assert.deepEqual(model.transition(state, 'reset', 101), model.initial());
});
check('duration is allowlisted and fixed after invitation', () => {
  let state = model.initial();
  for (const value of [0, -60, 1, Infinity, '60', null]) assert.strictEqual(model.transition(state, 'duration', 0, value), state);
  state = model.transition(state, 'duration', 0, 60);
  assert.equal(state.duration, 60);
  state = model.transition(state, 'invite', 0);
  assert.strictEqual(model.transition(state, 'duration', 0, 900), state);
});
const expectedStatus = {
  product: 'Silk', stage: 'development_preview', live_messaging: false,
  owner_authentication: { state: 'not_configured' }, durable_storage: { state: 'not_configured' },
  connections: ['grok', 'dot'].map(id => ({ id, connected: false, inbound: 'unverified', outbound: 'unverified' }))
};
check('status validator rejects unsupported live claims', () => {
  assert.equal(model.validStatus(expectedStatus), true);
  for (const bad of [null, {}, { ...expectedStatus, live_messaging: true }, { ...expectedStatus, connections: [] }, { ...expectedStatus, connections: [{ id: 'grok', connected: true }] }]) assert.equal(model.validStatus(bad), false);
});

function makeDom(status = expectedStatus, networkError = false) {
  const ids = [...fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8').matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  const env = { now: 1000, requests: [], intervals: new Map(), timers: new Map(), timerId: 0 };
  class Element {
    constructor(id) { this.id = id; this.textContent = ''; this.dataset = {}; this.attributes = {}; this.children = []; this.listeners = {}; this.disabled = false; this.hidden = false; this.value = ''; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    setAttribute(name, value) { this.attributes[name] = value; }
    removeAttribute(name) { delete this.attributes[name]; }
    replaceChildren() { this.children = []; }
    append(child) { this.children.push(child); }
    focus() { env.document.activeElement = this; }
    click(detail = 1) { if (!this.disabled && !this.hidden) { this.focus(); this.listeners.click?.({ target: this, detail }); } }
    change(value) { this.value = String(value); this.listeners.change?.({ target: this }); }
  }
  const elements = Object.fromEntries(ids.map(id => [id, new Element(id)]));
  const steps = [0, 1, 2, 3].map(index => new Element(`step-${index}`));
  const document = {
    activeElement: null, hidden: false, listeners: {},
    getElementById: id => { assert.ok(elements[id], `HTML has required element ${id}`); return elements[id]; },
    querySelectorAll: selector => { assert.equal(selector, '[data-step]'); return steps; },
    createElement: tag => new Element(tag),
    addEventListener(name, callback) { this.listeners[name] = callback; }
  };
  env.document = document;
  env.elements = elements;
  env.steps = steps;
  class FakeDate extends Date { static now() { return env.now; } }
  const context = vm.createContext({
    document, Date: FakeDate, AbortController,
    setInterval: callback => { const id = ++env.timerId; env.intervals.set(id, callback); return id; },
    clearInterval: id => env.intervals.delete(id),
    setTimeout: callback => { const id = ++env.timerId; env.timers.set(id, callback); return id; },
    clearTimeout: id => env.timers.delete(id),
    fetch: async (url, options) => { env.requests.push({ url, options }); if (networkError) throw new Error('Offline'); return { ok: true, json: async () => status }; }
  });
  vm.runInContext(fs.readFileSync(path.join(publicDir, 'app.js'), 'utf8'), context, { filename: 'app.js' });
  return env;
}
const env = makeDom();
const el = env.elements;
check('mock-DOM initializes accessible simulation controls', () => {
  assert.equal(el.advance.disabled, false);
  assert.equal(el.revoke.disabled, true);
  assert.equal(el.reset.disabled, true);
  assert.equal(el.receipt.hidden, true);
  assert.equal(env.steps[0].attributes['aria-current'], 'step');
});
check('double-click cannot consent accidentally', () => {
  el.advance.click();
  assert.equal(el.advance.textContent, 'Give demo consent');
  el.advance.click(2);
  assert.equal(el.advance.textContent, 'Give demo consent');
  assert.equal(el['grant-status'].textContent, 'Consent required');
});
check('mock-DOM happy path includes explicit unsigned receipt', () => {
  for (let i = 0; i < 3; i++) el.advance.click();
  assert.equal(el.receipt.hidden, false);
  assert.equal(el.advance.disabled, true);
  assert.equal(el['activity-list'].children.length, 4);
  assert.equal(el['sample-time'].hidden, false);
  assert.equal(env.document.activeElement, el.reset);
  assert.equal(el.announcer.textContent.includes('No message was sent'), true);
});
check('mock-DOM revoke retains receipt and stops timer', () => {
  el.revoke.click();
  assert.equal(el.receipt.hidden, false);
  assert.equal(el.revoke.disabled, true);
  assert.equal(el.advance.disabled, true);
  assert.equal(el['grant-status'].textContent, 'Example access revoked');
  assert.equal(env.intervals.size, 0);
});
check('mock-DOM reset clears activity and returns focus', () => {
  el.reset.click();
  assert.equal(el.receipt.hidden, true);
  assert.equal(el['activity-list'].children.length, 1);
  assert.equal(el.advance.textContent, 'Create example invite');
  assert.equal(env.document.activeElement, el.advance);
});
check('mock-DOM decline blocks progress', () => {
  el.advance.click(); el.decline.click();
  assert.equal(el.advance.disabled, true);
  assert.equal(el['grant-status'].textContent, 'Invitation declined');
  assert.equal(env.document.activeElement, el.reset);
  el.reset.click();
});
check('mock-DOM countdown expires and cancels pending approval', () => {
  el.duration.change(60);
  el.advance.click(); el.advance.click(); el.advance.click();
  assert.equal(env.intervals.size, 1);
  env.now += 60000;
  [...env.intervals.values()][0]();
  assert.equal(el['grant-status'].textContent, 'Example permission expired');
  assert.equal(el.advance.disabled, true);
  assert.equal(el.receipt.hidden, true);
  assert.equal(env.intervals.size, 0);
});
check('visibility resume validates expiry before proceeding', () => {
  el.reset.click(); el.duration.change(60);
  el.advance.click(); el.advance.click();
  env.now += 60000;
  env.document.listeners.visibilitychange();
  assert.equal(el.advance.disabled, true);
  assert.equal(el['grant-status'].textContent, 'Example permission expired');
});
check('only one read-only same-origin status request without cookies', () => {
  assert.equal(env.requests.length, 1);
  const { url, options } = env.requests[0];
  assert.equal(url, '/api/status');
  assert.equal(options.method, 'GET');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.body, undefined);
});
(async () => {
  const offline = makeDom(undefined, true);
  const invalid = makeDom({ ...expectedStatus, live_messaging: true });
  await new Promise(resolve => setImmediate(resolve));
  check('validated API status is rendered accurately', () => assert.equal(el['status-source'].textContent, 'Development status checked. Live messaging is not enabled.'));
  check('offline API leaves the standalone walkthrough functional', () => {
    assert.equal(offline.elements['status-source'].textContent, 'Status service unavailable. Grok → dot remains not connected.');
    assert.equal(offline.elements.advance.disabled, false);
    assert.equal(offline.timers.size, 0);
  });
  check('unverified API claims fail closed', () => assert.equal(invalid.elements['status-source'].textContent, 'Status service unavailable. Grok → dot remains not connected.'));
  console.log(`\n${checks} public model and mock-DOM checks passed. Browser rendering was not tested.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
