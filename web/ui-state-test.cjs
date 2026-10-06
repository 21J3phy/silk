/* Dependency-free UI state regression checks in a deliberately minimal mock DOM.
 * These test request/state behavior, not browser rendering or accessibility.
 * Run: node web/ui-state-test.cjs
 */
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto').webcrypto;

class Node {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.listeners = {};
    this.attrs = {}; this.className = ''; this.value = ''; this.checked = false; this.disabled = false;
    this._text = ''; this.parent = null;
    this.classList = { toggle: (name, force) => { const set = new Set(this.className.split(' ').filter(Boolean)); const on = force === undefined ? !set.has(name) : force; on ? set.add(name) : set.delete(name); this.className = [...set].join(' '); }, contains: (name) => this.className.split(' ').includes(name) };
  }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get isConnected() { return !!this.parent || !!this.id; }
  append(...nodes) { for (let node of nodes) { if (typeof node === 'string') { const child = new Node('#text'); child.textContent = node; node = child; } node.parent = this; this.children.push(node); } }
  replaceChildren(...nodes) { this.children.forEach((n) => { n.parent = null; }); this.children = []; this._text = ''; this.append(...nodes); }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  async fire(type) { for (const listener of this.listeners[type] || []) await listener({ target: this, preventDefault() {} }); }
  setAttribute(key, value) { this.attrs[key] = value; }
  removeAttribute(key) { delete this.attrs[key]; }
  contains(node) { return this === node || this.children.some((child) => child.contains(node)); }
  matches(selector) {
    if (selector.startsWith('.')) return this.classList.contains(selector.slice(1));
    if (selector === 'input:checked') return this.tagName === 'INPUT' && this.checked;
    const tag = selector.match(/^[a-z]+/i)?.[0];
    if (tag && this.tagName !== tag.toUpperCase()) return false;
    for (const match of selector.matchAll(/\[([^\]]+)\]/g)) {
      if (match[1] === 'open') { if (!this.open) return false; }
      else if (match[1].startsWith('data-')) {
        const key = match[1].slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase());
        if (!(key in this.dataset)) return false;
      }
    }
    return !!tag || selector.startsWith('[');
  }
  querySelectorAll(selector) { return this.children.flatMap((c) => [...(c.matches(selector) ? [c] : []), ...c.querySelectorAll(selector)]); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  focus() { document.activeElement = this; }
  reset() { if (this.id === 'message-form') nodes['meeting-title'].value = 'Project sync'; if (this.id === 'invitation-form') nodes['invitation-purpose'].value = 'Find a time for a 30-minute project sync.'; }
  scrollIntoView() {}
  setCustomValidity(value) { this.validityMessage = value; }
  reportValidity() { return !this.validityMessage; }
}
const nodes = {};
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
for (const match of html.matchAll(/<([a-z0-9-]+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
  const node = nodes[match[3]] = new Node(match[1]); node.id = match[3];
  node.className = match[2].match(/class="([^"]+)"/)?.[1] || '';
  node.value = match[2].match(/value="([^"]+)"/)?.[1] || '';
  if (match[2].includes('data-mutation')) node.dataset.mutation = '';
}
for (const name of ['invite', 'consent', 'propose', 'approve']) { const node = new Node('span'); node.className = 'step-number'; nodes[`step-${name}`].append(node); }
const document = { getElementById: (id) => { if (!nodes[id]) throw new Error(`Missing node ${id}`); return nodes[id]; }, createElement: (tag) => new Node(tag), createTextNode: (value) => { const n = new Node('#text'); n.textContent = value; return n; }, querySelectorAll: (selector) => Object.values(nodes).flatMap((n) => [...(n.matches(selector) ? [n] : []), ...n.querySelectorAll(selector)]), addEventListener() {}, hidden: false, activeElement: null };
const owners = [{ id: 'alice', name: 'Alice Chen' }, { id: 'bob', name: 'Bob Rivera' }];
const agents = [{ id: 'atlas', owner_id: 'alice', name: 'Atlas', description: 'Alice’s assistant', provider: 'Local fixture', fingerprint: 'abc' }, { id: 'nova', owner_id: 'bob', name: 'Nova', description: 'Bob’s assistant', provider: 'Local fixture', fingerprint: 'def' }];
const option = { start: '2026-10-07T14:00:00Z', duration_minutes: 30 };
let serverOwner = 'alice';
let grants = [{ id: 'g1', invitation_id: 'i1', from_agent: 'atlas', to_agent: 'nova', scope: 'meeting.coordinate', status: 'active', created_at: 1791300000, expires_at: 1791303600, max_turns: 4, turns_used: 0, rate_per_minute: 6, ttl_seconds: 300 }];
let messages = [];
let calls = [];
let failMessage = false;
let holdState = null;
function state() { return { demo: true, current_owner: owners.find((o) => o.id === serverOwner), owners, agents, invitations: [], grants: structuredClone(grants), messages: structuredClone(messages), audit: [], suggested_options: [option], private_availability: [], server_time: 1791300000, limits: { max_options: 3 } }; }
async function fetchMock(url, init) {
  const payload = init.body ? JSON.parse(init.body) : null;
  calls.push({ url, payload });
  if (url === '/api/session') { if (payload) serverOwner = payload.owner_id; return response({ csrf_token: `csrf-${serverOwner}`, current_owner: owners.find((o) => o.id === serverOwner), owners, demo: true }); }
  if (url === '/api/state') { const result = state(); if (holdState) return new Promise((resolve) => { holdState.resolve = () => resolve(response(result)); }); return response(result); }
  if (url === '/api/messages') {
    if (failMessage) throw new TypeError('Simulated dropped response');
    return response({ message: { id: 'm1' }, duplicate: false });
  }
  throw new Error(`Unexpected request ${url}`);
}
function response(body) { return { ok: true, status: 200, json: async () => body }; }
const window = { setTimeout, setInterval() {}, addEventListener() {}, matchMedia: () => ({ matches: true }) };
const context = vm.createContext({ document, window, console, fetch: fetchMock, AbortController, clearTimeout, Intl, crypto, Uint8Array, setTimeout, structuredClone });
const source = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8').replace('  reconnect();\n})();', '  globalThis.ui = { reconnect, switchOwner, refreshState, openComposer, closeComposer, invalidateChangedMessageIntent, state: () => ({ ownerId, epoch, busy, online, composeGrantId, pendingMessageAttempt, state }) };\n})();');
vm.runInContext(source, context);
const ui = context.ui;

(async () => {
  await ui.reconnect();
  assert.equal(ui.state().ownerId, 'alice'); assert.equal(ui.state().online, true);
  assert.ok(nodes.directory.textContent.includes('Atlas'));
  ui.openComposer('g1');
  nodes['meeting-title'].value = 'Project sync';
  failMessage = true;
  await nodes['message-form'].fire('submit');
  const first = calls.filter((c) => c.url === '/api/messages').at(-1).payload;
  assert.ok(first.idempotency_key); assert.equal(ui.state().pendingMessageAttempt.key, first.idempotency_key);
  await nodes['message-form'].fire('submit');
  assert.equal(calls.filter((c) => c.url === '/api/messages').at(-1).payload.idempotency_key, first.idempotency_key, 'Network retry must reuse its key');
  ui.closeComposer(); ui.openComposer('g1');
  assert.equal(ui.state().pendingMessageAttempt.key, first.idempotency_key, 'Closing/reopening must retain the same intent key');
  await ui.reconnect();
  assert.equal(ui.state().pendingMessageAttempt.key, first.idempotency_key, 'Same-owner reconnect must retain the key');
  assert.equal(nodes['meeting-title'].value, 'Project sync');
  nodes['meeting-title'].value = 'Changed intent'; await nodes['meeting-title'].fire('input');
  assert.equal(ui.state().pendingMessageAttempt, null, 'Changing payload invalidates key');
  await nodes['message-form'].fire('submit');
  const second = calls.filter((c) => c.url === '/api/messages').at(-1).payload;
  assert.notEqual(second.idempotency_key, first.idempotency_key);
  failMessage = false;
  await nodes['message-form'].fire('submit');
  assert.equal(calls.filter((c) => c.url === '/api/messages').at(-1).payload.idempotency_key, second.idempotency_key);
  assert.equal(ui.state().pendingMessageAttempt, null, 'Confirmed delivery resets key');
  assert.equal(ui.state().composeGrantId, null);
  ui.openComposer('g1'); nodes['meeting-title'].value = 'Unsaved Alice draft';
  holdState = {};
  const staleRead = ui.refreshState(true);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const release = holdState.resolve; holdState = null;
  await ui.switchOwner('bob');
  release(); await staleRead;
  assert.equal(ui.state().ownerId, 'bob'); assert.equal(ui.state().state.current_owner.id, 'bob', 'A stale Alice response cannot overwrite Bob state');
  assert.equal(nodes['meeting-title'].value, 'Project sync', 'Switching owners clears draft');
  assert.equal(ui.state().composeGrantId, null);
  assert.equal(ui.state().pendingMessageAttempt, null);
  assert.ok(nodes['message-form'].classList.contains('hidden'));
  console.log('PASS: startup/render; retry idempotency; close/reopen; same-owner reconnect; changed intent; confirmed delivery; stale response after owner switch; draft clearing.');
})().catch((error) => { console.error(error); process.exitCode = 1; });
