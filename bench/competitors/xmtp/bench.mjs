#!/usr/bin/env node
// XMTP (dev network) measurement for comparison with Silk.
//
//   node bench.mjs --n 100 --out <path.json> [--warmup 10] [--rt 30] [--ids 3]
//
// The orchestrator (this process) spawns every XMTP client in its own child
// process so RSS/CPU numbers are per-client and cold. The environment is
// hard-coded to "dev"; production/mainnet is never contacted. Sends are strictly
// sequential (each waits for delivery before the next).

import { execFile, execFileSync, fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promises as dns } from 'node:dns';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';

const SELF = fileURLToPath(import.meta.url);
const HERE = path.dirname(SELF);
const ENV = 'dev';
const API_HOST = 'grpc.dev.xmtp.network';
const REST_BASE = 'https://dev.xmtp.network';
const DB_ROOT = '/tmp/silk-competitors/xmtp-db';
const TEXT = 'Can we coordinate a time? This is untrusted message data.';
const REPLY = 'ok';
const RECV_TIMEOUT_MS = 30_000;

const { values: args } = parseArgs({
  options: {
    role: { type: 'string', default: 'main' },
    n: { type: 'string', default: '100' },
    warmup: { type: 'string', default: '10' },
    rt: { type: 'string', default: '30' },
    ids: { type: 'string', default: '3' },
    out: { type: 'string' },
  },
});

// ---------- small utilities ----------

const nowMs = () => Number(process.hrtime.bigint()) / 1e6; // system-wide monotonic clock on macOS/Linux
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mb = (bytes) => Math.round((bytes / 1048576) * 10) / 10;
const r3 = (x) => (x == null ? null : Math.round(x * 1000) / 1000);

function quantile(sorted, p) {
  const pos = (sorted.length - 1) * p; // linear interpolation, same as Python statistics.quantiles(method="inclusive")
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

function summarize(xs) {
  if (!xs.length) return { samples: 0, p50: null, p90: null, p99: null, mean: null };
  const s = [...xs].sort((a, b) => a - b);
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  return { samples: s.length, p50: r3(quantile(s, 0.5)), p90: r3(quantile(s, 0.9)), p99: r3(quantile(s, 0.99)), mean: r3(mean) };
}

const median = (xs) => r3(quantile([...xs].sort((a, b) => a - b), 0.5));

// Typed message queue over a child-process IPC channel. `handlers` consume a type instead of queueing it.
function mailbox(proc, handlers = {}) {
  const queue = [];
  const waiters = [];
  proc.on('message', (m) => {
    if (handlers[m.type]) return handlers[m.type](m);
    const i = waiters.findIndex((w) => w.type === m.type);
    if (i >= 0) waiters.splice(i, 1)[0].resolve(m);
    else queue.push(m);
  });
  const failAll = (err) => waiters.splice(0).forEach((w) => w.reject(err));
  proc.on('exit', (code) => failAll(new Error(`child exited with code ${code}`)));
  proc.on('disconnect', () => failAll(new Error('IPC channel closed')));
  return (type, timeoutMs = 300_000) => {
    const i = queue.findIndex((m) => m.type === type);
    if (i >= 0) return Promise.resolve(queue.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        waiters.splice(waiters.indexOf(w), 1);
        reject(new Error(`timed out waiting for "${type}"`));
      }, timeoutMs);
      const w = {
        type,
        resolve: (m) => (clearTimeout(timer), resolve(m)),
        reject: (e) => (clearTimeout(timer), reject(e)),
      };
      waiters.push(w);
    });
  };
}

function rssSampler() {
  const s = { peak: 0, windowPeak: 0 };
  const tick = () => {
    const r = process.memoryUsage.rss();
    if (r > s.peak) s.peak = r;
    if (r > s.windowPeak) s.windowPeak = r;
  };
  tick();
  setInterval(tick, 20).unref();
  return s;
}

const loadedNativeLibs = () =>
  process.report.getReport().sharedObjects.filter((p) => p.endsWith('.node')).map((p) => path.relative(HERE, p));

// ---------- XMTP client helpers (used in child processes) ----------

async function loadSdk() {
  const t0 = nowMs();
  const sdk = await import('@xmtp/node-sdk');
  const accounts = await import('viem/accounts');
  const { toBytes } = await import('viem');
  return { sdk, accounts, toBytes, importMs: nowMs() - t0 };
}

function makeSigner(lib, privateKey) {
  const account = lib.accounts.privateKeyToAccount(privateKey);
  const identifier = { identifier: account.address.toLowerCase(), identifierKind: 0 /* IdentifierKind.Ethereum */ };
  const signer = {
    type: 'EOA',
    getIdentifier: () => identifier,
    signMessage: async (message) => lib.toBytes(await account.signMessage({ message })),
  };
  return { identifier, signer };
}

// Same defaults @xmtp/agent-sdk applies (device sync off, appVersion set).
const clientOptions = (dbPath, dbEncryptionKey) => ({
  env: ENV,
  dbPath,
  dbEncryptionKey,
  disableDeviceSync: true,
  appVersion: 'silk-bench/1',
});

async function freshClient(lib, dbPath) {
  const privateKey = lib.accounts.generatePrivateKey();
  const dbEncryptionKey = `0x${randomBytes(32).toString('hex')}`;
  const { signer } = makeSigner(lib, privateKey);
  const client = await lib.sdk.Client.create(signer, clientOptions(dbPath, dbEncryptionKey));
  return { client, privateKey, dbEncryptionKey };
}

function apiCounters(client) {
  const toNum = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, Number(v)]));
  return { ...toNum(client.debugInformation.apiStatistics()), ...toNum(client.debugInformation.apiIdentityStatistics()) };
}

function childSetup() {
  process.on('disconnect', () => process.exit(1));
  process.on('unhandledRejection', (e) => {
    console.error(`[${args.role}]`, e);
    process.exit(1);
  });
}

// ---------- child roles ----------

// Fresh identity registration (mode=create) or re-open from the local DB (mode=build).
async function roleIdentity() {
  childSetup();
  const recv = mailbox(process);
  const cfg = await recv('config');
  const lib = await loadSdk();
  const t0 = nowMs();
  let client, privateKey, dbEncryptionKey;
  if (cfg.mode === 'create') {
    ({ client, privateKey, dbEncryptionKey } = await freshClient(lib, cfg.dbPath));
  } else {
    ({ privateKey, dbEncryptionKey } = cfg);
    const { identifier } = makeSigner(lib, privateKey);
    client = await lib.sdk.Client.build(identifier, clientOptions(cfg.dbPath, dbEncryptionKey));
  }
  const ms = nowMs() - t0;
  process.send({
    type: 'result',
    ms,
    importMs: lib.importMs,
    privateKey,
    dbEncryptionKey,
    inboxId: client.inboxId,
    installationId: client.installationId,
    isRegistered: client.isRegistered,
    libxmtpVersion: client.libxmtpVersion,
    nativeLibs: loadedNativeLibs(),
  });
  await client.close();
  process.exit(0);
}

// B: waits on a live stream; reports receive timestamps; optionally echoes "ok".
async function roleReceiver() {
  childSetup();
  const rss = rssSampler();
  let echo = false;
  const recv = mailbox(process, {
    echo: (m) => ((echo = m.on), process.send({ type: 'echo-ack' })),
    cpu: () => process.send({ type: 'cpu', usage: process.cpuUsage() }),
  });
  const cfg = await recv('config');
  const lib = await loadSdk();
  const t0 = nowMs();
  const { client } = await freshClient(lib, cfg.dbPath);
  const createMs = nowMs() - t0;
  await sleep(2000);
  const idleRss = process.memoryUsage.rss();
  process.send({ type: 'ready', inboxId: client.inboxId, createMs, idleRss });

  const { peer } = await recv('listen');
  await client.preferences.setConsentStates([
    { entityType: 1 /* ConsentEntityType.InboxId */, entity: peer, state: 1 /* ConsentState.Allowed */ },
  ]);
  const stream = await client.conversations.streamAllMessages();
  process.send({ type: 'listening' });
  recv('finish', 24 * 3600_000).then(() => stream.end());

  let dm;
  for await (const msg of stream) {
    const t = nowMs();
    if (msg.senderInboxId === client.inboxId) continue;
    process.send({ type: 'recv', id: msg.id, t, typeId: msg.contentType?.typeId });
    if (echo && msg.content === TEXT) {
      dm ??= await client.conversations.getConversationById(msg.conversationId);
      await dm.sendText(REPLY);
    }
  }
  process.send({ type: 'final', idleRss, peakRss: rss.peak, apiTotal: apiCounters(client) });
  await client.close();
  process.exit(0);
}

// A: creates the DM, runs warmup, the timed send loop, then the roundtrip loop.
async function roleSender() {
  childSetup();
  const rss = rssSampler();
  const receipts = new Map();
  const pending = new Map();
  const recv = mailbox(process, {
    recv: (m) => {
      receipts.set(m.id, m.t);
      pending.get(m.id)?.(m.t);
    },
  });
  const waitReceipt = (id) =>
    receipts.has(id)
      ? Promise.resolve(receipts.get(id))
      : new Promise((resolve) => {
          const timer = setTimeout(() => (pending.delete(id), resolve(null)), RECV_TIMEOUT_MS);
          pending.set(id, (t) => (clearTimeout(timer), pending.delete(id), resolve(t)));
        });

  const cfg = await recv('config');
  const lib = await loadSdk();
  let t0 = nowMs();
  const { client } = await freshClient(lib, cfg.dbPath);
  const createMs = nowMs() - t0;
  await sleep(2000);
  const idleRss = process.memoryUsage.rss();
  process.send({
    type: 'ready',
    inboxId: client.inboxId,
    createMs,
    idleRss,
    libxmtpVersion: client.libxmtpVersion,
    nativeLibs: loadedNativeLibs(),
  });

  const { peer, n, warmup, rt } = await recv('run');
  t0 = nowMs();
  const dm = await client.conversations.createDm(peer);
  const dmCreateMs = nowMs() - t0;

  let warmDelivered = 0;
  for (let i = 0; i < warmup; i++) {
    const id = await dm.sendText(TEXT);
    if ((await waitReceipt(id)) !== null) warmDelivered++;
  }
  if (warmup > 0 && warmDelivered === 0) throw new Error('receiver did not get any warmup message');

  process.send({ type: 'loop-start', conversationId: dm.id });
  await recv('go');
  const send = [];
  const deliver = [];
  let lost = 0;
  const api0 = apiCounters(client);
  const cpu0 = process.cpuUsage();
  rss.windowPeak = 0;
  const loopStart = nowMs();
  for (let i = 0; i < n; i++) {
    const ts = nowMs();
    const id = await dm.sendText(TEXT);
    send.push(nowMs() - ts);
    const tr = await waitReceipt(id);
    if (tr === null) lost++;
    else deliver.push(tr - ts);
  }
  const loopMs = nowMs() - loopStart;
  const cpu = process.cpuUsage(cpu0);
  const api1 = apiCounters(client);
  const loopPeakRss = rss.windowPeak;
  process.send({ type: 'loop-end' });
  await recv('go');

  // Roundtrip: A -> B (stream) -> B replies "ok" -> A (stream).
  const replies = [];
  let replyWaiter = null;
  const aStream = await client.conversations.streamAllMessages();
  (async () => {
    for await (const m of aStream) {
      if (m.senderInboxId === client.inboxId || m.content !== REPLY) continue;
      const t = nowMs();
      if (replyWaiter) replyWaiter(t);
      else replies.push(t);
    }
  })();
  const nextReply = () =>
    replies.length
      ? Promise.resolve(replies.shift())
      : new Promise((resolve) => {
          const timer = setTimeout(() => ((replyWaiter = null), resolve(null)), RECV_TIMEOUT_MS);
          replyWaiter = (t) => (clearTimeout(timer), (replyWaiter = null), resolve(t));
        });
  process.send({ type: 'rt-start' });
  await recv('go');
  const roundtrip = [];
  let rtLost = 0;
  for (let i = 0; i < rt; i++) {
    replies.length = 0; // drop a late reply from a timed-out sample
    const ts = nowMs();
    await dm.sendText(TEXT);
    const tr = await nextReply();
    if (tr === null) rtLost++;
    else roundtrip.push(tr - ts);
  }

  const apiDelta = Object.fromEntries(Object.keys(api1).map((k) => [k, api1[k] - api0[k]]));
  process.send({
    type: 'result',
    createMs,
    dmCreateMs,
    conversationId: dm.id,
    warmDelivered,
    send,
    deliver,
    lost,
    roundtrip,
    rtLost,
    loopMs,
    cpu,
    apiDelta,
    apiTotal: apiCounters(client),
    idleRss,
    peakRss: rss.peak,
    loopPeakRss,
  });
  await recv('exit');
  await aStream.end();
  await client.close();
  process.exit(0);
}

// ---------- orchestrator ----------

function spawnRole(role, config) {
  const child = fork(SELF, ['--role', role], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  child.send({ type: 'config', ...config });
  return child;
}

async function runIdentity(config) {
  const child = spawnRole('identity', config);
  const res = await mailbox(child)('result', 120_000);
  await new Promise((r) => (child.exitCode !== null ? r() : child.once('exit', r)));
  return res;
}

// Per-connection cumulative byte counters for one pid (macOS nettop, no sudo needed).
async function nettopFlows(pid) {
  if (process.platform !== 'darwin') return null;
  try {
    const { stdout } = await promisify(execFile)('nettop', ['-L', '1', '-p', String(pid), '-J', 'bytes_in,bytes_out', '-x'], { timeout: 20_000 });
    const flows = {};
    for (const line of stdout.split('\n')) {
      const m = line.match(/^((?:tcp|udp)[46] \S+),(\d+),(\d+),/);
      if (m) flows[m[1]] = { in: Number(m[2]), out: Number(m[3]) };
    }
    return flows;
  } catch {
    return null;
  }
}

function flowDelta(before, after, n) {
  if (!before || !after) return null;
  let bytesIn = 0;
  let bytesOut = 0;
  let opened = 0;
  for (const [k, v] of Object.entries(after)) {
    const b = before[k];
    if (!b) opened++;
    bytesIn += v.in - (b?.in ?? 0);
    bytesOut += v.out - (b?.out ?? 0);
  }
  const closed = Object.keys(before).filter((k) => !after[k]).length;
  return {
    in_per_msg: Math.round(bytesIn / n),
    out_per_msg: Math.round(bytesOut / n),
    total_per_msg: Math.round((bytesIn + bytesOut) / n),
    connections_before: Object.keys(before).length,
    connections_after: Object.keys(after).length,
    connections_opened: opened,
    connections_closed: closed, // >0 means bytes on closed connections were missed (lower bound)
    remotes: [...new Set(Object.keys(after).map((k) => k.split('<->')[1]))],
  };
}

// Protobuf size of an xmtp EncodedContent (content layer, before MLS encryption).
function encodedContentSize(ec) {
  const vlen = (n) => (n < 128 ? 1 : 1 + vlen(Math.floor(n / 128)));
  const lenField = (tag, len) => vlen((tag << 3) | 2) + vlen(len) + len;
  const varField = (tag, v) => (v ? vlen(tag << 3) + vlen(v) : 0);
  const s = (x) => Buffer.byteLength(x);
  const t = ec.type;
  let size = lenField(1, lenField(1, s(t.authorityId)) + lenField(2, s(t.typeId)) + varField(3, t.versionMajor) + varField(4, t.versionMinor));
  for (const [k, v] of Object.entries(ec.parameters ?? {})) size += lenField(2, lenField(1, s(k)) + lenField(2, s(v)));
  if (ec.fallback != null) size += lenField(3, s(ec.fallback));
  size += lenField(4, ec.content.length);
  if (ec.compression != null) size += varField(5, ec.compression);
  return size;
}

// Sizes of the newest stored (encrypted) group messages, read back via the dev node's REST gateway.
async function storedMessageBytes(conversationId, limit) {
  try {
    const res = await fetch(`${REST_BASE}/mls/v1/query-group-messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        group_id: Buffer.from(conversationId, 'hex').toString('base64'),
        paging_info: { limit, direction: 'SORT_DIRECTION_DESCENDING' },
      }),
    });
    const body = await res.json();
    const sizes = (body.messages ?? []).map((m) => m.v1?.data).filter(Boolean).map((d) => Buffer.from(d, 'base64').length);
    return sizes.length ? sizes : null;
  } catch {
    return null;
  }
}

function tcpConnectMs(host) {
  return new Promise((resolve, reject) => {
    const t0 = nowMs();
    const sock = net.connect({ host, port: 443 });
    sock.setTimeout(5000, () => (sock.destroy(), reject(new Error('timeout'))));
    sock.once('error', reject);
    sock.once('connect', () => (resolve(nowMs() - t0), sock.destroy()));
  });
}

async function probeNetwork() {
  const cname = await dns.resolveCname(API_HOST).catch(() => []);
  const ips = await dns.resolve4(API_HOST).catch(() => []);
  const rtts = [];
  for (let i = 0; i < 5; i++) rtts.push(await tcpConnectMs(ips[0] ?? API_HOST).catch(() => null));
  const region = cname.join(' ').match(/\.([a-z]{2}-[a-z]+-\d)\.amazonaws\.com/)?.[1] ?? null;
  const regionNames = { 'us-east-1': 'N. Virginia', 'us-east-2': 'Ohio', 'us-west-1': 'N. California', 'us-west-2': 'Oregon', 'eu-west-1': 'Ireland', 'eu-central-1': 'Frankfurt' };
  return {
    endpoint: `https://${API_HOST}:443`,
    cname,
    ipv4: ips,
    location: region ? `AWS ${region} (${regionNames[region] ?? 'see AWS docs'}), from the ELB CNAME` : 'unknown',
    tcp_connect_ms: summarize(rtts.filter((x) => x != null)),
  };
}

function installSizes() {
  const nm = path.join(HERE, 'node_modules');
  const du = (p) => Number(execFileSync('du', ['-sk', p], { encoding: 'utf8' }).split('\t')[0]) * 1024;
  const find = (...expr) => execFileSync('find', [nm, ...expr], { encoding: 'utf8' }).split('\n').filter(Boolean);
  const pkgVersion = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;

  const bindingDirs = find('-type', 'd', '-path', '*/@xmtp/node-bindings');
  const nodeFiles = find('-name', '*.node', '-type', 'f');
  const host = `${process.platform}-${process.arch}`;
  const otherPlatformBytes = nodeFiles.filter((f) => !path.basename(f).includes(host)).reduce((a, f) => a + fs.statSync(f).size, 0);
  const total = du(nm);

  const topLevel = {};
  for (const entry of fs.readdirSync(nm).filter((e) => !e.startsWith('.'))) {
    const dirs = entry.startsWith('@') ? fs.readdirSync(path.join(nm, entry)).map((s) => `${entry}/${s}`) : [entry];
    for (const d of dirs) topLevel[d] = mb(du(path.join(nm, d)));
  }
  return {
    node_modules: mb(total),
    node_modules_without_other_platform_binaries: mb(total - otherPlatformBytes),
    native_binding_packages: bindingDirs.map((d) => ({
      package: `@xmtp/node-bindings@${pkgVersion(d)}`,
      path: path.relative(HERE, d),
      mb: mb(du(d)),
      host_binary_mb: mb(nodeFiles.filter((f) => f.startsWith(d) && path.basename(f).includes(host)).reduce((a, f) => a + fs.statSync(f).size, 0)),
      platform_binaries: nodeFiles.filter((f) => f.startsWith(d)).length,
    })),
    per_package: topLevel,
    node_runtime: nodeRuntime(),
  };
}

// The node executable plus any non-system shared libraries it links (Homebrew node is a thin
// launcher around libnode + openssl + icu + ...; the official nodejs.org build is one static file).
function nodeRuntime() {
  const bin = fs.realpathSync(process.execPath);
  const libs = new Set();
  if (process.platform === 'darwin') {
    const stack = [bin];
    while (stack.length) {
      const file = stack.pop();
      const deps = execFileSync('otool', ['-L', file], { encoding: 'utf8' }).split('\n').slice(1);
      for (const line of deps) {
        let dep = line.trim().split(' (')[0];
        if (!dep || dep.startsWith('/usr/lib/') || dep.startsWith('/System/')) continue;
        const name = dep.replace(/^@(rpath|loader_path)\//, '');
        dep = [dep, path.join(path.dirname(file), name), path.join(path.dirname(bin), '../lib', name)].find((p) => fs.existsSync(p));
        if (!dep) continue;
        dep = fs.realpathSync(dep);
        if (dep !== bin && !libs.has(dep)) libs.add(dep), stack.push(dep);
      }
    }
  }
  const binBytes = fs.statSync(bin).size;
  const libBytes = [...libs].reduce((a, f) => a + fs.statSync(f).size, 0);
  return { path: bin, binary_mb: mb(binBytes), linked_non_system_libs: libs.size, linked_libs_mb: mb(libBytes), total_mb: mb(binBytes + libBytes) };
}

function versions() {
  const v = (p) => JSON.parse(fs.readFileSync(path.join(HERE, 'node_modules', p, 'package.json'), 'utf8')).version;
  return {
    '@xmtp/node-sdk': v('@xmtp/node-sdk'),
    '@xmtp/node-bindings': v('@xmtp/node-bindings'),
    '@xmtp/content-type-primitives': v('@xmtp/content-type-primitives'),
    viem: v('viem'),
    '@xmtp/node-bindings (nested under content-type-primitives, installed but not loaded)': v('@xmtp/content-type-primitives/node_modules/@xmtp/node-bindings'),
    node: process.version,
    env: ENV,
  };
}

function machine() {
  let osName = `${os.type()} ${os.release()}`;
  if (process.platform === 'darwin') {
    osName = `macOS ${execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim()}`;
  }
  return { cores: os.cpus().length, cpu: os.cpus()[0].model, os: osName };
}

async function main() {
  const n = Number(args.n);
  const warmup = Number(args.warmup);
  const rt = Number(args.rt);
  const ids = Number(args.ids);
  if (!args.out) throw new Error('--out <path> is required');
  const runDir = path.join(DB_ROOT, `run-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  fs.mkdirSync(runDir, { recursive: true });
  const log = (...m) => console.error('[bench]', ...m);
  const children = [];
  process.on('exit', () => children.forEach((c) => c.exitCode === null && c.kill()));

  const network = await probeNetwork();
  log('network', JSON.stringify(network));
  const install = installSizes();

  // Registration and re-open, each in a fresh process.
  const created = [];
  for (let i = 0; i < ids; i++) {
    const r = await runIdentity({ mode: 'create', dbPath: path.join(runDir, `identity-${i}.db3`) });
    if (!r.isRegistered) throw new Error('fresh client not registered');
    created.push(r);
    log(`register ${i}: ${r.ms.toFixed(1)} ms (import ${r.importMs.toFixed(1)} ms)`);
  }
  const reopened = [];
  for (const [i, c] of created.entries()) {
    const r = await runIdentity({ mode: 'build', dbPath: path.join(runDir, `identity-${i}.db3`), privateKey: c.privateKey, dbEncryptionKey: c.dbEncryptionKey });
    if (r.installationId !== c.installationId || !r.isRegistered) throw new Error('re-open produced a different installation');
    reopened.push(r);
    log(`reopen ${i}: ${r.ms.toFixed(1)} ms`);
  }

  // Messaging: B (receiver) and A (sender) in separate processes.
  let A = null;
  const B = spawnRole('receiver', { dbPath: path.join(runDir, 'receiver.db3') });
  children.push(B);
  const bMail = mailbox(B, { recv: (m) => A?.send(m) });
  const bReady = await bMail('ready');
  A = spawnRole('sender', { dbPath: path.join(runDir, 'sender.db3') });
  children.push(A);
  const aMail = mailbox(A);
  const aReady = await aMail('ready');
  log(`clients ready: A=${aReady.inboxId.slice(0, 12)}… B=${bReady.inboxId.slice(0, 12)}…`);

  B.send({ type: 'listen', peer: aReady.inboxId });
  await bMail('listening');
  A.send({ type: 'run', peer: bReady.inboxId, n, warmup, rt });

  const { conversationId } = await aMail('loop-start', 600_000);
  const [aNet0, bNet0] = await Promise.all([nettopFlows(A.pid), nettopFlows(B.pid)]);
  B.send({ type: 'cpu' });
  const bCpu0 = (await bMail('cpu')).usage;
  log(`warmup done; timed loop of ${n}`);
  A.send({ type: 'go' });
  await aMail('loop-end', 3600_000);
  B.send({ type: 'cpu' });
  const bCpu1 = (await bMail('cpu')).usage;
  const [aNet1, bNet1] = await Promise.all([nettopFlows(A.pid), nettopFlows(B.pid)]);
  const storedSizes = await storedMessageBytes(conversationId, Math.min(n, 5)); // newest messages are A's timed sends
  A.send({ type: 'go' });

  await aMail('rt-start');
  B.send({ type: 'echo', on: true });
  await bMail('echo-ack');
  log(`roundtrip loop of ${rt}`);
  A.send({ type: 'go' });
  const res = await aMail('result', 3600_000);
  A.send({ type: 'exit' });
  B.send({ type: 'finish' });
  const bFinal = await bMail('final');

  const { encodeText } = await import('@xmtp/node-sdk');
  const perMsg = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v).map(([k, v]) => [k, r3(v / n)]));

  const out = {
    system: 'xmtp-dev',
    timestamp: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    machine: machine(),
    versions: { ...versions(), libxmtp: aReady.libxmtpVersion },
    params: { n, warmup, roundtrip_samples: rt, identities: ids, text: TEXT, text_chars: TEXT.length, timeout_ms: RECV_TIMEOUT_MS },
    install_mb: install,
    sdk_import_ms: median([...created, ...reopened].map((r) => r.importMs)),
    register_ms: {
      median: median(created.map((r) => r.ms)),
      runs: created.map((r) => r3(r.ms)),
      cold_median_incl_import: median(created.map((r) => r.ms + r.importMs)),
    },
    reopen_ms: {
      median: median(reopened.map((r) => r.ms)),
      runs: reopened.map((r) => r3(r.ms)),
      cold_median_incl_import: median(reopened.map((r) => r.ms + r.importMs)),
    },
    send_ms: summarize(res.send),
    deliver_ms: summarize(res.deliver),
    roundtrip_ms: summarize(res.roundtrip),
    lost: { deliver: res.lost, roundtrip: res.rtLost, warmup_delivered: `${res.warmDelivered}/${warmup}` },
    rss_mb: {
      sender: { idle: mb(res.idleRss), peak: mb(res.peakRss), peak_during_timed_loop: mb(res.loopPeakRss) },
      receiver: { idle: mb(bFinal.idleRss), peak: mb(bFinal.peakRss) },
    },
    cpu_ms_per_msg: r3((res.cpu.user + res.cpu.system) / 1000 / n),
    receiver_cpu_ms_per_msg: r3((bCpu1.user - bCpu0.user + bCpu1.system - bCpu0.system) / 1000 / n),
    bytes_per_msg: {
      sender: flowDelta(aNet0, aNet1, n),
      receiver: flowDelta(bNet0, bNet1, n),
      encoded_content_bytes: encodedContentSize(encodeText(TEXT)),
      stored_encrypted_message_bytes: storedSizes,
      method: 'nettop per-connection cumulative bytes (TLS+HTTP/2+gRPC framing included) snapshotted before/after the timed loop, divided by n',
    },
    api_calls_per_msg: perMsg(res.apiDelta),
    messages_sent: { app_messages: warmup + n + 2 * rt, sender_api_totals: res.apiTotal, receiver_api_totals: bFinal.apiTotal },
    network,
    extra: {
      loop_seconds: r3(res.loopMs / 1000),
      dm_create_ms: r3(res.dmCreateMs),
      sender_create_ms: r3(res.createMs),
      receiver_create_ms: r3(bReady.createMs),
      sdk_import_runs_ms: [...created, ...reopened].map((r) => r3(r.importMs)),
      native_libs_loaded: aReady.nativeLibs,
      conversation_id: res.conversationId,
      db_dir: runDir,
    },
    notes: [
      `XMTP env "dev" via @xmtp/node-sdk createBackend(); gRPC endpoint ${network.endpoint} -> ${network.cname.join(', ') || 'no CNAME'} (${network.ipv4.join(', ')}); location: ${network.location}. TCP connect to it: p50 ${network.tcp_connect_ms.p50} ms.`,
      'Client options mirror @xmtp/agent-sdk defaults: disableDeviceSync=true, appVersion set; local SQLite DB encrypted with a random 32-byte key; DBs under ' + DB_ROOT + '.',
      'send_ms = conversation.sendText() promise (non-optimistic: MLS-encrypt, publish, and wait for the intent to be confirmed by the network).',
      'deliver_ms = hrtime just before A.sendText() to the moment B\'s already-open streamAllMessages() iterator yields that message id (B in another process; process.hrtime is a system-wide monotonic clock). Sends are sequential: the next send starts only after delivery.',
      'roundtrip_ms = A.sendText() -> B stream -> B.sendText("ok") -> A stream yields the reply.',
      'register_ms = generate key + Client.create() (inbox id lookup, local DB create, signature, identity + key package publish). reopen_ms = Client.build() on the existing DB (still does a network inbox-id lookup). Both measured after SDK import in a fresh process; cold_* adds the import of @xmtp/node-sdk + viem.',
      'cpu_ms_per_msg = sender process.cpuUsage (all threads incl. the Rust/tokio runtime) over the timed loop / n. RSS sampled every 20 ms.',
      'B explicitly allows A\'s inbox (preferences.setConsentStates) before A creates the DM.',
      'encoded_content_bytes = protobuf EncodedContent for the text (content layer, before MLS). stored_encrypted_message_bytes = MLS ciphertext sizes of the newest timed messages as stored by the dev node (read via its REST gateway).',
    ],
  };
  for (const [side, d] of Object.entries(out.bytes_per_msg)) {
    if (d?.connections_closed) out.notes.push(`${side}: ${d.connections_closed} connection(s) closed during the timed loop, so its bytes_per_msg is a lower bound.`);
  }

  fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
  fs.writeFileSync(args.out, JSON.stringify(out, null, 2) + '\n');
  console.log(JSON.stringify(out, null, 2));
  process.exit(0);
}

const roles = { main, identity: roleIdentity, receiver: roleReceiver, sender: roleSender };
await roles[args.role]();
