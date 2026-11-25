// The example page end to end in headless Chromium: serve the built site (dist/, from
// `npm run build`) under /wasmnet/ as GitHub Pages does, run the HTTP example, check the
// journal, the outcome and both captures, run it again with the same seed, and check that a
// browser without JSPI gets a clear message.
//
//   node test/run.mjs
//
// NATIVE_JOURNAL=<file>: the output of `cargo run -p wasmnet-host --example http` (same seed,
// 42); every event the native run journals must appear in the browser run with the same time,
// device and fields. DEMO_URL=<url>: test a deployed site instead of the local build.
// CHROMIUM=<path>: the browser to use (default: /usr/bin/chromium if present, else Playwright's).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

import { serve } from '../scripts/serve.mjs';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const site = path.join(web, 'dist');
const deployed = process.env.DEMO_URL;
if (!deployed && !fs.existsSync(path.join(site, 'main.js'))) {
  console.error('dist/ is not built: run `npm run build` first');
  process.exit(2);
}

const server = deployed ? null : await serve(site, { port: 0 });
const url = deployed ?? `http://127.0.0.1:${server.address().port}/wasmnet/`;
const executablePath = process.env.CHROMIUM ?? (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined);
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('console', (m) => {
  if (m.type() === 'error') errors.push(m.text());
});
const external = [];
page.on('request', (r) => {
  if (!r.url().startsWith(url) && !r.url().startsWith('data:') && !r.url().startsWith('blob:')) external.push(r.url());
});

const steps = [];
async function step(name, fn) {
  const t0 = performance.now();
  try {
    const detail = await fn();
    const ms = Math.round(performance.now() - t0);
    steps.push({ name, ok: true, ms, detail });
    console.log(`[pass] ${name} (${ms} ms)${detail ? ` ${JSON.stringify(detail)}` : ''}`);
  } catch (e) {
    steps.push({ name, ok: false, error: e.message });
    console.log(`[FAIL] ${name}: ${e.message.split('\n').slice(0, 8).join('\n    ')}`);
  }
}

/** Runs the example with `seed`; resolves to the page's record of the run and the captures' bytes. */
async function run(seed) {
  await page.fill('#seed', String(seed));
  await page.click('#run');
  await page.waitForFunction(() => ['done', 'failed', 'error'].includes(document.body.dataset.state), null, { timeout: 120_000 });
  const state = await page.evaluate(() => document.body.dataset.state);
  if (state !== 'done') throw new Error(`run ended ${state}: ${await page.textContent('#status')}`);
  const record = await page.evaluate(() => window.wasmnetRun);
  const pcaps = await page.evaluate(async () => {
    const out = {};
    for (const a of document.querySelectorAll('#captures a')) {
      out[a.dataset.link] = { file: a.download, bytes: Array.from(new Uint8Array(await (await fetch(a.href)).arrayBuffer())) };
    }
    return out;
  });
  return { record, pcaps, status: await page.textContent('#status'), lines: await page.locator('#journal li').count() };
}

const fieldsOf = (e) => Object.fromEntries(e.fields);
const events = (record, kind, device) => record.journal.filter((e) => e.record === 'event' && e.kind === kind && (!device || e.device === device));

/** Reads a pcap-ng file's blocks: the section header first, then at least one packet. */
function checkPcapng(bytes) {
  const b = Buffer.from(bytes);
  if (b.length < 28 || b.readUInt32LE(0) !== 0x0a0d0d0a) throw new Error('no pcap-ng section header block');
  if (b.readUInt32LE(8) !== 0x1a2b3c4d) throw new Error('unexpected byte-order magic');
  const types = {};
  for (let at = 0; at < b.length; ) {
    const type = b.readUInt32LE(at);
    const len = b.readUInt32LE(at + 4);
    if (len < 12 || len % 4 !== 0 || at + len > b.length || b.readUInt32LE(at + len - 4) !== len) throw new Error(`bad block at byte ${at}`);
    types[type] = (types[type] ?? 0) + 1;
    at += len;
  }
  const packets = (types[6] ?? 0) + (types[3] ?? 0);
  if (!types[1]) throw new Error('no interface description block');
  if (packets === 0) throw new Error('no packets');
  return packets;
}

let first;

await step('loads and compiles the components', async () => {
  const t0 = performance.now();
  await page.goto(url);
  const notice = await page.isVisible('#loading');
  await page.waitForFunction(() => document.body.dataset.state !== 'loading', null, { timeout: 120_000 });
  const state = await page.evaluate(() => document.body.dataset.state);
  if (state !== 'ready') throw new Error(`state ${state}: ${await page.textContent('#status')}`);
  if (await page.isVisible('#loading')) throw new Error('the loading notice is still shown');
  return { readyMs: Math.round(performance.now() - t0), loadingNoticeShown: notice, size: await page.textContent('#size') };
});

await step('runs the example (seed 42)', async () => {
  first = await run(42);
  const r = first.record;
  const done = events(r, 'http-get-done', 'client');
  if (done.length !== 1) throw new Error(`http-get-done: ${done.length} events`);
  const f = fieldsOf(done[0]);
  if (f.status !== '200' || f['body-bytes'] !== '19') throw new Error(`http-get-done ${JSON.stringify(f)}`);
  const exit = events(r, 'app-exit', 'client');
  if (exit.length !== 1 || fieldsOf(exit[0]).status !== 'ok' || fieldsOf(exit[0]).app !== 'http-get') throw new Error(`app-exit ${JSON.stringify(exit)}`);
  if (r.outcome.kind !== 'quiescent') throw new Error(`outcome ${JSON.stringify(r.outcome)}`);
  if (!r.outcome.daemons.some((d) => d.startsWith('server') && d.includes('http-server'))) throw new Error(`the server is not serving: ${JSON.stringify(r.outcome)}`);
  if (first.lines !== r.journal.length) throw new Error(`${first.lines} lines on the page, ${r.journal.length} entries`);
  return { status: first.status, entries: r.journal.length, outcome: await page.textContent('#outcome'), done: `${done[0].at} ns ${done[0].fields.map((x) => x.join('=')).join(' ')}` };
});

await step('both captures are pcap-ng with packets', async () => {
  const names = Object.keys(first.pcaps);
  if (names.length !== 2) throw new Error(`links: ${names.join(', ')}`);
  return Object.fromEntries(Object.entries(first.pcaps).map(([name, p]) => [p.file, `${p.bytes.length} bytes, ${checkPcapng(p.bytes)} packets`]));
});

await step('the same seed gives the same journal and captures', async () => {
  const again = await run(42);
  const a = JSON.stringify(first.record.journal);
  const b = JSON.stringify(again.record.journal);
  if (a !== b) {
    const i = first.record.journal.findIndex((e, n) => JSON.stringify(e) !== JSON.stringify(again.record.journal[n]));
    throw new Error(`journals differ at entry ${i}: ${JSON.stringify(first.record.journal[i])} vs ${JSON.stringify(again.record.journal[i])}`);
  }
  if (JSON.stringify(first.record.outcome) !== JSON.stringify(again.record.outcome)) throw new Error('outcomes differ');
  for (const [name, p] of Object.entries(first.pcaps)) {
    const q = again.pcaps[name];
    if (!q || Buffer.compare(Buffer.from(p.bytes), Buffer.from(q.bytes)) !== 0) throw new Error(`${name}: captures differ`);
  }
  return { entries: again.record.journal.length };
});

await step('another seed still fetches the page', async () => {
  const other = await run(7);
  const done = events(other.record, 'http-get-done', 'client');
  if (done.length !== 1 || fieldsOf(done[0]).status !== '200') throw new Error(JSON.stringify(done));
  return { entries: other.record.journal.length };
});

/** FNV-1a 64 of a string's UTF-8, in hex, as the HTTP apps journal a body's (`body-fnv`). */
function fnv(text) {
  let h = 0xcbf29ce484222325n;
  for (const b of Buffer.from(text, 'utf8')) h = BigInt.asUintN(64, (h ^ BigInt(b)) * 0x100000001b3n);
  return h.toString(16).padStart(16, '0');
}

await step('what an embedder controls: commands, arguments and environment', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('controls', '42'));
  const a = r.answers;
  const want = { block: { ok: 'blocked' }, paths: { ok: 'block 0 3' }, server: null };
  for (const [k, v] of Object.entries(want)) {
    if (JSON.stringify(a[k]) !== JSON.stringify(v)) throw new Error(`answer ${k}: ${JSON.stringify(a[k])}, want ${JSON.stringify(v)}`);
  }
  if (!a.unknown?.err?.includes('unknown command')) throw new Error(`answer unknown: ${JSON.stringify(a.unknown)}`);
  // The operator event at 5 ms unblocked the ports again.
  if (a.after?.ok === undefined || a.after.ok.includes('block 0 3')) throw new Error(`after the run: ${JSON.stringify(a.after)}`);
  const unblocked = events(r, 'ports-unblocked', 'sw');
  if (unblocked.length !== 1 || unblocked[0].at !== '5000000') throw new Error(`ports-unblocked ${JSON.stringify(unblocked)}`);
  if (events(r, 'ports-blocked', 'sw').length !== 1) throw new Error('no ports-blocked event');
  // The server's page is its arguments and its environment variable, as it read them.
  const body = '-v two words|hello from the tab';
  const responses = events(r, 'http-response', 'server');
  if (responses.length !== 1 || fieldsOf(responses[0])['body-fnv'] !== fnv(body)) throw new Error(`http-response ${JSON.stringify(responses)}, want body-fnv ${fnv(body)}`);
  const done = events(r, 'http-get-done', 'client');
  if (done.length !== 1 || fieldsOf(done[0]).status !== '200' || fieldsOf(done[0])['body-bytes'] !== String(Buffer.byteLength(body))) throw new Error(`http-get-done ${JSON.stringify(done)}`);
  return { answers: a, switchEvents: unblocked.map((e) => `${e.at} ${e.kind}`), body: fieldsOf(responses[0])['body-fnv'] };
});

if (process.env.NATIVE_JOURNAL) {
  await step('agrees with the native example', async () => {
    // The native example prints `<t> ns  <device> <kind> k=v ...` for events and
    // `<t> ns  <device> <message>` for log lines; an event's kind has no spaces and its fields are
    // all `k=v`.
    const text = fs.readFileSync(process.env.NATIVE_JOURNAL, 'utf8');
    const native = [];
    for (const l of text.split('\n')) {
      const m = /^\s*(\d+) ns {2}(\S+)\s+(.*)$/.exec(l);
      if (m) native.push({ at: m[1], device: m[2], text: m[3].trimEnd() });
    }
    const key = (at, device, text) => `${at} ${device} ${text}`;
    const browserLines = first.record.journal.filter((e) => e.record !== 'output').map((e) =>
      key(e.at, e.device, e.record === 'event' ? [e.kind, ...e.fields.map((f) => f.join('='))].join(' ') : e.record === 'log' ? e.message : e.line),
    );
    const nativeLines = native.map((n) => key(n.at, n.device, n.text));
    const count = (xs) => xs.reduce((m, x) => m.set(x, (m.get(x) ?? 0) + 1), new Map());
    const [b, n] = [count(browserLines), count(nativeLines)];
    const onlyNative = [...n].filter(([k, c]) => (b.get(k) ?? 0) < c).map(([k]) => k);
    const onlyBrowser = [...b].filter(([k, c]) => (n.get(k) ?? 0) < c).map(([k]) => k);
    const order = browserLines.length === nativeLines.length && browserLines.every((l, i) => l === nativeLines[i]);
    console.log(`       native ${nativeLines.length} lines, browser ${browserLines.length}; same order: ${order}`);
    for (const l of onlyNative) console.log(`       only native:  ${l}`);
    for (const l of onlyBrowser) console.log(`       only browser: ${l}`);
    // Lines in another place within their instant: the order of work inside one instant follows
    // the runtime.
    for (let i = 0; i < Math.min(browserLines.length, nativeLines.length); i++) {
      if (browserLines[i] !== nativeLines[i]) console.log(`       line ${i}: native  ${nativeLines[i]}\n               browser ${browserLines[i]}`);
    }
    if (onlyNative.length > 0 || onlyBrowser.length > 0) throw new Error(`${onlyNative.length} native line(s) missing, ${onlyBrowser.length} extra`);
    // Its captures (`target/http/<link>.pcapng`), if they are next to it: reported, not required.
    const dir = path.join(path.dirname(process.env.NATIVE_JOURNAL), 'http');
    const captures = {};
    for (const [name, p] of Object.entries(first.pcaps)) {
      const file = path.join(dir, p.file);
      if (fs.existsSync(file)) captures[p.file] = Buffer.compare(fs.readFileSync(file), Buffer.from(p.bytes)) === 0 ? 'identical' : 'differs';
    }
    return { lines: nativeLines.length, sameOrder: order, captures };
  });
}

await step('a browser without JSPI gets a clear message', async () => {
  const other = await browser.newPage();
  await other.addInitScript(() => {
    delete WebAssembly.Suspending;
    delete WebAssembly.promising;
  });
  await other.goto(url);
  await other.waitForFunction(() => document.body.dataset.state === 'unsupported', null, { timeout: 10_000 });
  const shown = await other.isVisible('#nojspi');
  const disabled = await other.isDisabled('#run');
  await other.close();
  if (!shown || !disabled) throw new Error(`message shown ${shown}, Run disabled ${disabled}`);
});

await step('fits a phone screen', async () => {
  await page.setViewportSize({ width: 375, height: 800 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  fs.mkdirSync(path.join(web, 'test-results'), { recursive: true });
  await page.screenshot({ path: path.join(web, 'test-results/phone.png'), fullPage: false });
  await page.setViewportSize({ width: 1100, height: 900 });
  await page.screenshot({ path: path.join(web, 'test-results/desktop.png'), fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.screenshot({ path: path.join(web, 'test-results/desktop-dark.png'), fullPage: true });
  if (overflow > 0) throw new Error(`the page scrolls sideways by ${overflow} px`);
});

await step('the notices page', async () => {
  const notices = await browser.newPage();
  await notices.goto(new URL('NOTICES.html', url).href);
  const text = await notices.textContent('body');
  // The licence texts of what the page ships travel with it: this repository's two, the
  // vendored TCP/IP stack, a crate from the registry, the kit and jco.
  for (const want of [
    'Apache License',
    'Permission is hereby granted, free of charge',
    'smoltcp',
    'httparse',
    'codelib-web',
    'codelib contributors',
    '@bytecodealliance/jco',
    'LLVM Exceptions to the Apache 2.0 License',
  ]) {
    if (!text.includes(want)) throw new Error(`the notices lack "${want}"`);
  }
  const overflow = await notices.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 0) throw new Error(`scrolls sideways by ${overflow} px`);
  await notices.close();
});

await step('the page made no external requests', async () => {
  if (external.length > 0) throw new Error(external.join(', '));
});

await browser.close();
server?.close();
if (errors.length > 0) console.log(`page errors:\n  ${errors.join('\n  ')}`);
const failed = steps.filter((s) => !s.ok).length;
fs.mkdirSync(path.join(web, 'test-results'), { recursive: true });
fs.writeFileSync(path.join(web, 'test-results/page.json'), `${JSON.stringify({ steps, errors, first: first?.record ?? null }, null, 2)}\n`);
console.log(failed === 0 ? `page test: all ${steps.length} steps passed` : `page test: ${failed} of ${steps.length} steps failed`);
process.exit(failed === 0 && errors.length === 0 ? 0 : 1);
