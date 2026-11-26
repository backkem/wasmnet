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

await step('devices created while the network runs: controllers, a restart, device events, changes.wait-any, stdin, generic ops, memory, a supplied component', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('runtime', '42'));
  if (r.outcome.kind !== 'deadline') throw new Error(`outcome ${JSON.stringify(r.outcome)}`);
  // An ungranted importer of wasmnet:infra is refused before it is instantiated.
  if (!r.notes?.refused?.includes('imports wasmnet:infra, but the network does not grant it')) throw new Error(`refused: ${JSON.stringify(r.notes)}`);
  // The infra-script controller: the router it created answers, stops, starts again (a fresh
  // instance the page made on demand) and answers again.
  const steps = Object.fromEntries(events(r, 'infra-script', 'ctl').map((e) => [fieldsOf(e).step, fieldsOf(e)]));
  const want = { 0: 'ok', 1: 'ok', 2: 'ok', 3: 'ok', 4: 'ok', 5: 'ok', 6: 'ok', 7: 'ok', 'on.0': 'ok' };
  for (const [n, result] of Object.entries(want)) {
    if (steps[n]?.result !== result) throw new Error(`step ${n}: ${JSON.stringify(steps[n])}`);
  }
  if (!steps[2].text.includes('10.0.1.0/24')) throw new Error(`routes: ${steps[2].text}`);
  if (!steps[6].text.includes('added')) throw new Error(`route-add: ${steps[6].text}`);
  // wasmnet:infra/events: the read at 7 ms, and the rule's read in answer to route-added (armed
  // with events.arm after every poll).
  if (!steps[7].kinds.split(',').includes('route-added')) throw new Error(`events: ${JSON.stringify(steps[7])}`);
  if (!steps['on.0'].kinds.split(',').includes('route-added')) throw new Error(`rule: ${JSON.stringify(steps['on.0'])}`);
  for (const kind of ['device-added', 'device-stopped', 'device-started']) {
    if (events(r, kind, 'r1').length !== 1) throw new Error(`r1 ${kind}: ${events(r, kind, 'r1').length}`);
  }
  if (events(r, 'route-added', 'r1').length !== 1) throw new Error('no route-added on the restarted router');
  // The replicas controller (an async app) made its two servers, and a client fetched from one.
  for (const name of ['web-1', 'web-2']) {
    if (events(r, 'device-added', name).length !== 1) throw new Error(`${name} was not created`);
  }
  const running = events(r, 'replicas-observed', 'rep').filter((e) => fieldsOf(e).phase === 'running');
  // Its period is 10 s: seeing them running within the run means changes.wait-any woke it.
  if (running.length < 2) throw new Error(`replicas-observed running: ${JSON.stringify(running)}`);
  const done = events(r, 'http-get-done', 'client');
  if (done.length !== 1 || fieldsOf(done[0]).status !== '200') throw new Error(`http-get-done ${JSON.stringify(done)}`);
  // Stdin, an operator event through the generic path: the controller read `replicas=3` from
  // its console (it makes the third instance at its next reconcile, after this run).
  const desired = events(r, 'replicas-desired', 'rep').map(fieldsOf);
  if (!desired.some((f) => f.from === 'stdin' && f.replicas === '3')) throw new Error(`replicas-desired ${JSON.stringify(desired)}`);
  // The other generic paths: both operator events applied, a malformed one refused, the
  // capture's snap length, the memory measured and a limit too small refused.
  if (r.notes.opStates !== JSON.stringify(['applied', 'applied'])) throw new Error(`op states ${r.notes.opStates}`);
  if (!r.notes.badOp.includes('`device` is required')) throw new Error(`bad op: ${r.notes.badOp}`);
  if (r.notes.snapLen !== '64') throw new Error(`snap length ${r.notes.snapLen}`);
  if (!(BigInt(r.notes.peakMemory) > 0n)) throw new Error(`peak memory ${r.notes.peakMemory}`);
  if (!r.notes.memory.includes('memory limit: growing a linear memory by')) throw new Error(`memory: ${r.notes.memory}`);
  // The supplied component: kept by the controller's store, and two instances made from its digest.
  const supplied = events(r, 'infra-supply', 'sup');
  if (supplied.length !== 1 || fieldsOf(supplied[0]).digest !== r.notes.digest) throw new Error(`infra-supply ${JSON.stringify(supplied)}, want ${r.notes.digest}`);
  for (const name of ['sup-1', 'sup-2']) {
    if (events(r, 'device-added', name).length !== 1) throw new Error(`${name} was not created from the supplied component`);
  }
  const supRunning = events(r, 'replicas-observed', 'sup').filter((e) => fieldsOf(e).phase === 'running');
  if (supRunning.length < 2) throw new Error(`sup replicas-observed running: ${JSON.stringify(supRunning)}`);
  return { refused: r.notes.refused, memory: r.notes.memory, peakMemory: r.notes.peakMemory, badOp: r.notes.badOp, events: steps[7].kinds, rule: `${steps['on.0'].event} seq ${steps['on.0'].seq}`, running: running.map((e) => `${e.at} ${fieldsOf(e).name}`), supplied: supRunning.map((e) => `${e.at} ${fieldsOf(e).name}`), routes: steps[2].text, fetched: done[0].at };
});

await step('a portable extension in the page: an embedder-built simulator serves its interface, a resource and 1 MiB, faults and life events', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('portable', '42'));
  const got = r.notes.lines;
  const wants = [
    'p pad-big size=1048576 tail=85868788898a8b8c8d8e8f9091929394 state=State::Written',
    // An option of the extension's from a plain object (`pad.fault-at`).
    'q device-crashed message=pad: append 3 failed',
    'r pad-boot boots=1',
    'r pad-dropped notes=2',
    // An operator event of the extension's from a plain object, timed at `p`.
    'p pad-cleared notes=3 by=operator',
    // An import no extension serves for this device.
    'lonely device-crashed message=wasmnet-test:pad/notes@0.1.0 is not served to this device',
  ];
  for (const want of wants) {
    if (!got.includes(want)) throw new Error(`no "${want}" in:\n${got}\noutcome: ${JSON.stringify(r.outcome)}\npage errors: ${errors.join(' | ')}`);
  }
  // The embedder's own exports and import on the simulator module.
  if (r.notes.notesOfR !== 'boot,log') throw new Error(`wn_pad_notes: ${r.notes.notesOfR}`);
  if (r.notes.stamped !== '42') throw new Error(`wn_pad_stamp: ${r.notes.stamped}`);
  if (!r.notes.refused.includes('four bytes')) throw new Error(`wn_pad_stamp refusal: ${r.notes.refused}`);
  // NATIVE_PAD: the same network natively (`page_scenario_native`): the same lines.
  if (process.env.NATIVE_PAD) {
    const [a, b] = [fs.readFileSync(process.env.NATIVE_PAD, 'utf8').trimEnd().split('\n'), got.split('\n')];
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] !== b[i]) throw new Error(`line ${i + 1}: native ${JSON.stringify(a[i])}, page ${JSON.stringify(b[i])}\npage:\n${got}`);
    }
  }
  return { lines: got.split('\n').length, native: Boolean(process.env.NATIVE_PAD) };
});

await step('a portable call carries 4 MiB through the page', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('portable-cost', '42'));
  return r.notes;
});

await step('portable exports in the page: called by name between runs and as an operator event, alike wasmtime; an embedder run loop; per-device imports', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('exports', '42'));
  const n = r.notes;
  const wants = {
    write: '{"value":"5n"}',
    size: '{"value":"11n"}',
    none: '{"value":null}',
    read: '{"value":"bytes:hello world"}',
    nope: 'null',
    // After the module's own run loop to 60 ms: six 64-byte appends.
    log: '{"value":"384n"}',
  };
  for (const [k, v] of Object.entries(wants)) {
    if (n[k] !== v) throw new Error(`${k}: ${n[k]}, want ${v}\n${JSON.stringify(n)}\npage errors: ${errors.join(' | ')}`);
  }
  if (!n.missing.startsWith('{"refused"')) throw new Error(`missing: ${n.missing}`);
  // From 30 ms (where the binding's run stopped) to 60 ms: the polls at 40, 50 and 60 ms.
  if (n.instants !== '3') throw new Error(`instants: ${n.instants}`);
  // NetworkOptions.deviceImports was asked for the device; instantiateCore saw its core modules.
  if (!n.asked.split(',').includes('p:pad_probe')) throw new Error(`deviceImports asked: ${n.asked}`);
  if (!(Number(n.cores) > 0)) throw new Error(`instantiateCore: ${n.cores}`);
  for (const e of ['wasmnet-test:pad/inspect', 'wasmnet:link/device']) {
    if (!n.exports.split(',').includes(e)) throw new Error(`exports: ${n.exports}`);
  }
  for (const l of ['p pad-written name=ext size=5', 'p pad-written name=ext size=11']) {
    if (!n.lines.includes(l)) throw new Error(`no "${l}" in ${n.lines}`);
  }
  return { exports: n.exports, bigMs: n.bigMs, instants: n.instants, cores: n.cores, jspiPlainNs: n.jspiPlainNs, jspiSuspendingNs: n.jspiSuspendingNs };
});

await step('disks in the page: an embedder-built simulator serves wasi:keyvalue and the extension, through stops, crashes and every fault, with the native lines and digests', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('disks', '42'));
  const got = r.notes.lines;
  const wants = [
    'p disk-power-loss disk=log kept=0 lost=2',
    'p disk-crash disk=state',
    'q kv-boot boots=41 entries=2 last=2',
    'q kv-fill answer=Err(Error::Full(',
    'r disk-dropped disk=log',
    'p kv-error what=open log error=Error::Other("a bad sector")',
  ];
  for (const want of wants) {
    if (!got.includes(want)) throw new Error(`no "${want}" in:\n${got}\noutcome: ${JSON.stringify(r.outcome)}\npage errors: ${errors.join(' | ')}`);
  }
  // NATIVE_DISK: the same network natively (`page_scenario_native` in crates/wasmnet-disk): the
  // same lines and the same digests.
  if (process.env.NATIVE_DISK) {
    const [a, b] = [fs.readFileSync(process.env.NATIVE_DISK, 'utf8').trimEnd().split('\n'), got.split('\n')];
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] !== b[i]) throw new Error(`line ${i + 1}: native ${JSON.stringify(a[i])}, page ${JSON.stringify(b[i])}\npage:\n${got}`);
    }
  }
  const digests = got.split('\n').filter((l) => l.startsWith('digest ')).length;
  return { lines: got.split('\n').length, digests, native: Boolean(process.env.NATIVE_DISK), ms: r.ms };
});

await step('what a disk costs in the page: a call by value size, and the digest and export of 64 MiB', async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('disk-cost', '42'));
  return r.notes;
});

/** Where two JSON texts first differ, with some context. */
function firstDifference(a, b) {
  let i = 0;
  while (i < a.length && a[i] === b[i]) i++;
  return `at ${i}: ${JSON.stringify(a.slice(Math.max(0, i - 120), i + 120))} vs ${JSON.stringify(b.slice(Math.max(0, i - 120), i + 120))}`;
}

await step('networks in sequence: a network replaced in mid-run leaves no trace, and the next equals a fresh page at its seed, twice', async () => {
  const fresh = await page.evaluate(() => window.wasmnetScenario('example', '8'));
  const r = await page.evaluate(() => window.wasmnetScenario('sequence', '7'));
  const want = JSON.stringify({ journal: fresh.journal, outcome: fresh.outcome, links: fresh.links });
  if (Number(r.notes.before) === 0) throw new Error('the first network journalled nothing before it was replaced');
  for (const label of ['first', 'second']) {
    const got = JSON.stringify(JSON.parse(r.notes[label]));
    if (got !== want) throw new Error(`the ${label} network after the replacement differs from a fresh page: ${firstDifference(got, want)}`);
  }
  return { replacedAfter: Number(r.notes.before), entries: fresh.journal.length, links: fresh.links.length };
});

await step("networks in sequence from an embedder's own export: a seed it computed, devices added from Rust, steps with a wait in its own Suspending import", async () => {
  const r = await page.evaluate(() => window.wasmnetScenario('pad-sequence', '5'));
  const fresh = await page.evaluate((seed) => window.wasmnetScenario('pad-fresh', seed), r.notes.seed);
  if (Number(r.notes.before) === 0) throw new Error('the first network journalled nothing before it was replaced');
  if (r.notes.pauses !== '6') throw new Error(`the export waited in its import ${r.notes.pauses} times, not 6`);
  if (r.notes.journal !== fresh.notes.journal) throw new Error(`the embedder's network differs from a fresh page: ${firstDifference(r.notes.journal, fresh.notes.journal)}`);
  if (r.notes.notes !== fresh.notes.notes) throw new Error(`p's notes: ${r.notes.notes} vs ${fresh.notes.notes}`);
  return { seed: r.notes.seed, replacedAfter: Number(r.notes.before), entries: JSON.parse(r.notes.journal).length, notes: r.notes.notes };
});

await step('what a frame-heavy run costs in the page: a 2 MB fetch through the switch, frames per second', async () => {
  const measure = async (scenario) => {
    const runs = [];
    for (let i = 0; i < 3; i++) runs.push((await page.evaluate((s) => window.wasmnetScenario(s, '42'), scenario)).notes);
    if (!runs[0].done.includes('status=200') || !runs[0].done.includes('body-bytes=2000000')) throw new Error(`${scenario}: the fetch: ${runs[0].done}`);
    if (runs.some((r) => r.frames !== runs[0].frames)) throw new Error(`${scenario}: frames: ${runs.map((r) => r.frames).join(', ')}`);
    return { frames: Number(runs[0].frames), ms: runs.map((r) => Number(r.ms)), framesPerSecond: runs.map((r) => Number(r.framesPerSecond)) };
  };
  // The same run with the switch called through the `Suspending` imports (its exports answer with a promise).
  return { sync: await measure('frames'), suspending: await measure('frames-suspending') };
});

/** A run's records (`records` in worker.ts), parsed; its events of `kind` on `device`. */
const recordsOf = (notes) => JSON.parse(notes.records);
const eventsIn = (rec, kind, device) => rec.journal.filter((e) => e.record === 'event' && e.kind === kind && e.device === device);

await step("a device's own import answers at a later virtual instant through its clock, the same on every run; instantiateCore sees each device's core modules", async () => {
  const a = (await page.evaluate(() => window.wasmnetScenario('device-clock', '42'))).notes;
  const b = (await page.evaluate(() => window.wasmnetScenario('device-clock', '42'))).notes;
  if (a.records !== b.records) throw new Error(`two runs differ: ${firstDifference(a.records, b.records)}`);
  if (a.waits !== b.waits) throw new Error(`the waits differ:\n${a.waits}\nvs\n${b.waits}`);
  const waits = a.waits.split('\n').filter((l) => l);
  if (waits.length === 0) throw new Error('the client never called its own wait-for');
  for (const w of waits) {
    const m = /^(\d+) \+(\d+) due (\d+) fired (\d+)$/.exec(w);
    if (!m || m[3] !== m[4] || BigInt(m[3]) !== BigInt(m[1]) + BigInt(m[2]) + 2_000_000n) throw new Error(`a wait that did not answer at its instant: ${w}`);
  }
  const done = eventsIn(recordsOf(a), 'http-get-done', 'client');
  if (done.length !== 1 || !done[0].fields.some(([k, v]) => k === 'status' && v === '200')) throw new Error(`http-get-done: ${JSON.stringify(done)}`);
  // Every core module of a device, in instantiation order: the devices one after another.
  const seen = a.cores.split(',');
  const order = seen.filter((d, i) => i === 0 || seen[i - 1] !== d);
  if (order.join(',') !== '0:sw,1:server,2:client') throw new Error(`instantiateCore was asked for ${a.cores}`);
  const count = (d) => seen.filter((x) => x === d).length;
  return { waits, doneAt: done[0].at, cores: { sw: count('0:sw'), server: count('1:server'), client: count('2:client') } };
});

await step('a device whose exports answer with a promise: the switch waited for inside the step, the same on every run', async () => {
  const a = (await page.evaluate(() => window.wasmnetScenario('device-suspends', '42'))).notes;
  const b = (await page.evaluate(() => window.wasmnetScenario('device-suspends', '42'))).notes;
  if (a.records !== b.records) throw new Error(`two runs differ: ${firstDifference(a.records, b.records)}`);
  const rec = recordsOf(a);
  const done = eventsIn(rec, 'http-get-done', 'client');
  if (done.length !== 1 || !done[0].fields.some(([k, v]) => k === 'status' && v === '200')) throw new Error(`http-get-done: ${JSON.stringify(done)}`);
  // The same network with the plain switch (the example at this seed): the same records?
  const plain = await page.evaluate(() => window.wasmnetScenario('example', '42'));
  const same = JSON.stringify(JSON.parse(a.records).journal) === JSON.stringify(plain.journal);
  return { entries: rec.journal.length, answers: a.answers, sameJournalAsPlainSwitch: same };
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
