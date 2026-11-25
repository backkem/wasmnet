// The example page: loads the simulator and the three components once (compiling their core
// modules on the page), then runs the network in a fresh Worker per click, showing the journal
// as it grows, the outcome and a download per link capture.

import { hasJspi, JSPI_MISSING } from './codelib-web/dist/jspi.js';
import { runInWorker } from './codelib-web/dist/worker/index.js';
import type { ComponentSource, JournalEntry, Outcome } from './network.js';
import type { Done, Init, Progress } from './worker.js';

/**
 * What the build wrote next to the page (scripts/build.mjs): each component's glue, and its core
 * modules by the name the glue asks for (`file`) and where they are (`path`, by content).
 */
interface Assets {
  simulator: { file: string; bytes: number };
  components: Record<string, { module: string; moduleBytes: number; coreModules: { file: string; path: string; bytes: number }[] }>;
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const seedInput = $<HTMLInputElement>('seed');
const runButton = $<HTMLButtonElement>('run');
const status = $('status');
const journal = $<HTMLOListElement>('journal');
const outcomeView = $('outcome');
const captures = $<HTMLUListElement>('captures');
const loading = $('loading');

function setStatus(text: string, state: string): void {
  status.textContent = text;
  document.body.dataset.state = state;
}

/** `300002900000` as `300 002 900 000`. */
const grouped = (n: bigint | number) => String(n).replace(/\B(?=(\d{3})+$)/g, ' ');

/** One journal line, as the native example prints it. */
function line(e: JournalEntry): string {
  const at = `${grouped(e.at)} ns`;
  let text: string;
  if (e.record === 'event') text = `${e.kind} ${e.fields.map(([k, v]) => `${k}=${v}`).join(' ')}`.trimEnd();
  else if (e.record === 'log') text = e.message;
  else text = `${e.stream}: ${e.line}`;
  return `${at.padStart(18)}  ${e.device.padEnd(7)} ${text}`;
}

function append(entries: JournalEntry[]): void {
  const atBottom = journal.scrollTop + journal.clientHeight >= journal.scrollHeight - 4;
  const frag = document.createDocumentFragment();
  for (const e of entries) {
    const li = document.createElement('li');
    li.className = e.record === 'event' ? 'event' : e.record === 'log' ? `log ${e.level}` : 'output';
    li.dataset.device = e.device;
    li.dataset.at = String(e.at);
    if (e.record === 'event') li.dataset.kind = e.kind;
    li.textContent = line(e);
    frag.append(li);
  }
  journal.append(frag);
  if (atBottom) journal.scrollTop = journal.scrollHeight;
}

function describe(o: Outcome): string {
  const at = `${grouped(o.at)} ns`;
  if (o.kind === 'quiescent') {
    const serving = o.daemons.length > 0 ? `; still serving: ${o.daemons.join(', ')}` : '';
    return `Quiescent at ${at}${serving}.`;
  }
  if (o.kind === 'deadline') return `Stopped at the deadline, ${at}, with ${o.pending} events queued.`;
  return `Failed at ${at}: ${o.message}`;
}

const urls: string[] = [];
function showCaptures(links: Done['links']): void {
  for (const u of urls.splice(0)) URL.revokeObjectURL(u);
  captures.replaceChildren();
  for (const l of links) {
    const url = URL.createObjectURL(new Blob([l.pcap as Uint8Array<ArrayBuffer>], { type: 'application/vnd.tcpdump.pcap' }));
    urls.push(url);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${l.name.replace(/:/g, '.')}.pcapng`;
    a.textContent = a.download;
    a.dataset.link = l.name;
    const li = document.createElement('li');
    li.append(a, ` ${grouped(l.pcap.length)} bytes`);
    captures.append(li);
  }
}

async function load(): Promise<{ simulator: WebAssembly.Module; components: Record<string, ComponentSource> }> {
  const assets = (await (await fetch('assets.json')).json()) as Assets;
  // Each distinct core module is downloaded and compiled once (both nodes share a netstack).
  const cores = new Map<string, { bytes: number; module?: Promise<WebAssembly.Module> }>();
  for (const c of Object.values(assets.components)) for (const f of c.coreModules) cores.set(f.path, { bytes: f.bytes });
  const glue = Object.values(assets.components).reduce((n, c) => n + c.moduleBytes, 0);
  const total = assets.simulator.bytes + glue + [...cores.values()].reduce((n, c) => n + c.bytes, 0);
  $('size').textContent = `${(total / 1e6).toFixed(1)} MB`;
  const simulator = WebAssembly.compileStreaming(fetch(assets.simulator.file));
  const compile = (path: string) => {
    const core = cores.get(path)!;
    core.module ??= WebAssembly.compileStreaming(fetch(path));
    return core.module;
  };
  const entries = await Promise.all(
    Object.entries(assets.components).map(async ([key, c]) => {
      const compiled = await Promise.all(c.coreModules.map(async (f) => [f.file, await compile(f.path)] as const));
      return [key, { url: new URL(c.module, document.baseURI).href, modules: Object.fromEntries(compiled) }] as const;
    }),
  );
  return { simulator: await simulator, components: Object.fromEntries(entries) };
}

async function main(): Promise<void> {
  if (!hasJspi()) {
    loading.hidden = true;
    $('nojspi').hidden = false;
    $('nojspi-detail').textContent = JSPI_MISSING;
    setStatus('This browser cannot run the example.', 'unsupported');
    return;
  }
  setStatus('Loading…', 'loading');
  let loaded: Awaited<ReturnType<typeof load>>;
  try {
    loaded = await load();
  } catch (err) {
    loading.hidden = true;
    setStatus(`Loading failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    return;
  }
  loading.hidden = true;
  runButton.disabled = false;
  setStatus('Ready. Pick a seed and press Run.', 'ready');

  // Another scenario of the Worker's, without the page's views: for tests and the console.
  const plain = (v: unknown) => JSON.parse(JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? String(x) : x)));
  (window as { wasmnetScenario?: unknown }).wasmnetScenario = async (scenario: Init['scenario'], seed = '42') => {
    const journal: JournalEntry[] = [];
    const run = runInWorker<Init, Done>(new URL('worker.js', import.meta.url), {
      init: { seed, scenario, ...loaded },
      timeoutMs: 120_000,
      onMessage: (p) => journal.push(...(p as Progress).entries),
    });
    const outcome = await run.outcome;
    if (outcome.status !== 'ok') throw new Error(`the run ended ${outcome.status}`);
    return plain({ journal, outcome: outcome.value.outcome, answers: outcome.value.answers ?? null });
  };

  runButton.addEventListener('click', async () => {
    const seed = seedInput.value.trim() || '0';
    if (!/^\d+$/.test(seed) || BigInt(seed) >= 1n << 64n) {
      setStatus('The seed is a whole number from 0 to 2^64 - 1.', 'error');
      return;
    }
    runButton.disabled = true;
    journal.replaceChildren();
    const entries: JournalEntry[] = [];
    delete (window as { wasmnetRun?: unknown }).wasmnetRun;
    outcomeView.textContent = '';
    captures.replaceChildren();
    setStatus('Running…', 'running');
    const run = runInWorker<Init, Done>(new URL('worker.js', import.meta.url), {
      init: { seed, ...loaded },
      timeoutMs: 120_000,
      onMessage: (p) => {
        const m = p as Progress;
        if (m.type === 'journal') {
          entries.push(...m.entries);
          append(m.entries);
        }
      },
    });
    const outcome = await run.outcome;
    runButton.disabled = false;
    if (outcome.status === 'ok') {
      outcomeView.textContent = describe(outcome.value.outcome);
      outcomeView.dataset.kind = outcome.value.outcome.kind;
      showCaptures(outcome.value.links);
      // The last run as plain JSON (times as decimal strings), for tests and the console.
      const plain = (v: unknown) => JSON.parse(JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? String(x) : x)));
      (window as { wasmnetRun?: unknown }).wasmnetRun = {
        seed,
        journal: plain(entries),
        outcome: plain(outcome.value.outcome),
        links: outcome.value.links.map((l) => l.name),
      };
      const events = journal.querySelectorAll('li').length;
      setStatus(`Done: ${events} journal entries in ${outcome.value.ms} ms of wall time.`, outcome.value.outcome.kind === 'failed' ? 'failed' : 'done');
    } else if (outcome.status === 'error') {
      setStatus(`The run failed: ${outcome.error.message}`, 'error');
    } else if (outcome.status === 'timeout') {
      setStatus(`The run took longer than ${outcome.limitMs / 1000} s and was stopped.`, 'error');
    } else {
      setStatus('Stopped.', 'error');
    }
  });
  seedInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !runButton.disabled) runButton.click();
  });
}

void main();
