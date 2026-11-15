// The example's Worker: one run of crates/wasmnet-host/examples/http.rs, in the browser.
//
//   client (http-get) ──100 µs── switch ──150 µs── server (http-server)
//     10.0.0.2                                        10.0.0.1
//
// One run per Worker (jco's runtime and the kit's event loop are global), started by the page
// with the kit's `runInWorker`: `init` carries the seed and the compiled modules, the journal
// streams back as messages while the network runs, and the outcome and the captures are the
// run's value.

import { serveRun } from './codelib-web/dist/worker/index.js';
import { Network, type ComponentSource, type JournalEntry, type Outcome } from './network.js';

declare const self: DedicatedWorkerGlobalScope;

export interface Init {
  seed: string;
  simulator: WebAssembly.Module;
  components: Record<string, ComponentSource>;
}

export interface Done {
  outcome: Outcome;
  links: { name: string; pcap: Uint8Array }[];
  /** Wall-clock time of the run itself (after loading), in ms. */
  ms: number;
}

/** A message the Worker posts while the network runs. */
export type Progress = { type: 'journal'; entries: JournalEntry[] };

serveRun<Init, Done>(async (init, ctx) => {
  const net = await Network.create(init.simulator, { seed: BigInt(init.seed), components: init.components });

  // The same network as examples/http.rs.
  const sw = await net.device('sw', 'switch', { ports: '4' });
  const server = await net.device('server', 'node-http-server', {
    mac: '02:00:00:00:00:01',
    ipv4: '10.0.0.1/24',
    'app.http-server.listen': '0.0.0.0:80',
  });
  const client = await net.device('client', 'node-http-get', {
    mac: '02:00:00:00:00:02',
    ipv4: '10.0.0.2/24',
    'hosts.web': '10.0.0.1',
    'app.http-get.url': 'http://web/',
    'app.http-get.start': '1ms',
  });
  net.link(server.port(0), sw.port(1), 150_000n);
  net.link(client.port(0), sw.port(2), 100_000n);

  ctx.running();
  const t0 = performance.now();
  const outcome = await net.run({ onJournal: (entries) => ctx.post({ type: 'journal', entries } satisfies Progress) });
  const ms = Math.round(performance.now() - t0);
  return { outcome, links: net.links().map((l) => ({ name: l.name, pcap: net.pcap(l) })), ms };
});

void self;
