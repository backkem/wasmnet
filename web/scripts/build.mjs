// Assembles the example page in dist/ (`npm run build`; `cargo xtask web` builds the Rust
// inputs first):
//
//   dist/index.html, style.css           the page (page/)
//   dist/main.js, worker.js, network.js, codec.js
//                                        src/, compiled by tsc
//   dist/codelib-web/dist/               the kit's browser modules (no transpile step, no CLI)
//   dist/wasmnet_web.wasm                the simulator (crates/wasmnet-web, wasm32-unknown-unknown)
//   dist/components/<stem>/              each device's component, transpiled with the kit
//   dist/cores/<hash>.wasm               their core modules, once per content
//   dist/assets.json                     what the page downloads, with sizes
//   dist/NOTICES.html                    the licences of what the page ships (notices.mjs)
//   dist/raw/switch.wasm                 the switch's component bytes, for the test's supplied component
//
// Every URL in the page is relative, so the site works under any base path (GitHub Pages
// serves it from /wasmnet/). The Rust inputs come from the workspace's target directory
// ($CARGO_TARGET_DIR, else ../target).

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { transpile } from 'codelib-web/transpile';

import { noticesHtml, shipped } from './notices.mjs';

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(web, 'dist');
const target = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(web, '..', 'target');
const release = join(target, 'wasm32-wasip2', 'release');
const simulator = join(target, 'wasm32-unknown-unknown', 'release', 'wasmnet_web.wasm');

/** The devices the example and its test scenarios use, by the key the Worker names them with. */
const COMPONENTS = ['switch', 'node-http-server', 'node-http-get', 'router', 'infra_script', 'node-replicas', 'pad_probe', 'disk_probe'];
/** Components built as examples (`components/clock-probe/examples`): their files live in `examples/`. */
const EXAMPLES = ['pad_probe', 'disk_probe'];
const wasmOf = (stem) => join(release, ...(EXAMPLES.includes(stem) ? ['examples'] : []), `${stem}.wasm`);
// The simulator with the test fixture `wasmnet-pad` installed: an embedder's own build of the module
// (`crates/wasmnet-web/examples/pad_page.rs`), for the page test's portable-extension steps.
const extended = join(target, 'wasm32-unknown-unknown', 'release', 'examples', 'pad_page.wasm');
// The simulator with the disks installed (`crates/wasmnet-disk-page`), for the page test's disk step.
const withDisks = join(target, 'wasm32-unknown-unknown', 'release', 'wasmnet_disk_page.wasm');

const missing = [simulator, ...COMPONENTS.map(wasmOf)].filter((p) => !existsSync(p));
if (missing.length > 0) {
  console.error(`build: missing ${missing.map((p) => relative(web, p)).join(', ')}`);
  console.error('run `cargo xtask build` and `cargo build -p wasmnet-web --target wasm32-unknown-unknown --release` first (or `cargo xtask web`)');
  process.exit(2);
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// The TypeScript: tsc from this package's own install.
const require = createRequire(import.meta.url);
const tsc = join(dirname(require.resolve('typescript/package.json')), 'bin', 'tsc');
try {
  execFileSync(process.execPath, [tsc, '-p', web], { stdio: 'inherit' });
} catch {
  console.error('build: tsc failed');
  process.exit(1);
}

for (const f of ['index.html', 'style.css']) cpSync(join(web, 'page', f), join(out, f));

// The kit's browser modules, as `codelib-web browser-files` lists and copies them (everything but
// its Node-only modules), at the path the binding imports them from.
const walk = (dir) => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : [join(dir, n)]));
const kitCli = join(dirname(require.resolve('codelib-web/package.json')), 'dist', 'cli.js');
const copied = execFileSync(process.execPath, [kitCli, 'browser-files', '-o', join(out, 'codelib-web', 'dist')], { encoding: 'utf8' });
const kitFiles = copied.split('\n').filter((l) => l.startsWith('  ')).length;

cpSync(simulator, join(out, 'wasmnet_web.wasm'));
const assets = {
  simulator: { file: 'wasmnet_web.wasm', bytes: statSync(simulator).size },
  components: {},
};
if (existsSync(extended)) {
  cpSync(extended, join(out, 'wasmnet_web_pad.wasm'));
  assets.extended = { file: 'wasmnet_web_pad.wasm', bytes: statSync(extended).size };
}
if (existsSync(withDisks)) {
  cpSync(withDisks, join(out, 'wasmnet_disk_page.wasm'));
  assets.disks = { file: 'wasmnet_disk_page.wasm', bytes: statSync(withDisks).size };
}

for (const stem of COMPONENTS) {
  const dir = join(out, 'components', stem);
  const t0 = performance.now();
  // As `codelib-web transpile <wasm> -o <dir> --name <stem> --no-wasi-async`: WASI 0.2's
  // blocking functions stay synchronous imports (the kit's virtual world never blocks them).
  const manifest = await transpile(wasmOf(stem), { outDir: dir, name: stem, noWasiAsync: true });
  rmSync(join(dir, 'interfaces'), { recursive: true, force: true });
  rmSync(join(dir, `${stem}.d.ts`), { force: true });
  // Core modules move to cores/<content hash>.wasm: both nodes embed the same netstack, which
  // the page then downloads and compiles once. It hands every component its modules compiled
  // (LoadOptions.modules), so jco's glue never fetches them by their own names.
  const coreModules = manifest.coreModules.map((file) => {
    const bytes = readFileSync(join(dir, file));
    const path = `cores/${createHash('sha256').update(bytes).digest('hex').slice(0, 32)}.wasm`;
    mkdirSync(join(out, 'cores'), { recursive: true });
    writeFileSync(join(out, path), bytes);
    rmSync(join(dir, file));
    return { file, path, bytes: bytes.length };
  });
  // Its import names (`ComponentSource.imports`): the simulator refuses a component that
  // imports `wasmnet:infra` for a device without the grant before the page instantiates it.
  const wit = execFileSync('wasm-tools', ['component', 'wit', wasmOf(stem)], { encoding: 'utf8' });
  const imports = [...wit.matchAll(/^\s*import ([\w-]+:[^;\s]+);$/gm)].map((m) => m[1]);
  assets.components[stem] = {
    module: `components/${stem}/${manifest.module}`,
    moduleBytes: statSync(join(dir, manifest.module)).size,
    coreModules,
    imports,
    // Its digest reference: a controller that supplies these bytes runs this transpile of them.
    digest: `sha256:${manifest.component}`,
  };
  const patches = manifest.patches.map((p) => `${p.name}x${p.count}`).join(' ');
  console.log(`  ${stem.padEnd(18)} ${manifest.coreModules.length} core modules, ${Math.round(performance.now() - t0)} ms; patches: ${patches || '(none)'}`);
}
// The switch's component bytes, which the page test's controller fetches from a store node and
// supplies (`wasmnet:infra/components`): its instances run from the transpile above.
mkdirSync(join(out, 'raw'), { recursive: true });
cpSync(join(release, 'switch.wasm'), join(out, 'raw', 'switch.wasm'));

writeFileSync(join(out, 'assets.json'), `${JSON.stringify(assets, null, 2)}\n`);

// The licences of what was just assembled travel with it.
const rest = shipped();
writeFileSync(join(out, 'NOTICES.html'), noticesHtml(rest));
console.log(`  notices: ${rest.crates.length} crates (${rest.crates.filter((c) => c.files.length === 0).length} without a licence file), ${rest.npm.length} npm packages`);

const total = walk(out).reduce((n, f) => n + statSync(f).size, 0);
console.log(`build: ${kitFiles} kit modules, ${COMPONENTS.length} components, ${(total / 1e6).toFixed(1)} MB -> ${relative(web, out)}`);
