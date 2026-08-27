// Browser ↔ ptransfer-cli interoperability over Tor onion services.
//
//   bun run build && bun run seed && bun tests/tools/interop-cli.ts
//
// Both directions are exercised against the CLI's `tor` proof of concept,
// which publishes an ephemeral onion address and echoes back every line:
//
//   client  the page opens a raw stream to a service `ptransfer tor serve`
//           publishes, and reads its echo back
//   server  the page publishes a service, and `ptransfer tor connect` sends a
//           line to it
//
// Environment:
//   PTRANSFER_BIN   the CLI to drive (default ../ptransfer-cli/target/release/ptransfer)
//   DIRECTORY_SEED  a directory snapshot, as in tests/live.test.ts
//   ONLY            "client" or "server" to run just one direction

import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { relative } from 'node:path';
import { openHarness, type BrowserHarness } from '../support/browser.ts';
import { REPO_ROOT } from '../support/server.ts';

const CLI =
  process.env.PTRANSFER_BIN ?? `${REPO_ROOT}/../ptransfer-cli/target/release/ptransfer`;
const SEED_PATH = process.env.DIRECTORY_SEED ?? `${REPO_ROOT}/tests/.directory-seed.json`;
const ONLY = process.env.ONLY ?? '';
const PORT = 9735;
const READY_TIMEOUT_MS = 4 * 60_000;

const started = Date.now();
const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;
const say = (line: string) => console.log(`${elapsed().padStart(8)} ${line}`);

/** Run the CLI, streaming its output to the console and to a collector. */
function run(args: string[], label: string) {
  const child = spawn(CLI, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const lines: string[] = [];
  for (const source of [child.stdout, child.stderr]) {
    source!.setEncoding('utf8');
    let pending = '';
    source!.on('data', (chunk: string) => {
      pending += chunk;
      let split;
      while ((split = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, split);
        pending = pending.slice(split + 1);
        lines.push(line);
        say(`[${label}] ${line}`);
      }
    });
  }
  return { child, lines };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(
  lines: string[],
  child: ChildProcess,
  predicate: (line: string) => boolean,
  what: string,
) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const found = lines.find(predicate);
    if (found !== undefined) return found;
    if (child.exitCode !== null) throw new Error(`${what}: the CLI exited early`);
    await sleep(250);
  }
  throw new Error(`${what}: nothing after ${READY_TIMEOUT_MS / 1000}s`);
}

/** The page opens a raw stream to a service the CLI publishes. */
async function pageAsClient(harness: BrowserHarness) {
  const { child, lines } = run(['tor', 'serve'], 'serve');
  try {
    await waitFor(lines, child, (line) => line === 'ready', 'serve never became ready');
    const address = lines
      .map((line) => /([a-z2-7]{56}\.onion)/.exec(line)?.[1])
      .find(Boolean)!;
    say(`serve is ready at ${address}`);

    const result = await harness.call('streamExchange', address, PORT, 'hello-from-the-page');
    say(`the page got "${result.reply}" back in ${result.seconds}s`);
    assert.equal(result.reply, 'hello-from-the-page');
  } finally {
    child.kill();
  }
}

/** The CLI opens a stream to a service the page publishes. */
async function pageAsServer(harness: BrowserHarness) {
  const published = await harness.call('servicePublish', { introPoints: 3 });
  say(`the page published ${published.address} in ${published.seconds}s`);
  await harness.call('serviceServeEcho');

  const { child, lines } = run(
    ['tor', 'connect', `${published.address}:${PORT}`, '--message', 'hello-from-the-cli'],
    'connect',
  );
  try {
    await waitFor(
      lines,
      child,
      (line) => line === 'hello-from-the-cli',
      'the CLI never got its echo back',
    );
    say('the CLI got its echo back');
    assert.deepEqual(await harness.call('serviceRequests'), ['hello-from-the-cli']);
  } finally {
    child.kill();
    await harness.call('serviceStop');
  }
}

const harness = await openHarness({ onLog: (line) => say(line) });
try {
  let seedUrl = null;
  try {
    await access(SEED_PATH, constants.R_OK);
    seedUrl = `/${relative(REPO_ROOT, SEED_PATH)}`;
  } catch {
    say('no directory seed; the bootstrap will take minutes');
  }
  const ready = await harness.call('create', { logPrefix: '[tor]' }, seedUrl);
  say(`client ready in ${ready.seconds}s`);

  if (ONLY !== 'server') await pageAsClient(harness);
  if (ONLY !== 'client') await pageAsServer(harness);
  say('interop passed');
} finally {
  await harness.close();
}
