#!/usr/bin/env node
// Runs the anonymous-signaling WASM client in headless Chrome against onion
// Nostr relays and reports which ones serve a REQ over WebSocket.
//
//   node scripts/onion-signaling-check/run.mjs ws://<addr>.onion [ws://...]
//
// Environment:
//   PLAYWRIGHT_CORE   directory holding node_modules/playwright-core
//                     (default: /tmp/ptransfer-web-live-e2e-cache, which
//                     pTransfer's live web test populates)
//   CHROME_PATH       Chrome-family binary (default: /usr/bin/google-chrome)
//   WEBRTC_BRIDGE=1   reach Snowflake over WebRTC instead of the direct
//                     WebSocket bridge (needs STUN; the direct path does not)
//   DIRECTORY_SEED    path to a directory snapshot (pTransfer's
//                     `npm run tor:directory` output) to bootstrap from
//                     instead of downloading the directory over Snowflake
//   TIMEOUT_SECONDS   whole-run budget (default 900)
//
// Serves the repository root on a loopback port so the page can import the
// checked-in `anonymous-signaling-wasm/pkg/` build; run `npm run build` first.

import { createReadStream } from 'node:fs';
import { access, readFile, stat } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..', '..');
const PLAYWRIGHT_ROOT = process.env.PLAYWRIGHT_CORE ?? '/tmp/ptransfer-web-live-e2e-cache';
const CHROME_PATH = process.env.CHROME_PATH ?? '/usr/bin/google-chrome';
const TIMEOUT_MS = Number(process.env.TIMEOUT_SECONDS ?? '900') * 1000;
const directorySeed = process.env.DIRECTORY_SEED
  ? await readFile(process.env.DIRECTORY_SEED, 'utf8')
  : null;
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

const relayUrls = process.argv.slice(2);
if (relayUrls.length === 0) {
  console.error('usage: run.mjs ws://<addr>.onion [ws://<addr>.onion ...]');
  process.exit(2);
}

await access(join(REPO_ROOT, 'anonymous-signaling-wasm/pkg/anonymous_signaling_wasm.js'), fsConstants.R_OK)
  .catch(() => {
    console.error('No anonymous-signaling-wasm/pkg build; run `npm run build` first.');
    process.exit(2);
  });

const server = createServer(async (request, response) => {
  const path = normalize(decodeURIComponent(new URL(request.url, 'http://localhost').pathname));
  const file = path === '/' ? join(SCRIPT_DIR, 'index.html') : join(REPO_ROOT, path);
  if (!file.startsWith(REPO_ROOT)) {
    response.writeHead(403).end();
    return;
  }
  try {
    const info = await stat(file);
    if (!info.isFile()) throw new Error('not a file');
  } catch {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
  createReadStream(file).pipe(response);
});
await new Promise((ready) => server.listen(0, '127.0.0.1', ready));
const origin = `http://127.0.0.1:${server.address().port}`;

const { chromium } = await import(pathToFileURL(join(PLAYWRIGHT_ROOT, 'node_modules/playwright-core/index.mjs')).href);
const browser = await chromium.launch({ executablePath: CHROME_PATH, headless: true });
const page = await browser.newPage();
const startedAt = Date.now();
const elapsed = () => ((Date.now() - startedAt) / 1000).toFixed(1).padStart(6);
page.on('console', (message) => console.log(`${elapsed()}s [page:${message.type()}] ${message.text()}`));
page.on('pageerror', (error) => console.log(`[page:error] ${error.message}`));

let exitCode = 1;
try {
  await page.goto(`${origin}/`);
  const outcome = await Promise.race([
    page.evaluate(
      ([urls, webrtc, seed]) => window.runCheck(urls, !webrtc, seed),
      [relayUrls, process.env.WEBRTC_BRIDGE === '1', directorySeed],
    ),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`run exceeded ${TIMEOUT_MS / 1000}s`)), TIMEOUT_MS),
    ),
  ]);
  console.log('');
  console.log(`bootstrap: ${outcome.bootstrapSeconds}s, directory cache: ${outcome.directoryCacheBytes} bytes`);
  for (const result of outcome.results) {
    console.log(
      result.ok
        ? `OK      ${result.relayUrl}  ${result.events} events, EOSE in ${result.seconds}s`
        : `FAILED  ${result.relayUrl}  ${result.error}`,
    );
  }
  exitCode = outcome.results.every((result) => result.ok) ? 0 : 1;
} catch (error) {
  console.error(`run failed: ${error instanceof Error ? error.message : error}`);
} finally {
  await browser.close();
  server.close();
}
process.exit(exitCode);
