// Launches headless Chrome on the harness page and hands tests a `call`
// function that runs one harness method inside it.

import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { REPO_ROOT, startServer } from './server.mjs';

const CHROME_PATH = process.env.CHROME_PATH ?? '/usr/bin/google-chrome';
const PACKAGE = join(REPO_ROOT, 'webtor-wasm', 'pkg', 'webtor_wasm.js');

async function requireFile(path, hint) {
  try {
    await access(path, constants.R_OK);
  } catch {
    throw new Error(`${path} is missing or unreadable. ${hint}`);
  }
}

/**
 * Open the harness. `onLog` receives every console line the page emits, which
 * is where the client's bootstrap progress shows up; a live run is quiet for
 * minutes otherwise.
 */
export async function openHarness({ onLog } = {}) {
  await requireFile(PACKAGE, 'Run `npm run build` first.');
  await requireFile(
    CHROME_PATH,
    'Set CHROME_PATH to a Chrome-family binary.',
  );

  const { chromium } = await import(
    pathToFileURL(
      join(REPO_ROOT, 'node_modules', 'playwright-core', 'index.mjs'),
    ).href
  );

  const server = await startServer();
  const browser = await chromium.launch({
    executablePath: CHROME_PATH,
    headless: true,
  });
  const page = await browser.newPage();
  if (onLog) {
    page.on('console', (message) => onLog(message.text()));
    page.on('pageerror', (error) => onLog(`page error: ${error.message}`));
  }
  await page.goto(`${server.origin}/`);
  await page.waitForFunction(() => Boolean(globalThis.harness));

  return {
    origin: server.origin,
    /**
     * Invoke `harness[method](...args)` in the page. A rejection there is
     * re-thrown here with its message intact, so tests can assert on it.
     */
    call(method, ...args) {
      return page.evaluate(
        ([name, callArgs]) => globalThis.harness[name](...callArgs),
        [method, args],
      );
    },
    async close() {
      await browser.close();
      await server.close();
    },
  };
}
