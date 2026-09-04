// The gateway in a browser, against the sample dynamic site in
// scripts/local-onion. Headless Chrome opens http://<address>.onion.intor.localhost
// on Vite's dev server, and everything it then sees came through the
// service worker, over Tor: the install, the bootstrap page, the site, a
// form POST, the cookies it sets, and a script's own request.
//
//   bun run build                                     # at the repository root
//   scripts/local-onion/onion.sh start && eval "$(scripts/local-onion/onion.sh env)"
//   scripts/local-bridge/bridge.sh start && eval "$(scripts/local-bridge/bridge.sh env)"
//   cd examples/onion-gateway && bun install && bun run test:e2e
//
// Environment:
//   SAMPLE_ONION        http://<address>.onion, what `onion.sh env` prints
//   BRIDGE_URL          a bridge instead of the public one, with
//   BRIDGE_FINGERPRINT  its identity; both or neither. Without one the worker
//                       bootstraps across the public Snowflake bridge.
//   DIRECTORY_BACKEND   a running directory backend to proxy `/api` to, as a
//                       port or an origin. Without one the test starts
//                       `webtor-directory-server` itself, which builds a
//                       seed from a directory authority in under a minute.
//   CHROME_PATH         Chrome-family binary (default /usr/bin/google-chrome)

import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import path from 'node:path';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import { chromium, type Browser, type Page } from 'playwright-core';

const EXAMPLE = path.resolve(import.meta.dirname, '..');
const CHROME_PATH = process.env.CHROME_PATH ?? '/usr/bin/google-chrome';
const SAMPLE_ONION = process.env.SAMPLE_ONION;
const BRIDGE_URL = process.env.BRIDGE_URL;
const BRIDGE_FINGERPRINT = process.env.BRIDGE_FINGERPRINT;
const DIRECTORY_BACKEND = process.env.DIRECTORY_BACKEND;
/** Any name under `.localhost` does; the browser resolves them all to loopback. */
const GATEWAY_HOST = 'intor.localhost';

/** Install, bootstrap, and a first rendezvous with the onion. */
const FIRST_PAGE_TIMEOUT_MS = 4 * 60_000;
/** A request on the circuit the first page built. */
const PAGE_TIMEOUT_MS = 90_000;
/**
 * How long the site may keep not answering. Its tor publishes the descriptor
 * a while after bootstrapping, and until then the gateway can only show its
 * error page; a reload asks again.
 */
const REACHABLE_DEADLINE_MS = 4 * 60_000;
const CASE_TIMEOUT = 6 * 60_000;

const started = Date.now();
const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;
const say = (line: string) => console.log(`  ${elapsed().padStart(7)} ${line}`);

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
  });
}

/** Relay a child's output into the log, one prefixed line at a time. */
function relayOutput(child: ChildProcess, prefix: string): void {
  for (const stream of [child.stdout!, child.stderr!]) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string) => {
      for (const line of chunk.split('\n')) if (line.trim()) say(`[${prefix}] ${line.trim()}`);
    });
  }
}

/** Poll `url` until it answers 200, or `child` exits, or `deadlineMs` passes. */
async function waitForListening(child: ChildProcess, url: string, deadlineMs: number): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`${url} exited with ${child.exitCode}`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline) {
      // Nothing else holds the process once this throws, so it goes here.
      child.kill();
      throw new Error(`${url} did not start answering in ${deadlineMs / 1000}s`);
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

/**
 * The example directory backend on a port of its own, built and run with
 * cargo, waited for until it serves a seed. The manifest says 503 until the
 * first build lands, and the worker would fall back to a Tor download if it
 * asked in that window — a path that also works, but not the one this suite
 * is here to drive.
 */
async function startBackend(port: number): Promise<ChildProcess> {
  const backend = spawn(
    'cargo',
    ['run', '-q', '-p', 'webtor-directory-server', '--', 'serve', '--listen', `127.0.0.1:${port}`],
    { cwd: EXAMPLE, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  relayOutput(backend, 'backend');
  await waitForListening(backend, `http://127.0.0.1:${port}/api/directory`, 5 * 60_000);
  return backend;
}

/**
 * Vite's dev server on a port of its own, with the bridge passed through as
 * the `VITE_` variables the worker reads and `/api` proxied to `backend`.
 * `--host 127.0.0.1` so the port is loopback only; the browser reaches it by
 * name all the same.
 */
async function startVite(port: number, backend: string): Promise<ChildProcess> {
  const env: NodeJS.ProcessEnv = { ...process.env, GATEWAY_DEV_BACKEND: backend };
  if (BRIDGE_URL && BRIDGE_FINGERPRINT) {
    env.VITE_BRIDGE_URL = BRIDGE_URL;
    env.VITE_BRIDGE_FINGERPRINT = BRIDGE_FINGERPRINT;
  }
  const vite = spawn(
    path.join(EXAMPLE, 'node_modules', '.bin', 'vite'),
    ['--host', '127.0.0.1', '--port', String(port), '--strictPort', '--clearScreen', 'false'],
    { cwd: EXAMPLE, env, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  relayOutput(vite, 'vite');
  await waitForListening(vite, `http://127.0.0.1:${port}/`, 30_000);
  return vite;
}

describe('the onion gateway against a dynamic onion site', () => {
  let onion: string;
  let origin: string;
  let backend: ChildProcess | undefined;
  let vite: ChildProcess | undefined;
  let browser: Browser | undefined;
  let page: Page;

  const text = (selector: string, timeout = PAGE_TIMEOUT_MS) =>
    page.locator(selector).innerText({ timeout });
  /**
   * Wait until `selector` says exactly `expected`. A locator keeps looking
   * through the navigations in between — a form's `303`, or the bootstrap
   * page a restarted worker shows — so this is how a step's outcome is read.
   */
  const expectText = async (selector: string, expected: string) => {
    await page
      .locator(selector)
      .filter({ hasText: new RegExp(`^${expected}$`) })
      .waitFor({ timeout: PAGE_TIMEOUT_MS });
  };

  before(async () => {
    assert.ok(
      SAMPLE_ONION,
      'SAMPLE_ONION is not set. Start scripts/local-onion/onion.sh and eval its `env`.',
    );
    onion = new URL(SAMPLE_ONION).hostname;
    assert.match(onion, /^[a-z2-7]{56}\.onion$/, `SAMPLE_ONION is ${SAMPLE_ONION}`);
    assert.equal(
      Boolean(BRIDGE_URL),
      Boolean(BRIDGE_FINGERPRINT),
      'BRIDGE_URL and BRIDGE_FINGERPRINT are set together or not at all',
    );

    let backendAt = DIRECTORY_BACKEND;
    if (!backendAt) {
      const backendPort = await freePort();
      backend = await startBackend(backendPort);
      backendAt = String(backendPort);
    }
    const port = await freePort();
    vite = await startVite(port, backendAt);
    origin = `http://${onion}.${GATEWAY_HOST}:${port}`;
    say(`gateway at ${origin}`);

    browser = await chromium.launch({ executablePath: CHROME_PATH, headless: true });
    page = await browser.newPage();
    page.on('console', (message) => say(`[page] ${message.text()}`));
    page.on('pageerror', (error) => say(`[page] error: ${error.message}`));
  });

  after(async () => {
    await browser?.close();
    vite?.kill();
    backend?.kill();
  });

  it('installs the worker, bootstraps, and shows the onion page', async () => {
    // The first visit is answered by the app, which registers the worker and
    // reloads; the reload gets the bootstrap page, which reloads when the
    // client is up; that reload is the one the onion answers. A locator
    // waits through all of it. If the onion is not findable yet the gateway
    // shows its error page instead, and a reload asks again.
    await page.goto(`${origin}/`);
    const deadline = Date.now() + REACHABLE_DEADLINE_MS;
    for (;;) {
      // Either the site, or a failure box the gateway has shown: the error
      // page's, or the bootstrap page's once a bootstrap fails. Anything in
      // between — the install, the bootstrap page and the moment it announces
      // the client is up and reloads — is waited through.
      await page.waitForFunction(
        () => {
          if (document.querySelector('h1')?.textContent === 'Sample onion') return true;
          const failure = document.querySelector<HTMLElement>('.failure');
          return failure !== null && !failure.hidden;
        },
        undefined,
        { timeout: FIRST_PAGE_TIMEOUT_MS },
      );
      const shown = await page.locator('h1').innerText();
      if (shown === 'Sample onion') break;
      const reason = await page.locator('.failure').innerText().catch(() => '(gone)');
      say(`gateway showed "${shown}": ${reason}`);
      assert.ok(Date.now() < deadline, `the onion never answered; last page was "${shown}"`);
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      await page.reload();
    }
    say('onion page shown');
    await expectText('#visits', 'Visit 1');
    assert.equal(await text('#who'), 'Not signed in');
    assert.equal(page.url(), `${origin}/`);
  }, CASE_TIMEOUT);

  it('keeps the cookies the onion set and sends them back', async () => {
    // The page's second load: the `visits` cookie the first one set went
    // into the worker's jar and out again on this request.
    await page.reload();
    await expectText('#visits', 'Visit 2');
  }, CASE_TIMEOUT);

  it('submits a form POST and follows the redirect, signed in', async () => {
    await page.fill('#login input[name="name"]', 'tester', { timeout: PAGE_TIMEOUT_MS });
    await page.click('#login button');
    // The onion answers `303 See Other` to `/`; the worker rewrites that
    // `Location` into this origin, and the browser follows it here.
    await expectText('#who', 'Signed in as tester');
    assert.equal(page.url(), `${origin}/`);
    assert.equal(await text('#visits'), 'Visit 3');
  }, CASE_TIMEOUT);

  it("carries a script's request with the jar and the onion's own Origin", async () => {
    const echoed = (await page.evaluate(async () => {
      const response = await fetch('/echo?via=script', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-requested-with': 'gateway-test' },
        body: '{"n":1}',
      });
      return { status: response.status, body: (await response.json()) as unknown };
    })) as {
      status: number;
      body: {
        method: string;
        query: Record<string, string>;
        headers: Record<string, string>;
        cookies: Record<string, string>;
        body: string;
      };
    };
    assert.equal(echoed.status, 200);
    const { body: seen } = echoed;
    assert.equal(seen.method, 'PUT');
    assert.deepEqual(seen.query, { via: 'script' });
    assert.equal(seen.body, '{"n":1}');
    assert.equal(seen.headers['content-type'], 'application/json');
    assert.equal(seen.headers['x-requested-with'], 'gateway-test');
    // What the worker says on the page's behalf, in the onion's terms.
    assert.equal(seen.headers.host, onion);
    assert.equal(seen.headers.origin, `http://${onion}`);
    assert.equal(seen.headers.referer, `http://${onion}/`);
    assert.equal(seen.headers['accept-encoding'], 'gzip, deflate');
    // And the jar: the session from the form, the visits from the pages.
    assert.equal(seen.cookies.session, 'tester');
    assert.equal(seen.cookies.visits, '3');
    assert.ok(seen.cookies.seen, `no seen cookie in ${JSON.stringify(seen.cookies)}`);
  }, CASE_TIMEOUT);

  it('signs out', async () => {
    await page.click('#logout button', { timeout: PAGE_TIMEOUT_MS });
    await expectText('#visits', 'Visit 4');
    assert.equal(page.url(), `${origin}/`);
    assert.equal(await text('#who'), 'Not signed in');
  }, CASE_TIMEOUT);

  it('passes the status the onion chose to the page', async () => {
    const response = await page.goto(`${origin}/nowhere`);
    assert.ok(response);
    assert.equal(response.status(), 404);
    assert.equal((await page.locator('body').innerText()).trim(), 'Nothing at /nowhere');
  }, CASE_TIMEOUT);
});
