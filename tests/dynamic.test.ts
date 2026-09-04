// End to end against the sample dynamic site in scripts/local-onion: the
// methods, bodies, cookies and redirects a static onion site never sends.
//
//   scripts/local-onion/onion.sh start
//   eval "$(scripts/local-onion/onion.sh env)"
//   eval "$(scripts/local-bridge/bridge.sh env)"   # optional, a fast bootstrap
//   bun run build && bun run test:dynamic
//
// Environment:
//   SAMPLE_ONION    http://<address>.onion, what `onion.sh env` prints
//   CHROME_PATH     Chrome-family binary (default /usr/bin/google-chrome)
//   and the bootstrap variables described in support/bootstrap.ts.

import assert from 'node:assert/strict';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import { clientOptions, seedUrl } from './support/bootstrap.ts';
import {
  openHarness,
  type BrowserHarness,
  type FetchOptions,
  type HarnessFetchResult,
} from './support/browser.ts';

const SAMPLE_ONION = process.env.SAMPLE_ONION;

/** Every case after the bootstrap begins its stream on the kept circuit. */
const CASE_TIMEOUT = 5 * 60_000;
/** One request, once the service is known to answer. */
const REQUEST_TIMEOUT_MS = 90_000;
/**
 * How long the first request may keep failing. The container's tor
 * publishes the descriptor a while after it bootstraps, and until an HSDir
 * has it the client can only report that the service is unknown.
 */
const REACHABLE_DEADLINE_MS = 4 * 60_000;

/** Whether the site's home page is sound, whatever the cookies on it. */
function assertHomePage(result: HarnessFetchResult, visit: number): void {
  assert.equal(result.status, 200);
  assert.match(result.headers['content-type'] ?? '', /text\/html/);
  assert.ok(result.text, 'body is not UTF-8 text');
  assert.match(result.text, /<h1>Sample onion<\/h1>/);
  assert.match(result.text, new RegExp(`<p id="visits">Visit ${visit}</p>`));
}

describe('webtor-wasm against a dynamic onion site', () => {
  let harness: BrowserHarness;
  let onion: string;
  const started = Date.now();
  const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;

  const echo = async (path: string, options: FetchOptions = {}) => {
    const result = await harness.call('fetch', `${onion}${path}`, {
      timeoutMs: REQUEST_TIMEOUT_MS,
      ...options,
    });
    assert.equal(result.status, 200, `echo answered HTTP ${result.status}: ${result.text}`);
    assert.ok(result.text, 'echo body is not text');
    return JSON.parse(result.text) as {
      method: string;
      path: string;
      query: Record<string, string>;
      headers: Record<string, string>;
      cookies: Record<string, string>;
      body: string;
    };
  };

  before(async () => {
    assert.ok(
      SAMPLE_ONION,
      'SAMPLE_ONION is not set. Start scripts/local-onion/onion.sh and eval its `env`.',
    );
    onion = SAMPLE_ONION.replace(/\/$/, '');
    assert.match(onion, /^http:\/\/[a-z2-7]{56}\.onion$/, `SAMPLE_ONION is ${SAMPLE_ONION}`);

    harness = await openHarness({
      onLog: (line) => console.log(`  ${elapsed().padStart(7)} ${line}`),
    });
    const { seconds } = await harness.call('create', clientOptions('[tor]'), await seedUrl());
    console.log(`  client ready in ${seconds}s`);

    // The first request waits for the service to be findable at all; every
    // case after it runs against a service that has answered once.
    const deadline = Date.now() + REACHABLE_DEADLINE_MS;
    for (let attempt = 1; ; attempt++) {
      try {
        const result = await harness.call('fetch', `${onion}/echo?probe=${attempt}`, {
          timeoutMs: REQUEST_TIMEOUT_MS,
        });
        assert.equal(result.status, 200);
        console.log(`  ${onion} answered on attempt ${attempt} in ${result.seconds}s`);
        break;
      } catch (error) {
        if (Date.now() > deadline) throw error;
        console.log(`  attempt ${attempt}: ${error instanceof Error ? error.message : error}`);
        await new Promise((resolve) => setTimeout(resolve, 5_000));
      }
    }
  });

  after(async () => {
    await harness?.close();
  });

  it('delivers every Set-Cookie header, in order', async () => {
    const result = await harness.call('fetch', `${onion}/`, { timeoutMs: REQUEST_TIMEOUT_MS });
    assertHomePage(result, 1);
    assert.match(result.text!, /<p id="who">Not signed in<\/p>/);
    assert.equal(result.setCookies.length, 2, JSON.stringify(result.setCookies));
    assert.equal(result.setCookies[0], 'visits=1; Path=/');
    assert.match(result.setCookies[1]!, /^seen=\d{4}-\d\d-\d\dT.*; Path=\/; Max-Age=3600$/);
  }, CASE_TIMEOUT);

  it('sends the cookies it is given', async () => {
    const echoed = await echo('/echo', { headers: { Cookie: 'visits=6; session=carried' } });
    assert.deepEqual(echoed.cookies, { visits: '6', session: 'carried' });

    const page = await harness.call('fetch', `${onion}/`, {
      headers: { Cookie: 'visits=6' },
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    assertHomePage(page, 7);
    assert.equal(page.setCookies[0], 'visits=7; Path=/');
  }, CASE_TIMEOUT);

  it('carries a form POST', async () => {
    const body = new URLSearchParams({ name: 'Ada L', note: 'a=b&c' }).toString();
    const echoed = await echo('/echo?from=form', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(echoed.method, 'POST');
    assert.deepEqual(echoed.query, { from: 'form' });
    assert.equal(echoed.body, body);
    assert.equal(echoed.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.equal(echoed.headers['content-length'], String(body.length));
  }, CASE_TIMEOUT);

  it('carries a JSON PUT and a bodiless DELETE', async () => {
    const put = await echo('/echo', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'webtor' },
      body: '{"n":1}',
    });
    assert.equal(put.method, 'PUT');
    assert.equal(put.body, '{"n":1}');
    assert.equal(put.headers['x-requested-with'], 'webtor');

    const del = await echo('/echo', { method: 'DELETE' });
    assert.equal(del.method, 'DELETE');
    assert.equal(del.body, '');
  }, CASE_TIMEOUT);

  it('refuses a sign-in with no Origin, as a site would', async () => {
    const result = await harness.call('fetch', `${onion}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'name=nobody',
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    assert.equal(result.status, 403);
    assert.match(result.text ?? '', /Cross-site request refused/);
  }, CASE_TIMEOUT);

  it('signs in, is remembered, and signs out', async () => {
    const signIn = await harness.call('fetch', `${onion}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: onion,
      },
      body: 'name=tester',
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    // A redirect comes back as the response it is; following it is the
    // caller's business, and a gateway's.
    assert.equal(signIn.status, 303);
    assert.equal(signIn.ok, false);
    assert.equal(signIn.headers.location, '/');
    assert.deepEqual(signIn.setCookies, ['session=tester; Path=/; HttpOnly']);

    const page = await harness.call('fetch', `${onion}/`, {
      headers: { Cookie: 'session=tester' },
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    assertHomePage(page, 1);
    assert.match(page.text!, /<p id="who">Signed in as tester<\/p>/);

    const signOut = await harness.call('fetch', `${onion}/logout`, {
      method: 'POST',
      headers: { Origin: onion, Cookie: 'session=tester' },
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    assert.equal(signOut.status, 303);
    assert.deepEqual(signOut.setCookies, ['session=; Path=/; Max-Age=0']);
  }, CASE_TIMEOUT);

  it('reports a status the site chose', async () => {
    const result = await harness.call('fetch', `${onion}/nowhere`, {
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
    assert.equal(result.status, 404);
    assert.equal(result.text, 'Nothing at /nowhere\n');
  }, CASE_TIMEOUT);
});
