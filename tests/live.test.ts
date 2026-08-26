// End to end against real onion services: one bootstrap, then HTTP and
// WebSocket over the circuits it builds.
//
//   bun run build && bun run seed && bun run test:live
//
// Environment:
//   DIRECTORY_SEED  path to a directory snapshot (default
//                   tests/.directory-seed.json, written by `bun run seed`).
//                   Without one the bootstrap downloads every HSDir
//                   microdescriptor over a single bridge circuit, which takes
//                   minutes and often exceeds the budget.
//   BRIDGE          "websocket" (default) or "webrtc"
//   STUN_URLS       comma-separated, for the webrtc bridge
//   CHROME_PATH     Chrome-family binary (default /usr/bin/google-chrome)

import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { relative } from 'node:path';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import {
  openHarness,
  type BrowserHarness,
  type CreateOptions,
} from './support/browser.ts';
import { REPO_ROOT } from './support/server.ts';
import {
  ATTEMPT_TIMEOUT_MS,
  HTTP_TARGETS,
  NIP11_TARGETS,
  WS_TARGETS,
  firstReachable,
} from './support/targets.ts';

const SEED_PATH = process.env.DIRECTORY_SEED ?? `${REPO_ROOT}/tests/.directory-seed.json`;
const BRIDGE = process.env.BRIDGE ?? 'websocket';
const STUN_URLS = (process.env.STUN_URLS ?? '')
  .split(',')
  .map((url) => url.trim())
  .filter(Boolean);

/** What the WebSocket cases ask a relay for; short, and always answered. */
const REQUEST = JSON.stringify(['REQ', 'webtor-test', { kinds: [1], limit: 2 }]);

/** Every case after the minutes-long bootstrap builds its own circuits. */
const CASE_TIMEOUT = 5 * 60_000;

describe('webtor-wasm over Tor', () => {
  let harness: BrowserHarness;
  const started = Date.now();
  const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;

  before(async () => {
    harness = await openHarness({
      onLog: (line) => console.log(`  ${elapsed().padStart(7)} ${line}`),
    });

    let seedUrl = null;
    try {
      await access(SEED_PATH, constants.R_OK);
      seedUrl = `/${relative(REPO_ROOT, SEED_PATH)}`;
    } catch {
      console.log(
        `  no directory seed at ${SEED_PATH}; bootstrapping from the network. ` +
          'Run `bun run seed` to make this fast.',
      );
    }

    const options: CreateOptions = { bridge: BRIDGE, logPrefix: '[tor]' };
    if (BRIDGE === 'webrtc') {
      assert.ok(STUN_URLS.length, 'BRIDGE=webrtc needs STUN_URLS');
      options.stunUrls = STUN_URLS;
    }
    const { seconds } = await harness.call('create', options, seedUrl);
    console.log(`  client ready in ${seconds}s`);
  });

  after(async () => {
    await harness?.close();
  });

  it('exports a re-seedable directory cache', async () => {
    const cache = await harness.call('directoryCache');
    assert.equal(cache.version, 2, 'cache format version');
    assert.ok(
      cache.consensusBytes > 100_000,
      `consensus looks too small: ${cache.consensusBytes} bytes`,
    );
    assert.ok(
      cache.microdescriptorBytes > 100_000,
      `microdescriptors look too small: ${cache.microdescriptorBytes} bytes`,
    );
  }, CASE_TIMEOUT);

  it('GETs an onion site', async () => {
    const { target, result } = await firstReachable(HTTP_TARGETS, (url) =>
      harness.call('fetch', url, { timeoutMs: ATTEMPT_TIMEOUT_MS }),
    );
    console.log(`  ${target} answered in ${result.seconds}s`);
    assert.equal(result.status, 200);
    assert.equal(result.ok, true);
    assert.match(result.headers['content-type'] ?? '', /text\/html/);
    assert.ok(result.byteLength > 0, 'body is empty');
    assert.ok(result.text, 'body is not UTF-8 text');
    assert.match(result.text, /<html/i);
  }, CASE_TIMEOUT);

  it('reports a status the server chose', async () => {
    // A path no onion site serves: the response has to come back as a
    // response, not as a thrown error.
    const { result } = await firstReachable(HTTP_TARGETS, (url) =>
      harness.call('fetch', `${url}webtor-test-${Date.now()}`, {
        timeoutMs: ATTEMPT_TIMEOUT_MS,
      }),
    );
    assert.ok(result.status >= 400, `expected a 4xx, got ${result.status}`);
    assert.equal(result.ok, false);
  }, CASE_TIMEOUT);

  it('sends caller-supplied headers', async () => {
    // Nostr relays answer `GET /` with NIP-11 JSON when the Accept header asks
    // for it, and with something else when it does not — so a JSON body here
    // is evidence the header reached the service.
    const { target, result } = await firstReachable(NIP11_TARGETS, async (url) => {
      const response = await harness.call('fetch', url, {
        headers: { Accept: 'application/nostr+json' },
        timeoutMs: ATTEMPT_TIMEOUT_MS,
      });
      if (response.status !== 200) {
        throw new Error(`answered HTTP ${response.status}`);
      }
      if (response.text === null) {
        throw new Error('answered with a body that is not UTF-8 text');
      }
      JSON.parse(response.text);
      return response;
    });
    assert.ok(result.text, 'response body is empty');
    const document: unknown = JSON.parse(result.text);
    assert.ok(typeof document === 'object' && document !== null);
    const name =
      'name' in document && typeof document.name === 'string'
        ? document.name
        : 'unnamed';
    console.log(`  ${target} is ${name}`);
  }, CASE_TIMEOUT);

  it('refuses a scheme it cannot carry', async () => {
    const host = new URL(HTTP_TARGETS[0]).host;
    await assert.rejects(
      () => harness.call('fetch', `https://${host}/`),
      /only http:\/\/ and ws:\/\//,
    );
    await assert.rejects(
      () => harness.call('wsOpen', `wss://${host}/`),
      /only http:\/\/ and ws:\/\//,
    );
    await assert.rejects(
      () => harness.call('wsOpen', `http://${host}/`),
      /connectWebSocket needs a ws:\/\/ URL/,
    );
  }, CASE_TIMEOUT);

  it('opens a WebSocket and exchanges text', async () => {
    const { target, result } = await firstReachable(WS_TARGETS, async (url) => {
      const { id, seconds } = await harness.call('wsOpen', url, {
        timeoutMs: ATTEMPT_TIMEOUT_MS,
      });
      try {
        await harness.call('wsSend', id, REQUEST);
        const read = await harness.call('wsReceiveUntil', id, ['EOSE'], 10);
        if (!read.matched) {
          throw new Error(
            `no EOSE after ${read.seen.length} messages${read.closed ? ' (closed)' : ''}`,
          );
        }
        return { seconds, seen: read.seen };
      } finally {
        await harness.call('wsClose', id).catch(() => {});
      }
    });
    console.log(
      `  ${target} upgraded in ${result.seconds}s, ${result.seen.length} messages`,
    );
    assert.ok(result.seen.length >= 1);
  }, CASE_TIMEOUT);

  it('refuses to send past maxMessageBytes', async () => {
    const { result } = await firstReachable(WS_TARGETS, async (url) => {
      const { id } = await harness.call('wsOpen', url, {
        maxMessageBytes: 4,
        timeoutMs: ATTEMPT_TIMEOUT_MS,
      });
      try {
        await assert.rejects(
          () => harness.call('wsSend', id, REQUEST),
          /exceeds maxMessageBytes/,
        );
        return 'refused';
      } finally {
        await harness.call('wsClose', id).catch(() => {});
      }
    });
    assert.equal(result, 'refused');
  }, CASE_TIMEOUT);

  it('refuses to receive past maxMessageBytes', async () => {
    const { result } = await firstReachable(WS_TARGETS, async (url) => {
      // Room for the request but not for an event: a relay's REQ reply carries
      // a signed event and runs to hundreds of bytes.
      const { id } = await harness.call('wsOpen', url, {
        maxMessageBytes: REQUEST.length + 8,
        timeoutMs: ATTEMPT_TIMEOUT_MS,
      });
      try {
        await harness.call('wsSend', id, REQUEST);
        for (let attempt = 0; attempt < 5; attempt++) {
          let message;
          try {
            message = await harness.call('wsReceive', id);
          } catch (error: unknown) {
            assert.ok(error instanceof Error);
            assert.match(error.message, /exceeds the size limit/);
            return 'refused';
          }
          // A relay with nothing to serve answers a short EOSE and never
          // sends anything over the limit; that proves nothing, so move on.
          if (message == null) break;
        }
        throw new Error('nothing this relay sent exceeded the limit');
      } finally {
        await harness.call('wsClose', id).catch(() => {});
      }
    });
    assert.equal(result, 'refused');
  }, CASE_TIMEOUT);

  // Last: it takes the client away.
  it('refuses work once closed', async () => {
    assert.equal(await harness.call('close'), 'closed');
    await assert.rejects(
      () => harness.call('fetch', HTTP_TARGETS[0], { timeoutMs: ATTEMPT_TIMEOUT_MS }),
      /client is closed/,
    );
    await assert.rejects(
      () => harness.call('wsOpen', WS_TARGETS[0]),
      /client is closed/,
    );
  }, CASE_TIMEOUT);
});
