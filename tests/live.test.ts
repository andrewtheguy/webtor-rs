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
//   BRIDGE_URL      a bridge to use instead of the public one, with
//   BRIDGE_FINGERPRINT  its RSA identity. Both or neither. `scripts/local-bridge`
//                   runs one on localhost and prints the fingerprint, which
//                   makes the directory download local instead of a download
//                   across the public bridge.
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
const BRIDGE_URL = process.env.BRIDGE_URL;
const BRIDGE_FINGERPRINT = process.env.BRIDGE_FINGERPRINT;

/** What the WebSocket cases ask a relay for; short, and always answered. */
const REQUEST = JSON.stringify(['REQ', 'webtor-test', { kinds: [1], limit: 2 }]);

/** Every case after the minutes-long bootstrap builds its own circuits. */
const CASE_TIMEOUT = 5 * 60_000;

describe('webtor-wasm over Tor', () => {
  let harness: BrowserHarness;
  // Set when the bootstrap was seeded, which decides whether this run had a
  // directory download in it at all.
  let seededFrom: string | null = null;
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
    // Half a bridge is not a usable bridge, and the half that is missing
    // decides whether the run is slow or insecure, so refuse both ways round
    // rather than falling back to the public one.
    assert.equal(
      Boolean(BRIDGE_URL),
      Boolean(BRIDGE_FINGERPRINT),
      'BRIDGE_URL and BRIDGE_FINGERPRINT are set together or not at all',
    );
    if (BRIDGE_URL && BRIDGE_FINGERPRINT) {
      options.bridgeUrl = BRIDGE_URL;
      options.bridgeFingerprint = BRIDGE_FINGERPRINT;
      console.log(`  using bridge ${BRIDGE_URL} (${BRIDGE_FINGERPRINT})`);
    }
    seededFrom = seedUrl;
    const { seconds } = await harness.call('create', options, seedUrl);
    console.log(`  client ready in ${seconds}s`);

    // What the binding's `verifyOnion` option used to do before `create`
    // resolved, now that no third-party address is compiled into the wasm:
    // prove the client completes a rendezvous before any case depends on it,
    // so a broken bootstrap fails here with one message naming what it tried
    // instead of as whichever case happened to run first.
    const verified = await firstReachable(HTTP_TARGETS, (url) =>
      harness.call('fetch', url, { timeoutMs: ATTEMPT_TIMEOUT_MS }),
    );
    assert.equal(
      verified.result.status,
      200,
      `${verified.target} answered HTTP ${verified.result.status}`,
    );
    console.log(
      `  client verified against ${verified.target} in ${verified.result.seconds}s`,
    );
  });

  after(async () => {
    await harness?.close();
  });

  it('exports a re-seedable directory cache', async () => {
    const cache = await harness.call('directoryCache');
    assert.equal(cache.version, 3, 'cache format version');
    assert.ok(
      cache.consensusBytes > 100_000,
      `consensus looks too small: ${cache.consensusBytes} bytes`,
    );
    // Five authority certificates are the minimum that can check a consensus,
    // and each is a couple of kilobytes.
    assert.ok(
      cache.certificateBytes > 5_000,
      `authority certificates look too small: ${cache.certificateBytes} bytes`,
    );
    assert.ok(
      cache.microdescriptorBytes > 100_000,
      `microdescriptors look too small: ${cache.microdescriptorBytes} bytes`,
    );
    // What a caller reads before deciding to keep this seed. A consensus is
    // timely for three hours and a time period lasts a day, so an installed
    // one is at most a period behind the wall clock — which is exactly the
    // slack a service covers by publishing to the neighbouring rings. Further
    // than that means the description is not describing this bootstrap.
    // Requiring the current period here would be requiring a policy webtor
    // does not hold, and would fail whenever a still-valid seed straddles a
    // boundary.
    assert.ok(
      Math.abs(cache.timePeriod - cache.timePeriodNow) <= 1,
      `the exported directory is in period ${cache.timePeriod}, but ` +
        `${cache.timePeriodNow} is in force now`,
    );
    assert.ok(
      Date.parse(cache.validUntil) > Date.now(),
      `the exported directory expired at ${cache.validUntil}`,
    );
  }, CASE_TIMEOUT);

  it('hands a downloaded directory to the caller as it arrives', async () => {
    const updates = await harness.call('directoryUpdates');

    if (seededFrom) {
      // Nothing changed: the directory in force is the one the caller
      // supplied, and announcing it back would report a change that never
      // happened.
      assert.deepEqual(
        updates,
        [],
        `a supplied seed was reported back: ${JSON.stringify(updates)}`,
      );
      return;
    }

    assert.equal(
      updates.length,
      1,
      `one download, so one announcement: ${JSON.stringify(updates)}`,
    );
    // The push and the pull have to be the same directory, or a caller that
    // stores what it is handed would seed the next run from something else.
    const cache = await harness.call('directoryCache');
    assert.equal(updates[0]?.bytes, cache.bytes);
    assert.equal(updates[0]?.timePeriod, cache.timePeriod);
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

  it('refuses a response past maxResponseBytes', async () => {
    // The limit is the request's own: a page that would fit any default is
    // refused when this request asks for less than it, and the error names the
    // number so a caller can tell the limit from a truncated transfer.
    await assert.rejects(
      () =>
        harness.call('fetch', HTTP_TARGETS[0], {
          timeoutMs: ATTEMPT_TIMEOUT_MS,
          maxResponseBytes: 1024,
        }),
      /1024-byte limit/,
    );
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

  // The other direction: this page runs the service, and the same client
  // reaches it over the network. Everything in between — introduction points,
  // the descriptor on the HSDirs, the rendezvous — is real Tor.
  it('publishes an onion service and answers a request on it', async () => {
    const body = `webtor onion service ${Date.now()}`;
    const published = await harness.call('servicePublish', { introPoints: 3 });
    console.log(`  published ${published.address} in ${published.seconds}s`);

    try {
      assert.match(published.address, /^[a-z2-7]{56}\.onion$/);
      assert.equal(await harness.call('serviceServeHttp', body), 'serving');
      const path = `/webtor-${Date.now()}`;
      const response = await harness.call(
        'fetch',
        `http://${published.address}${path}`,
        { timeoutMs: ATTEMPT_TIMEOUT_MS },
      );
      console.log(`  round trip in ${response.seconds}s`);
      assert.equal(response.status, 200);
      assert.equal(response.text, body);

      const served = await harness.call('serviceRequests');
      assert.deepEqual(served, [`GET ${path} HTTP/1.1`]);
    } finally {
      await harness.call('serviceStop').catch(() => {});
    }
  }, CASE_TIMEOUT);

  // A second client, bootstrapped where there is no `window`: a dedicated
  // worker has the global scope a service worker has, so a client that
  // bootstraps and completes a rendezvous here runs in a service-worker
  // gateway too. Two GETs to one service, because the second is meant to
  // begin on the circuit the first built rather than rendezvous again.
  it('runs in a dedicated worker and reuses the circuit to a service', async () => {
    const options: CreateOptions = { bridge: BRIDGE };
    if (BRIDGE === 'webrtc') options.stunUrls = STUN_URLS;
    if (BRIDGE_URL && BRIDGE_FINGERPRINT) {
      options.bridgeUrl = BRIDGE_URL;
      options.bridgeFingerprint = BRIDGE_FINGERPRINT;
    }
    const created = await harness.call('workerCreate', options, seededFrom);
    console.log(`  worker client ready in ${created.seconds}s`);

    try {
      const { target, result: first } = await firstReachable(HTTP_TARGETS, (url) =>
        harness.call('workerFetch', url, { timeoutMs: ATTEMPT_TIMEOUT_MS }),
      );
      assert.equal(first.status, 200);
      assert.ok(first.byteLength > 0, 'first body is empty');

      const second = await harness.call('workerFetch', target, {
        timeoutMs: ATTEMPT_TIMEOUT_MS,
      });
      console.log(
        `  worker GETs took ${first.seconds}s, then ${second.seconds}s on the kept circuit`,
      );
      assert.equal(second.status, 200);
      assert.ok(second.byteLength > 0, 'second body is empty');

      const logs = await harness.call('workerLogs');
      const descriptorFetches = logs.filter(
        (line) =>
          line.includes('Fetching the onion service descriptor') &&
          line.includes(new URL(target).host),
      );
      assert.equal(
        descriptorFetches.length,
        1,
        `one descriptor fetch for two streams:\n${logs.join('\n')}`,
      );
      assert.ok(
        logs.some((line) => line.includes('kept circuit')),
        `the second stream began on the kept circuit:\n${logs.join('\n')}`,
      );
    } finally {
      await harness.call('workerClose').catch(() => {});
    }
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
