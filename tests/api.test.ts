// The half of the API that answers without touching the network: the URL
// helpers, reading a directory seed, and the option validation every call runs
// before it costs anything. One case connects to a closed loopback port, to
// watch a caller's log sink fill up on the way to a failure.
//
//   bun run test
//
// Needs a build (`bun run build`) and a Chrome-family binary (CHROME_PATH).

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import { openHarness, type BrowserHarness } from './support/browser.ts';
import { REPO_ROOT } from './support/server.ts';

const ONION = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion';

/** Matches `DIRECTORY_CACHE_VERSION`; an older envelope is refused. */
const CACHE_VERSION = 3;

/**
 * A seed carrying the consensus fixture the Rust tests use: no relays worth
 * connecting to, `valid-after 2020-08-27 13:00:00`, and no `hsdir_interval`,
 * so its time periods are a day long and begin at noon UTC.
 */
async function fixtureSeed(): Promise<string> {
  const consensus = await readFile(
    join(REPO_ROOT, 'webtor', 'testdata', 'microdesc-consensus.txt'),
    'utf8',
  );
  return JSON.stringify({
    version: CACHE_VERSION,
    consensus,
    certificates: '',
    microdescriptors: '',
  });
}

describe('webtor-wasm API', () => {
  let harness: BrowserHarness;

  before(async () => {
    harness = await openHarness();
  });

  after(async () => {
    await harness?.close();
  });

  describe('isOnionHost', () => {
    it('accepts a v3 address', async () => {
      assert.equal(await harness.call('isOnionHost', ONION), true);
    });

    it('rejects v2, clearnet and wrong case', async () => {
      for (const host of [
        'facebookcorewwwi.onion',
        'example.com',
        ONION.toUpperCase(),
        `${ONION}.example.com`,
        '',
      ]) {
        assert.equal(await harness.call('isOnionHost', host), false, host);
      }
    });
  });

  describe('parseOnionUrl', () => {
    it('splits a URL into its pieces', async () => {
      const parsed = await harness.call(
        'parseOnionUrl',
        `HTTP://${ONION}:8080/api/ip?format=json`,
      );
      assert.deepEqual(parsed, {
        scheme: 'http',
        host: ONION,
        port: 8080,
        pathAndQuery: '/api/ip?format=json',
      });
    });

    it('defaults the port and the path', async () => {
      const parsed = await harness.call('parseOnionUrl', `ws://${ONION}`);
      assert.equal(parsed.port, 80);
      assert.equal(parsed.pathAndQuery, '/');
    });

    it('refuses TLS schemes, since the circuit already encrypts', async () => {
      await assert.rejects(
        () => harness.call('parseOnionUrl', `https://${ONION}/`),
        /only http:\/\/ and ws:\/\//,
      );
      await assert.rejects(
        () => harness.call('parseOnionUrl', `wss://${ONION}/`),
        /only http:\/\/ and ws:\/\//,
      );
    });

    it('refuses anything that is not a v3 onion host', async () => {
      for (const url of [
        'ws://relay.example.com',
        'http://abcdefghijklmnop.onion/',
        `ws://user@${ONION}/`,
        `ws://${ONION}/#fragment`,
        `ws://${ONION}:99999/`,
        ONION,
      ]) {
        await assert.rejects(() => harness.call('parseOnionUrl', url), url);
      }
    });
  });

  describe('describeDirectory', () => {
    it('reads a seed\'s window and the ring it places descriptors on', async () => {
      const described = await harness.call('describeDirectory', await fixtureSeed(), [
        Date.UTC(2020, 7, 27, 13, 0, 0),
        Date.UTC(2020, 7, 27, 11, 0, 0),
        Date.UTC(2020, 7, 28, 13, 0, 0),
      ]);

      assert.equal(described.validAfter, '2020-08-27T13:00:00.000Z');
      assert.equal(described.validUntil, '2020-08-27T16:00:00.000Z');
      assert.equal(described.timePeriod, 18501);
      // 11:00 is before that day's boundary and so a period behind, which is
      // the case a caller checks for: a consensus can still be valid there
      // while placing every descriptor on the ring the network has left.
      assert.deepEqual(described.periods, [18501, 18500, 18502]);
    });

    it('describes a long-expired seed rather than refusing it', async () => {
      // The fixture expired in 2020. Reading it is what lets a caller say why
      // it is throwing a stored seed away.
      const described = await harness.call('describeDirectory', await fixtureSeed());
      assert.equal(described.timePeriod, 18501);
    });

    it('refuses a seed it cannot read', async () => {
      await assert.rejects(
        () => harness.call('describeDirectory', 'not a seed'),
        /Failed to read the Tor directory seed/,
      );
      await assert.rejects(
        () =>
          harness.call(
            'describeDirectory',
            JSON.stringify({
              version: CACHE_VERSION,
              consensus: 'not a consensus\n',
              certificates: '',
              microdescriptors: '',
            }),
          ),
        /Failed to parse consensus/,
      );
    });
  });

  describe('create options', () => {
    it('names an option it does not know', async () => {
      await assert.rejects(
        () => harness.call('createRejects', { directorySeeed: 'typo' }),
        /has no option "directorySeeed"/,
      );
    });

    it('rejects an unknown bridge', async () => {
      await assert.rejects(
        () => harness.call('createRejects', { bridge: 'meek' }),
        /must be "websocket" or "webrtc"/,
      );
    });

    it('requires STUN for the webrtc bridge, and refuses it otherwise', async () => {
      await assert.rejects(
        () => harness.call('createRejects', { bridge: 'webrtc' }),
        /requires at least one STUN URL/,
      );
      await assert.rejects(
        () =>
          harness.call('createRejects', {
            bridge: 'websocket',
            stunUrls: ['stun:stun.example.com'],
          }),
        /applies to the webrtc bridge only/,
      );
    });

    it('takes a bridge URL and its identity together, or neither', async () => {
      await assert.rejects(
        () => harness.call('createRejects', { bridgeUrl: 'ws://localhost:8080/' }),
        /needs "bridgeFingerprint"/,
      );
      await assert.rejects(
        () =>
          harness.call('createRejects', {
            bridgeFingerprint: '2B280B23E1107BB62ABFC40DDCC8824814F80A72',
          }),
        /needs "bridgeUrl"/,
      );
      await assert.rejects(
        () =>
          harness.call('createRejects', {
            bridge: 'webrtc',
            stunUrls: ['stun:stun.example.com'],
            bridgeUrl: 'ws://localhost:8080/',
            bridgeFingerprint: '2B280B23E1107BB62ABFC40DDCC8824814F80A72',
          }),
        /apply to the websocket bridge only/,
      );
    });

    it('checks the bridge fingerprint before spending a bootstrap on it', async () => {
      await assert.rejects(
        () =>
          harness.call('createRejects', {
            bridgeUrl: 'ws://localhost:8080/',
            bridgeFingerprint: '2B280B23E1107BB6',
          }),
        /must be 40 hex characters/,
      );
      await assert.rejects(
        () =>
          harness.call('createRejects', {
            bridgeUrl: 'ws://localhost:8080/',
            bridgeFingerprint: 'ZZ280B23E1107BB62ABFC40DDCC8824814F80A72',
          }),
        /must be 40 hex characters/,
      );
    });

    it('takes a log sink of the caller\'s own, in place of the console one', async () => {
      await assert.rejects(
        () => harness.call('createRejects', { onLog: 7 }),
        /must be a function/,
      );
      await assert.rejects(
        () => harness.call('createRejectsWithLogger', { logPrefix: '[x]' }),
        /"onLog" replaces/,
      );
      await assert.rejects(
        () => harness.call('createRejectsWithLogger', { log: false }),
        /"onLog" replaces/,
      );
    });

    it('gives a caller\'s sink the lines the console would have had', async () => {
      // Nothing answers on port 1, so this fails in milliseconds. What it
      // fails after is the point: the sink is the caller's function, and the
      // level travels with the line.
      const lines = await harness.call('createLogging', {
        bridgeUrl: 'ws://127.0.0.1:1/',
        bridgeFingerprint: '2B280B23E1107BB62ABFC40DDCC8824814F80A72',
        connectionTimeoutMs: 10_000,
      });

      assert.ok(
        lines.some((line) => line.startsWith('info: ') && line.includes('Snowflake')),
        `no bridge progress reached the sink: ${JSON.stringify(lines)}`,
      );
    });

    it('type-checks each field', async () => {
      await assert.rejects(
        () => harness.call('createRejects', { connectionTimeoutMs: -1 }),
        /must be a non-negative whole number/,
      );
      await assert.rejects(
        () => harness.call('createRejects', { connectionTimeoutMs: 1.5 }),
        /must be a non-negative whole number/,
      );
      await assert.rejects(
        () => harness.call('createRejects', { logPrefix: 7 }),
        /must be a string/,
      );
      await assert.rejects(
        () => harness.call('createRejects', { stunUrls: 'stun:one' }),
        /must be an array of strings/,
      );
    });
  });
});
