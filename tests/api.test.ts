// The half of the API that answers without touching the network: the URL
// helpers and the option validation every call runs before it costs anything.
//
//   bun run test
//
// Needs a build (`bun run build`) and a Chrome-family binary (CHROME_PATH).

import assert from 'node:assert/strict';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import { openHarness, type BrowserHarness } from './support/browser.ts';

const ONION = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion';

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
