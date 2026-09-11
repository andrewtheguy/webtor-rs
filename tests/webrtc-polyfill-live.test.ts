// The webrtc bridge end to end outside a browser: the built package under
// Bun, node-datachannel's `RTCPeerConnection`, public STUN servers and the
// public Snowflake bridge, bootstrapped and then used to fetch an onion page.
//
// The one part played here is the volunteer proxy. A real one is whoever the
// broker matches, which a test cannot choose and which may not turn up, so
// this file stands in for the broker, answers webtor's offer itself, and
// relays the data channel to the bridge's WebSocket the way a Snowflake proxy
// does. Everything past that proxy is the real network.
//
//   bun run seed                 # optional: keeps the bootstrap to seconds
//   bun run test:live:polyfill
//
// Needs a build (`bun run build`). STUN_URLS overrides the STUN servers and
// DIRECTORY_SEED names the snapshot, as for the other live suites.

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'bun:test';
import { SEED_PATH, STUN_URLS } from './support/bootstrap.ts';
import { RTCPeerConnection, loadWebtor, standInForBroker } from './support/polyfill.ts';
import { ATTEMPT_TIMEOUT_MS, HTTP_TARGETS, firstReachable } from './support/targets.ts';

/** Where a Snowflake proxy sends what a client gives it. */
const BRIDGE_WEBSOCKET = 'wss://snowflake.torproject.net/';
const PUBLIC_STUN = ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'];

/**
 * Relay a client's data channel to the bridge, message for message, as a
 * Snowflake proxy does. What the client sends before the WebSocket is up is
 * held until it is, and either side closing closes the other.
 */
function relayToBridge(channel: RTCDataChannel): void {
  const bridge = new WebSocket(BRIDGE_WEBSOCKET);
  bridge.binaryType = 'arraybuffer';
  const early: ArrayBuffer[] = [];

  channel.onmessage = ({ data }) => {
    if (bridge.readyState === WebSocket.OPEN) bridge.send(data);
    else early.push(data);
  };
  bridge.onopen = () => {
    for (const data of early.splice(0)) bridge.send(data);
  };
  bridge.onmessage = ({ data }) => {
    if (channel.readyState === 'open') channel.send(data);
  };
  bridge.onclose = () => channel.close();
  channel.onclose = () => bridge.close();
}

async function directorySeed(): Promise<string | undefined> {
  try {
    return await readFile(SEED_PATH, 'utf8');
  } catch {
    console.log(
      `  no directory seed at ${SEED_PATH}; bootstrapping from the network. ` +
        'Run `bun run seed` to make this fast.',
    );
    return undefined;
  }
}

describe('webrtc bridge with node-datachannel over the network', () => {
  it('bootstraps through a relaying proxy and fetches an onion page', async () => {
    const webtor = await loadWebtor();
    const stunUrls = STUN_URLS.length ? STUN_URLS : PUBLIC_STUN;
    const broker = standInForBroker(relayToBridge);
    const started = Date.now();
    const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;

    let client: Awaited<ReturnType<typeof webtor.WebtorClient.create>> | undefined;
    try {
      client = await webtor.WebtorClient.create({
        bridge: 'webrtc',
        stunUrls,
        rtcPeerConnection: RTCPeerConnection,
        directorySeed: await directorySeed(),
        onLog: (line: string) => console.log(`  ${elapsed().padStart(7)} ${line}`),
      });
      console.log(`  bootstrapped in ${elapsed()}`);

      const reached = client;
      const verified = await firstReachable(HTTP_TARGETS, (url) =>
        reached.fetch(url, { timeoutMs: ATTEMPT_TIMEOUT_MS }),
      );
      assert.equal(
        verified.result.status,
        200,
        `${verified.target} answered HTTP ${verified.result.status}`,
      );
      assert.match(verified.result.text(), /<html/i);
      console.log(`  fetched ${verified.target} in ${elapsed()}`);
    } finally {
      await client?.close();
      broker.restore();
    }

    // Checked last, so that a network which drops UDP still shows whether the
    // bridge was reachable: the proxy is on loopback, so the channel opens on
    // host candidates alone, and only this says the STUN servers answered.
    const offer = JSON.parse(broker.polls[0]?.offer ?? '{}');
    assert.match(
      offer.sdp ?? '',
      /typ srflx/,
      `no server-reflexive candidate from ${stunUrls.join(', ')}`,
    );
  });
});
