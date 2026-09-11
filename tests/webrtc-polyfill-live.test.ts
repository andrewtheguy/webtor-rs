// The webrtc bridge end to end outside a browser: the built package under
// Bun, node-datachannel's `RTCPeerConnection`, public STUN servers and the
// public Snowflake bridge, bootstrapped and then used to fetch an onion page.
//
// The one part played here is the volunteer proxy. A real one is whoever the
// broker matches, which a test cannot choose and which may not turn up, so
// this file stands in for the broker, answers webtor's offer itself, and
// relays the data channel to the bridge's WebSocket the way a Snowflake proxy
// does. Everything past that proxy is the real network. Being the proxy is
// also what lets a case take it away, as a volunteer closing a tab would.
//
//   bun run seed                 # optional: keeps the bootstrap to seconds
//   bun run test:live:polyfill
//
// Needs a build (`bun run build`). STUN_URLS overrides the STUN servers and
// DIRECTORY_SEED names the snapshot, as for the other live suites.

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import { SEED_PATH, STUN_URLS } from './support/bootstrap.ts';
import {
  RTCPeerConnection,
  type WebtorClient,
  loadWebtor,
  standInForBroker,
} from './support/polyfill.ts';
import { ATTEMPT_TIMEOUT_MS, HTTP_TARGETS, firstReachable } from './support/targets.ts';

/** Where a Snowflake proxy sends what a client gives it. */
const BRIDGE_WEBSOCKET = 'wss://snowflake.torproject.net/';
const PUBLIC_STUN = ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'];
/** What a Turbo connection opens with, before its 8-byte client ID. */
const TURBO_TOKEN = '1293605d278175f5';

/** A proxy this file is running for webtor. */
interface Relay {
  /** The Turbo client ID the connection opened with, once it has. */
  clientId?: string;
  /** Go away mid-session, as a volunteer's proxy does. */
  cut(): void;
}

const relays: Relay[] = [];

/**
 * Relay a client's data channel to the bridge, message for message, as a
 * Snowflake proxy does. What the client sends before the WebSocket is up is
 * held until it is, and either side closing closes the other.
 */
function relayToBridge(channel: RTCDataChannel): void {
  const bridge = new WebSocket(BRIDGE_WEBSOCKET);
  bridge.binaryType = 'arraybuffer';
  const early: ArrayBuffer[] = [];
  const relay: Relay = {
    cut() {
      channel.close();
      bridge.close();
    },
  };
  relays.push(relay);

  channel.onmessage = ({ data }) => {
    if (relay.clientId === undefined) {
      const hex = Buffer.from(data).toString('hex');
      if (hex.startsWith(TURBO_TOKEN)) relay.clientId = hex.slice(TURBO_TOKEN.length, 32);
    }
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
  const stunUrls = STUN_URLS.length ? STUN_URLS : PUBLIC_STUN;
  const logs: string[] = [];
  const started = Date.now();
  const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)}s`;
  let broker: ReturnType<typeof standInForBroker>;
  let client: WebtorClient;
  let target = HTTP_TARGETS[0];

  before(async () => {
    const webtor = await loadWebtor();
    broker = standInForBroker(relayToBridge);
    client = await webtor.WebtorClient.create({
      bridge: 'webrtc',
      stunUrls,
      rtcPeerConnection: RTCPeerConnection,
      directorySeed: await directorySeed(),
      onLog: (line: string) => {
        logs.push(line);
        console.log(`  ${elapsed().padStart(7)} ${line}`);
      },
    });
    console.log(`  bootstrapped in ${elapsed()}`);
  });

  after(async () => {
    await client?.close();
    broker?.restore();
  });

  it('fetches an onion page through a relaying proxy', async () => {
    const verified = await firstReachable(HTTP_TARGETS, (url) =>
      client.fetch(url, { timeoutMs: ATTEMPT_TIMEOUT_MS }),
    );
    assert.equal(
      verified.result.status,
      200,
      `${verified.target} answered HTTP ${verified.result.status}`,
    );
    assert.match(verified.result.text(), /<html/i);
    target = verified.target;
    console.log(`  fetched ${target} in ${elapsed()}`);
  });

  it('carries on through another proxy when the first goes away', async () => {
    assert.equal(relays.length, 1, 'expected the bootstrap to use one proxy');
    relays[0].cut();

    // The kept circuit is still there on the far side of the bridge: the
    // session moves to a new proxy under it, and KCP resends what the cut
    // lost, so this needs neither a new channel nor a new rendezvous.
    const response = await client.fetch(target, { timeoutMs: ATTEMPT_TIMEOUT_MS });
    assert.equal(response.status, 200);
    console.log(`  fetched ${target} again, after the cut, in ${elapsed()}`);

    assert.equal(relays.length, 2, 'expected exactly one more proxy');
    assert.ok(relays[1].clientId, 'the second proxy saw no Turbo header');
    assert.equal(relays[1].clientId, relays[0].clientId, 'the session changed its client ID');
    assert.equal(
      logs.filter((line) => line === 'Establishing Snowflake bridge channel').length,
      1,
      'the bridge channel was opened again rather than carried over',
    );
  });

  it('gathered a server-reflexive candidate from the STUN servers', () => {
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
