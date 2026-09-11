// The webrtc bridge outside a browser: the built package loaded under Bun,
// building its peer connection with node-datachannel's `RTCPeerConnection`,
// the implementation the README names for a host that has none of its own.
//
// No browser and no network. This file stands in for `fetch` to play the
// Snowflake broker, answers webtor's offer with a second node-datachannel
// peer on loopback as a volunteer proxy would, and runs the STUN server the
// offer's candidates are gathered against. No bridge sits behind that proxy,
// so every bootstrap here fails; what it fails on is what shows the proxy's
// bytes reached webtor. `webrtc-polyfill-live.test.ts` puts the real bridge
// behind the proxy.
//
//   bun run test
//
// Needs a build (`bun run build`).

import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import {
  type BrokerReply,
  type Poll,
  RTCPeerConnection,
  type Webtor,
  loadWebtor,
  standInForBroker,
} from './support/polyfill.ts';

/** The public bridge's identity, the only one the webrtc bridge asks for. */
const PUBLIC_FINGERPRINT = '2B280B23E1107BB62ABFC40DDCC8824814F80A72';
/** What a Turbo connection opens with, before its 8-byte client id. */
const TURBO_TOKEN = '1293605d278175f5';

/**
 * A STUN server on loopback that answers every binding request with the
 * address it came from. An unreachable one would hold ICE gathering for
 * webtor's whole ten-second wait; and the server-reflexive candidate this one
 * yields is what shows the STUN URL webtor was given reached the peer
 * connection.
 */
async function startStun(): Promise<{ url: string; close(): void }> {
  const socket = createSocket('udp4');
  socket.on('message', (request, from) => {
    // A binding request: type, length, magic cookie, 12-byte transaction id.
    if (request.length < 20 || request.readUInt16BE(0) !== 0x0001) return;
    const response = Buffer.alloc(32);
    response.writeUInt16BE(0x0101, 0); // binding success
    response.writeUInt16BE(12, 2); // one attribute, 12 bytes with its header
    request.copy(response, 4, 4, 20); // the cookie and the transaction id
    response.writeUInt16BE(0x0020, 20); // XOR-MAPPED-ADDRESS
    response.writeUInt16BE(8, 22);
    response.writeUInt8(0x01, 25); // IPv4
    response.writeUInt16BE(from.port ^ 0x2112, 26);
    const address = from.address
      .split('.')
      .reduce((value, octet) => value * 256 + Number(octet), 0);
    response.writeUInt32BE((address ^ 0x2112a442) >>> 0, 28);
    socket.send(response, from.port, from.address);
  });
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
  return {
    url: `stun:127.0.0.1:${socket.address().port}`,
    close: () => socket.close(),
  };
}

/** One data channel webtor opened, as the proxy on the other end saw it. */
interface ProxyChannel {
  label: string;
  /** The first message on it, as hex, or what it was if not binary. */
  first: string;
  /** When that arrived, in `performance.now()` milliseconds. */
  at: number;
}

/** What the stand-in broker and proxies saw of one bootstrap. */
interface Rendezvous {
  /** Why `WebtorClient.create` rejected. */
  error: string;
  polls: Poll[];
  channels: ProxyChannel[];
}

/** How the `index`th proxy answers webtor's first message; `null` is silence. */
type ProxyReply = (index: number) => string | Uint8Array<ArrayBuffer> | null;

async function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} within ${ms} ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** The Turbo client ID a connection opened with, from its first message. */
function clientId(channel: ProxyChannel): string {
  assert.match(channel.first, new RegExp(`^${TURBO_TOKEN}[0-9a-f]{16}$`));
  return channel.first.slice(TURBO_TOKEN.length);
}

/**
 * Bootstrap a client over the webrtc bridge with this file as its broker and
 * its volunteer proxies. The broker answers its first polls as
 * `brokerReplies` says and matches a proxy after that, and each proxy answers
 * the first message webtor sends it as `reply` says. No bridge is behind any
 * of them, so the bootstrap fails, on whatever webtor makes of the replies.
 *
 * Resolves once webtor has closed every data channel it opened, since a
 * connection it gave up and left open would leak one per redial.
 */
async function bootstrapThrough(
  webtor: Webtor,
  stunUrl: string,
  reply: ProxyReply,
  brokerReplies: BrokerReply[] = [],
): Promise<Rendezvous> {
  const channels: ProxyChannel[] = [];
  const closes: Promise<void>[] = [];

  const broker = standInForBroker((channel) => {
    const index = closes.length;
    closes.push(
      new Promise<void>((resolve) => {
        channel.onclose = () => resolve();
      }),
    );
    channel.onmessage = ({ data }) => {
      if (channels[index]) return;
      channels[index] = {
        label: channel.label,
        first:
          data instanceof ArrayBuffer
            ? Buffer.from(data).toString('hex')
            : `a ${typeof data}: ${String(data)}`,
        at: performance.now(),
      };
      const answer = reply(index);
      if (typeof answer === 'string') channel.send(answer);
      else if (answer) channel.send(answer);
    };
  }, brokerReplies);

  let error = '';
  try {
    const client = await webtor.WebtorClient.create({
      bridge: 'webrtc',
      stunUrls: [stunUrl],
      rtcPeerConnection: RTCPeerConnection,
      connectionTimeoutMs: 60_000,
      log: false,
    });
    await client.close();
  } catch (failure) {
    error = String(failure);
  }

  try {
    await within(Promise.all(closes), 5_000, 'webtor did not close every data channel');
  } finally {
    broker.restore();
  }
  assert.ok(error, 'bootstrap succeeded with no bridge behind the proxy');
  assert.ok(channels.length, `nothing arrived at a proxy: ${error}`);
  return { error, polls: broker.polls, channels };
}

describe('webrtc bridge with node-datachannel under Bun', () => {
  let webtor: Webtor;
  let stun: { url: string; close(): void };

  before(async () => {
    webtor = await loadWebtor();
    stun = await startStun();
  });

  after(() => {
    stun?.close();
  });

  it('negotiates through the broker and carries binary both ways', async () => {
    // One Turbo data frame of four bytes: too short to be a KCP segment, so
    // KCP refusing it is what shows it came through Turbo as binary.
    const seen = await bootstrapThrough(webtor, stun.url, () => new Uint8Array([0x84, 1, 2, 3, 4]));

    assert.equal(seen.polls.length, 1);
    const [poll] = seen.polls;
    assert.equal(poll.version, '1.0');
    assert.equal(poll.fingerprint, PUBLIC_FINGERPRINT);
    assert.equal(poll.nat, 'unrestricted');
    const offer = JSON.parse(poll.offer);
    assert.equal(offer.type, 'offer');
    assert.match(offer.sdp, / 127\.0\.0\.1 \d+ typ srflx/, 'no candidate from the STUN server');

    assert.equal(seen.channels[0].label, 'webrtc');
    clientId(seen.channels[0]);
    assert.match(seen.error, /KCP input error: InvalidSegmentSize\(4\)/);
  });

  it('carries the session to another proxy, and gives it up after three deliver nothing', async () => {
    // A proxy that sends text is one webtor stops using. The session goes on
    // through the next, which must open with the same client ID for the
    // bridge to know it; three that deliver nothing end it.
    const seen = await bootstrapThrough(webtor, stun.url, () => 'not binary');

    assert.equal(seen.polls.length, 3);
    assert.equal(seen.channels.length, 3);
    const ids = new Set(seen.channels.map(clientId));
    assert.equal(ids.size, 1, `the session changed its client ID: ${[...ids].join(', ')}`);
    assert.match(seen.error, /3 connections in a row delivered nothing/);
  });

  it('moves off a proxy that opens and then says nothing', async () => {
    // Twenty seconds: the bridge's smux speaks every ten, so a connection
    // this quiet is not carrying the session.
    const seen = await bootstrapThrough(webtor, stun.url, (index) =>
      index === 0 ? null : 'not binary',
    );

    assert.equal(seen.polls.length, 3);
    const quiet = (seen.polls[1].at - seen.channels[0].at) / 1000;
    assert.ok(quiet >= 19.5, `gave up on the silent proxy after ${quiet.toFixed(1)} s`);
    assert.equal(new Set(seen.channels.map(clientId)).size, 1);
  });

  it('asks for open proxies once a strict one is unreachable', async () => {
    // Twenty seconds, most of it waiting as the official client does: ten
    // after a broker that had no proxy, then webtor's ten-second wait for a
    // data channel that never opens.
    const seen = await bootstrapThrough(webtor, stun.url, () => 'not binary', [
      'no proxies',
      'unreachable',
    ]);
    const [empty, unreachable, open] = seen.polls;

    // A broker with no proxy says nothing about the NAT; an unreachable proxy
    // matched for an unrestricted one does, for the rest of the client's life.
    assert.deepEqual(
      seen.polls.map((poll) => poll.nat),
      ['unrestricted', 'unrestricted', 'unknown', 'unknown', 'unknown'],
    );
    const gap = (unreachable.at - empty.at) / 1000;
    assert.ok(gap >= 9.5, `polled again ${gap.toFixed(1)} s after "no proxies"`);
    const waited = (open.at - unreachable.at) / 1000;
    assert.ok(waited >= 9.5, `gave up on the unreachable proxy after ${waited.toFixed(1)} s`);
  });
});
