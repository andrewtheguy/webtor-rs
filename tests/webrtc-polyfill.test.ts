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

/** What the stand-in broker and proxy saw of one bootstrap. */
interface Rendezvous {
  /** Why `WebtorClient.create` rejected. */
  error: string;
  /** Every broker poll, the last being the one whose proxy answered. */
  polls: Poll[];
  /** The label of the data channel webtor opened. */
  label: string;
  /** The first message on it, as hex, or what it was if not binary. */
  first: string;
}

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

/**
 * Bootstrap a client over the webrtc bridge with this file as its broker and
 * its volunteer proxy. The broker answers its first polls as `brokerReplies`
 * says and matches a proxy after that. The proxy answers the first message
 * webtor sends it with `reply`, and the bootstrap fails on whatever webtor
 * makes of that.
 *
 * Resolves once webtor has closed its side as well, since a failed attempt
 * that left its peer connection open would leak one per retry.
 */
async function bootstrapThrough(
  webtor: Webtor,
  stunUrl: string,
  reply: string | Uint8Array<ArrayBuffer>,
  brokerReplies: BrokerReply[] = [],
): Promise<Rendezvous> {
  const seen: Partial<Rendezvous> = {};
  let channelClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    channelClosed = resolve;
  });

  const broker = standInForBroker((channel) => {
    seen.label = channel.label;
    channel.onmessage = ({ data }) => {
      if (seen.first !== undefined) return;
      seen.first =
        data instanceof ArrayBuffer
          ? Buffer.from(data).toString('hex')
          : `a ${typeof data}: ${String(data)}`;
      if (typeof reply === 'string') channel.send(reply);
      else channel.send(reply);
    };
    channel.onclose = () => channelClosed();
  }, brokerReplies);

  try {
    const client = await webtor.WebtorClient.create({
      bridge: 'webrtc',
      stunUrls: [stunUrl],
      rtcPeerConnection: RTCPeerConnection,
      connectionTimeoutMs: 60_000,
      log: false,
    });
    await client.close();
    seen.error = '';
  } catch (error) {
    seen.error = String(error);
  }

  try {
    if (broker.polls.length) await within(closed, 5_000, 'webtor did not close its data channel');
  } finally {
    broker.restore();
  }
  assert.ok(seen.error, 'bootstrap succeeded with no bridge behind the proxy');
  assert.equal(
    broker.polls.length,
    brokerReplies.length + 1,
    `expected a poll per broker reply and one more: ${seen.error}`,
  );
  assert.ok(seen.first !== undefined, `nothing arrived at the proxy: ${seen.error}`);
  seen.polls = broker.polls;
  return seen as Rendezvous;
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
    const seen = await bootstrapThrough(webtor, stun.url, new Uint8Array([0x84, 1, 2, 3, 4]));

    const [poll] = seen.polls;
    assert.equal(poll.version, '1.0');
    assert.equal(poll.fingerprint, PUBLIC_FINGERPRINT);
    assert.equal(poll.nat, 'unrestricted');
    const offer = JSON.parse(poll.offer);
    assert.equal(offer.type, 'offer');
    assert.match(offer.sdp, / 127\.0\.0\.1 \d+ typ srflx/, 'no candidate from the STUN server');

    assert.equal(seen.label, 'webrtc');
    assert.match(seen.first, new RegExp(`^${TURBO_TOKEN}[0-9a-f]{16}$`));
    assert.match(seen.error, /KCP input error: InvalidSegmentSize\(4\)/);
  });

  it('refuses a text message from the proxy', async () => {
    const seen = await bootstrapThrough(webtor, stun.url, 'not binary');
    assert.match(seen.error, /Snowflake WebRTC received a non-binary message/);
  });

  it('asks for open proxies once a strict one is unreachable', async () => {
    // Twenty seconds, most of it waiting as the official client does: ten
    // after a broker that had no proxy, then webtor's ten-second wait for a
    // data channel that never opens.
    const seen = await bootstrapThrough(webtor, stun.url, 'not binary', [
      'no proxies',
      'unreachable',
    ]);
    const [empty, unreachable, open] = seen.polls;

    // A broker with no proxy says nothing about the NAT; an unreachable proxy
    // matched for an unrestricted one does.
    assert.deepEqual(
      seen.polls.map((poll) => poll.nat),
      ['unrestricted', 'unrestricted', 'unknown'],
    );
    const gap = (unreachable.at - empty.at) / 1000;
    assert.ok(gap >= 9.5, `polled again ${gap.toFixed(1)} s after "no proxies"`);
    const waited = (open.at - unreachable.at) / 1000;
    assert.ok(waited >= 9.5, `gave up on the unreachable proxy after ${waited.toFixed(1)} s`);
    assert.match(seen.error, /Snowflake WebRTC received a non-binary message/);
  });
});
