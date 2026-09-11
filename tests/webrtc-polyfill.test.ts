// The webrtc bridge outside a browser: the built package loaded under Bun,
// building its peer connection with node-datachannel's `RTCPeerConnection`,
// the implementation the README names for a host that has none of its own.
//
// No browser and no network. This file stands in for `fetch` to play the
// Snowflake broker, answers webtor's offer with a second node-datachannel
// peer on loopback as a volunteer proxy would, and runs the STUN server the
// offer's candidates are gathered against. No bridge sits behind that proxy,
// so every bootstrap here fails; what it fails on is what shows the proxy's
// bytes reached webtor.
//
//   bun run test
//
// Needs a build (`bun run build`).

import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll as after, beforeAll as before, describe, it } from 'bun:test';
import { RTCPeerConnection } from 'node-datachannel/polyfill';
import { REPO_ROOT } from './support/server.ts';

const PACKAGE = join(REPO_ROOT, 'crates', 'webtor-wasm', 'pkg');
const BROKER_URL = 'https://snowflake-broker.torproject.net/client';
/** The public bridge's identity, the only one the webrtc bridge asks for. */
const PUBLIC_FINGERPRINT = '2B280B23E1107BB62ABFC40DDCC8824814F80A72';
/** What a Turbo connection opens with, before its 8-byte client id. */
const TURBO_TOKEN = '1293605d278175f5';

/** The part of the package this file uses, typed without needing a build. */
interface Webtor {
  default(init: { module_or_path: BufferSource }): Promise<unknown>;
  WebtorClient: { create(options: object): Promise<{ close(): Promise<void> }> };
}

/**
 * Load the package the way a Bun or Node host does: the glue would fetch the
 * binary next to itself, which under Bun is a `file:` URL, so the bytes are
 * read here and handed over.
 */
async function loadWebtor(): Promise<Webtor> {
  const webtor: Webtor = await import(join(PACKAGE, 'webtor_wasm.js'));
  await webtor.default({
    module_or_path: await readFile(join(PACKAGE, 'webtor_wasm_bg.wasm')),
  });
  return webtor;
}

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
  /** The poll's version line and its JSON, as the broker received them. */
  version: string;
  poll: { offer: string; nat: string; fingerprint: string };
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

async function gathered(peer: RTCPeerConnection): Promise<void> {
  if (peer.iceGatheringState === 'complete') return;
  await new Promise<void>((resolve) => {
    peer.onicegatheringstatechange = () => {
      if (peer.iceGatheringState === 'complete') resolve();
    };
  });
}

/**
 * Bootstrap a client over the webrtc bridge with this file as its broker and
 * its volunteer proxy. The proxy answers the first message webtor sends it
 * with `reply`, and the bootstrap fails on whatever webtor makes of that.
 *
 * Resolves once webtor has closed its side as well, since a failed attempt
 * that left its peer connection open would leak one per retry.
 */
async function bootstrapThrough(
  webtor: Webtor,
  stunUrl: string,
  reply: string | Uint8Array,
): Promise<Rendezvous> {
  const seen: Partial<Rendezvous> = {};
  let proxy: RTCPeerConnection | undefined;
  let channelClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    channelClosed = resolve;
  });

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url !== BROKER_URL) throw new Error(`unexpected fetch of ${request.url}`);
    const body = await request.text();
    const newline = body.indexOf('\n');
    seen.version = body.slice(0, newline);
    seen.poll = JSON.parse(body.slice(newline + 1));

    const answering = new RTCPeerConnection({ iceServers: [] });
    proxy = answering;
    answering.ondatachannel = ({ channel }) => {
      seen.label = channel.label;
      channel.binaryType = 'arraybuffer';
      channel.onmessage = ({ data }) => {
        if (seen.first !== undefined) return;
        seen.first =
          data instanceof ArrayBuffer
            ? Buffer.from(data).toString('hex')
            : `a ${typeof data}: ${String(data)}`;
        channel.send(reply);
      };
      channel.onclose = () => channelClosed();
    };
    await answering.setRemoteDescription(JSON.parse(seen.poll?.offer ?? ''));
    await answering.setLocalDescription(await answering.createAnswer());
    await gathered(answering);
    return Response.json({ answer: JSON.stringify(answering.localDescription) });
  }) as typeof fetch;

  try {
    const client = await webtor.WebtorClient.create({
      bridge: 'webrtc',
      stunUrls: [stunUrl],
      rtcPeerConnection: RTCPeerConnection,
      connectionTimeoutMs: 20_000,
      log: false,
    });
    await client.close();
    seen.error = '';
  } catch (error) {
    seen.error = String(error);
  } finally {
    globalThis.fetch = realFetch;
  }

  try {
    if (proxy) await within(closed, 5_000, 'webtor did not close its data channel');
  } finally {
    proxy?.close();
  }
  assert.ok(seen.error, 'bootstrap succeeded with no bridge behind the proxy');
  assert.ok(seen.poll, `webtor never reached the broker: ${seen.error}`);
  assert.ok(seen.first !== undefined, `nothing arrived at the proxy: ${seen.error}`);
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

    assert.equal(seen.version, '1.0');
    assert.equal(seen.poll.fingerprint, PUBLIC_FINGERPRINT);
    assert.equal(seen.poll.nat, 'unrestricted');
    const offer = JSON.parse(seen.poll.offer);
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
});
