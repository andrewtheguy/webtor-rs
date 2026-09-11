// The built package under Bun, with node-datachannel's `RTCPeerConnection`
// for its webrtc bridge, and this process standing in for the Snowflake
// broker that pairs the bridge with a volunteer proxy.

import { access, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { RTCPeerConnection } from 'node-datachannel/polyfill';
import { REPO_ROOT } from './server.ts';

const PACKAGE = join(REPO_ROOT, 'crates', 'webtor-wasm', 'pkg');
export const BROKER_URL = 'https://snowflake-broker.torproject.net/client';

export { RTCPeerConnection };

/** The part of the package these suites use, typed without needing a build. */
export interface WebtorClient {
  fetch(url: string, options?: object): Promise<{ status: number; text(): string }>;
  close(): Promise<void>;
}

export interface Webtor {
  default(init: { module_or_path: BufferSource }): Promise<unknown>;
  WebtorClient: { create(options: object): Promise<WebtorClient> };
}

/**
 * Load the package the way a Bun or Node host does: the glue would fetch the
 * binary next to itself, which under Bun is a `file:` URL, so the bytes are
 * read here and handed over.
 */
export async function loadWebtor(): Promise<Webtor> {
  const glue = join(PACKAGE, 'webtor_wasm.js');
  try {
    await access(glue, constants.R_OK);
  } catch {
    throw new Error(`${glue} is missing or unreadable. Run \`bun run build\` first.`);
  }
  const webtor: Webtor = await import(glue);
  await webtor.default({
    module_or_path: await readFile(join(PACKAGE, 'webtor_wasm_bg.wasm')),
  });
  return webtor;
}

/** A client poll, as the broker received it. */
export interface Poll {
  /** The line before the JSON. */
  version: string;
  offer: string;
  nat: string;
  fingerprint: string;
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
 * Stand in for `fetch` as the Snowflake broker. Every client poll is answered
 * with a new node-datachannel peer on loopback, which hands the data channel
 * webtor opens to `proxy`, as the broker would have matched a volunteer proxy
 * and passed it the offer. Anything else fetched is refused, since webtor has
 * nothing else to fetch.
 *
 * `restore` puts the real `fetch` back and closes every peer.
 */
export function standInForBroker(proxy: (channel: RTCDataChannel) => void): {
  polls: Poll[];
  restore(): void;
} {
  const polls: Poll[] = [];
  const peers: RTCPeerConnection[] = [];
  const realFetch = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url !== BROKER_URL) throw new Error(`unexpected fetch of ${request.url}`);
    const body = await request.text();
    const newline = body.indexOf('\n');
    const poll: Poll = { version: body.slice(0, newline), ...JSON.parse(body.slice(newline + 1)) };
    polls.push(poll);

    const peer = new RTCPeerConnection({ iceServers: [] });
    peers.push(peer);
    peer.ondatachannel = ({ channel }) => {
      channel.binaryType = 'arraybuffer';
      proxy(channel);
    };
    await peer.setRemoteDescription(JSON.parse(poll.offer));
    await peer.setLocalDescription(await peer.createAnswer());
    await gathered(peer);
    return Response.json({ answer: JSON.stringify(peer.localDescription) });
  }) as typeof fetch;

  return {
    polls,
    restore() {
      globalThis.fetch = realFetch;
      for (const peer of peers) peer.close();
    },
  };
}
