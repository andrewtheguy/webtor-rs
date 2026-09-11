// The websocket bridge's Turbo session under Bun, against a bridge of this
// file's own on loopback: one that takes webtor's connection, drops it, and
// refuses the next ones for a while, as a bridge instance that is briefly
// down or overloaded does.
//
// No network. The bridge speaks no Tor, so the bootstrap fails; what matters
// is how webtor dialed it on the way.
//
//   bun run test
//
// Needs a build (`bun run build`).

import assert from 'node:assert/strict';
import { beforeAll as before, describe, it } from 'bun:test';
import { type Webtor, loadWebtor } from './support/polyfill.ts';

/** Any well-formed identity serves: nothing gets as far as checking it. */
const FINGERPRINT = '2B280B23E1107BB62ABFC40DDCC8824814F80A72';
/** What a Turbo connection opens with, before its 8-byte client ID. */
const TURBO_TOKEN = '1293605d278175f5';

/** One connection webtor tried, as the bridge saw it. */
interface Attempt {
  /** When it arrived, in `performance.now()` milliseconds. */
  at: number;
  refused: boolean;
  /** The Turbo client ID it opened with, once it has. */
  clientId?: string;
}

/**
 * A WebSocket bridge on loopback that refuses the connections `refuse` names,
 * by index, with a 503, and accepts the rest only to close each once webtor's
 * Turbo header is in.
 */
function startBridge(refuse: Set<number>) {
  const attempts: Attempt[] = [];
  const server = Bun.serve<{ attempt: Attempt }, never>({
    hostname: '127.0.0.1',
    port: 0,
    fetch(request, server) {
      const attempt: Attempt = { at: performance.now(), refused: refuse.has(attempts.length) };
      attempts.push(attempt);
      if (attempt.refused) return new Response('bridge busy', { status: 503 });
      if (server.upgrade(request, { data: { attempt } })) return undefined;
      return new Response('expected a WebSocket', { status: 400 });
    },
    websocket: {
      message(socket, message) {
        const { attempt } = socket.data;
        if (attempt.clientId !== undefined) return;
        const hex = typeof message === 'string' ? '' : Buffer.from(message).toString('hex');
        attempt.clientId = hex.startsWith(TURBO_TOKEN) ? hex.slice(TURBO_TOKEN.length) : hex;
        socket.close();
      },
    },
  });
  return { url: `ws://127.0.0.1:${server.port}/`, attempts, stop: () => server.stop(true) };
}

describe('websocket bridge session under Bun', () => {
  let webtor: Webtor;

  before(async () => {
    webtor = await loadWebtor();
  });

  it('dials again, backing off, while the bridge refuses the replacement', async () => {
    // Taken, refused, refused, then taken twice more. Refusals are not
    // connections, so they do not count toward the three that deliver
    // nothing; the session ends on those three.
    const bridge = startBridge(new Set([1, 2]));
    let error = '';
    try {
      const client = await webtor.WebtorClient.create({
        bridgeUrl: bridge.url,
        bridgeFingerprint: FINGERPRINT,
        connectionTimeoutMs: 30_000,
        log: false,
      });
      await client.close();
    } catch (failure) {
      error = String(failure);
    } finally {
      bridge.stop();
    }

    const { attempts } = bridge;
    assert.deepEqual(
      attempts.map((attempt) => attempt.refused),
      [false, true, true, false, false],
      error,
    );
    assert.match(error, /3 connections in a row delivered nothing/);

    const accepted = attempts.filter((attempt) => !attempt.refused);
    for (const { clientId } of accepted) assert.match(clientId ?? '', /^[0-9a-f]{16}$/);
    const ids = new Set(accepted.map((attempt) => attempt.clientId));
    assert.equal(ids.size, 1, `the session changed its client ID: ${[...ids].join(', ')}`);

    const gap = (from: number) => (attempts[from + 1].at - attempts[from].at) / 1000;
    assert.ok(gap(1) >= 0.9, `dialed ${gap(1).toFixed(1)} s after the first refusal`);
    assert.ok(gap(2) >= 1.9, `dialed ${gap(2).toFixed(1)} s after the second refusal`);
  });
});
