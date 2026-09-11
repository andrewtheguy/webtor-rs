// The websocket bridge's Turbo session under Bun, against a bridge of this
// file's own on loopback: one that takes webtor's connection, drops it, and
// then refuses the next ones for a while, or never answers them, as a bridge
// instance that is briefly down or wedged does.
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
/** How long the bridge holds a session no connection has. */
const SESSION_RETENTION_S = 60;

/**
 * What the bridge does with a connection: take it only to close it once
 * webtor's Turbo header is in, refuse it with a 503, or never answer it.
 */
type Behaviour = 'take' | 'refuse' | 'hang';

/** One connection webtor tried, as the bridge saw it. */
interface Attempt {
  /** When it arrived, in `performance.now()` milliseconds. */
  at: number;
  behaviour: Behaviour;
  /** The Turbo client ID it opened with, once it has. */
  clientId?: string;
  /** When the bridge closed it, once it has. */
  closed?: number;
}

/** A WebSocket bridge on loopback that treats the `index`th connection as `plan` says. */
function startBridge(plan: (index: number) => Behaviour) {
  const attempts: Attempt[] = [];
  const server = Bun.serve<{ attempt: Attempt }, never>({
    hostname: '127.0.0.1',
    port: 0,
    // A connection left hanging is the point of one case.
    idleTimeout: 0,
    fetch(request, server) {
      const attempt: Attempt = { at: performance.now(), behaviour: plan(attempts.length) };
      attempts.push(attempt);
      if (attempt.behaviour === 'refuse') return new Response('bridge busy', { status: 503 });
      if (attempt.behaviour === 'hang') return new Promise<Response>(() => {});
      if (server.upgrade(request, { data: { attempt } })) return undefined;
      return new Response('expected a WebSocket', { status: 400 });
    },
    websocket: {
      message(socket, message) {
        const { attempt } = socket.data;
        if (attempt.clientId !== undefined) return;
        const hex = typeof message === 'string' ? '' : Buffer.from(message).toString('hex');
        attempt.clientId = hex.startsWith(TURBO_TOKEN) ? hex.slice(TURBO_TOKEN.length) : hex;
        attempt.closed = performance.now();
        socket.close();
      },
    },
  });
  return { url: `ws://127.0.0.1:${server.port}/`, attempts, stop: () => server.stop(true) };
}

/** Bootstrap through `bridge`, which fails; resolves with why, and when. */
async function bootstrapThrough(
  webtor: Webtor,
  bridge: ReturnType<typeof startBridge>,
): Promise<{ error: string; failed: number }> {
  try {
    const client = await webtor.WebtorClient.create({
      bridgeUrl: bridge.url,
      bridgeFingerprint: FINGERPRINT,
      connectionTimeoutMs: 120_000,
      log: false,
    });
    await client.close();
    assert.fail('bootstrap succeeded through a bridge that speaks no Tor');
  } catch (failure) {
    return { error: String(failure), failed: performance.now() };
  } finally {
    bridge.stop();
  }
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
    const bridge = startBridge((index) => (index === 1 || index === 2 ? 'refuse' : 'take'));
    const { error } = await bootstrapThrough(webtor, bridge);

    const { attempts } = bridge;
    assert.deepEqual(
      attempts.map((attempt) => attempt.behaviour),
      ['take', 'refuse', 'refuse', 'take', 'take'],
      error,
    );
    assert.match(error, /3 connections in a row delivered nothing/);

    const taken = attempts.filter((attempt) => attempt.behaviour === 'take');
    for (const { clientId } of taken) assert.match(clientId ?? '', /^[0-9a-f]{16}$/);
    const ids = new Set(taken.map((attempt) => attempt.clientId));
    assert.equal(ids.size, 1, `the session changed its client ID: ${[...ids].join(', ')}`);

    const gap = (from: number) => (attempts[from + 1].at - attempts[from].at) / 1000;
    assert.ok(gap(1) >= 0.9, `dialed ${gap(1).toFixed(1)} s after the first refusal`);
    assert.ok(gap(2) >= 1.9, `dialed ${gap(2).toFixed(1)} s after the second refusal`);
  });

  it(
    'gives up a replacement that never answers once the bridge has let the session go',
    async () => {
      // A minute, all of it waiting on a bridge that took the connection and
      // never answered the upgrade. The session has to end then, for its Tor
      // channel to close and be opened again, rather than wait on a dial for
      // ever; here the bootstrap's own timeout is twice that.
      const bridge = startBridge((index) => (index === 0 ? 'take' : 'hang'));
      const { error, failed } = await bootstrapThrough(webtor, bridge);

      const [first] = bridge.attempts;
      assert.ok(first.closed, error);
      assert.ok(bridge.attempts.length >= 2, error);
      assert.match(error, /Snowflake session lost/);
      const waited = (failed - first.closed) / 1000;
      assert.ok(
        waited >= SESSION_RETENTION_S - 0.5 && waited < SESSION_RETENTION_S + 3,
        `the session ended ${waited.toFixed(1)} s after its connection was lost: ${error}`,
      );
    },
    90_000,
  );
});
