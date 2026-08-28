import {
  type Event as NostrEvent,
  finalizeEvent,
  generateSecretKey,
  verifyEvent,
} from 'nostr-tools';
import { directorySeedStore } from '../../shared/directory-cache';
import { loadWebtor } from './webtor';

export const ONION_RELAYS = [
  'ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion',
  'ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion',
] as const;

const EVENT_KIND = 24_243;
const RELAY_TIMEOUT_MS = 120_000;
/**
 * The Tor Project's own onion site. Fetching it exercises the whole client —
 * HSDir lookup, introduction, rendezvous and a stream — so this app knows
 * whether a later failure is its relays or its client. Which onion is worth
 * reaching is this app's question, not the library's, so the check lives
 * here.
 */
const VERIFY_URL =
  'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/';
const VERIFY_TIMEOUT_MS = 240_000;
const MESSAGE_TIMEOUT_MS = 45_000;
const STUN_URLS = [
  'stun:stun.l.google.com:19302',
  'stun:stun1.l.google.com:19302',
  'stun:stun.cloudflare.com:3478',
];

type WebtorMessage =
  | { type: 'text'; text: string }
  | { type: 'binary'; bytes: Uint8Array };

interface OnionSocket {
  send(text: string): Promise<unknown>;
  receive(): Promise<WebtorMessage | null | undefined>;
  close(): Promise<unknown>;
}

interface OnionResponse {
  status: number;
  ok: boolean;
}

interface OnionClient {
  connectWebSocket(
    url: string,
    options?: { timeoutMs: number },
  ): Promise<OnionSocket>;
  fetch(url: string, options?: { timeoutMs: number }): Promise<OnionResponse>;
  close(): Promise<unknown>;
}

export type LogLevel = 'info' | 'success' | 'error';

export interface ProofLog {
  level: LogLevel;
  message: string;
  detail?: string;
}

export interface RoundTripOptions {
  bridge: 'websocket' | 'webrtc';
  message: string;
  relay: 'auto' | (typeof ONION_RELAYS)[number];
  onLog(entry: ProofLog): void;
}

export interface RoundTripResult {
  relay: string;
  eventId: string;
  pubkey: string;
  content: string;
  elapsedMs: number;
}

type RelayMessage = unknown[];
type MatchResult<T> =
  | { matched: false }
  | { matched: true; value: T };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function compactRelayMessage(message: RelayMessage): string {
  const type = typeof message[0] === 'string' ? message[0] : 'unknown';
  if (type === 'EVENT') {
    const event = message[2];
    if (isNostrEvent(event)) return `EVENT ${event.id.slice(0, 12)}…`;
  }
  if (type === 'OK') {
    return `OK ${String(message[1]).slice(0, 12)}… ${String(message[2])}`;
  }
  return JSON.stringify(message).slice(0, 180);
}

function isNostrEvent(value: unknown): value is NostrEvent {
  if (typeof value !== 'object' || value === null) return false;
  const event = value as Record<string, unknown>;
  return (
    typeof event.id === 'string' &&
    typeof event.pubkey === 'string' &&
    typeof event.created_at === 'number' &&
    typeof event.kind === 'number' &&
    Array.isArray(event.tags) &&
    typeof event.content === 'string' &&
    typeof event.sig === 'string'
  );
}

function withDeadline<T>(
  operation: Promise<T>,
  timeoutMs: number,
  description: string,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeout = globalThis.setTimeout(
      () =>
        reject(
          new Error(`${description} timed out after ${timeoutMs / 1000}s`),
        ),
      timeoutMs,
    );
    void operation.then(
      (value) => {
        globalThis.clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        globalThis.clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

async function receiveMatching<T>(
  socket: OnionSocket,
  description: string,
  onLog: RoundTripOptions['onLog'],
  match: (message: RelayMessage) => MatchResult<T>,
): Promise<T> {
  const receiveLoop = async (): Promise<T> => {
    while (true) {
      const inbound = await socket.receive();
      if (inbound == null) {
        throw new Error(`Relay closed while waiting for ${description}`);
      }
      if (inbound.type !== 'text') {
        throw new Error('Relay sent a binary Nostr message');
      }

      let message: unknown;
      try {
        message = JSON.parse(inbound.text);
      } catch {
        throw new Error('Relay sent invalid JSON');
      }
      if (!Array.isArray(message)) {
        throw new Error('Relay sent a non-array Nostr message');
      }

      onLog({
        level: 'info',
        message: 'Relay → browser',
        detail: compactRelayMessage(message),
      });
      const result = match(message);
      if (result.matched) return result.value;
    }
  };

  return withDeadline(receiveLoop(), MESSAGE_TIMEOUT_MS, description);
}

async function closeQuietly(socket: OnionSocket | undefined): Promise<void> {
  await socket?.close().catch(() => undefined);
}

async function openSocketPair(
  client: OnionClient,
  relay: string,
): Promise<{ subscriber: OnionSocket; publisher: OnionSocket }> {
  const results = await Promise.allSettled([
    client.connectWebSocket(relay, { timeoutMs: RELAY_TIMEOUT_MS }),
    client.connectWebSocket(relay, { timeoutMs: RELAY_TIMEOUT_MS }),
  ]);

  if (results[0].status === 'fulfilled' && results[1].status === 'fulfilled') {
    return { subscriber: results[0].value, publisher: results[1].value };
  }

  await Promise.all(
    results.map((result) =>
      result.status === 'fulfilled' ? closeQuietly(result.value) : undefined,
    ),
  );
  const failures = results
    .filter(
      (result): result is PromiseRejectedResult =>
        result.status === 'rejected',
    )
    .map((result) => errorMessage(result.reason));
  throw new Error(failures.join('; '));
}

async function proveOnRelay(
  client: OnionClient,
  relay: string,
  event: NostrEvent,
  marker: string,
  onLog: RoundTripOptions['onLog'],
): Promise<void> {
  onLog({
    level: 'info',
    message: 'Opening two independent onion WebSockets',
    detail: relay,
  });
  const { subscriber, publisher } = await openSocketPair(client, relay);
  const subscriptionId = `webtor-poc-${crypto.randomUUID().slice(0, 8)}`;

  try {
    const eose = receiveMatching(subscriber, 'EOSE', onLog, (message) => {
      if (message[0] === 'EOSE' && message[1] === subscriptionId) {
        return { matched: true, value: undefined };
      }
      return { matched: false };
    });
    const request = [
      'REQ',
      subscriptionId,
      {
        kinds: [EVENT_KIND],
        authors: [event.pubkey],
        '#t': [marker],
        since: event.created_at - 5,
        limit: 1,
      },
    ];
    onLog({
      level: 'info',
      message: 'Subscriber → relay',
      detail: `REQ ${subscriptionId}`,
    });
    await subscriber.send(JSON.stringify(request));
    await eose;
    onLog({
      level: 'success',
      message: 'Subscription is live',
      detail: 'EOSE received before publication',
    });

    const receivedEvent = receiveMatching<NostrEvent>(
      subscriber,
      'published event',
      onLog,
      (message) => {
        const candidate = message[2];
        if (
          message[0] !== 'EVENT' ||
          message[1] !== subscriptionId ||
          !isNostrEvent(candidate) ||
          candidate.id !== event.id
        ) {
          return { matched: false };
        }
        if (!verifyEvent(candidate)) {
          throw new Error('Subscriber received an event with an invalid signature');
        }
        return { matched: true, value: candidate };
      },
    );
    const publicationAck = receiveMatching(
      publisher,
      'positive publication acknowledgement',
      onLog,
      (message) => {
        if (message[0] !== 'OK' || message[1] !== event.id) {
          return { matched: false };
        }
        if (message[2] !== true) {
          throw new Error(`Relay rejected the event: ${String(message[3] ?? '')}`);
        }
        return { matched: true, value: undefined };
      },
    );

    onLog({
      level: 'info',
      message: 'Publisher → relay',
      detail: `EVENT ${event.id.slice(0, 12)}…`,
    });
    await publisher.send(JSON.stringify(['EVENT', event]));
    const [inbound] = await Promise.all([
      receivedEvent,
      publicationAck,
    ] as const);

    if (inbound.content !== event.content || inbound.pubkey !== event.pubkey) {
      throw new Error('Received event does not match the published event');
    }
    await subscriber.send(JSON.stringify(['CLOSE', subscriptionId]));
    onLog({
      level: 'success',
      message: 'Signed message made a complete round trip',
      detail: event.content,
    });
  } finally {
    await Promise.all([closeQuietly(subscriber), closeQuietly(publisher)]);
  }
}

const store = directorySeedStore('webtor-nostr-onion-poc');

export async function runNostrRoundTrip(
  options: RoundTripOptions,
): Promise<RoundTripResult> {
  const started = performance.now();
  const onLog = options.onLog;
  const directory = await store.load();
  onLog({
    level: 'info',
    message: 'Loading webtor WASM',
    detail: `Directory source: ${directory.source}`,
  });

  const module = await loadWebtor();
  onLog({
    level: 'info',
    message: 'Bootstrapping Tor and verifying an onion rendezvous',
    detail:
      options.bridge === 'websocket'
        ? 'Direct Snowflake WebSocket bridge'
        : 'Snowflake volunteer WebRTC proxy',
  });
  const client = (await module.WebtorClient.create({
    bridge: options.bridge,
    ...(options.bridge === 'webrtc' ? { stunUrls: STUN_URLS } : {}),
    directorySeed: directory.value,
    connectionTimeoutMs: 300_000,
    // Every directory this client downloads, kept for the next run. A seed
    // that came from here is never handed back, so this fires only when there
    // is something new to store.
    onDirectoryChange: (cache: string) => {
      void store.save(cache);
      onLog({
        level: 'info',
        message: 'Saved the validated directory in IndexedDB',
      });
    },
    logPrefix: '[nostr-onion-poc]',
  })) as OnionClient;

  try {
    const verified = await client.fetch(VERIFY_URL, {
      timeoutMs: VERIFY_TIMEOUT_MS,
    });
    if (!verified.ok) {
      throw new Error(`${VERIFY_URL} answered HTTP ${verified.status}`);
    }
    onLog({
      level: 'success',
      message: 'Tor client is verified',
      detail: `${VERIFY_URL} answered HTTP ${verified.status}`,
    });
    const secretKey = generateSecretKey();
    const marker = `webtor-poc:${crypto.randomUUID()}`;
    const event = finalizeEvent(
      {
        kind: EVENT_KIND,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['t', marker],
          ['expiration', String(Math.floor(Date.now() / 1000) + 300)],
        ],
        content: options.message,
      },
      secretKey,
    );
    onLog({
      level: 'info',
      message: 'Created an ephemeral signed Nostr event',
      detail: `${event.id.slice(0, 12)}… · kind ${EVENT_KIND}`,
    });

    const relays = options.relay === 'auto' ? ONION_RELAYS : [options.relay];
    const failures: string[] = [];
    for (const relay of relays) {
      try {
        await proveOnRelay(client, relay, event, marker, onLog);
        return {
          relay,
          eventId: event.id,
          pubkey: event.pubkey,
          content: event.content,
          elapsedMs: Math.round(performance.now() - started),
        };
      } catch (error) {
        const message = errorMessage(error);
        failures.push(`${relay}: ${message}`);
        onLog({
          level: 'error',
          message: 'Relay attempt failed',
          detail: `${relay} · ${message}`,
        });
      }
    }
    throw new Error(`No onion relay completed the proof. ${failures.join(' | ')}`);
  } finally {
    await client.close();
    onLog({ level: 'info', message: 'Closed Tor client and both relay sockets' });
  }
}
