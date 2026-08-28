// The whole proof: bootstrap a Tor client in this tab, publish a v3 onion
// service from it, answer HTTP on the streams clients open, and — with the
// same client — fetch the address back over the network.

import { directorySeedStore } from '../../shared/directory-cache';
import { loadWebtor } from './webtor';

export type LogLevel = 'info' | 'success' | 'error';

export interface LogEntry {
  at: number;
  level: LogLevel;
  message: string;
}

export interface ServedRequest {
  at: number;
  line: string;
}

export interface StartOptions {
  bridge: 'websocket' | 'webrtc';
  introPoints: number;
  onLog: (entry: LogEntry) => void;
  onRequest: (request: ServedRequest) => void;
}

export interface RunningService {
  address: string;
  /** GET the service's own address back through Tor. */
  fetchSelf(path: string): Promise<SelfFetch>;
  stop(): Promise<void>;
}

export interface SelfFetch {
  status: number;
  seconds: number;
  text: string;
}

/** STUN servers the `webrtc` bridge needs to find its own address. */
const STUN_URLS = ['stun:stun.l.google.com:19302'];

/**
 * A bridge to use instead of the public one, from `.env.local`:
 *
 *   VITE_BRIDGE_URL=ws://localhost:8080/
 *   VITE_BRIDGE_FINGERPRINT=<what scripts/local-bridge prints>
 *
 * Worth doing while iterating, because the client fetches the consensus and
 * every HSDir microdescriptor one hop from the bridge: against a local one
 * that download is local too. Both or neither — a URL without an identity
 * would be a request to trust whatever answers.
 */
const BRIDGE_URL = import.meta.env.VITE_BRIDGE_URL;
const BRIDGE_FINGERPRINT = import.meta.env.VITE_BRIDGE_FINGERPRINT;

if (Boolean(BRIDGE_URL) !== Boolean(BRIDGE_FINGERPRINT)) {
  throw new Error(
    'Set VITE_BRIDGE_URL and VITE_BRIDGE_FINGERPRINT together, or neither',
  );
}

/** How long the page waits for its own service to answer. */
const SELF_FETCH_TIMEOUT_MS = 240_000;

/**
 * How much of a request head this will read before giving up on a client.
 * Anyone on the network can open a stream to a published service, and one
 * that never sends the blank line would otherwise grow this tab's memory
 * without bound.
 */
const MAX_REQUEST_HEAD_BYTES = 16 * 1024;

function page(address: string, served: number): string {
  return `<!doctype html>
<meta charset="utf-8">
<title>webtor onion service</title>
<h1>Served from a browser tab.</h1>
<p>This page came out of a Tor circuit that ends in someone's browser: no
server, no application proxy, no port forwarded.</p>
<p>Address: <code>${address}</code></p>
<p>Requests answered so far: ${served}</p>
<p>Generated at ${new Date().toISOString()}</p>
`;
}

const store = directorySeedStore('webtor-onion-service-poc');

export async function startOnionService(
  options: StartOptions,
): Promise<RunningService> {
  const log = (level: LogLevel, message: string) =>
    options.onLog({ at: Date.now(), level, message });

  const { WebtorClient } = await loadWebtor();
  const seed = await store.load();
  log('info', `Tor directory: ${seed.source}`);

  const client = await WebtorClient.create({
    bridge: options.bridge,
    ...(options.bridge === 'webrtc' ? { stunUrls: STUN_URLS } : {}),
    ...(BRIDGE_URL && BRIDGE_FINGERPRINT
      ? { bridgeUrl: BRIDGE_URL, bridgeFingerprint: BRIDGE_FINGERPRINT }
      : {}),
    ...(seed.value ? { directorySeed: seed.value } : {}),
    // Keep every directory this client downloads, not just the one it started
    // with: a published service refreshes the directory for as long as it is
    // up, and downloading one over a single bridge circuit is the slowest part
    // of a cold start.
    onDirectoryChange: (cache: string) => {
      void store.save(cache).then((stored) => {
        if (stored) log('info', 'Stored a fresh Tor directory for the next start');
      });
    },
    logPrefix: '[onion-service-poc]',
  });
  log('success', 'Tor client bootstrapped');

  let service;
  try {
    log('info', 'Establishing introduction points and publishing a descriptor…');
    service = await client.publishOnionService({
      introPoints: options.introPoints,
    });
  } catch (error) {
    await client.close();
    throw error;
  }
  const address: string = service.onionAddress;
  log('success', `Published ${address}`);

  let served = 0;
  let stopped = false;

  // The accept loop runs for as long as the service does. Each client gets
  // its own task so a slow one cannot hold up the next.
  void (async () => {
    for (;;) {
      const stream = await service.accept();
      if (stream == null || stopped) return;
      void (async () => {
        // Its own decoder: one shared between clients would carry a partial
        // multi-byte character from one stream into the next.
        const decoder = new TextDecoder();
        try {
          let request = '';
          let headBytes = 0;
          let oversized = false;
          while (!request.includes('\r\n\r\n')) {
            const chunk = await stream.receive();
            if (chunk == null) break;
            headBytes += chunk.length;
            if (headBytes > MAX_REQUEST_HEAD_BYTES) {
              oversized = true;
              break;
            }
            request += decoder.decode(chunk, { stream: true });
          }
          if (oversized) {
            log('error', 'A client sent an oversized request head');
            await stream.send(
              'HTTP/1.1 431 Request Header Fields Too Large\r\n' +
                'Content-Length: 0\r\n' +
                'Connection: close\r\n\r\n',
            );
            return;
          }
          const line = request.split('\r\n', 1)[0] ?? '(empty request)';
          served += 1;
          options.onRequest({ at: Date.now(), line });

          const body = page(address, served);
          await stream.send(
            'HTTP/1.1 200 OK\r\n' +
              'Content-Type: text/html; charset=utf-8\r\n' +
              `Content-Length: ${new TextEncoder().encode(body).length}\r\n` +
              'Connection: close\r\n\r\n' +
              body,
          );
        } catch (error) {
          log('error', `A client stream failed: ${String(error)}`);
        } finally {
          await stream.close().catch(() => undefined);
        }
      })();
    }
  })();

  return {
    address,
    async fetchSelf(path: string): Promise<SelfFetch> {
      const started = performance.now();
      const response = await client.fetch(`http://${address}${path}`, {
        timeoutMs: SELF_FETCH_TIMEOUT_MS,
      });
      return {
        status: response.status,
        seconds: Number(((performance.now() - started) / 1000).toFixed(1)),
        text: response.text(),
      };
    },
    async stop(): Promise<void> {
      stopped = true;
      try {
        await service.close();
      } finally {
        // A service that failed to withdraw is all the more reason to take
        // the client's circuits down with it.
        await client.close();
      }
      log('info', 'Service withdrawn and client closed');
    },
  };
}
