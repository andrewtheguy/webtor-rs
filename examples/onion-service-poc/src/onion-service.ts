// The whole proof: bootstrap a Tor client in this tab, publish a v3 onion
// service from it, answer HTTP on the streams clients open, and — with the
// same client — fetch the address back over the network.

import { loadDirectorySeed, saveDirectoryCache } from './directory-cache';
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

/** How long the page waits for its own service to answer. */
const SELF_FETCH_TIMEOUT_MS = 240_000;

function page(address: string, served: number): string {
  return `<!doctype html>
<meta charset="utf-8">
<title>webtor onion service</title>
<h1>Served from a browser tab.</h1>
<p>This page came out of a Tor circuit that ends in someone's browser: no
server, no proxy, no port forwarded.</p>
<p>Address: <code>${address}</code></p>
<p>Requests answered so far: ${served}</p>
<p>Generated at ${new Date().toISOString()}</p>
`;
}

export async function startOnionService(
  options: StartOptions,
): Promise<RunningService> {
  const log = (level: LogLevel, message: string) =>
    options.onLog({ at: Date.now(), level, message });

  const { WebtorClient } = await loadWebtor();
  const seed = await loadDirectorySeed();
  log('info', `Tor directory: ${seed.source}`);

  const client = await WebtorClient.create({
    bridge: options.bridge,
    ...(options.bridge === 'webrtc' ? { stunUrls: STUN_URLS } : {}),
    ...(seed.value ? { directorySeed: seed.value } : {}),
    logPrefix: '[onion-service-poc]',
  });
  log('success', 'Tor client bootstrapped');

  // Keep the validated directory for the next load; downloading it over a
  // single bridge circuit is the slowest part of a cold start.
  void client
    .directoryCache()
    .then((cache: string) => saveDirectoryCache(cache))
    .catch(() => undefined);

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
  const decoder = new TextDecoder();

  // The accept loop runs for as long as the service does. Each client gets
  // its own task so a slow one cannot hold up the next.
  void (async () => {
    for (;;) {
      const stream = await service.accept();
      if (stream == null || stopped) return;
      void (async () => {
        try {
          let request = '';
          while (!request.includes('\r\n\r\n')) {
            const chunk = await stream.receive();
            if (chunk == null) break;
            request += decoder.decode(chunk, { stream: true });
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
      await service.close();
      await client.close();
      log('info', 'Service withdrawn and client closed');
    },
  };
}
