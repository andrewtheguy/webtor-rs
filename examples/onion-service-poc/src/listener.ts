// The listening side: publish a v3 onion service from this tab and take
// messages on it. A message is the body of `POST /message`; anything else
// gets a small page saying what this address is.

import { createClient, logger, type Bridge, type LogEntry } from './tor-client';

export interface ReceivedMessage {
  at: number;
  text: string;
}

export interface ListenOptions {
  bridge: Bridge;
  introPoints: number;
  onLog: (entry: LogEntry) => void;
  onMessage: (message: ReceivedMessage) => void;
}

export interface Listener {
  address: string;
  stop(): Promise<void>;
}

/**
 * How much of a request this will read before giving up on a client. Anyone
 * on the network can open a stream to a published service, and one that
 * never finishes would otherwise grow this tab's memory without bound.
 */
const MAX_HEAD_BYTES = 16 * 1024;
const MAX_BODY_BYTES = 64 * 1024;

/**
 * Sent on every answer so the sending page can read it with the browser's
 * `fetch`, which in Tor Browser is a different origin arriving over a
 * different Tor.
 */
const CORS = 'Access-Control-Allow-Origin: *\r\n';

function response(status: string, body: string, type = 'text/plain'): string {
  return (
    `HTTP/1.1 ${status}\r\n` +
    `Content-Type: ${type}; charset=utf-8\r\n` +
    `Content-Length: ${new TextEncoder().encode(body).length}\r\n` +
    CORS +
    'Connection: close\r\n\r\n' +
    body
  );
}

function page(address: string, received: number): string {
  return `<!doctype html>
<meta charset="utf-8">
<title>webtor listener</title>
<h1>A browser tab is listening here.</h1>
<p>POST a message to <code>http://${address}/message</code> and it shows up
in that tab. Messages received so far: ${received}.</p>
`;
}

interface Request {
  method: string;
  path: string;
  body: string;
}

/** Read one HTTP/1.1 request off a stream, or null if it was not one. */
async function readRequest(
  stream: { receive(): Promise<Uint8Array | null> },
): Promise<Request | 'too-large' | null> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  let headEnd = -1;
  const decoder = new TextDecoder();
  const joined = () => {
    const all = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      all.set(chunk, offset);
      offset += chunk.length;
    }
    return all;
  };
  // The head, up to the blank line.
  while (headEnd < 0) {
    const chunk = await stream.receive();
    if (chunk == null) return null;
    chunks.push(chunk);
    total += chunk.length;
    if (total > MAX_HEAD_BYTES) return 'too-large';
    headEnd = decoder.decode(joined()).indexOf('\r\n\r\n');
  }
  const head = decoder.decode(joined()).slice(0, headEnd);
  const [line = '', ...headers] = head.split('\r\n');
  const [method = '', path = '/'] = line.split(' ');
  const lengthHeader = headers.find((header) =>
    header.toLowerCase().startsWith('content-length:'),
  );
  const length = Number(lengthHeader?.split(':')[1]?.trim() ?? '0');
  if (!Number.isInteger(length) || length < 0) return null;
  if (length > MAX_BODY_BYTES) return 'too-large';
  // Then the body, whose start may already have arrived with the head.
  const bodyStart = new TextEncoder().encode(head).length + 4;
  while (total < bodyStart + length) {
    const chunk = await stream.receive();
    if (chunk == null) return null;
    chunks.push(chunk);
    total += chunk.length;
  }
  const body = new TextDecoder().decode(
    joined().subarray(bodyStart, bodyStart + length),
  );
  return { method, path, body };
}

export async function startListener(options: ListenOptions): Promise<Listener> {
  const log = logger(options.onLog);
  const client = await createClient(options.bridge, log);

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
  log('success', `Listening at ${address}`);

  let received = 0;
  let stopped = false;

  // The accept loop runs for as long as the service does. Each client gets
  // its own task so a slow one cannot hold up the next.
  void (async () => {
    for (;;) {
      const stream = await service.accept();
      if (stream == null || stopped) return;
      void (async () => {
        try {
          const request = await readRequest(stream);
          if (request === 'too-large') {
            log('error', 'A client sent an oversized request');
            await stream.send(response('413 Content Too Large', ''));
          } else if (request == null) {
            log('error', 'A client hung up before finishing a request');
          } else if (request.method === 'POST' && request.path === '/message') {
            received += 1;
            options.onMessage({ at: Date.now(), text: request.body });
            await stream.send(response('200 OK', `received ${received}\n`));
          } else {
            await stream.send(
              response('200 OK', page(address, received), 'text/html'),
            );
          }
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
