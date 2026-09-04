// The gateway: a service worker that owns one origin,
// `http://<address>.onion.<root>`, and answers every request on it by
// making the same request of `http://<address>.onion` over Tor. The Tor
// client lives in the worker, bootstrapped over Snowflake from a directory
// the page may have served or a previous run stored; no page on the origin
// ever sees it, only the responses. The onion's cookies live here too, since
// the browser keeps none for a response a worker made up.
//
// Two things a service worker forbids shape this file. `import()` is not
// allowed here, so the WASM package is imported statically and instantiated
// lazily; and top-level `await` is not allowed either, so every listener is
// registered synchronously and the bootstrap begins on the first request.

import init, { WebtorClient } from '@andrewtheguy/webtor-wasm';
import webtorWasmUrl from '@andrewtheguy/webtor-wasm/webtor_wasm_bg.wasm?url';
import { directorySeedStore } from '../../shared/directory-cache';
import { cookieJar } from './cookies';
import { gatewayUrl, isOnionHost, parseGatewayHost } from './gateway-host';
import { bootstrapPage, errorPage } from './gateway-pages';
import type {
  GatewayLevel,
  GatewayLine,
  GatewayPhase,
  GatewayProgress,
  GatewaySubscribe,
} from './protocol';

declare const self: ServiceWorkerGlobalScope;

/** Long enough for a first rendezvous, which can take minutes over Snowflake. */
const REQUEST_TIMEOUT_MS = 240_000;

/**
 * The most one response may occupy. The client buffers a response whole, and
 * its own default of 8 MiB is sized for an API call; a static site's
 * downloads run larger, and this worker has nothing else to hold in memory.
 */
const MAX_RESPONSE_BYTES = 256 * 1024 * 1024;

/**
 * The most a request body may weigh. It is buffered whole here and once more
 * in the client, so this is a bound on memory, not on what a site may accept.
 */
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;

/**
 * Request headers that are not carried to the onion as the page sent them.
 * Everything else is: a page's `Content-Type`, `Authorization` or
 * `X-Requested-With` is what makes its request mean what it means.
 */
const DROPPED_REQUEST_HEADERS = new Set([
  // Set here, from the request itself, in the onion's terms.
  'accept-encoding',
  'cookie',
  'origin',
  'referer',
  // Set by the client from the framing it puts on the wire.
  'host',
  'content-length',
  'connection',
  'transfer-encoding',
  // Conditional: a `304` carries a `Content-Length` and no body, which the
  // client would wait on until the stream ended.
  'if-match',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'if-unmodified-since',
  // About a connection this worker is not the end of.
  'expect',
  'keep-alive',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'upgrade',
]);

/**
 * Response headers not passed to the page: the ones about the onion
 * connection rather than the content, and `Set-Cookie`, which goes into the
 * jar here — the browser would drop it from a worker's response anyway.
 */
const WITHHELD_RESPONSE_HEADERS = new Set([
  'connection',
  'content-length',
  'keep-alive',
  'set-cookie',
  'transfer-encoding',
]);

/** Statuses `Response` refuses a body for. */
const BODYLESS_STATUSES = new Set([101, 204, 205, 304]);

/** `Content-Encoding`s the worker undoes itself; see `toResponse`. */
const DECODABLE_ENCODINGS = new Set(['gzip', 'deflate', 'deflate-raw']);

/**
 * What the onion is told it may compress with: the codings above and nothing
 * else, so a `br` or `zstd` body the worker could not undo never arrives.
 * (`deflate-raw` is a `DecompressionStream` format, not an HTTP coding.)
 */
const ACCEPT_ENCODING = 'gzip, deflate';

/**
 * A bridge to use instead of the public one, from `.env.local`:
 *
 *   VITE_BRIDGE_URL=ws://localhost:8080/
 *   VITE_BRIDGE_FINGERPRINT=<what scripts/local-bridge prints>
 *
 * Both or neither — a URL without an identity would be a request to trust
 * whatever answers.
 */
const BRIDGE_URL = import.meta.env.VITE_BRIDGE_URL;
const BRIDGE_FINGERPRINT = import.meta.env.VITE_BRIDGE_FINGERPRINT;

if (Boolean(BRIDGE_URL) !== Boolean(BRIDGE_FINGERPRINT)) {
  throw new Error('Set VITE_BRIDGE_URL and VITE_BRIDGE_FINGERPRINT together, or neither');
}

const here = new URL(self.location.href);
const gateway = parseGatewayHost(here.hostname);
/** The gateway's own host with its port, which is what onion URLs map onto. */
const rootHost = gateway && `${gateway.root}${here.port ? `:${here.port}` : ''}`;

const store = directorySeedStore('webtor-onion-gateway');
const cookies = cookieJar('webtor-onion-gateway-cookies', gateway?.onion ?? '');

type TorClient = Awaited<ReturnType<typeof WebtorClient.create>>;

// The bootstrap's state, kept in module scope: a browser stops an idle
// service worker after roughly half a minute, and every restart begins here
// again, with nothing but what the directory store kept.
let bootstrap: Promise<TorClient> | null = null;
let phase: GatewayPhase = 'starting';
let failure: string | null = null;
let lines: GatewayLine[] = [];
/** Pages that asked to follow the bootstrap, by client id. */
const subscribers = new Set<string>();

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function progress(): GatewayProgress {
  return { type: 'progress', onion: gateway?.onion ?? '', phase, lines, failure };
}

async function broadcast(): Promise<void> {
  const update = progress();
  for (const id of subscribers) {
    const client = await self.clients.get(id);
    if (client) client.postMessage(update);
    else subscribers.delete(id);
  }
}

function log(level: GatewayLevel, message: string): void {
  lines = [...lines, { at: Date.now(), level, message }];
  console[level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'info'](`[gateway] ${message}`);
  void broadcast();
}

async function createClient(onion: string): Promise<TorClient> {
  phase = 'starting';
  failure = null;
  lines = [];
  log('info', `Gateway for ${onion}`);
  await init({ module_or_path: webtorWasmUrl });
  const seed = await store.load();
  log('info', `Tor directory: ${seed.source}`);
  const client: TorClient = await WebtorClient.create({
    // Only the WebSocket bridge: the WebRTC one needs `RTCPeerConnection`,
    // which a worker does not have.
    bridge: 'websocket',
    ...(BRIDGE_URL && BRIDGE_FINGERPRINT
      ? { bridgeUrl: BRIDGE_URL, bridgeFingerprint: BRIDGE_FINGERPRINT }
      : {}),
    ...(seed.value ? { directorySeed: seed.value } : {}),
    onDirectoryChange: (cache: string) => {
      void store.save(cache).then((stored) => {
        if (stored) log('info', 'Stored a fresh Tor directory for the next start');
      });
    },
    // The worker's console is out of sight; the lines go to the page instead.
    onLog: (message: string, level: GatewayLevel) => log(level, message),
  });
  phase = 'ready';
  log('success', 'Tor client bootstrapped');
  return client;
}

/** The client, starting a bootstrap if none is under way. */
function client(onion: string): Promise<TorClient> {
  bootstrap ??= createClient(onion).catch((error: unknown) => {
    bootstrap = null;
    phase = 'failed';
    failure = describe(error);
    log('error', `Bootstrap failed: ${failure}`);
    throw error;
  });
  return bootstrap;
}

/**
 * The onion URL a request on this origin stands for, or `null` when the
 * request is not for this origin's onion. A page's absolute URL to its own
 * `http://<address>.onion/…` counts too, since that is what its links and
 * assets often say; a URL to any *other* onion does not, and goes to the
 * network to fail there, because answering it here would let one site read
 * another across origins with no CORS check in the way.
 */
function onionUrl(url: URL): string | null {
  if (!gateway) return null;
  const sameOrigin = url.origin === here.origin;
  const ownOnion =
    url.protocol === 'http:' &&
    url.hostname === gateway.onion &&
    (url.port === '' || url.port === '80');
  return sameOrigin || ownOnion ? `http://${gateway.onion}${url.pathname}${url.search}` : null;
}

/**
 * Where a redirect points, said in gateway terms. A `Location` on an onion
 * over plain HTTP — this one or another — becomes that onion's gateway
 * origin, so following it stays inside the gateway; anything else is passed
 * on as the onion said it.
 */
function rewriteLocation(location: string, target: string): string {
  if (!rootHost) return location;
  let resolved: URL;
  try {
    resolved = new URL(location, target);
  } catch {
    return location;
  }
  if (resolved.protocol !== 'http:' || !isOnionHost(resolved.hostname)) return location;
  if (resolved.port !== '' && resolved.port !== '80') return location;
  return gatewayUrl(
    resolved.hostname,
    rootHost,
    `${resolved.pathname}${resolved.search}${resolved.hash}`,
  );
}

interface Upstream {
  status: number;
  headers: Headers;
  bytes(): Uint8Array;
}

/**
 * A `Response` for what the onion sent. The body arrives whole, so the
 * connection-level headers describe a transfer that is over and are dropped.
 * A compressed body is decompressed here too: the browser inflates only what
 * came off its own network stack, not what a worker hands it, and a
 * `Content-Encoding` left on a synthetic response would make the page
 * unreadable.
 */
function toResponse(upstream: Upstream, target: string, headOnly: boolean): Response {
  if (upstream.status < 200 || upstream.status > 599) {
    return new Response(`The onion answered with HTTP status ${upstream.status}`, {
      status: 502,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }
  const headers = new Headers();
  upstream.headers.forEach((value, name) => {
    if (!WITHHELD_RESPONSE_HEADERS.has(name)) headers.set(name, value);
  });
  const location = headers.get('location');
  if (location !== null) headers.set('location', rewriteLocation(location, target));

  let body: BodyInit | null = upstream.bytes() as Uint8Array<ArrayBuffer>;
  const encoding = headers.get('content-encoding')?.trim().toLowerCase();
  if (encoding && DECODABLE_ENCODINGS.has(encoding)) {
    body = new Response(body).body!.pipeThrough(
      new DecompressionStream(encoding as CompressionFormat),
    );
    headers.delete('content-encoding');
  }
  if (headOnly || BODYLESS_STATUSES.has(upstream.status)) body = null;
  return new Response(body, { status: upstream.status, headers });
}

function textResponse(status: number, text: string): Response {
  return new Response(text, {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  });
}

function htmlResponse(status: number, html: string): Response {
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

/**
 * The `Referer` the onion should see, or `null` for none: the page's own
 * URL, in onion terms, when it was on this gateway. The browser has already
 * applied the page's referrer policy by the time a worker sees the request.
 */
function refererFor(request: Request): string | null {
  if (request.referrer === '' || request.referrer === 'about:client') return null;
  try {
    return onionUrl(new URL(request.referrer));
  } catch {
    return null;
  }
}

/**
 * The request body, whole, or `null` once it has run past
 * `MAX_REQUEST_BYTES`. It is read a chunk at a time and the stream cancelled
 * as soon as the limit is crossed, so a body far past it costs the worker no
 * more memory than the limit itself.
 */
async function readBody(request: Request): Promise<Uint8Array | null> {
  if (request.body === null) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_REQUEST_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function answer(request: Request, target: string): Promise<Response> {
  const onion = gateway!.onion;
  const navigation = request.mode === 'navigate';
  const requested = new URL(request.url);
  const method = request.method.toUpperCase();
  const carriesBody = method !== 'GET' && method !== 'HEAD';

  // A GET navigation gets a page to watch the bootstrap from, rather than a
  // tab that spins for a minute or more. Anything else waits: a subresource
  // because the page that asked for it is already showing, a form submission
  // because the bootstrap page would replay it as a GET without its body.
  if (phase !== 'ready' || bootstrap === null) {
    const pending = client(onion);
    if (navigation && !carriesBody) {
      pending.catch(() => undefined);
      return htmlResponse(
        200,
        bootstrapPage(onion, `${requested.pathname}${requested.search}`),
      );
    }
  }

  let tor: TorClient;
  try {
    tor = await client(onion);
  } catch (error) {
    const detail = `The Tor client could not bootstrap: ${describe(error)}`;
    return navigation
      ? htmlResponse(502, errorPage(onion, 'Not connected', detail))
      : textResponse(502, detail);
  }

  let body: Uint8Array | undefined;
  if (carriesBody) {
    const read = await readBody(request);
    if (read === null) {
      const detail = `The request body is over ${MAX_REQUEST_BYTES} bytes, the most this gateway forwards.`;
      return navigation
        ? htmlResponse(413, errorPage(onion, 'Request too large', detail))
        : textResponse(413, detail);
    }
    body = read;
  }

  const headers: Record<string, string> = {};
  request.headers.forEach((value, name) => {
    if (!DROPPED_REQUEST_HEADERS.has(name)) headers[name] = value;
  });
  // The browser's own `Accept-Encoding` is not exposed to a worker, and what
  // it would ask for includes codings the worker cannot decode.
  headers['accept-encoding'] = ACCEPT_ENCODING;
  // The browser adds `Origin`, `Referer` and `Cookie` after a worker has
  // answered, and in the gateway's terms; the onion wants them in its own,
  // above all for a CSRF check that compares them with its `Host`.
  const referer = refererFor(request);
  if (referer !== null) headers.referer = referer;
  if (carriesBody) headers.origin = `http://${onion}`;
  const cookie = await cookies.headerFor(requested.pathname);
  if (cookie !== null) headers.cookie = cookie;

  try {
    // A HEAD goes out as a GET: the client frames a response by its
    // `Content-Length`, and a HEAD's body never comes.
    const upstream: Upstream = await tor.fetch(target, {
      method: method === 'HEAD' ? 'GET' : method,
      headers,
      ...(body ? { body } : {}),
      timeoutMs: REQUEST_TIMEOUT_MS,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    });
    await cookies.set(upstream.headers.getSetCookie(), requested.pathname);
    return toResponse(upstream, target, method === 'HEAD');
  } catch (error) {
    const detail = describe(error);
    log('error', `${method} ${requested.pathname}: ${detail}`);
    return navigation
      ? htmlResponse(502, errorPage(onion, 'The onion did not answer', detail))
      : textResponse(502, detail);
  }
}

self.addEventListener('install', () => {
  void self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const target = onionUrl(new URL(event.request.url));
  if (target !== null) event.respondWith(answer(event.request, target));
});

self.addEventListener('message', (event) => {
  const data: unknown = event.data;
  const isSubscribe = (value: unknown): value is GatewaySubscribe =>
    typeof value === 'object' && value !== null && (value as { type?: unknown }).type === 'subscribe';
  if (!isSubscribe(data) || !(event.source instanceof Client)) return;
  subscribers.add(event.source.id);
  event.source.postMessage(progress());
});
