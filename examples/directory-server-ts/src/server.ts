// The two directory endpoints, answered from the store on disk.
//
//   GET /api/directory                the manifest, never cached
//   GET /api/directory/<name>.json    a seed, immutable for as long as it is valid
//   GET /api/health
//
// Both directory answers carry `Access-Control-Allow-Origin: *`: the worker
// asking is on an onion's origin, not this host's. With a web root the rest
// of the site is served too, falling back to `index.html` for the paths the
// gateway's own router handles.

import fs from 'node:fs/promises';
import path from 'node:path';
import { isSeedName, readManifest, seedName, type Manifest } from './store.ts';

export const DIRECTORY_PATH = '/api/directory';
/** What the manifest tells a worker to wait when there is nothing to serve. */
const RETRY_AFTER_SECONDS = 30;
/** A seed stays cacheable at least this long, however close to expiry. */
const MIN_MAX_AGE_SECONDS = 60;

export interface ServerOptions {
  /** The store `bun run tor:directory` writes. */
  store: string;
  /** A built site to serve beside the endpoints, with `index.html` as the fallback. */
  webRoot?: string;
  now?: () => Date;
  log?: (line: string) => void;
}

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, HEAD',
};

export function createHandler(options: ServerOptions): (request: Request) => Promise<Response> {
  const now = options.now ?? (() => new Date());
  const log = options.log ?? (() => {});
  const store = options.store;
  const webRoot = options.webRoot;

  return async (request) => {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return json(request, { error: 'method not allowed' }, { status: 405, headers: CORS });
      }
      if (url.pathname === '/api/health') return json(request, { ok: true }, { headers: CORS });
      if (url.pathname === DIRECTORY_PATH) return manifest(request);
      if (url.pathname.startsWith(`${DIRECTORY_PATH}/`)) {
        return seed(request, url.pathname.slice(DIRECTORY_PATH.length + 1));
      }
      return json(request, { error: 'not found' }, { status: 404, headers: CORS });
    }
    if (webRoot && (request.method === 'GET' || request.method === 'HEAD')) {
      return serveStatic(request, webRoot, url.pathname);
    }
    return new Response('not found', { status: 404 });
  };

  async function manifest(request: Request): Promise<Response> {
    const headers = { ...CORS, 'cache-control': 'no-cache' };
    const current = await readManifest(store);
    if (!current) {
      return json(
        request,
        { error: 'no directory has been built yet; run `bun run tor:directory`' },
        { status: 503, headers: { ...headers, 'retry-after': String(RETRY_AFTER_SECONDS) } },
      );
    }
    if (Date.parse(current.validUntil) <= now().getTime()) {
      log(`The directory expired at ${current.validUntil}; run \`bun run tor:directory\``);
      return json(
        request,
        { error: `the directory expired at ${current.validUntil}; run \`bun run tor:directory\`` },
        { status: 503, headers: { ...headers, 'retry-after': String(RETRY_AFTER_SECONDS) } },
      );
    }
    return json(request, current, { headers });
  }

  async function seed(request: Request, segment: string): Promise<Response> {
    const name = segment.endsWith('.json') ? segment.slice(0, -'.json'.length) : segment;
    const plain = isSeedName(name) ? Bun.file(path.join(store, `${name}.json`)) : null;
    if (!plain || !(await plain.exists())) {
      return json(request, { error: 'no such directory' }, { status: 404, headers: CORS });
    }

    const current = await readManifest(store);
    const maxAge = maxAgeFor(current && seedName(current) === name ? current : null, now());
    const headers: Record<string, string> = {
      ...CORS,
      'content-type': 'application/json',
      'cache-control': `public, max-age=${maxAge}, immutable`,
      etag: `"${name}"`,
      vary: 'accept-encoding',
    };
    if (request.headers.get('if-none-match')?.includes(`"${name}"`)) {
      return new Response(null, { status: 304, headers });
    }

    const gzip = Bun.file(path.join(store, `${name}.json.gz`));
    const acceptsGzip = /(^|,)\s*gzip\s*(;|,|$)/.test(request.headers.get('accept-encoding') ?? '');
    const body = acceptsGzip && (await gzip.exists()) ? gzip : plain;
    if (body === gzip) headers['content-encoding'] = 'gzip';
    log(
      `Serving directory ${name} (${body === gzip ? 'gzip' : 'plain'}, ${(body.size / 1024 / 1024).toFixed(1)} MiB) to ${request.headers.get('origin') ?? 'an unnamed origin'}`,
    );
    return file(request, body, { headers });
  }
}

/** Seconds a seed may be cached: until it expires, and never under a minute. */
function maxAgeFor(manifest: Manifest | null, now: Date): number {
  if (!manifest) return MIN_MAX_AGE_SECONDS;
  const remaining = Math.floor((Date.parse(manifest.validUntil) - now.getTime()) / 1000);
  return Math.max(MIN_MAX_AGE_SECONDS, remaining);
}

/** A file under `root`, or `index.html` for anything that is not one. */
async function serveStatic(request: Request, root: string, pathname: string): Promise<Response> {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    // A stray `%` is not a path in this site, or any.
    return new Response('not found', { status: 404 });
  }
  const relative = path.posix.normalize(decoded).replace(/^\/+/, '');
  const resolved = path.resolve(root, relative);
  const inside = resolved === path.resolve(root) || resolved.startsWith(path.resolve(root) + path.sep);
  const isFile = inside && (await fs.stat(resolved).then((s) => s.isFile(), () => false));
  const target = isFile ? resolved : path.join(root, 'index.html');
  const body = Bun.file(target);
  if (!(await body.exists())) return new Response('not found', { status: 404 });
  return file(request, body, {
    headers: { 'cache-control': isFile && relative.startsWith('assets/') ? 'public, max-age=31536000, immutable' : 'no-cache' },
  });
}

function json(request: Request, value: unknown, init: ResponseInit = {}): Response {
  const body = JSON.stringify(value);
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  headers.set('content-length', String(Buffer.byteLength(body)));
  return new Response(request.method === 'HEAD' ? null : body, { ...init, headers });
}

function file(request: Request, body: Bun.BunFile, init: ResponseInit): Response {
  const headers = new Headers(init.headers);
  if (!headers.has('content-type')) headers.set('content-type', body.type);
  headers.set('content-length', String(body.size));
  return new Response(request.method === 'HEAD' ? null : body, { ...init, headers });
}
