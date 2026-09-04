import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { type Seed } from './seed.ts';
import { createHandler, DIRECTORY_PATH } from './server.ts';
import { MANIFEST_FILE, readManifest, writeSeed } from './store.ts';

const VALID_AFTER = new Date('2026-09-04T18:00:00Z');
/** A seed with the lifetime of a real one, built from `encoded` instead of the network. */
function seed(encoded: string, validAfter = VALID_AFTER): Seed {
  const hour = 3_600_000;
  return {
    name: `${validAfter.toISOString().replace(/[-:]|\.\d{3}/g, '')}-${Bun.hash(encoded).toString(16).padStart(16, '0').slice(0, 16)}`,
    encoded,
    validAfter,
    freshUntil: new Date(validAfter.getTime() + hour),
    validUntil: new Date(validAfter.getTime() + 3 * hour),
    relays: 9000,
  };
}

let store: string;
let webRoot: string;
const logged: string[] = [];
/** Ten minutes into the seed's life, unless a test moves it. */
let now = new Date('2026-09-04T18:10:00Z');
const handler = () => createHandler({ store, webRoot, now: () => now, log: (line) => logged.push(line) });
const get = (pathname: string, init: RequestInit = {}) =>
  handler()(new Request(`http://gateway.test${pathname}`, init));

beforeEach(async () => {
  store = await fs.mkdtemp(path.join(os.tmpdir(), 'webtor-directory-'));
  webRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'webtor-web-'));
  await fs.writeFile(path.join(webRoot, 'index.html'), '<title>gateway</title>');
  await fs.mkdir(path.join(webRoot, 'assets'));
  await fs.writeFile(path.join(webRoot, 'assets', 'app.js'), 'console.log(1)');
  logged.length = 0;
  now = new Date('2026-09-04T18:10:00Z');
});
afterEach(async () => {
  await fs.rm(store, { recursive: true, force: true });
  await fs.rm(webRoot, { recursive: true, force: true });
});

describe('the store', () => {
  it('installs a seed with its gzip twin and points the manifest at it', async () => {
    const first = seed('{"version":3,"consensus":"one"}');
    const manifest = await writeSeed(store, first);
    expect(manifest).toEqual({
      url: `${DIRECTORY_PATH}/${first.name}.json`,
      validAfter: '2026-09-04T18:00:00Z',
      freshUntil: '2026-09-04T19:00:00Z',
      validUntil: '2026-09-04T21:00:00Z',
      bytes: first.encoded.length,
      relays: 9000,
    });
    expect(await readManifest(store)).toEqual(manifest);
    const gz = await fs.readFile(path.join(store, `${first.name}.json.gz`));
    expect(Buffer.from(Bun.gunzipSync(gz)).toString()).toBe(first.encoded);
  });

  it('keeps the seed the previous manifest named and removes older ones', async () => {
    const one = seed('{"version":3,"consensus":"one"}', new Date('2026-09-04T16:00:00Z'));
    const two = seed('{"version":3,"consensus":"two"}', new Date('2026-09-04T17:00:00Z'));
    const three = seed('{"version":3,"consensus":"three"}');
    await writeSeed(store, one);
    await writeSeed(store, two);
    await writeSeed(store, three);
    const files = (await fs.readdir(store)).sort();
    expect(files).toEqual(
      [MANIFEST_FILE, `${two.name}.json`, `${two.name}.json.gz`, `${three.name}.json`, `${three.name}.json.gz`].sort(),
    );
  });
});

describe('the manifest endpoint', () => {
  it('answers 503 with Retry-After until a directory has been built', async () => {
    const response = await get(DIRECTORY_PATH);
    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('30');
    expect(response.headers.get('cache-control')).toBe('no-cache');
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(((await response.json()) as { error: string }).error).toContain('tor:directory');
  });

  it('answers the stored manifest, uncached, for any origin', async () => {
    const current = seed('{"version":3}');
    await writeSeed(store, current);
    const response = await get(DIRECTORY_PATH, { headers: { origin: 'http://x.onion.gateway.test' } });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-cache');
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(await response.json()).toEqual(await readManifest(store));
  });

  it('answers 503 once the stored directory has expired', async () => {
    await writeSeed(store, seed('{"version":3}'));
    now = new Date('2026-09-04T21:00:00Z');
    const response = await get(DIRECTORY_PATH);
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: string }).error).toContain('expired at 2026-09-04T21:00:00Z');
    expect(logged.some((line) => line.includes('expired'))).toBe(true);
  });
});

describe('the seed endpoint', () => {
  it('serves the seed immutable until it expires, with an ETag', async () => {
    const current = seed('{"version":3,"consensus":"one"}');
    await writeSeed(store, current);
    const response = await get(`${DIRECTORY_PATH}/${current.name}.json`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/json');
    // Ten minutes in, two hours fifty remain.
    expect(response.headers.get('cache-control')).toBe('public, max-age=10200, immutable');
    expect(response.headers.get('etag')).toBe(`"${current.name}"`);
    expect(response.headers.get('vary')).toBe('accept-encoding');
    expect(response.headers.get('content-encoding')).toBeNull();
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(await response.text()).toBe(current.encoded);
    expect(logged.at(-1)).toContain(`Serving directory ${current.name} (plain`);
  });

  it('serves the precompressed form to a client that takes gzip', async () => {
    const current = seed('{"version":3,"consensus":"one"}');
    await writeSeed(store, current);
    const response = await get(`${DIRECTORY_PATH}/${current.name}.json`, {
      headers: { 'accept-encoding': 'br, gzip;q=0.8' },
    });
    expect(response.headers.get('content-encoding')).toBe('gzip');
    const body = Buffer.from(await response.arrayBuffer());
    expect(Number(response.headers.get('content-length'))).toBe(body.length);
    expect(Buffer.from(Bun.gunzipSync(body)).toString()).toBe(current.encoded);
  });

  it('answers 304 to a client that already has it', async () => {
    const current = seed('{"version":3}');
    await writeSeed(store, current);
    const response = await get(`${DIRECTORY_PATH}/${current.name}.json`, {
      headers: { 'if-none-match': `"${current.name}"` },
    });
    expect(response.status).toBe(304);
    expect(response.headers.get('cache-control')).toContain('immutable');
  });

  it('serves a superseded seed briefly and refuses names it does not have', async () => {
    const old = seed('{"version":3,"consensus":"old"}', new Date('2026-09-04T17:00:00Z'));
    await writeSeed(store, old);
    await writeSeed(store, seed('{"version":3,"consensus":"new"}'));
    const superseded = await get(`${DIRECTORY_PATH}/${old.name}.json`);
    expect(superseded.status).toBe(200);
    expect(superseded.headers.get('cache-control')).toBe('public, max-age=60, immutable');

    expect((await get(`${DIRECTORY_PATH}/20260904T000000Z-0000000000000000.json`)).status).toBe(404);
    expect((await get(`${DIRECTORY_PATH}/..%2Fmanifest.json`)).status).toBe(404);
    expect((await get(`${DIRECTORY_PATH}/manifest.json`)).status).toBe(404);
  });

  it('answers HEAD with the headers and no body', async () => {
    const current = seed('{"version":3}');
    await writeSeed(store, current);
    const response = await get(`${DIRECTORY_PATH}/${current.name}.json`, { method: 'HEAD' });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-length')).toBe(String(current.encoded.length));
    expect(await response.text()).toBe('');
  });
});

describe('the rest of the site', () => {
  it('serves files under the web root and index.html for everything else', async () => {
    const asset = await get('/assets/app.js');
    expect(asset.status).toBe(200);
    expect(await asset.text()).toBe('console.log(1)');
    expect(asset.headers.get('cache-control')).toContain('immutable');

    const route = await get('/abc.onion/some/page');
    expect(route.status).toBe(200);
    expect(await route.text()).toBe('<title>gateway</title>');
    expect(route.headers.get('cache-control')).toBe('no-cache');

    const escape = await get('/..%2F..%2Fetc%2Fpasswd');
    expect(await escape.text()).toBe('<title>gateway</title>');
  });

  it('answers 404 under /api for what is not an endpoint, and 405 for other methods', async () => {
    expect((await get('/api/nothing')).status).toBe(404);
    expect((await get(DIRECTORY_PATH, { method: 'POST' })).status).toBe(405);
    const health = await get('/api/health');
    expect(health.status).toBe(200);
    expect(health.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('answers 404, not an error, to a path that does not decode', async () => {
    expect((await get('/%E0%A4%A')).status).toBe(404);
  });
});
