import { describe, expect, it } from 'bun:test';
import { directoryUrl, loadDirectory } from './directory';

const MANIFEST = {
  url: '/api/directory/20260904T180000Z-0123456789abcdef.json',
  validAfter: '2026-09-04T18:00:00Z',
  freshUntil: '2026-09-04T19:00:00Z',
  validUntil: '2026-09-04T21:00:00Z',
  bytes: 13,
  relays: 9000,
};

/** A `fetch` that answers from a table of URLs and records what was asked. */
function fakeFetch(answers: Record<string, () => Response>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const answer = answers[url];
    return answer ? answer() : new Response('not here', { status: 404 });
  }) as typeof fetch;
  return { fetchFn, calls };
}

describe('the directory URL', () => {
  it('is the gateway host’s own /api/directory unless one is configured', () => {
    expect(directoryUrl(undefined, 'http:', 'intor.localhost:5173')).toBe(
      'http://intor.localhost:5173/api/directory',
    );
    expect(directoryUrl('https://seeds.example/tor/current', 'http:', 'intor.localhost:5173')).toBe(
      'https://seeds.example/tor/current',
    );
  });
});

describe('loading a directory', () => {
  it('reads the manifest uncached, then the seed it names, relative to it', async () => {
    const { fetchFn, calls } = fakeFetch({
      'http://intor.localhost:5173/api/directory': () => Response.json(MANIFEST),
      'http://intor.localhost:5173/api/directory/20260904T180000Z-0123456789abcdef.json': () =>
        new Response('{"version":3}'),
    });
    const loaded = await loadDirectory('http://intor.localhost:5173/api/directory', fetchFn);
    expect(loaded.seed).toBe('{"version":3}');
    expect(loaded.manifest).toEqual(MANIFEST);
    expect(loaded.seedUrl).toBe(
      'http://intor.localhost:5173/api/directory/20260904T180000Z-0123456789abcdef.json',
    );
    expect(calls[0]!.init?.cache).toBe('no-cache');
    expect(calls[1]!.init?.cache).toBeUndefined();
  });

  it('follows an absolute seed URL to another host', async () => {
    const { fetchFn } = fakeFetch({
      'http://intor.localhost:5173/api/directory': () =>
        Response.json({ ...MANIFEST, url: 'https://cdn.example/seeds/x.json' }),
      'https://cdn.example/seeds/x.json': () => new Response('{"version":3}'),
    });
    const loaded = await loadDirectory('http://intor.localhost:5173/api/directory', fetchFn);
    expect(loaded.seedUrl).toBe('https://cdn.example/seeds/x.json');
  });

  it('fails when the backend has nothing yet', async () => {
    const { fetchFn } = fakeFetch({
      'http://gw/api/directory': () =>
        Response.json({ error: 'not yet' }, { status: 503, headers: { 'retry-after': '30' } }),
    });
    await expect(loadDirectory('http://gw/api/directory', fetchFn)).rejects.toThrow('HTTP 503');
  });

  it('fails on a malformed manifest or a seed that is not one', async () => {
    const malformed = fakeFetch({
      'http://gw/api/directory': () => Response.json({ url: 42 }),
    });
    await expect(loadDirectory('http://gw/api/directory', malformed.fetchFn)).rejects.toThrow(
      'malformed',
    );

    const notASeed = fakeFetch({
      'http://gw/api/directory': () => Response.json(MANIFEST),
      'http://gw/api/directory/20260904T180000Z-0123456789abcdef.json': () =>
        new Response('<html>login</html>'),
    });
    await expect(loadDirectory('http://gw/api/directory', notASeed.fetchFn)).rejects.toThrow(
      'not one',
    );
  });
});
