import { describe, expect, it } from 'bun:test';
import {
  type Cookie,
  cookieHeader,
  cookieJar,
  defaultPath,
  parseSetCookie,
  pathMatches,
  withCookie,
} from './cookies';

const HOST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion';
const NOW = Date.UTC(2026, 8, 4, 12, 0, 0);

function parse(header: string, requestPath = '/'): Cookie | null {
  return parseSetCookie(header, HOST, requestPath, NOW);
}

describe('defaultPath', () => {
  it('is the request path up to its last slash', () => {
    expect(defaultPath('/')).toBe('/');
    expect(defaultPath('/login')).toBe('/');
    expect(defaultPath('/app/login')).toBe('/app');
    expect(defaultPath('/app/')).toBe('/app');
    expect(defaultPath('')).toBe('/');
  });
});

describe('pathMatches', () => {
  it('matches a prefix only at a segment boundary', () => {
    expect(pathMatches('/', '/anything')).toBe(true);
    expect(pathMatches('/app', '/app')).toBe(true);
    expect(pathMatches('/app', '/app/x')).toBe(true);
    expect(pathMatches('/app/', '/app/x')).toBe(true);
    expect(pathMatches('/app', '/apple')).toBe(false);
    expect(pathMatches('/app/x', '/app')).toBe(false);
  });
});

describe('parseSetCookie', () => {
  it('reads the name, value and attributes', () => {
    const cookie = parse('session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax', '/login');
    expect(cookie).toMatchObject({ name: 'session', value: 'abc123', path: '/', expires: null });
  });

  it('defaults the path from the request', () => {
    expect(parse('a=1', '/app/login')?.path).toBe('/app');
    expect(parse('a=1; Path=relative', '/app/login')?.path).toBe('/app');
  });

  it('keeps a value with an equals sign in it', () => {
    expect(parse('token=a=b==')?.value).toBe('a=b==');
  });

  it('turns Max-Age and Expires into an instant, Max-Age first', () => {
    expect(parse('a=1; Max-Age=60')?.expires).toBe(NOW + 60_000);
    expect(parse('a=1; Expires=Fri, 04 Sep 2026 13:00:00 GMT')?.expires).toBe(NOW + 3_600_000);
    expect(parse('a=1; Expires=Fri, 04 Sep 2026 13:00:00 GMT; Max-Age=60')?.expires).toBe(NOW + 60_000);
    expect(parse('a=1; Expires=nonsense')?.expires).toBeNull();
    expect(parse('a=1; Max-Age=0')?.expires).toBeLessThan(NOW);
  });

  it('accepts only the onion as a domain', () => {
    expect(parse(`a=1; Domain=${HOST}`)).not.toBeNull();
    expect(parse(`a=1; Domain=.${HOST}`)).not.toBeNull();
    expect(parse('a=1; Domain=onion')).toBeNull();
    expect(parse('a=1; Domain=example.com')).toBeNull();
  });

  it('refuses what is not a cookie', () => {
    expect(parse('')).toBeNull();
    expect(parse('novalue')).toBeNull();
    expect(parse('=value')).toBeNull();
    expect(parse(`big=${'x'.repeat(5000)}`)).toBeNull();
  });
});

describe('withCookie and cookieHeader', () => {
  it('replaces a cookie by name and path and keeps its creation time', () => {
    const first = { ...parse('a=1')!, created: NOW - 5000 };
    let jar = withCookie([], first, NOW);
    jar = withCookie(jar, parse('a=2')!, NOW);
    expect(jar).toHaveLength(1);
    expect(jar[0]).toMatchObject({ value: '2', created: NOW - 5000 });
  });

  it('keeps cookies of the same name on different paths apart', () => {
    let jar = withCookie([], parse('a=root; Path=/')!, NOW);
    jar = withCookie(jar, parse('a=app; Path=/app')!, NOW);
    expect(jar).toHaveLength(2);
    expect(cookieHeader(jar, '/app/x', NOW)).toBe('a=app; a=root');
    expect(cookieHeader(jar, '/other', NOW)).toBe('a=root');
  });

  it('deletes through a lapsed replacement', () => {
    let jar = withCookie([], parse('a=1')!, NOW);
    jar = withCookie(jar, parse('a=; Max-Age=0')!, NOW);
    expect(jar).toHaveLength(0);
  });

  it('leaves lapsed cookies out of the header', () => {
    const jar = withCookie([], parse('a=1; Max-Age=60')!, NOW);
    expect(cookieHeader(jar, '/', NOW + 59_000)).toBe('a=1');
    expect(cookieHeader(jar, '/', NOW + 60_000)).toBeNull();
  });

  it('orders by path length, then by age', () => {
    let jar = withCookie([], { ...parse('b=1')!, created: NOW - 2 }, NOW);
    jar = withCookie(jar, { ...parse('a=1')!, created: NOW - 1 }, NOW);
    jar = withCookie(jar, parse('c=1; Path=/deep')!, NOW);
    expect(cookieHeader(jar, '/deep/x', NOW)).toBe('c=1; b=1; a=1');
  });

  it('evicts the least recently used past the limit', () => {
    let jar: Cookie[] = [];
    for (let i = 0; i < 180; i += 1) {
      jar = withCookie(jar, { ...parse(`c${i}=1`)!, accessed: NOW - 1000 + i }, NOW);
    }
    expect(jar).toHaveLength(180);
    jar = withCookie(jar, parse('newest=1')!, NOW);
    expect(jar).toHaveLength(180);
    expect(jar.some((c) => c.name === 'c0')).toBe(false);
    expect(jar.some((c) => c.name === 'newest')).toBe(true);
  });
});

describe('cookieJar', () => {
  it('keeps every cookie when responses set them at the same time', async () => {
    // No IndexedDB here, so the jar lives in memory; what is under test is
    // that two sets in flight together do not each start from the same jar.
    const jar = cookieJar('webtor-onion-gateway-cookies-test', HOST);
    await Promise.all([jar.set(['a=1; Path=/'], '/'), jar.set(['b=2; Path=/'], '/')]);
    expect(await jar.headerFor('/')).toBe('a=1; b=2');
  });
});
