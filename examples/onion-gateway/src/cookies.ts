// The onion's cookies, kept by the worker.
//
// The browser will not do this for the gateway: `Set-Cookie` is dropped from
// any response a service worker constructs, and the `Cookie` header the
// browser would send is never shown to one. So the worker keeps the jar
// itself — one per origin, which is one per onion — takes every `Set-Cookie`
// out of a response before the page sees it, and puts the matching `Cookie`
// on each request it forwards. The rules are RFC 6265's, for a single host:
// there is no domain to match but the onion's own, and `Secure` is honoured
// rather than refused, since the circuit is the secure channel.

/** The most one cookie's name and value may take up together, RFC 6265 §6.1. */
const MAX_COOKIE_BYTES = 4096;
/** The most cookies one onion may set before the least recently used go. */
const MAX_COOKIES = 180;

export interface Cookie {
  name: string;
  value: string;
  /** Always begins with `/`. */
  path: string;
  /** When it lapses, in epoch milliseconds, or `null` for a session cookie. */
  expires: number | null;
  /** When the cookie was first set, kept across replacements, RFC 6265 §5.3. */
  created: number;
  /** When a request last carried it, which decides eviction. */
  accessed: number;
}

/**
 * The path a `Set-Cookie` without a usable `Path` gets, RFC 6265 §5.1.4: the
 * request path up to, not including, its last `/`, or `/` when that would be
 * nothing.
 */
export function defaultPath(requestPath: string): string {
  if (!requestPath.startsWith('/')) return '/';
  const lastSlash = requestPath.lastIndexOf('/');
  return lastSlash === 0 ? '/' : requestPath.slice(0, lastSlash);
}

/** Whether a cookie set for `cookiePath` goes on a request for `requestPath`, RFC 6265 §5.1.4. */
export function pathMatches(cookiePath: string, requestPath: string): boolean {
  if (cookiePath === requestPath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

/**
 * A `Set-Cookie` header as a cookie for `host`, set by a request for
 * `requestPath` at `now`, or `null` when it is not one this jar takes: no
 * name, too large, or for some other domain. A cookie already lapsed is
 * returned lapsed, so that storing it deletes what it replaces.
 */
export function parseSetCookie(
  header: string,
  host: string,
  requestPath: string,
  now: number,
): Cookie | null {
  const [pair = '', ...attributes] = header.split(';');
  const separator = pair.indexOf('=');
  if (separator === -1) return null;
  const name = pair.slice(0, separator).trim();
  const value = pair.slice(separator + 1).trim();
  if (name === '' || name.length + value.length > MAX_COOKIE_BYTES) return null;

  let path = defaultPath(requestPath);
  let expires: number | null = null;
  let maxAge: number | null = null;
  for (const attribute of attributes) {
    const eq = attribute.indexOf('=');
    const attributeName = (eq === -1 ? attribute : attribute.slice(0, eq)).trim().toLowerCase();
    const attributeValue = eq === -1 ? '' : attribute.slice(eq + 1).trim();
    switch (attributeName) {
      case 'path':
        if (attributeValue.startsWith('/')) path = attributeValue;
        break;
      case 'domain': {
        // The only domain a cookie may claim here is the onion itself; a
        // cookie for anything else is one this host may not set.
        const domain = attributeValue.replace(/^\./, '').toLowerCase();
        if (domain !== '' && domain !== host) return null;
        break;
      }
      case 'max-age':
        if (/^-?\d+$/.test(attributeValue)) maxAge = Number(attributeValue);
        break;
      case 'expires': {
        const at = Date.parse(attributeValue);
        if (!Number.isNaN(at)) expires = at;
        break;
      }
      // `Secure`, `HttpOnly`, `SameSite` and anything unknown change nothing
      // in a jar that only ever speaks to the one host over its own circuit.
      default:
        break;
    }
  }
  // `Max-Age` wins over `Expires`, RFC 6265 §5.3; a non-positive one lapses now.
  if (maxAge !== null) expires = maxAge <= 0 ? now - 1 : now + maxAge * 1000;
  return { name, value, path, expires, created: now, accessed: now };
}

function lapsed(cookie: Cookie, now: number): boolean {
  return cookie.expires !== null && cookie.expires <= now;
}

/**
 * `jar` with `cookie` set: a cookie of the same name and path is replaced,
 * keeping its creation time; one already lapsed only removes that; and past
 * `MAX_COOKIES`, the least recently used go first.
 */
export function withCookie(jar: readonly Cookie[], cookie: Cookie, now: number): Cookie[] {
  const previous = jar.find((c) => c.name === cookie.name && c.path === cookie.path);
  const kept = jar.filter((c) => c !== previous && !lapsed(c, now));
  if (lapsed(cookie, now)) return kept;
  kept.push(previous ? { ...cookie, created: previous.created } : cookie);
  kept.sort((a, b) => b.accessed - a.accessed);
  return kept.slice(0, MAX_COOKIES);
}

/**
 * The `Cookie` header for a request to `requestPath`, or `null` when nothing
 * applies. Longer paths come first, then earlier-set cookies, RFC 6265
 * §5.4. The cookies that went are marked as accessed.
 */
export function cookieHeader(jar: readonly Cookie[], requestPath: string, now: number): string | null {
  const sent = jar
    .filter((cookie) => !lapsed(cookie, now) && pathMatches(cookie.path, requestPath))
    .sort((a, b) => b.path.length - a.path.length || a.created - b.created);
  if (sent.length === 0) return null;
  for (const cookie of sent) cookie.accessed = now;
  return sent.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
}

export interface CookieJar {
  /** The `Cookie` header for a request to `requestPath`, or `null`. */
  headerFor(requestPath: string): Promise<string | null>;
  /** Take in what a response to `requestPath` set. */
  set(setCookies: readonly string[], requestPath: string): Promise<void>;
}

/**
 * The jar for `host`, kept in the IndexedDB database `name` so that it
 * outlives the worker, which a browser stops after half a minute idle. Kept
 * whole in memory once loaded and written back whole after every change; a
 * store that will not open leaves a jar that lasts as long as the worker.
 */
export function cookieJar(name: string, host: string): CookieJar {
  const STORE_NAME = 'cookies';
  const KEY = 'jar';

  let loaded: Promise<Cookie[]> | null = null;
  /** Changes in the order they were asked for, each after the last. */
  let writing: Promise<void> = Promise.resolve();

  function openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Could not open IndexedDB'));
    });
  }

  async function load(): Promise<Cookie[]> {
    if (!globalThis.indexedDB) return [];
    let database: IDBDatabase | undefined;
    try {
      database = await openDatabase();
      const stored = await new Promise<unknown>((resolve, reject) => {
        const request = database!.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(KEY);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error('IndexedDB read failed'));
      });
      return Array.isArray(stored) ? (stored as Cookie[]) : [];
    } catch (error) {
      console.info(`[${name}] Could not read the cookie jar:`, error);
      return [];
    } finally {
      database?.close();
    }
  }

  async function save(jar: Cookie[]): Promise<void> {
    if (!globalThis.indexedDB) return;
    let database: IDBDatabase | undefined;
    try {
      database = await openDatabase();
      await new Promise<void>((resolve, reject) => {
        const transaction = database!.transaction(STORE_NAME, 'readwrite');
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB write failed'));
        transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB write aborted'));
        transaction.objectStore(STORE_NAME).put(jar, KEY);
      });
    } catch (error) {
      console.info(`[${name}] Could not save the cookie jar:`, error);
    } finally {
      database?.close();
    }
  }

  function jar(): Promise<Cookie[]> {
    loaded ??= load();
    return loaded;
  }

  return {
    async headerFor(requestPath) {
      return cookieHeader(await jar(), requestPath, Date.now());
    },

    async set(setCookies, requestPath) {
      if (setCookies.length === 0) return;
      // The whole read-modify-write goes through the queue, not just the
      // write: two responses arriving together would otherwise each start
      // from the same jar and the second would put back a jar without the
      // first's cookies.
      const done = writing.then(async () => {
        const now = Date.now();
        let cookies = await jar();
        for (const header of setCookies) {
          const cookie = parseSetCookie(header, host, requestPath, now);
          if (cookie) cookies = withCookie(cookies, cookie, now);
        }
        loaded = Promise.resolve(cookies);
        await save(cookies.map((cookie) => ({ ...cookie })));
      });
      writing = done.catch(() => undefined);
      await done;
    },
  };
}
