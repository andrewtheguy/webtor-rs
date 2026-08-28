/**
 * Keeping a Tor directory across page loads, in IndexedDB.
 *
 * webtor hands out a directory as one opaque string and takes one back; where
 * it lives in between is entirely the embedding page's business, which is why
 * none of this is in the library. Both examples want the same answer — a
 * served snapshot if the dev server has one, otherwise whatever the last run
 * stored — so they share this rather than each carrying a copy of it.
 */

const DATABASE_VERSION = 1;
const STORE_NAME = 'tor-directory';
const CACHE_KEY = 'current';
const SNAPSHOT_URL = '/tor-directory.json';

export interface DirectorySeed {
  value: string | undefined;
  source: 'served snapshot' | 'browser cache' | 'Tor download';
}

export interface DirectorySeedStore {
  /** The best seed on hand, and where it came from. */
  load(): Promise<DirectorySeed>;
  /** Keep `cache` for the next load. Failures are reported, never thrown. */
  save(cache: string): Promise<void>;
}

/**
 * A store of this page's own. `name` is the IndexedDB database and the prefix
 * on anything this reports, so two examples served from one origin never read
 * each other's directory.
 */
export function directorySeedStore(name: string): DirectorySeedStore {
  function openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error('Could not open IndexedDB'));
    });
  }

  async function loadStoredCache(): Promise<string | undefined> {
    if (!globalThis.indexedDB) return undefined;
    let database: IDBDatabase | undefined;
    try {
      database = await openDatabase();
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const value = await requestResult<unknown>(
        transaction.objectStore(STORE_NAME).get(CACHE_KEY),
      );
      return typeof value === 'string' ? value : undefined;
    } catch (error) {
      console.info(`[${name}] Could not read directory cache:`, error);
      return undefined;
    } finally {
      database?.close();
    }
  }

  return {
    async load(): Promise<DirectorySeed> {
      const snapshot = await loadSnapshot();
      if (snapshot) return { value: snapshot, source: 'served snapshot' };

      const cached = await loadStoredCache();
      if (cached) return { value: cached, source: 'browser cache' };

      return { value: undefined, source: 'Tor download' };
    },

    async save(cache: string): Promise<void> {
      if (!globalThis.indexedDB) return;
      let database: IDBDatabase | undefined;
      try {
        database = await openDatabase();
        const transaction = database.transaction(STORE_NAME, 'readwrite');
        const complete = transactionComplete(transaction);
        transaction.objectStore(STORE_NAME).put(cache, CACHE_KEY);
        await complete;
      } catch (error) {
        console.info(`[${name}] Could not save directory cache:`, error);
      } finally {
        database?.close();
      }
    },
  };
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction failed'));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
  });
}

/**
 * A directory the dev server is serving, which is how a cold start avoids
 * pulling tens of megabytes over one bridge circuit. `bun run tor:directory`
 * writes it.
 */
async function loadSnapshot(): Promise<string | undefined> {
  try {
    const response = await fetch(SNAPSHOT_URL, {
      cache: 'no-store',
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok) return undefined;
    const snapshot = await response.text();
    return snapshot.startsWith('{"version":') ? snapshot : undefined;
  } catch {
    return undefined;
  }
}
