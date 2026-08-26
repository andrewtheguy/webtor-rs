const DATABASE_NAME = 'webtor-nostr-onion-poc';
const DATABASE_VERSION = 1;
const STORE_NAME = 'tor-directory';
const CACHE_KEY = 'current';
const SNAPSHOT_URL = '/tor-directory.json';

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
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
    console.info('[nostr-onion-poc] Could not read directory cache:', error);
    return undefined;
  } finally {
    database?.close();
  }
}

export interface DirectorySeed {
  value: string | undefined;
  source: 'served snapshot' | 'browser cache' | 'Tor download';
}

export async function loadDirectorySeed(): Promise<DirectorySeed> {
  const snapshot = await loadSnapshot();
  if (snapshot) return { value: snapshot, source: 'served snapshot' };

  const cached = await loadStoredCache();
  if (cached) return { value: cached, source: 'browser cache' };

  return { value: undefined, source: 'Tor download' };
}

export async function saveDirectoryCache(cache: string): Promise<void> {
  if (!globalThis.indexedDB) return;
  let database: IDBDatabase | undefined;
  try {
    database = await openDatabase();
    const transaction = database.transaction(STORE_NAME, 'readwrite');
    const complete = transactionComplete(transaction);
    transaction.objectStore(STORE_NAME).put(cache, CACHE_KEY);
    await complete;
  } catch (error) {
    console.info('[nostr-onion-poc] Could not save directory cache:', error);
  } finally {
    database?.close();
  }
}
