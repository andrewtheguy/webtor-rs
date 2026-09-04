// The directory on disk: the seeds and a manifest naming the current one.
//
//   <store>/manifest.json          what `/api/directory` answers
//   <store>/<name>.json            a seed, as `directorySeed` takes it
//   <store>/<name>.json.gz         the same, gzipped ahead of time
//
// `bun run tor:directory` writes here and the server reads here, on every
// request, so a rebuild takes effect without a restart. The seed a previous
// manifest named is kept for one more rebuild: a worker that read the old
// manifest a moment ago is still fetching it.

import fs from 'node:fs/promises';
import path from 'node:path';
import { iso8601, type Seed } from './seed.ts';

export const MANIFEST_FILE = 'manifest.json';
/** Where `bun run tor:directory` writes and `bun run serve` reads unless told otherwise: `./directory`. */
export const DEFAULT_STORE = path.join(import.meta.dirname, '..', 'directory');
/** Where the server answers seeds, and so what the manifest's `url` is relative to. */
export const SEED_URL_PREFIX = '/api/directory/';

/** The manifest, exactly as the contract has the server answer it. */
export interface Manifest {
  url: string;
  validAfter: string;
  freshUntil: string;
  validUntil: string;
  bytes: number;
  relays: number;
}

export function manifestFor(seed: Seed): Manifest {
  return {
    url: `${SEED_URL_PREFIX}${seed.name}.json`,
    validAfter: iso8601(seed.validAfter),
    freshUntil: iso8601(seed.freshUntil),
    validUntil: iso8601(seed.validUntil),
    bytes: Buffer.byteLength(seed.encoded),
    relays: seed.relays,
  };
}

/** The seed name a manifest's `url` ends in. */
export function seedName(manifest: Manifest): string {
  return path.posix.basename(manifest.url, '.json');
}

/** Whether `name` is a name `assembleSeed` gives: nothing else in the store, nothing that walks the file system. */
export function isSeedName(name: string): boolean {
  return /^\d{8}T\d{6}Z-[0-9a-f]{16}$/.test(name);
}

export async function readManifest(store: string): Promise<Manifest | null> {
  try {
    return JSON.parse(await fs.readFile(path.join(store, MANIFEST_FILE), 'utf8')) as Manifest;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * Install `seed` as the current one: write it and its gzipped form, point the
 * manifest at it, and remove every seed but it and the one the manifest named
 * before.
 */
export async function writeSeed(store: string, seed: Seed): Promise<Manifest> {
  await fs.mkdir(store, { recursive: true });
  const previous = await readManifest(store);
  const keep = new Set([seed.name, ...(previous ? [seedName(previous)] : [])]);

  const encoded = Buffer.from(seed.encoded);
  await fs.writeFile(path.join(store, `${seed.name}.json`), encoded);
  await fs.writeFile(path.join(store, `${seed.name}.json.gz`), Bun.gzipSync(encoded));

  // The manifest is what every request reads, so it changes in one step.
  const manifest = manifestFor(seed);
  const manifestPath = path.join(store, MANIFEST_FILE);
  await fs.writeFile(`${manifestPath}.tmp`, JSON.stringify(manifest, null, 2));
  await fs.rename(`${manifestPath}.tmp`, manifestPath);

  for (const entry of await fs.readdir(store)) {
    const name = entry.replace(/\.json(\.gz)?$/, '');
    if (name !== entry && entry !== MANIFEST_FILE && !keep.has(name)) {
      await fs.rm(path.join(store, entry));
    }
  }
  return manifest;
}
