// What every live suite reads from the environment to bootstrap a client:
// the directory seed, and the bridge to use instead of the public one.
//
//   DIRECTORY_SEED  path to a directory snapshot (default
//                   tests/.directory-seed.json, written by `bun run seed`).
//                   Without one the bootstrap downloads every HSDir
//                   microdescriptor over a single bridge circuit, which takes
//                   minutes across the public bridge and seconds across a
//                   local one.
//   BRIDGE          "websocket" (default) or "webrtc"
//   STUN_URLS       comma-separated, for the webrtc bridge
//   BRIDGE_URL      a bridge to use instead of the public one, with
//   BRIDGE_FINGERPRINT  its RSA identity. Both or neither. `scripts/local-bridge`
//                   runs one on localhost and prints both.

import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { relative } from 'node:path';
import type { CreateOptions } from './browser.ts';
import { REPO_ROOT } from './server.ts';

export const SEED_PATH = process.env.DIRECTORY_SEED ?? `${REPO_ROOT}/tests/.directory-seed.json`;
export const BRIDGE = process.env.BRIDGE ?? 'websocket';
export const STUN_URLS = (process.env.STUN_URLS ?? '')
  .split(',')
  .map((url) => url.trim())
  .filter(Boolean);
export const BRIDGE_URL = process.env.BRIDGE_URL;
export const BRIDGE_FINGERPRINT = process.env.BRIDGE_FINGERPRINT;

/**
 * The seed's URL on the harness server, or `null` when there is no seed
 * file; the page fetches it itself, since tens of megabytes do not want to
 * travel through CDP.
 */
export async function seedUrl(): Promise<string | null> {
  try {
    await access(SEED_PATH, constants.R_OK);
    return `/${relative(REPO_ROOT, SEED_PATH)}`;
  } catch {
    console.log(
      `  no directory seed at ${SEED_PATH}; bootstrapping from the network. ` +
        'Run `bun run seed` or start scripts/local-bridge to make this fast.',
    );
    return null;
  }
}

/** `WebtorClient.create` options for the bridge the environment names. */
export function clientOptions(logPrefix?: string): CreateOptions {
  const options: CreateOptions = { bridge: BRIDGE };
  if (logPrefix) options.logPrefix = logPrefix;
  if (BRIDGE === 'webrtc') {
    assert.ok(STUN_URLS.length, 'BRIDGE=webrtc needs STUN_URLS');
    options.stunUrls = STUN_URLS;
  }
  // Half a bridge is not a usable bridge, and the half that is missing
  // decides whether the run is slow or insecure, so refuse both ways round
  // rather than falling back to the public one.
  assert.equal(
    Boolean(BRIDGE_URL),
    Boolean(BRIDGE_FINGERPRINT),
    'BRIDGE_URL and BRIDGE_FINGERPRINT are set together or not at all',
  );
  if (BRIDGE_URL && BRIDGE_FINGERPRINT) {
    options.bridgeUrl = BRIDGE_URL;
    options.bridgeFingerprint = BRIDGE_FINGERPRINT;
  }
  return options;
}
