// One Tor client per side of the conversation, bootstrapped over Snowflake
// from this tab. Both the listener and the sender start here.

import { directorySeedStore } from '../../shared/directory-cache';
import { loadWebtor } from './webtor';

export type Bridge = 'websocket' | 'webrtc';

export type LogLevel = 'info' | 'success' | 'error';

export interface LogEntry {
  at: number;
  level: LogLevel;
  message: string;
}

export type Log = (level: LogLevel, message: string) => void;

/** STUN servers the `webrtc` bridge needs to find its own address. */
const STUN_URLS = ['stun:stun.l.google.com:19302'];

/**
 * A bridge to use instead of the public one, from `.env.local`:
 *
 *   VITE_BRIDGE_URL=ws://localhost:8080/
 *   VITE_BRIDGE_FINGERPRINT=<what scripts/local-bridge prints>
 *
 * Worth doing while iterating, because the client fetches the consensus and
 * every HSDir microdescriptor one hop from the bridge: against a local one
 * that download is local too. Both or neither — a URL without an identity
 * would be a request to trust whatever answers.
 */
const BRIDGE_URL = import.meta.env.VITE_BRIDGE_URL;
const BRIDGE_FINGERPRINT = import.meta.env.VITE_BRIDGE_FINGERPRINT;

if (Boolean(BRIDGE_URL) !== Boolean(BRIDGE_FINGERPRINT)) {
  throw new Error(
    'Set VITE_BRIDGE_URL and VITE_BRIDGE_FINGERPRINT together, or neither',
  );
}

const store = directorySeedStore('webtor-onion-service-poc');

export function logger(onLog: (entry: LogEntry) => void): Log {
  return (level, message) => onLog({ at: Date.now(), level, message });
}

export async function createClient(bridge: Bridge, log: Log) {
  const { WebtorClient } = await loadWebtor();
  const seed = await store.load();
  log('info', `Tor directory: ${seed.source}`);

  const client = await WebtorClient.create({
    bridge,
    ...(bridge === 'webrtc' ? { stunUrls: STUN_URLS } : {}),
    ...(BRIDGE_URL && BRIDGE_FINGERPRINT
      ? { bridgeUrl: BRIDGE_URL, bridgeFingerprint: BRIDGE_FINGERPRINT }
      : {}),
    ...(seed.value ? { directorySeed: seed.value } : {}),
    // Keep every directory this client downloads, not just the one it started
    // with: a published service refreshes the directory for as long as it is
    // up, and downloading one over a single bridge circuit is the slowest part
    // of a cold start.
    onDirectoryChange: (cache: string) => {
      void store.save(cache).then((stored) => {
        if (stored) log('info', 'Stored a fresh Tor directory for the next start');
      });
    },
    logPrefix: '[onion-service-poc]',
  });
  log('success', 'Tor client bootstrapped');
  return client;
}
