// The sending side: POST a message to someone's `.onion` address, either
// through a Tor client bootstrapped in this tab over Snowflake, or through
// the browser's own Tor when the page is open in Tor Browser.

import { createClient, logger, type Bridge, type LogEntry } from './tor-client';
import { browserFetch } from './tor-browser';

/** Which Tor carries the message. Only Tor Browser has a `browser` one. */
export type SendVia = 'webtor' | 'browser';

export interface SendOptions {
  address: string;
  message: string;
  via: SendVia;
  bridge: Bridge;
  onLog: (entry: LogEntry) => void;
}

export interface Delivery {
  via: SendVia;
  status: number;
  seconds: number;
  text: string;
}

/** Long enough for a first rendezvous, which can take minutes over Snowflake. */
const SEND_TIMEOUT_MS = 240_000;

const ADDRESS = /^[a-z2-7]{56}\.onion$/;

/** The address as typed, in any of the forms people paste, or null. */
export function normalizeAddress(input: string): string | null {
  const address = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
  return ADDRESS.test(address) ? address : null;
}

// The tab's own client survives across sends: bootstrapping is the slow part,
// and the circuits it built to reach an address are reused for the next one.
let clientPromise: ReturnType<typeof createClient> | null = null;

function client(bridge: Bridge, onLog: (entry: LogEntry) => void) {
  clientPromise ??= createClient(bridge, logger(onLog)).catch((error) => {
    clientPromise = null;
    throw error;
  });
  return clientPromise;
}

export async function sendMessage(options: SendOptions): Promise<Delivery> {
  const url = `http://${options.address}/message`;
  const headers = { 'Content-Type': 'text/plain; charset=utf-8' };
  const started = performance.now();
  let status: number;
  let text: string;
  if (options.via === 'browser') {
    ({ status, text } = await browserFetch(url, SEND_TIMEOUT_MS, {
      method: 'POST',
      headers,
      body: options.message,
    }));
  } else {
    const tor = await client(options.bridge, options.onLog);
    const response = await tor.fetch(url, {
      method: 'POST',
      headers,
      body: options.message,
      timeoutMs: SEND_TIMEOUT_MS,
    });
    status = response.status;
    text = response.text();
  }
  return {
    via: options.via,
    status,
    seconds: Number(((performance.now() - started) / 1000).toFixed(1)),
    text,
  };
}
