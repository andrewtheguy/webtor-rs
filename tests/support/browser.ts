// Launches headless Chrome on the harness page and hands tests a `call`
// function that runs one harness method inside it.

import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { REPO_ROOT, startServer } from './server.ts';

const CHROME_PATH = process.env.CHROME_PATH ?? '/usr/bin/google-chrome';
const PACKAGE = join(REPO_ROOT, 'webtor-wasm', 'pkg', 'webtor_wasm.js');

async function requireFile(path: string, hint: string): Promise<void> {
  try {
    await access(path, constants.R_OK);
  } catch {
    throw new Error(`${path} is missing or unreadable. ${hint}`);
  }
}

/**
 * Open the harness. `onLog` receives every console line the page emits, which
 * is where the client's bootstrap progress shows up; a live run is quiet for
 * minutes otherwise.
 */
export interface OnionUrl {
  scheme: string;
  host: string;
  port: number;
  pathAndQuery: string;
}

export interface CreateOptions {
  bridge?: string;
  connectionTimeoutMs?: number;
  logPrefix?: string;
  maxMessageBytes?: number;
  stunUrls?: string[];
  verifyOnion?: boolean | string;
  [option: string]: unknown;
}

export interface FetchOptions {
  body?: Uint8Array | string;
  headers?: Record<string, string>;
  method?: string;
  timeoutMs?: number;
}

export interface WebSocketOptions {
  maxMessageBytes?: number;
  timeoutMs?: number;
}

export interface HarnessFetchResult {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  byteLength: number;
  text: string | null;
  seconds: number;
}

export interface HarnessCalls {
  isOnionHost: { args: [host: string]; result: boolean };
  parseOnionUrl: { args: [url: string]; result: OnionUrl };
  createRejects: { args: [options: Record<string, unknown>]; result: string };
  create: {
    args: [options: CreateOptions, seedUrl: string | null];
    result: { seconds: number };
  };
  directoryCache: {
    args: [];
    result: {
      bytes: number;
      version: number;
      consensusBytes: number;
      microdescriptorBytes: number;
    };
  };
  close: { args: []; result: string };
  fetch: {
    args: [url: string, options?: FetchOptions];
    result: HarnessFetchResult;
  };
  wsOpen: {
    args: [url: string, options?: WebSocketOptions];
    result: { id: number; seconds: number };
  };
  wsSend: { args: [id: number, text: string]; result: string };
  wsSendBinary: { args: [id: number, bytes: number[]]; result: string };
  wsReceive: {
    args: [id: number];
    result:
      | { type: 'text'; text: string }
      | { type: 'binary'; bytes: number[] }
      | null;
  };
  wsReceiveUntil: {
    args: [id: number, kinds: string[], limit: number];
    result: { closed: boolean; matched?: string; seen: string[] };
  };
  wsClose: { args: [id: number]; result: string };
}

type HarnessMethod = keyof HarnessCalls;

export interface BrowserHarness {
  origin: string;
  call<Method extends HarnessMethod>(
    method: Method,
    ...args: HarnessCalls[Method]['args']
  ): Promise<HarnessCalls[Method]['result']>;
  close(): Promise<void>;
}

interface OpenHarnessOptions {
  onLog?: (line: string) => void;
}

declare global {
  var harness: Record<string, (...args: unknown[]) => unknown> | undefined;
}

export async function openHarness(
  { onLog }: OpenHarnessOptions = {},
): Promise<BrowserHarness> {
  await requireFile(PACKAGE, 'Run `bun run build` first.');
  await requireFile(
    CHROME_PATH,
    'Set CHROME_PATH to a Chrome-family binary.',
  );

  const server = await startServer();
  const browser = await chromium.launch({
    executablePath: CHROME_PATH,
    headless: true,
  });
  const page = await browser.newPage();
  if (onLog) {
    page.on('console', (message) => onLog(message.text()));
    page.on('pageerror', (error) => onLog(`page error: ${error.message}`));
  }
  await page.goto(`${server.origin}/`);
  await page.waitForFunction(() => Boolean(globalThis.harness));

  return {
    origin: server.origin,
    /**
     * Invoke `harness[method](...args)` in the page. A rejection there is
     * re-thrown here with its message intact, so tests can assert on it.
     */
    call<Method extends HarnessMethod>(
      method: Method,
      ...args: HarnessCalls[Method]['args']
    ): Promise<HarnessCalls[Method]['result']> {
      return page.evaluate(
        ([name, callArgs]: [string, unknown[]]) => {
          const call = globalThis.harness?.[name];
          if (!call) throw new Error(`Harness has no method "${name}"`);
          return call(...callArgs);
        },
        [method, args] as [string, unknown[]],
      ) as Promise<HarnessCalls[Method]['result']>;
    },
    async close() {
      await browser.close();
      await server.close();
    },
  };
}
