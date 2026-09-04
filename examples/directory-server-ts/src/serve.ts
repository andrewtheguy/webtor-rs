#!/usr/bin/env bun
// Serve the directory endpoints from the store `bun run tor:directory` writes.
//
//   bun run serve                                  # 127.0.0.1:5180, ./directory
//   bun run serve --listen 0.0.0.0:8080 --web-root ../onion-gateway/dist
//
// Nothing here refreshes the directory: run `bun run tor:directory` again
// before the current one expires, and the next request picks it up.

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { createHandler, DIRECTORY_PATH } from './server.ts';
import { DEFAULT_STORE, readManifest } from './store.ts';

const { values } = parseArgs({
  options: {
    listen: { type: 'string', short: 'l', default: process.env.WEBTOR_DIRECTORY_LISTEN ?? '127.0.0.1:5180' },
    store: { type: 'string', default: process.env.WEBTOR_DIRECTORY_STORE ?? DEFAULT_STORE },
    'web-root': { type: 'string', default: process.env.WEBTOR_DIRECTORY_WEB_ROOT },
  },
});

const listen = /^(.*):(\d+)$/.exec(values.listen);
if (!listen) throw new Error(`--listen wants host:port, not ${values.listen}`);
const [, hostname, port] = listen;

const store = path.resolve(values.store);
const webRoot = values['web-root'] ? path.resolve(values['web-root']) : undefined;
if (webRoot) {
  await fs.access(path.join(webRoot, 'index.html')).catch(() => {
    throw new Error(`${webRoot} has no index.html to serve`);
  });
}

const manifest = await readManifest(store);
console.log(
  manifest
    ? `Serving directory ${manifest.url} from ${store}, valid until ${manifest.validUntil}`
    : `No directory in ${store} yet; ${DIRECTORY_PATH} answers 503 until \`bun run tor:directory\` has run`,
);

const server = Bun.serve({
  hostname,
  port: Number(port),
  // A seed is tens of megabytes; give a slow client time to take it.
  idleTimeout: 120,
  fetch: createHandler({ store, webRoot, log: console.log }),
});
console.log(`Listening on http://${server.hostname}:${server.port}${webRoot ? `, serving ${webRoot}` : ''}`);
