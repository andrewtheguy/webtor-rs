// Serves the repository over loopback so a page can import the built
// `webtor-wasm/pkg/` and fetch a directory seed without a bundler.

import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..', '..');
const HARNESS = join(REPO_ROOT, 'tests', 'harness', 'index.html');

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

/**
 * Start the server on a random loopback port.
 *
 * 127.0.0.1 rather than a hostname or a LAN address: the browser treats
 * loopback as a secure context, which is what `crypto.getRandomValues` needs,
 * and every key the client generates goes through it.
 */
export async function startServer(): Promise<{
  origin: string;
  close(): Promise<void>;
}> {
  const server = createServer(async (request, response) => {
    const path = normalize(
      decodeURIComponent(
        new URL(request.url ?? '/', 'http://localhost').pathname,
      ),
    );
    // The browser asks for a favicon on its own; a 404 for it is the only
    // noise in an otherwise readable console log.
    if (path === '/favicon.ico') {
      response.writeHead(204).end();
      return;
    }
    const file = path === '/' ? HARNESS : join(REPO_ROOT, path);
    if (!file.startsWith(REPO_ROOT)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const info = await stat(file);
      if (!info.isFile()) throw new Error('not a file');
      response.writeHead(200, {
        'content-type': MIME[extname(file)] ?? 'application/octet-stream',
        'content-length': info.size,
      });
      createReadStream(file).pipe(response);
    } catch {
      response.writeHead(404).end();
    }
  });

  await new Promise<void>((ready) => server.listen(0, '127.0.0.1', ready));
  const address = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${address.port}`,
    async close() {
      await new Promise<void>((closed) => server.close(() => closed()));
    },
  };
}
