import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

/** Where the page registers the gateway from, in development and in a build. */
const SERVICE_WORKER_URL = '/sw.js';
const SERVICE_WORKER_SOURCE = '/src/sw.ts';

/**
 * Where the directory backend is listening, so `/api` on the dev server
 * reaches it from every onion origin. 5180 is `webtor-directory-server`'s
 * default; a port or a full origin overrides it:
 *
 *   GATEWAY_DEV_BACKEND=5181 bun run dev
 *   GATEWAY_DEV_BACKEND=http://192.168.1.10:5180 bun run dev
 */
const backend = process.env.GATEWAY_DEV_BACKEND ?? '5180';
const backendUrl = /^\d+$/.test(backend) ? `http://127.0.0.1:${backend}` : backend;

function webtorWasmDirectory(): string {
  const require = createRequire(path.join(import.meta.dirname, 'package.json'));
  return fs.realpathSync(
    path.dirname(require.resolve('@andrewtheguy/webtor-wasm/package.json')),
  );
}

/**
 * Serve the service worker from the site root while developing. A worker can
 * control no path above its own script's directory, so registering the
 * source at `/src/sw.ts` would leave it in charge of `/src/` and nothing
 * else; the built output puts it at `/sw.js`, and this makes the dev server
 * answer the same URL with the transformed source.
 */
function serviceWorkerAtRoot(): Plugin {
  return {
    name: 'gateway-service-worker-at-root',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((request, _response, next) => {
        if (request.url === SERVICE_WORKER_URL) request.url = SERVICE_WORKER_SOURCE;
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), serviceWorkerAtRoot()],
  build: {
    rollupOptions: {
      input: {
        main: path.join(import.meta.dirname, 'index.html'),
        sw: path.join(import.meta.dirname, 'src', 'sw.ts'),
      },
      output: {
        // The worker's URL is what browsers hold registrations by, so it
        // gets no content hash; everything else keeps Vite's naming.
        entryFileNames: (chunk) =>
          chunk.name === 'sw' ? 'sw.js' : 'assets/[name]-[hash].js',
      },
    },
  },
  server: {
    // Every onion gets an origin of its own under whatever host the gateway
    // is opened on: `<address>.onion.intor.localhost` and the like.
    allowedHosts: ['.localhost'],
    fs: {
      // Both live outside this example: the seed store is shared with the
      // other examples, and bun installs the local WASM package as a symlink.
      allow: [
        import.meta.dirname,
        path.join(import.meta.dirname, '..', 'shared'),
        webtorWasmDirectory(),
      ],
    },
    // A rebuilt WASM binary and stale JS glue must never share one page load.
    hmr: false,
    // The directory endpoints come from the backend; the worker asks for
    // them on the gateway host and the browser keeps one copy for every
    // onion origin under it.
    proxy: {
      '/api': backendUrl,
    },
  },
});
