import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

function webtorWasmDirectory(): string {
  const require = createRequire(path.join(import.meta.dirname, 'package.json'));
  return fs.realpathSync(
    path.dirname(require.resolve('@andrewtheguy/webtor-wasm/package.json')),
  );
}

export default defineConfig({
  plugins: [react()],
  server: {
    // Reachable through a Cloudflare quick tunnel (`cloudflared tunnel --url`),
    // which is how the page gets opened in Tor Browser on another machine.
    allowedHosts: ['.trycloudflare.com'],
    fs: {
      // Both live outside this example: the seed store is shared with the
      // other one, and bun installs the local WASM package as a symlink.
      allow: [
        import.meta.dirname,
        path.join(import.meta.dirname, '..', 'shared'),
        webtorWasmDirectory(),
      ],
    },
    // A rebuilt WASM binary and stale JS glue must never share one page load.
    hmr: false,
  },
});
