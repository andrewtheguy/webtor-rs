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
    fs: {
      // Bun installs the local WASM package as a symlink outside this example.
      allow: [import.meta.dirname, webtorWasmDirectory()],
    },
    // A rebuilt WASM binary and stale JS glue must never share one page load.
    hmr: false,
  },
});
