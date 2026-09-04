#!/usr/bin/env bun
// Build a directory seed from a directory authority and install it in the
// store the server reads from, or write it as one bare file.
//
//   bun run tor:directory                       # into ./directory, for `bun run serve`
//   bun run tor:directory --store /srv/tor      # into another store
//   bun src/build.ts --seed public/tor-directory.json   # one file, for the other examples
//
// A microdesc consensus is valid for three hours and the client rejects an
// expired one, so run this again before `validUntil` passes; `serve` answers
// 503 once it has.

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { Authorities, DEFAULT_AUTHORITIES } from './authority.ts';
import { iso8601 } from './seed.ts';
import { DEFAULT_STORE, writeSeed } from './store.ts';

const { values } = parseArgs({
  options: {
    store: { type: 'string', default: process.env.WEBTOR_DIRECTORY_STORE ?? DEFAULT_STORE },
    seed: { type: 'string' },
    authority: { type: 'string', multiple: true },
  },
});

const authorities = new Authorities(values.authority?.length ? values.authority : DEFAULT_AUTHORITIES);
const started = performance.now();
const seed = await authorities.buildSeed(console.log);
const mib = (Buffer.byteLength(seed.encoded) / 1024 / 1024).toFixed(1);
const seconds = ((performance.now() - started) / 1000).toFixed(0);

if (values.seed) {
  const output = path.resolve(values.seed);
  await fs.mkdir(path.dirname(output), { recursive: true });
  await fs.writeFile(output, seed.encoded);
  console.log(`Wrote ${output} (${mib} MiB) in ${seconds}s; rebuild before ${iso8601(seed.validUntil)}`);
} else {
  const store = path.resolve(values.store);
  const manifest = await writeSeed(store, seed);
  console.log(
    `Installed ${seed.name} (${mib} MiB, ${manifest.relays} relays) in ${store} in ${seconds}s; rebuild before ${manifest.validUntil}`,
  );
}
