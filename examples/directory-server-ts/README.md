# directory-server-ts

The onion gateway's directory endpoints, from TypeScript on Bun, with the
seed built by hand. It answers the same contract as
[`examples/directory-server`](../directory-server) — the two URLs the gateway's
README documents under *The directory endpoints* — but has no refresh loop:
a script builds the seed when you run it, and the server reads whatever the
script last wrote.

```bash
cd examples/directory-server-ts
bun install
bun run tor:directory    # builds ./directory/<name>.json and manifest.json, about a minute
bun run serve            # answers on 127.0.0.1:5180
```

With `serve` running, `bun run dev` in `examples/onion-gateway` proxies `/api`
to it, and the worker on every onion origin fetches
`http://intor.localhost:5173/api/directory`. `bun run backend:ts` in the
gateway is the same `serve`.

## What the script writes

`bun run tor:directory` fetches the current microdesc consensus from a
directory authority over plain HTTP, the authority certificates that check its
signatures and the microdescriptor of every relay it names, and puts them in
the JSON `directorySeed` accepts. It checks that the result could be installed
— a strict majority of signatures from the authorities the client pins, enough
relays in each role, most microdescriptors present — but verifies no
signature itself; the client does that against its pinned authorities before
installing a single relay, so a seed needs no trust between here and there.

The result goes into `./directory` (`--store` or `WEBTOR_DIRECTORY_STORE` for
another place):

```
directory/
  manifest.json                              what /api/directory answers
  20260904T180000Z-3f1c9a7b2e4d6c80.json     the seed, named by valid-after and its own SHA-256
  20260904T180000Z-3f1c9a7b2e4d6c80.json.gz  the same, gzipped ahead of time
```

The manifest is replaced in one step, so a running server picks up a rebuild
on its next request. The seed the previous manifest named is kept for one more
rebuild, for a worker that read that manifest a moment before; older ones are
removed.

A consensus is valid for three hours and the client refuses an expired one.
Run the script again before the `validUntil` it prints; from `cron`, once an
hour a few minutes past the hour suits the authorities' publication schedule.
Once the stored seed has expired the manifest answers `503` saying so, and the
worker downloads a directory over Tor instead.

`bun src/build.ts --seed <path>` writes the bare seed to one file instead,
which is what `bun run tor:directory` in `examples/nostr-onion-poc` and
`examples/onion-service-poc` uses for their `public/tor-directory.json`.

## What the server answers

```
GET /api/directory                the manifest; Cache-Control: no-cache; 503 with Retry-After when there is no valid seed
GET /api/directory/<name>.json    the seed; public, max-age=<seconds to validUntil>, immutable; ETag; gzip when accepted
GET /api/health
```

Every `/api` answer carries `Access-Control-Allow-Origin: *`, because the
worker asking lives on an onion's origin. `--listen host:port` (or
`WEBTOR_DIRECTORY_LISTEN`) moves it off `127.0.0.1:5180`, and
`--web-root <dir>` (or `WEBTOR_DIRECTORY_WEB_ROOT`) serves a built gateway
beside the endpoints, falling back to its `index.html` for the paths the
gateway's own router handles:

```bash
bun run serve --listen 0.0.0.0:8080 --web-root ../onion-gateway/dist
```

`bun run test` covers the consensus reading, the store and the endpoints
without touching the network; `bun run typecheck` runs `tsc`.
