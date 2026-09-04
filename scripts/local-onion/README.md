# A dynamic onion site on localhost

The public onion sites the live suite uses are static, and nobody's to
change: they answer a `GET` and set no cookies. That leaves everything a
form-driven site does — a `POST` with a body, a `303` back to the page, a
`Set-Cookie` and the `Cookie` on the next request, an `Origin` check — with
nothing to test it against. This container is that site: a tor client
publishing one onion service, and behind it the small dynamic site in
`server.ts`, which signs a visitor in from a form, counts visits in a cookie,
refuses a cross-site `POST`, and echoes any request back as JSON.

Two suites use it. `bun run test:dynamic` at the repository root drives the
`WebtorClient` API against it directly, and `bun run test:e2e` in the
`onion-gateway` repository's `gateway` directory opens it in headless Chrome
through the service worker gateway.

## Run it

`onion.sh` wraps the container commands, the same way `scripts/local-bridge`
does, and shares its engine detection: podman or docker, whichever answers
`info`, or `CONTAINER_ENGINE` to name one.

```bash
scripts/local-onion/onion.sh start     # builds the image if it is missing
scripts/local-onion/onion.sh status
scripts/local-onion/onion.sh logs      # follow, ctrl-c to detach
scripts/local-onion/onion.sh stop
```

`start` waits for tor to generate the service's key and prints the address
the tests need:

```
export SAMPLE_ONION=http://tdk2c4al3iiftupaegxagb6wr5ptsfzhwxxk64ujjid7ksayefj7lwyd.onion
```

`env` prints that line alone and `address` the bare hostname, so a shell can
take it directly:

```bash
eval "$(scripts/local-onion/onion.sh env)" && bun run test:dynamic
```

The container runs with `--rm` and no volume, so **the address is new on
every start**: read it from `env` each time rather than keeping one. And an
address is not yet a reachable service. Its tor has to bootstrap, which
`status` reports, and then publish the descriptor to the HSDirs, which takes
a while longer and nothing reports; both suites retry their first request for
up to four minutes for that reason. In practice the site answers within a
minute or two of `start`.

Nothing is published on the host. The site listens on the container's
loopback, tor forwards the onion's port 80 to it, and that is the only way in
— which is the point. To look at the site without Tor, run it bare:

```bash
PORT=8000 bun scripts/local-onion/server.ts
```

Its handler is exported, and `server.test.ts` checks it without a socket; that
file runs as part of `bun run test`.

## With the local bridge

The sample onion and the local bridge are independent containers. The bridge
makes the *client's* bootstrap fast; the onion is what the client then talks
to. Start both for a quick run:

```bash
scripts/local-bridge/bridge.sh start && eval "$(scripts/local-bridge/bridge.sh env)"
scripts/local-onion/onion.sh start && eval "$(scripts/local-onion/onion.sh env)"
bun run test:dynamic
```

## What the site does

| Request | Answer |
| --- | --- |
| `GET /` | The page: `#visits` counts this visitor's visits from a `visits` cookie and sets it one higher, alongside a `seen` cookie with a `Max-Age`, so every response carries two `Set-Cookie` headers. `#who` says who the `session` cookie names. A sign-in and a sign-out form. |
| `POST /login` | `name` from a form body. `303` to `/` with `session=<name>; Path=/; HttpOnly`. Refused with `403` unless `Origin` is `http://<Host>`, the check a real site makes and the one a gateway forwarding a form has to pass. |
| `POST /logout` | The same check; `303` to `/` with the session cookie lapsed. |
| `/echo` | Any method. JSON with the method, path, query, every request header, the parsed cookies and the body as text. |
| anything else | `404`. |

## What this is not

A site anyone should visit, or a tor anyone should copy. It keeps no key, has
no SocksPort and runs for as long as a test takes.
