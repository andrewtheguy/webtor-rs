# Onion gateway

A Vite/React app that browses plain-HTTP onion sites through a service worker,
the way [`ipfs/service-worker-gateway`](https://github.com/ipfs/service-worker-gateway)
browses IPFS content: each site gets an origin of its own, and a service
worker on that origin runs a Tor client compiled to WASM. Every request the
page makes — the document, its style sheets, images, scripts, the forms it
submits and the API calls its scripts make — is carried to the onion over
circuits the worker builds itself, and the cookies the onion sets come back
with the next one. No external Tor daemon or application proxy is involved.
The one thing a backend provides is a fresh Tor directory, over two plain HTTP
URLs any server can answer; see [The directory endpoints](#the-directory-endpoints).

```
http://<address>.onion.intor.localhost:5173/some/path
       └────────────┘ └───────────────────┘
        the onion      the gateway's own host
```

`intor.localhost` is just where the gateway happens to be opened; the onion's
origin is `<address>.onion.` prefixed to whatever host that is. Chrome and
Firefox resolve every `*.localhost` name to the loopback address and treat it
as a secure context, which is what a service worker needs.

## Run it

Build the WASM package first, then install and start the example:

```bash
cd /path/to/webtor-rs
bun run build
cd examples/onion-gateway
bun install
bun run dev
```

Open `http://intor.localhost:5173/` and paste an onion address, or go straight
to `http://<address>.onion.intor.localhost:5173/`. A path-style URL on the root
host, `http://intor.localhost:5173/<address>.onion/path`, redirects to the
subdomain form.

The first visit to an onion installs the worker on that origin and shows a
page that follows the Tor bootstrap; the page you asked for loads on its own
once the client is up. Bootstrapping needs a Tor directory, and downloading one
over a single Snowflake circuit takes minutes, so run the directory backend in
a second terminal:

```bash
bun run backend        # cargo run -p webtor-directory-server -- serve
```

It builds a seed from a directory authority in under a minute, rebuilds it as
each hourly consensus is published, and serves it on `127.0.0.1:5180`; the
dev server proxies `/api` there, so the worker on every onion origin finds it
at `http://intor.localhost:5173/api/directory`. `GATEWAY_DEV_BACKEND` names
another port or origin. `bun run backend:ts` is the TypeScript backend in
`examples/directory-server-ts` on the same port instead: it refreshes nothing
itself, so run its `bun run tor:directory` first and again within three hours.
Seeded, a client bootstraps in a few seconds and the first page arrives after
one rendezvous, about ten seconds in; later requests to the same onion begin
on the circuit the first one built and take about a second each. Without a
backend the worker says so and downloads the directory over Tor instead.

`bun run build` produces a static `dist/` with the worker at `/sw.js`. The
backend serves it too — `webtor-directory-server serve --web-root dist` is
the whole deployment — or any server that falls back to `index.html` for
unknown paths hosts it, with the directory endpoints behind `/api/directory`
on the same host or wherever `VITE_DIRECTORY_URL` points. As in the other
examples, `VITE_BRIDGE_URL` and `VITE_BRIDGE_FINGERPRINT` in `.env.local` point
the client at a bridge of your own, such as `scripts/local-bridge`.

## Test it

`bun run test` checks the cookie jar's rules without a browser. `bun run
test:e2e` is the gateway itself, in headless Chrome, against the dynamic
sample site that `scripts/local-onion` publishes as an onion service: the
install, the bootstrap page, the site's first page, a reload that carries the
cookie it set, a form sign-in answered with a `303` and a session cookie, a
script's `fetch` whose `Origin`, `Referer` and `Cookie` arrive in the onion's
terms, and a sign-out. It starts the directory backend and Vite on ports of
their own — `DIRECTORY_BACKEND` names a backend already running instead — and
reads `SAMPLE_ONION` from the environment, plus `BRIDGE_URL` and
`BRIDGE_FINGERPRINT` for a bridge of your own, which it hands to the worker
as the `VITE_` variables:

```bash
bun run build                                    # at the repository root
scripts/local-onion/onion.sh start && eval "$(scripts/local-onion/onion.sh env)"
scripts/local-bridge/bridge.sh start && eval "$(scripts/local-bridge/bridge.sh env)"
cd examples/onion-gateway && bun run test:e2e
```

`CHROME_PATH` names the browser, as for the suites under `tests/`.

## How a request travels

1. **Landing.** `http://intor.localhost:5173/` is a page with an address field.
   It sends the browser to `http://<address>.onion.intor.localhost:5173/`.
2. **Install.** No worker controls that origin yet, so the server answers with
   this app, which sees the onion in its own hostname, registers `/sw.js` for
   the whole origin, waits for it to activate, and reloads.
3. **Bootstrap.** The reload is the first request the worker sees. A
   navigation gets a page that follows the bootstrap through
   `postMessage`, while the worker loads the WASM, fetches the directory the
   backend serves — one URL on the gateway's host, so the browser's HTTP
   cache holds one copy for every onion origin under it — and bootstraps a
   client over the Snowflake WebSocket bridge. Nothing is stored: a worker
   that restarts asks again, and the cache answers.
4. **Serve.** Once the client is ready the page reloads itself, and from then
   on every request on the origin is one `client.fetch` of the same method,
   path and body on `http://<address>.onion`, with the onion's cookies on it.
   The status, headers and body come back as a `Response`; a `Location` on an
   onion is rewritten so a redirect stays inside the gateway, and a
   `Set-Cookie` goes into the worker's jar.

The client bootstraps only in the worker, and only the worker touches the
onion. Pages on the origin see ordinary responses — with the onion's own
`Content-Security-Policy`, `X-Frame-Options` and the rest passed through —
and the browser gives each onion the isolation it gives any origin: its own
storage, worker, and the jar of cookies that worker keeps.

## The directory endpoints

The worker asks two URLs for its Tor directory, and any backend that answers
them serves the gateway. By default they are on the gateway's own host; a
deployment with the backend elsewhere sets `VITE_DIRECTORY_URL` to the
manifest's absolute URL at build time.

```
GET /api/directory
200 {"url": "/api/directory/20260904T180000Z-3fa9c1d2e5b70a41.json",
     "validAfter": "2026-09-04T18:00:00Z", "freshUntil": "2026-09-04T19:00:00Z",
     "validUntil": "2026-09-04T21:00:00Z", "bytes": 40736969, "relays": 9453}
503 while no seed has been built yet (with `Retry-After`)

GET /api/directory/<name>.json
200 the seed, as `directorySeed` takes it
```

- **The manifest** names the current seed and its lifetime. It is answered
  with `Cache-Control: no-cache`, since it is the one thing that changes, and
  `url` may be relative to it or absolute — a CDN, say.
- **The seed** is what `webtor-directory-server snapshot` writes, or what a
  client's `directoryCache()` returns: a microdesc consensus, the authority
  certificates that check it and its microdescriptors, in one JSON document
  the client revalidates against the pinned directory authorities before it
  installs any of it. Its name is unique to its bytes, so the response is
  `immutable` with a `max-age` running to `validUntil`, and gzip when the
  request accepts it, which roughly halves the forty megabytes.
- **CORS.** Both answer with `Access-Control-Allow-Origin: *`. The worker
  asking is on an onion's origin, not the gateway's.
- **Freshness** is the backend's job. A consensus is published every hour and
  valid for three; the example backend refreshes a few minutes after each
  `freshUntil` and keeps the previous seed served for a worker that read the
  manifest just before. A stale seed is not fatal to the client, which keeps
  the microdescriptors it can still use and downloads only the consensus.

`examples/directory-server` is one backend: a Rust binary that fetches the
documents from a directory authority over plain HTTP, checks them with the
same code the client uses on a seed, and serves them as above, refreshing on
its own. `examples/directory-server-ts` is another, in TypeScript on Bun, with
no refresh loop: `bun run tor:directory` writes a seed and its manifest to a
directory on disk, and `bun run serve` answers from whatever is there. The
gateway does not depend on either being the one.

## What the gateway does and does not forward

- **Methods.** Any, with the request body: a form `POST`, a `PUT` or `DELETE`
  from a script, `multipart/form-data` uploads included. A body is buffered
  whole in the worker, up to 32 MiB; anything larger is answered `413`. A
  `HEAD` is sent as a `GET` and the body dropped here, because the client
  frames a response by its `Content-Length` and a `HEAD` response never
  delivers those bytes.
- **Request headers.** Everything the page sent, `Content-Type`,
  `Authorization`, `Range` and custom headers included, except three kinds.
  Conditional headers are not forwarded, because a `304` carries a
  `Content-Length` with no body; connection-level ones (`Connection`,
  `Content-Length`, `Transfer-Encoding`, `Upgrade` and the like) are set by the
  client; and `Accept-Encoding`, `Origin`, `Referer` and `Cookie` are set by
  the worker in the onion's terms, since the browser adds its own versions
  only after a worker has answered, naming the gateway. `Origin` is
  `http://<address>.onion` on any request with a body and `Referer` the
  page's own URL translated to the onion, which is what a CSRF check
  comparing them with `Host` expects.
- **Cookies.** The browser keeps none for a worker's responses, so the worker
  keeps them: every `Set-Cookie` an onion sends goes into a jar in the
  origin's IndexedDB, and the cookies whose path matches go out on each
  request as `Cookie`. `Expires`, `Max-Age` and `Path` are honoured; `Domain`
  may name only the onion itself; `Secure` is accepted, since the circuit is
  the secure channel; `HttpOnly` and `SameSite` change nothing, since no page
  can read the jar and no request reaches it from another site. Session
  cookies live until the onion expires them or the origin's storage is
  cleared, because a worker has no notion of a browser session.
- **Response headers.** Everything except the connection-level ones
  (`Connection`, `Content-Length`, `Transfer-Encoding`, `Keep-Alive`) and
  `Set-Cookie`, which stays in the worker. A gzip- or deflate-compressed body
  is decompressed in the worker, since the browser inflates only what came
  off its own network stack.
- **URLs.** Requests on the gateway origin, plus a page's requests for
  absolute `http://<address>.onion/…` URLs to *its own* onion, which is what
  its links and assets often say. A request for any other onion goes to the
  network to fail there: answering it here would let one site read another
  across origins with no CORS check in the way. A site's own CSP still
  applies; one that says `default-src 'self'` blocks its own absolute onion
  URLs, since the document's origin is the gateway's.
- **Ports.** The onion's port 80 only; the port in the gateway URL is the
  gateway's.
- **Size.** A response is buffered whole in the worker before the page sees
  any of it, up to 256 MiB; anything larger fails with a `502`.

## Limits

- **Plain HTTP only.** The onion's port 80, no TLS, and no WebSockets: a
  service worker never sees a WebSocket handshake, so a site that needs one
  wants the `WebtorClient` API directly, as the other examples use it.
- **Cookies are the worker's, not the page's.** A script's `document.cookie`
  is the gateway origin's jar, which the onion never sees, and the onion's
  cookies are never visible to a script. A site that reads its own cookies
  from JavaScript sees none.
- **A form submitted while the client is down waits.** The bootstrap page
  reloads what it was asked for as a `GET`, so only a `GET` navigation gets
  it; a `POST` holds the tab until the client is up, up to the four minutes
  the request itself may take.
- **The worker does not stay up.** A browser stops an idle service worker
  within about half a minute, and the Tor client, its bridge channel and its
  circuits go with it. The next request bootstraps again — from the cached
  directory, so in seconds — and a navigation shows the bootstrap page once
  more. The bootstrap page keeps the worker alive while it is showing; a
  loaded site does not.
- **Absolute links leave the gateway.** A link to `http://<address>.onion/…`
  is followed by the browser as a navigation to that host, which no worker
  controls, so it fails to resolve. Only redirects are rewritten; page
  content is passed through untouched.
- **No directory without the backend.** The worker stores nothing between
  starts, so what it has is what the backend serves and the browser's HTTP
  cache kept. With the backend down and the cache cold, a bootstrap downloads
  the directory over Tor, which takes minutes.
- **The WebSocket bridge only.** The WebRTC bridge needs `RTCPeerConnection`,
  which a worker does not have.
