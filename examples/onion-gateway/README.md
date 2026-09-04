# Onion gateway

A Vite/React app that browses static onion sites through a service worker,
the way [`ipfs/service-worker-gateway`](https://github.com/ipfs/service-worker-gateway)
browses IPFS content: each site gets an origin of its own, and a service
worker on that origin runs a Tor client compiled to WASM. Every request the
page makes — the document, its style sheets, images, scripts — is fetched from
the onion over circuits the worker builds itself. No external Tor daemon,
application proxy, or backend is involved.

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
once the client is up. Bootstrapping downloads a Tor directory over a single
Snowflake circuit unless a snapshot is on hand, so create one before starting
Vite:

```bash
bun run tor:directory
```

The generated `public/tor-directory.json` is intentionally ignored: a
microdescriptor consensus is valid for only a few hours, so rebuild it shortly
before testing rather than committing it. With a snapshot, a client bootstraps
in a few seconds and the first page arrives after one rendezvous, about ten
seconds in; later requests to the same onion begin on the circuit the first one
built and take about a second each.

`bun run build` produces a static `dist/` with the worker at `/sw.js`; any
server that falls back to `index.html` for unknown paths, `bun run preview`
included, hosts it. As in the other examples, `VITE_BRIDGE_URL` and
`VITE_BRIDGE_FINGERPRINT` in `.env.local` point the client at a bridge of your
own, such as `scripts/local-bridge`.

## How a request travels

1. **Landing.** `http://intor.localhost:5173/` is a page with an address field.
   It sends the browser to `http://<address>.onion.intor.localhost:5173/`.
2. **Install.** No worker controls that origin yet, so the server answers with
   this app, which sees the onion in its own hostname, registers `/sw.js` for
   the whole origin, waits for it to activate, and reloads.
3. **Bootstrap.** The reload is the first request the worker sees. A
   navigation gets a page that follows the bootstrap through
   `postMessage`, while the worker loads the WASM, takes the best directory it
   has — the served snapshot, else what a previous run stored in IndexedDB —
   and bootstraps a client over the Snowflake WebSocket bridge. Every
   directory the client later downloads is stored for the next start.
4. **Serve.** Once the client is ready the page reloads itself, and from then
   on every request on the origin is one `client.fetch` of the same path on
   `http://<address>.onion`. The status, headers and body come back as a
   `Response`; a `Location` on an onion is rewritten so a redirect stays inside
   the gateway.

The client bootstraps only in the worker, and only the worker touches the
onion. Pages on the origin see ordinary responses — with the onion's own
`Content-Security-Policy`, `X-Frame-Options` and the rest passed through —
and the browser gives each onion the isolation it gives any origin: its own
cookies, storage, and worker.

## What the gateway does and does not forward

- **Methods.** `GET` and `HEAD`, which is what static content needs. Anything
  else is answered `405` by the gateway. A `HEAD` is sent as a `GET` and the
  body dropped here, because the client frames a response by its
  `Content-Length` and a `HEAD` response never delivers those bytes.
- **Request headers.** `Accept`, `Accept-Language` and `Range`. Conditional
  headers are not forwarded, for the same reason: a `304` carries a
  `Content-Length` with no body.
- **Response headers.** Everything except the connection-level ones
  (`Connection`, `Content-Length`, `Transfer-Encoding`, `Keep-Alive`). A
  gzip- or deflate-compressed body is decompressed in the worker, since the
  browser inflates only what came off its own network stack. `Set-Cookie` is
  dropped by the browser on any response a worker constructs.
- **URLs.** Requests on the gateway origin, plus a page's requests for
  absolute `http://<address>.onion/…` URLs to *its own* onion, which is what
  its links and assets often say. A request for any other onion goes to the
  network to fail there: answering it here would let one site read another
  across origins with no CORS check in the way. A site's own CSP still
  applies; one that says `default-src 'self'` blocks its own absolute onion
  URLs, since the document's origin is the gateway's.
- **Ports.** The onion's port 80 only; the port in the gateway URL is the
  gateway's.

## Limits

- **Static content only.** No `POST`, no cookies, no WebSockets. A site that
  needs those wants the `WebtorClient` API directly, as the other examples use
  it.
- **The worker does not stay up.** A browser stops an idle service worker
  within about half a minute, and the Tor client, its bridge channel and its
  circuits go with it. The next request bootstraps again — from the stored
  directory, so in seconds — and a navigation shows the bootstrap page once
  more. The bootstrap page keeps the worker alive while it is showing; a
  loaded site does not.
- **Absolute links leave the gateway.** A link to `http://<address>.onion/…`
  is followed by the browser as a navigation to that host, which no worker
  controls, so it fails to resolve. Only redirects are rewritten; page
  content is passed through untouched.
- **One directory per origin.** IndexedDB is per origin, so every onion's
  worker stores its own copy of the directory. The served snapshot, when there
  is one, is shared by all of them.
- **The WebSocket bridge only.** The WebRTC bridge needs `RTCPeerConnection`,
  which a worker does not have.
