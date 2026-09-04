// A small dynamic site: what a static one never needs, in one file. It
// signs a visitor in from a form, counts their visits in a cookie, refuses a
// cross-site POST, and echoes any request back as JSON. The container in
// this directory puts it behind a Tor onion service so that webtor, and the
// onion gateway built on it, can be tested against methods, bodies, cookies
// and redirects rather than against a page that is the same every time.
//
// It also runs bare, for looking at it without Tor in the way:
//
//   PORT=8000 bun scripts/local-onion/server.ts

/** The one cookie a request is signed in by, holding the visitor's name. */
const SESSION_COOKIE = 'session';
/** How many times this visitor has seen `/`. */
const VISITS_COOKIE = 'visits';
/** When this visitor last saw `/`; expires on its own, unlike the others. */
const SEEN_COOKIE = 'seen';
const SEEN_MAX_AGE_SECONDS = 3600;

const HTML = 'text/html; charset=utf-8';
const JSON_TYPE = 'application/json; charset=utf-8';
const TEXT = 'text/plain; charset=utf-8';

function escape(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

/** The `Cookie` header as a map, last value winning for a repeated name. */
export function parseCookies(header: string | null): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const pair of header?.split(';') ?? []) {
    const separator = pair.indexOf('=');
    if (separator === -1) continue;
    const name = pair.slice(0, separator).trim();
    if (name !== '') cookies[name] = decodeURIComponent(pair.slice(separator + 1).trim());
  }
  return cookies;
}

function text(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { 'content-type': TEXT, ...headers } });
}

/**
 * A `303 See Other` to `location`, the answer a form POST gets, so that the
 * browser GETs the result rather than offering to POST again on a reload.
 */
function seeOther(location: string, cookies: string[]): Response {
  const headers = new Headers({ location, 'content-type': TEXT });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(`See ${location}\n`, { status: 303, headers });
}

/**
 * Whether a state-changing request came from this site. The check a real
 * site does: `Origin` has to be this host, the one the request was made to.
 * A gateway that forwards a form has to say the onion's name here rather
 * than its own, which is exactly what this exists to find out.
 */
function sameOrigin(request: Request): boolean {
  const host = request.headers.get('host');
  const origin = request.headers.get('origin');
  return host !== null && origin !== null && origin.toLowerCase() === `http://${host.toLowerCase()}`;
}

function crossSite(request: Request): Response {
  const origin = request.headers.get('origin') ?? '(none)';
  const host = request.headers.get('host') ?? '(none)';
  return text(403, `Cross-site request refused: Origin ${origin} does not match Host ${host}\n`);
}

function home(request: Request): Response {
  const cookies = parseCookies(request.headers.get('cookie'));
  const name = cookies[SESSION_COOKIE];
  const visits = (Number.parseInt(cookies[VISITS_COOKIE] ?? '0', 10) || 0) + 1;
  const who = name ? `Signed in as ${escape(name)}` : 'Not signed in';
  const body = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sample onion</title></head>
<body>
<h1>Sample onion</h1>
<p id="visits">Visit ${visits}</p>
<p id="who">${who}</p>
<form id="login" method="post" action="/login">
  <label>Name <input name="name" autocomplete="off"></label>
  <button type="submit">Sign in</button>
</form>
<form id="logout" method="post" action="/logout">
  <button type="submit">Sign out</button>
</form>
<p><a href="/echo">Echo this request</a></p>
</body>
</html>
`;
  const headers = new Headers({ 'content-type': HTML, 'cache-control': 'no-store' });
  // Two cookies on one response: a client that keeps only the last
  // `Set-Cookie` header loses one of them.
  headers.append('set-cookie', `${VISITS_COOKIE}=${visits}; Path=/`);
  headers.append(
    'set-cookie',
    `${SEEN_COOKIE}=${new Date().toISOString()}; Path=/; Max-Age=${SEEN_MAX_AGE_SECONDS}`,
  );
  return new Response(body, { status: 200, headers });
}

async function login(request: Request): Promise<Response> {
  if (!sameOrigin(request)) return crossSite(request);
  const form = new URLSearchParams(await request.text());
  const name = form.get('name')?.trim() ?? '';
  if (name === '') return text(400, 'A name is required\n');
  return seeOther('/', [`${SESSION_COOKIE}=${encodeURIComponent(name)}; Path=/; HttpOnly`]);
}

function logout(request: Request): Response {
  if (!sameOrigin(request)) return crossSite(request);
  return seeOther('/', [`${SESSION_COOKIE}=; Path=/; Max-Age=0`]);
}

/** Everything about a request, as JSON, for a test to read back. */
async function echo(request: Request, url: URL): Promise<Response> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, name) => {
    headers[name] = value;
  });
  return new Response(
    JSON.stringify(
      {
        method: request.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        headers,
        cookies: parseCookies(request.headers.get('cookie')),
        body: await request.text(),
      },
      null,
      2,
    ),
    { status: 200, headers: { 'content-type': JSON_TYPE, 'cache-control': 'no-store' } },
  );
}

/** Answer one request. Exported so the site can be tested without a socket. */
export async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  switch (url.pathname) {
    case '/':
      return method === 'GET' || method === 'HEAD' ? home(request) : text(405, 'GET only\n');
    case '/login':
      return method === 'POST' ? login(request) : text(405, 'POST only\n');
    case '/logout':
      return method === 'POST' ? logout(request) : text(405, 'POST only\n');
    case '/echo':
      return echo(request, url);
    default:
      return text(404, `Nothing at ${url.pathname}\n`);
  }
}

if (import.meta.main) {
  const port = Number(process.env.PORT ?? 8000);
  // Loopback only: tor in the same container forwards the onion's port 80
  // here, and nothing else is meant to reach it.
  const server = Bun.serve({ hostname: '127.0.0.1', port, fetch: handle });
  console.log(`sample site on http://127.0.0.1:${server.port}/`);
}
