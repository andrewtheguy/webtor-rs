// Whether this page's own `fetch` reaches `.onion` addresses — true in Tor
// Browser, where every request the browser makes goes through its bundled
// Tor. Nothing about the browser advertises that, so it is checked the only
// honest way: by trying.
//
// Outside Tor Browser the probe fails fast — Firefox refuses to resolve
// `.onion` at all, and everywhere else the DNS lookup is an NXDOMAIN. The
// request is opaque (`no-cors`), so all it learns is whether a connection
// happened.

/** torproject.org's own onion address. */
const PROBE_URL =
  'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/';

/** A rendezvous through Tor Browser normally takes a few seconds. */
const PROBE_TIMEOUT_MS = 30_000;

export async function browserReachesOnion(): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    await fetch(PROBE_URL, {
      mode: 'no-cors',
      cache: 'no-store',
      signal: controller.signal,
    });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Request an onion address with the browser's own network stack, i.e.
 * through Tor Browser's Tor rather than this tab's client. The service must
 * allow cross-origin reads, or the browser hides the response.
 */
export async function browserFetch(
  url: string,
  timeoutMs: number,
  init: RequestInit = {},
): Promise<{ status: number; text: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...init,
      cache: 'no-store',
      signal: controller.signal,
    });
    return { status: response.status, text: await response.text() };
  } finally {
    clearTimeout(timer);
  }
}
