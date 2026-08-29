// Whether this page's own `fetch` reaches `.onion` addresses — true in Tor
// Browser and Onion Browser, where every request the browser makes goes
// through a Tor. Nothing about the browser advertises that, so it is checked
// the only honest way: by trying.
//
// Elsewhere the probe fails fast — Firefox refuses to resolve `.onion` at
// all, and everywhere else the DNS lookup is an NXDOMAIN. The request is
// opaque (`no-cors`), so all it learns is whether a connection happened. A
// probe can also fail where a send would have worked (a slow first
// rendezvous, a browser that hides the failure mode), so the answer is a
// default for the page, not a verdict.

/** torproject.org's own onion address. */
const PROBE_URL =
  'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/';

/** A rendezvous normally takes a few seconds; on a phone, sometimes more. */
const PROBE_TIMEOUT_MS = 60_000;

export type Probe =
  | { reachable: true; seconds: number }
  | { reachable: false; reason: string };

export async function browserReachesOnion(): Promise<Probe> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  const started = performance.now();
  try {
    await fetch(PROBE_URL, {
      mode: 'no-cors',
      cache: 'no-store',
      signal: controller.signal,
    });
    return {
      reachable: true,
      seconds: Number(((performance.now() - started) / 1000).toFixed(1)),
    };
  } catch (error) {
    return {
      reachable: false,
      reason: controller.signal.aborted
        ? `no answer within ${PROBE_TIMEOUT_MS / 1000}s`
        : error instanceof Error
          ? error.message
          : String(error),
    };
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
