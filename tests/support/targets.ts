// The public onion services the live suite runs against.
//
// Nothing here is under our control, so every target is a list and a test
// takes the first one that answers. Relay addresses come from
// https://github.com/0xtrr/onion-service-nostr-relays, which tracks no uptime;
// docs/onion-relay-probe-2026-08-25.md records one pass over the whole list.

/** The Tor Project's own site, served as a v3 onion over plain HTTP. */
export const HTTP_TARGETS = [
  'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/',
];

/**
 * Nostr relays. They answer a plain `GET /` with NIP-11 JSON when asked for
 * `application/nostr+json`, which is what makes them useful twice: once as an
 * HTTP endpoint with a caller-set header, once as a WebSocket endpoint.
 */
export const RELAYS = [
  'oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion',
  'gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion',
  'nerostrrgb5fhj6dnzhjbgmnkpy2berdlczh6tuh2jsqrjok3j4zoxid.onion',
  'nostrwinemdptvqukjttinajfeedhf46hfd5bz2aj2q5uwp7zros3nad.onion',
];

export const WS_TARGETS = RELAYS.map((host) => `ws://${host}`);
export const NIP11_TARGETS = RELAYS.map((host) => `http://${host}/`);

/**
 * How long one candidate gets before the next is tried. Well under the
 * client's own default: a case that walks four dead relays at 240 s each
 * spends sixteen minutes proving what the first two minutes already showed.
 */
export const ATTEMPT_TIMEOUT_MS = 90_000;

/**
 * Try `attempt` against each candidate and return the first success.
 *
 * A single dead onion should not fail a run, but every candidate failing
 * should — and the error then carries what each one said, since "the client is
 * broken" and "these four services are down" look identical from one failure.
 */
export async function firstReachable<Result>(
  candidates: string[],
  attempt: (candidate: string) => Promise<Result>,
): Promise<{ target: string; result: Result }> {
  const failures: string[] = [];
  for (const candidate of candidates) {
    const started = Date.now();
    try {
      const result = await attempt(candidate);
      return { target: candidate, result };
    } catch (error: unknown) {
      const seconds = ((Date.now() - started) / 1000).toFixed(1);
      const message = error instanceof Error ? error.message : String(error);
      console.log(`  ✗ ${candidate} after ${seconds}s: ${message}`);
      failures.push(`${candidate}: ${message}`);
    }
  }
  throw new Error(`No candidate answered:\n  ${failures.join('\n  ')}`);
}
