// Fetching the documents a seed is made of from a directory authority.
//
// Authorities answer on their DirPort with bare HTTP/1.0, which `fetch`
// refuses to frame, so this talks to them with the raw HTTP client. A `.z`
// suffix asks for the zlib-compressed form of any document.

import http from 'node:http';
import zlib from 'node:zlib';
import {
  assembleSeed,
  certificatesPath,
  CONSENSUS_PATH,
  CONSENSUS_THRESHOLD,
  countCertificates,
  countMicrodescriptors,
  microdescriptorPaths,
  summarizeConsensus,
  type Seed,
} from './seed.ts';

/** Directory authorities that serve their DirPort over plain HTTP, tried in order. */
export const DEFAULT_AUTHORITIES: readonly string[] = [
  'http://45.66.35.11:80', // dizum
  'http://204.13.164.118:80', // bastet
  'http://131.188.40.189:80', // gabelmoo
  'http://199.58.81.140:80', // longclaw
  'http://171.25.193.9:443', // maatuska (plain HTTP on 443)
];

const REQUEST_TIMEOUT_MS = 60_000;
/** Microdescriptor batches in flight at once. */
const PARALLEL_REQUESTS = 4;
/**
 * Relays leave the network between the consensus and this fetch, so a few
 * missing microdescriptors are normal; a shortfall past this is a broken
 * authority or a truncated transfer.
 */
const MIN_MICRODESCRIPTOR_FRACTION = 0.9;

export type Log = (line: string) => void;

/** The authorities to fetch from, sharing a few kept connections. */
export class Authorities {
  private readonly agent = new http.Agent({ keepAlive: true, maxSockets: PARALLEL_REQUESTS });
  private readonly urls: readonly string[];

  constructor(urls: readonly string[]) {
    this.urls = urls;
    if (urls.length === 0) throw new Error('at least one directory authority URL is needed');
  }

  /** GET `path` from the first authority that serves it, inflated when `path` asked for the compressed form. */
  async get(path: string): Promise<string> {
    const failures: string[] = [];
    for (const authority of this.urls) {
      try {
        const body = await this.getFrom(authority, path);
        const bytes = path.endsWith('.z') ? zlib.inflateSync(body) : body;
        return bytes.toString('utf8');
      } catch (error: unknown) {
        failures.push(`${authority}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    throw new Error(`no directory authority served ${path}\n  ${failures.join('\n  ')}`);
  }

  private getFrom(authority: string, path: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const request = http.get(
        `${authority}${path}`,
        {
          agent: this.agent,
          timeout: REQUEST_TIMEOUT_MS,
          headers: { 'user-agent': 'webtor-directory-server-ts' },
        },
        (response) => {
          if (response.statusCode !== 200) {
            response.resume();
            reject(new Error(`HTTP ${response.statusCode}`));
            return;
          }
          const chunks: Buffer[] = [];
          response.on('data', (chunk: Buffer) => chunks.push(chunk));
          response.on('end', () => resolve(Buffer.concat(chunks)));
          response.on('error', reject);
        },
      );
      request.on('timeout', () => request.destroy(new Error('request timed out')));
      request.on('error', reject);
    });
  }

  /** Fetch the current consensus, its certificates and every microdescriptor it names, and assemble the seed. */
  async buildSeed(log: Log = () => {}): Promise<Seed> {
    log('Fetching the current microdesc consensus');
    const consensus = await this.get(`${CONSENSUS_PATH}.z`);
    const summary = summarizeConsensus(consensus);
    log(
      `Consensus of ${summary.relays} relays, valid ${summary.validAfter.toISOString()} to ${summary.validUntil.toISOString()}, signed by ${summary.signers.length} known authorities`,
    );

    const certificates = await this.get(`${certificatesPath(summary.signers)}.z`);
    const certificateCount = countCertificates(certificates);
    if (certificateCount < CONSENSUS_THRESHOLD) {
      throw new Error(
        `received ${certificateCount} authority certificates; the client needs ${CONSENSUS_THRESHOLD}`,
      );
    }

    const paths = microdescriptorPaths(summary.digests);
    log(`Fetching ${summary.digests.length} microdescriptors in ${paths.length} batches`);
    const microdescriptors = await this.fetchAll(paths, log);
    const received = countMicrodescriptors(microdescriptors);
    log(`Received ${received} of ${summary.digests.length} microdescriptors`);
    if (received < summary.digests.length * MIN_MICRODESCRIPTOR_FRACTION) {
      throw new Error(
        `only ${received} of ${summary.digests.length} microdescriptors came back, too few for a seed`,
      );
    }

    return assembleSeed(consensus, summary, certificates, microdescriptors);
  }

  /**
   * The documents at `paths`, concatenated in order, a few requests at a time.
   * A batch no authority serves is left out rather than failing the fetch:
   * whether the shortfall is acceptable is `buildSeed`'s floor to judge.
   */
  private async fetchAll(paths: string[], log: Log): Promise<string> {
    const bodies: string[] = new Array(paths.length).fill('');
    let next = 0;
    let done = 0;
    const worker = async () => {
      while (next < paths.length) {
        const index = next++;
        try {
          bodies[index] = withTrailingNewline(await this.get(`${paths[index]}.z`));
        } catch (error: unknown) {
          log(
            `Microdescriptor batch ${index + 1}/${paths.length} failed: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
        done++;
        if (done % 20 === 0 || done === paths.length) {
          log(`Fetched microdescriptor batch ${done}/${paths.length}`);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(PARALLEL_REQUESTS, paths.length) }, worker));
    return bodies.join('');
  }
}

/**
 * Documents are concatenated, and each is line-based, so a body that does
 * not end its last line would glue it to the next document's first.
 */
function withTrailingNewline(body: string): string {
  return body === '' || body.endsWith('\n') ? body : `${body}\n`;
}
