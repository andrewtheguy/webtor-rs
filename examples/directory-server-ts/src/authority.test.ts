import { describe, expect, it } from 'bun:test';
import { Authorities } from './authority.ts';
import { CERTIFICATES, consensus } from './fixtures.ts';
import { DIGESTS_PER_REQUEST } from './seed.ts';

/**
 * Authorities that answer from a table instead of the network: the consensus
 * and certificates always, and each microdescriptor batch as `batches` says.
 */
function fake(relays: number, batches: (index: number) => string | Error) {
  const authorities = new Authorities(['http://authority.test']);
  const asked: string[] = [];
  let batch = 0;
  authorities.get = async (path: string) => {
    asked.push(path);
    if (path.startsWith('/tor/status-vote/')) return consensus(relays, 5);
    if (path.startsWith('/tor/keys/')) return CERTIFICATES;
    const answer = batches(batch++);
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { authorities, asked };
}

/** A batch of `count` microdescriptors, the last one missing its final newline. */
function batch(count: number): string {
  return Array.from({ length: count }, () => 'onion-key\nid ed25519 x').join('\n');
}

describe('building a seed', () => {
  it('survives a batch no authority serves when most microdescriptors arrived', async () => {
    const relays = DIGESTS_PER_REQUEST * 2 + 20;
    const logged: string[] = [];
    const { authorities, asked } = fake(relays, (index) =>
      index === 2 ? new Error('no directory authority served it') : batch(DIGESTS_PER_REQUEST),
    );
    const seed = await authorities.buildSeed((line) => logged.push(line));
    expect(asked.filter((path) => path.startsWith('/tor/micro/d/'))).toHaveLength(3);
    expect(logged.some((line) => line.startsWith('Microdescriptor batch 3/3 failed'))).toBe(true);
    expect(seed.relays).toBe(relays);
    // Each body was made to end its last line, so the documents stay apart.
    const { microdescriptors } = JSON.parse(seed.encoded) as { microdescriptors: string };
    expect(microdescriptors.match(/^onion-key$/gm)).toHaveLength(DIGESTS_PER_REQUEST * 2);
    expect(microdescriptors.includes('xonion-key')).toBe(false);
  });

  it('refuses a seed when too many microdescriptors are missing', async () => {
    const { authorities } = fake(DIGESTS_PER_REQUEST * 2, (index) =>
      index === 1 ? new Error('no directory authority served it') : batch(DIGESTS_PER_REQUEST),
    );
    await expect(authorities.buildSeed()).rejects.toThrow('too few for a seed');
  });
});
