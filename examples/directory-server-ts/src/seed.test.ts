import { describe, expect, it } from 'bun:test';
import {
  assembleSeed,
  certificatesPath,
  compactUtc,
  countCertificates,
  countMicrodescriptors,
  DIGESTS_PER_REQUEST,
  iso8601,
  microdescriptorPaths,
  summarizeConsensus,
} from './seed.ts';
import { consensus, digest } from './fixtures.ts';

describe('summarizing a consensus', () => {
  it('reads the lifetime, relays, digests and known signers', () => {
    const summary = summarizeConsensus(consensus(120, 5));
    expect(summary.validAfter.toISOString()).toBe('2026-09-04T18:00:00.000Z');
    expect(summary.freshUntil.toISOString()).toBe('2026-09-04T19:00:00.000Z');
    expect(summary.validUntil.toISOString()).toBe('2026-09-04T21:00:00.000Z');
    expect(summary.relays).toBe(120);
    expect(summary.digests).toHaveLength(120);
    expect(summary.digests[7]).toBe(digest(7));
    // The unknown authority in the footer is not one.
    expect(summary.signers).toHaveLength(5);
    expect(summary.signers[0]).toEqual({ id: 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58', sk: 'AAAA' });
  });

  it('deduplicates digests and ignores relays outside the footer', () => {
    const duplicate = consensus(120, 5).replace(`m ${digest(3)}`, `m ${digest(4)}`);
    expect(summarizeConsensus(duplicate).digests).toHaveLength(119);
  });

  it('refuses a consensus the client could never install', () => {
    expect(() => summarizeConsensus(consensus(120, 4))).toThrow('signed by 4 known authorities');
    expect(() => summarizeConsensus(consensus(50, 5))).toThrow('too few for a seed');
    expect(() => summarizeConsensus('network-status-version 3 microdesc\n')).toThrow('no valid-after line');
  });
});

describe('the documents a seed needs', () => {
  it('names the certificates by sorted lower-case fingerprint pairs', () => {
    expect(
      certificatesPath([
        { id: 'E8A9', sk: 'AAAA' },
        { id: '2710', sk: 'BBBB' },
      ]),
    ).toBe('/tor/keys/fp-sk/2710-bbbb+e8a9-aaaa');
  });

  it('batches microdescriptor digests by the URL length limit', () => {
    const digests = Array.from({ length: DIGESTS_PER_REQUEST * 2 + 1 }, (_, index) => digest(index));
    const paths = microdescriptorPaths(digests);
    expect(paths).toHaveLength(3);
    expect(paths[0]!.startsWith(`/tor/micro/d/${digest(0)}-${digest(1)}-`)).toBe(true);
    expect(paths[2]).toBe(`/tor/micro/d/${digest(DIGESTS_PER_REQUEST * 2)}`);
  });

  it('counts what came back', () => {
    expect(countCertificates('dir-key-certificate-version 3\nx\ndir-key-certificate-version 3\n')).toBe(2);
    expect(countMicrodescriptors('onion-key\nx\nonion-key\nntor-onion-key y\nonion-key\n')).toBe(3);
  });
});

describe('assembling a seed', () => {
  it('is the JSON the client installs, named by valid-after and its own hash', () => {
    const body = consensus(120, 5);
    const seed = assembleSeed(body, summarizeConsensus(body), 'certs', 'onion-key\n');
    expect(seed.name).toMatch(/^20260904T180000Z-[0-9a-f]{16}$/);
    expect(JSON.parse(seed.encoded)).toEqual({
      version: 3,
      consensus: body,
      certificates: 'certs',
      microdescriptors: 'onion-key\n',
    });
    expect(seed.encoded.startsWith('{"version":')).toBe(true);
    expect(seed.relays).toBe(120);
    expect(seed.validUntil.toISOString()).toBe('2026-09-04T21:00:00.000Z');

    const other = assembleSeed(body, summarizeConsensus(body), 'certs', 'onion-key\nonion-key\n');
    expect(other.name).not.toBe(seed.name);
  });

  it('formats times the way the manifest and file names carry them', () => {
    const at = new Date('2000-02-29T00:00:00Z');
    expect(iso8601(at)).toBe('2000-02-29T00:00:00Z');
    expect(compactUtc(at)).toBe('20000229T000000Z');
  });
});
