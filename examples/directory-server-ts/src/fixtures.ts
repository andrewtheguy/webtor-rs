// Test fixtures: a consensus shaped like a real one, small enough to read.

/** A consensus of `relays` relays, every one Fast, Stable, V2Dir and an HSDir, signed by `signers` known authorities. */
export function consensus(relays: number, signers: number, extra = ''): string {
  const header = [
    'network-status-version 3 microdesc',
    'vote-status consensus',
    'valid-after 2026-09-04 18:00:00',
    'fresh-until 2026-09-04 19:00:00',
    'valid-until 2026-09-04 21:00:00',
  ];
  const entries = Array.from({ length: relays }, (_, index) => [
    `r relay${index} AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-09-04 12:00:00 10.0.0.${index % 256} 9001 0`,
    `m ${digest(index)}`,
    's Fast HSDir Running Stable V2Dir Valid',
    'w Bandwidth=1000',
  ]).flat();
  const known = [
    ['E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58', 'AAAA'],
    ['27102BC123E7AF1D4741AE047E160C91ADC76B21', 'BBBB'],
    ['ED03BB616EB2F60BEC80151114BB25CEF515B226', 'CCCC'],
    ['23D15D965BC35114467363C165C4F724B64B4F66', 'DDDD'],
    ['49015F787433103580E3B66A1707A00E60F2D15B', 'EEEE'],
    ['F533C81CEF0BC0267857C99B2F471ADF249FA232', 'FFFF'],
  ].slice(0, signers);
  const footer = [
    'directory-footer',
    ...known.map(([id, sk]) => `directory-signature sha256 ${id} ${sk}\n-----BEGIN SIGNATURE-----\nxx\n-----END SIGNATURE-----`),
    'directory-signature 0000000000000000000000000000000000000000 1111\n-----BEGIN SIGNATURE-----\nxx\n-----END SIGNATURE-----',
  ];
  return [...header, ...entries, extra, ...footer].join('\n') + '\n';
}

/** A distinct 43-character base64 digest per relay. */
export function digest(index: number): string {
  return String(index).padStart(43, 'A');
}

/** Certificates enough for the client's threshold, in shape only. */
export const CERTIFICATES = Array.from({ length: 5 }, () => 'dir-key-certificate-version 3\nx\n').join('');
