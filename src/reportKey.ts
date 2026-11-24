/**
 * Touchque's report key: the public half only (the private half never leaves
 * Touchque's servers). `kid` names it in each envelope, so a new key can come
 * with a new tag version while Touchque still opens reports of the old one.
 */
export interface ReportKey {
  kid: string;
  jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
}

export const REPORT_KEY: ReportKey = {
  kid: '9d8a2f55',
  jwk: { kty: 'EC', crv: 'P-256', x: 'QXrbInfJL8yPadD1kbcSDFajSop7_-DoK7oTbEO5sGU', y: 'LqIO9D9uliBoFiR1kLk_1hT3eKvoFQqqkhydzFAkM5Y' },
};
