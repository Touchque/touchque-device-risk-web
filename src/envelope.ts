/**
 * The report, encrypted so only Touchque can read it: the page, its other
 * scripts, extensions and the visitor see an opaque string, and a changed byte
 * makes it unreadable.
 *
 *   tqe1.<kid>.<epk>.<iv>.<ct>     (base64url parts)
 *
 * A one-time P-256 key pair, ECDH with Touchque's report key (REPORT_KEY, its
 * public half), HKDF-SHA256 (salt: the one-time public key, info
 * "touchque-device-report:v1") gives an AES-256-GCM key; the additional data
 * is "tqe1.<kid>". Without WebCrypto (an http page) the report goes as it is.
 *
 * It hides what the tag collects and keeps it from being edited on the way; a
 * person who controls the browser can still change values before they are
 * encrypted (the key is public by nature): the server's consistency checks and
 * its own signals are there for that.
 */
import { REPORT_KEY, type ReportKey } from './reportKey';

const PREFIX = 'tqe1';
const INFO = new TextEncoder().encode('touchque-device-report:v1');

function b64url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The envelope of `json` for Touchque's key, or null without WebCrypto. */
export async function sealReport(json: string, key: ReportKey = REPORT_KEY, subtle: SubtleCrypto | undefined = globalThis.crypto?.subtle): Promise<string | null> {
  if (!subtle || !key) return null;
  try {
    const peer = await subtle.importKey('jwk', { ...key.jwk, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const mine = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
    const epk = new Uint8Array(await subtle.exportKey('raw', mine.publicKey));
    const shared = await subtle.deriveBits({ name: 'ECDH', public: peer }, mine.privateKey, 256);
    const hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const aes = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: epk, info: INFO }, hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const iv = new Uint8Array(12);
    globalThis.crypto.getRandomValues(iv);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`${PREFIX}.${key.kid}`) }, aes, new TextEncoder().encode(json),
    ));
    return [PREFIX, key.kid, b64url(epk), b64url(iv), b64url(ct)].join('.');
  } catch {
    return null;
  }
}
