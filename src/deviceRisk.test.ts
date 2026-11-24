import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { createHash, verify, webcrypto } from 'node:crypto';
import { createBrowserKey, deviceSealMessage, type BrowserKeyStore } from './browserKey';
import {
  buildDeviceRiskReport, createDeviceRisk, osFamily, browserFamily, tamperFindings, vmFindings, automationFindings, consistencyFindings, jsEngine,
  type DeviceRiskBody, type DeviceRiskReport,
} from './deviceRisk';
import { sealReport } from './envelope';
import { REPORT_KEY } from './reportKey';

const ORIGIN = 'https://app.example.com';

function memoryStore(): BrowserKeyStore {
  let pair: CryptoKeyPair | undefined;
  return {
    async load() { return pair; },
    async save(p) { if (!pair) pair = p; return pair; },
    async remove() { pair = undefined; },
  };
}

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() { return data.size; },
    clear: () => data.clear(),
    getItem: (k: string) => (data.has(k) ? data.get(k)! : null),
    key: (i: number) => Array.from(data.keys())[i] ?? null,
    removeItem: (k: string) => { data.delete(k); },
    setItem: (k: string, v: string) => { data.set(k, String(v)); },
  } as Storage;
}

const nodeKey = () => createBrowserKey({ store: memoryStore(), crypto: webcrypto as unknown as Crypto, origin: ORIGIN });
const bodyOf = (r: DeviceRiskReport) => JSON.parse(r.body) as DeviceRiskBody;

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal('localStorage', memoryStorage());
  Object.defineProperty(window, 'localStorage', { value: globalThis.localStorage, configurable: true });
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null as never);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('deviceRisk report', () => {
  test('carries the purpose, origin, a fresh nonce, the stored id and coarse traits', async () => {
    const a = bodyOf(await buildDeviceRiskReport({ purpose: 'sign_up', browserKey: null }));
    const b = bodyOf(await buildDeviceRiskReport({ purpose: 'sign_up', browserKey: null }));
    expect(a.v).toBe(1);
    expect(a.p).toBe('sign_up');
    expect(a.aud).toBe(window.location.origin);
    expect(a.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(b.nonce).not.toBe(a.nonce);
    expect(a.sid).toMatch(/^tq2_[0-9a-f]{32}$/);
    expect(b.sid).toBe(a.sid);
    expect(a.t.scr).toMatch(/^\d+x\d+$/);
    expect(typeof a.t.tz).toBe('string');
    expect(a.t.lang.length).toBeLessThanOrEqual(3);
    expect(a.t.mt).toMatch(/^[0-9a-f]{16}$/);
    // jsdom draws nothing: those parts are null, never an error.
    expect(a.t.cv).toBeNull();
    expect(a.t.gpu).toBeNull();
  });

  test('an unknown purpose is sent as sign_in', async () => {
    const r = await buildDeviceRiskReport({ purpose: 'tracking' as never, browserKey: null });
    expect(bodyOf(r).p).toBe('sign_in');
  });

  test('sealed with the browser key over the exact body text, verifiable with Node crypto', async () => {
    const r = await buildDeviceRiskReport({ purpose: 'sign_in', browserKey: nodeKey() });
    expect(r.seal).toBeDefined();
    const digest = createHash('sha256').update(r.body, 'utf8').digest('base64url');
    const s = r.seal!;
    expect(s.aud).toBe(ORIGIN);
    const ok = verify('sha256', Buffer.from(deviceSealMessage(s.aud, s.iat, s.nonce, digest), 'utf8'),
      { key: s.jwk as unknown as webcrypto.JsonWebKey, format: 'jwk', dsaEncoding: 'ieee-p1363' }, Buffer.from(s.sig, 'base64url'));
    expect(ok).toBe(true);
    // The seal message is not a browser proof's message.
    expect(deviceSealMessage('a', 1, 'n', 'd').startsWith('touchque-device:v1\n')).toBe(true);
  });

  test('unsealed without a key, and with a custom key that cannot seal', async () => {
    expect((await buildDeviceRiskReport({ purpose: 'sign_in', browserKey: null })).seal).toBeUndefined();
    const custom = { proof: async () => null, thumbprint: async () => null, forget: async () => { } };
    expect((await buildDeviceRiskReport({ purpose: 'sign_in', browserKey: custom })).seal).toBeUndefined();
  });

  test('collect encodes base64url JSON under the size limit and never throws', async () => {
    const encoded = await createDeviceRisk().collect({ purpose: 'password_reset', browserKey: null, encrypt: false });
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded.length).toBeLessThanOrEqual(6144);
    const report = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as DeviceRiskReport;
    expect(bodyOf(report).p).toBe('password_reset');
  });
});

/** jsdom's own functions are JavaScript: the ones there before a test patched anything stand in for native code. */
function jsdomNatives(): (fn: unknown) => boolean {
  const own = new Set<unknown>([Function.prototype.toString]);
  for (const proto of [Navigator.prototype, Screen.prototype, HTMLCanvasElement.prototype, Intl.DateTimeFormat.prototype, Date.prototype]) {
    for (const d of Object.values(Object.getOwnPropertyDescriptors(proto))) { own.add(d.get); own.add(d.value); }
  }
  return (fn) => typeof fn !== 'function' || own.has(fn);
}

describe('findings', () => {
  test('a clean page has no tampering', () => {
    expect(tamperFindings(window, jsdomNatives())).toEqual([]);
  });

  test('with the real native check, jsdom (JavaScript, not a browser) looks patched', () => {
    expect(tamperFindings(window)).toContain('nav_user_agent');
  });

  test('a getter replaced on the prototype and a property defined on the instance', () => {
    const natives = jsdomNatives();
    const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent')!;
    Object.defineProperty(Navigator.prototype, 'userAgent', { get: function userAgent() { return 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0'; }, configurable: true });
    Object.defineProperty(navigator, 'platform', { value: 'Win32', configurable: true });
    try {
      const found = tamperFindings(window, natives);
      expect(found).toContain('nav_user_agent');
      expect(found).toContain('nav_own_property');
    } finally {
      Object.defineProperty(Navigator.prototype, 'userAgent', d);
      delete (navigator as unknown as Record<string, unknown>).platform;
    }
  });

  test('a User-Agent that names another OS than the platform', () => {
    vi.spyOn(navigator, 'platform', 'get').mockReturnValue('MacIntel');
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0');
    expect(tamperFindings(window, () => true)).toContain('ua_platform_mismatch');
  });

  test('software and virtual graphics, webdriver', () => {
    expect(vmFindings(window, 'Google Inc. (Google)|ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)')).toContain('soft_gpu');
    expect(vmFindings(window, 'VMware, Inc.|SVGA3D; build: RELEASE; LLVM;')).toContain('vm_gpu');
    expect(vmFindings(window, 'Apple|Apple M2')).not.toContain('vm_gpu');
    Object.defineProperty(navigator, 'webdriver', { value: true, configurable: true });
    try {
      expect(vmFindings(window, null)).toContain('webdriver');
    } finally {
      delete (navigator as unknown as Record<string, unknown>).webdriver;
    }
  });
});

describe('coarse labels', () => {
  test('OS and browser families with the major version', () => {
    const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15';
    expect(osFamily(mac, 'MacIntel')).toBe('macOS');
    expect(browserFamily(mac)).toEqual({ br: 'Safari', bv: 18 });
    const edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0';
    expect(osFamily(edge, 'Win32')).toBe('Windows');
    expect(browserFamily(edge)).toEqual({ br: 'Edge', bv: 130 });
    expect(osFamily('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)', 'iPhone')).toBe('iOS');
    expect(osFamily('Mozilla/5.0 (Linux; Android 14; Pixel 8)', 'Linux armv8l')).toBe('Android');
  });
});

describe('deviceRisk.identify', () => {
  const SITE_KEY = `tqpk_${'a'.repeat(32)}`;

  test('posts the report with the site key as text/plain and returns the identification', async () => {
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ visitorId: 'tqv_x', requestId: 'dre_y', confidence: 0.99 }) }) as never);
    const out = await createDeviceRisk().identify({ siteKey: SITE_KEY, purpose: 'sign_up', browserKey: null, apiBaseUrl: 'https://api.example.com/', fetch: fetchMock as unknown as typeof fetch });
    expect(out).toEqual({ visitorId: 'tqv_x', requestId: 'dre_y', confidence: 0.99 });
    const [url, init] = (fetchMock.mock.calls[0] as unknown) as [string, RequestInit];
    expect(url).toBe('https://api.example.com/device-risk/identify');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('text/plain');
    const sent = JSON.parse(init.body as string);
    expect(sent.siteKey).toBe(SITE_KEY);
    // Encrypted for Touchque: an opaque envelope naming Touchque's key.
    expect(sent.report).toMatch(new RegExp(`^tqe1\\.${REPORT_KEY.kid}\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{16}\\.[A-Za-z0-9_-]+$`));
    expect(sent.report).not.toContain('sign_up');
  });

  test('the envelope opens with the private half only, to the report; a changed byte does not', async () => {
    const pair = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
    const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    const key = { kid: 'testkey1', jwk: { kty: 'EC' as const, crv: 'P-256' as const, x: jwk.x!, y: jwk.y! } };
    const json = JSON.stringify({ v: 1, body: '{"v":1,"p":"sign_in"}' });
    const sealed = (await sealReport(json, key))!;
    const [, kid, epkB, ivB, ctB] = sealed.split('.');
    expect(kid).toBe('testkey1');
    const open = async (ct: Uint8Array) => {
      const epk = Buffer.from(epkB, 'base64url');
      const peer = await webcrypto.subtle.importKey('raw', epk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const bits = await webcrypto.subtle.deriveBits({ name: 'ECDH', public: peer }, pair.privateKey, 256);
      const hkdf = await webcrypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
      const aes = await webcrypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: epk, info: new TextEncoder().encode('touchque-device-report:v1') }, hkdf, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      return new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(ivB, 'base64url'), additionalData: new TextEncoder().encode('tqe1.testkey1') }, aes, ct));
    };
    const ct = new Uint8Array(Buffer.from(ctB, 'base64url'));
    expect(await open(ct)).toBe(json);
    ct[0] ^= 1;
    await expect(open(ct)).rejects.toThrow();
  });

  test('a refusal or a network error resolves null; a bad site key throws at once', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => { });
    const refused = vi.fn(async () => ({ ok: false, status: 403, json: async () => ({ code: 'origin_not_allowed' }) }) as never);
    expect(await createDeviceRisk().identify({ siteKey: SITE_KEY, purpose: 'sign_in', browserKey: null, fetch: refused as unknown as typeof fetch })).toBeNull();
    const down = vi.fn(async () => { throw new TypeError('Failed to fetch'); });
    expect(await createDeviceRisk().identify({ siteKey: SITE_KEY, purpose: 'sign_in', browserKey: null, fetch: down as unknown as typeof fetch })).toBeNull();
    await expect(createDeviceRisk().identify({ siteKey: 'pk_live', purpose: 'sign_in' })).rejects.toThrow(/siteKey/);
  });
});

describe('automation tools on the page (2.3.0)', () => {
  const clean = () => {
    for (const k of ['cdc_adoQpoasnfa76pfcZLmcfl_Array', '__playwright__binding__', 'callPhantom', '__nightmare']) delete (window as unknown as Record<string, unknown>)[k];
    document.documentElement.removeAttribute('webdriver');
  };
  afterEach(clean);

  test('names the tool whose marks are there, and nothing on a plain page', () => {
    expect(automationFindings(window).filter((c) => c !== 'cdp')).toEqual([]);
    const w = window as unknown as Record<string, unknown>;
    w.cdc_adoQpoasnfa76pfcZLmcfl_Array = [];
    w.__playwright__binding__ = () => {};
    w.callPhantom = () => {};
    w.__nightmare = {};
    expect(automationFindings(window).filter((c) => c !== 'cdp')).toEqual(['nightmare', 'phantomjs', 'playwright', 'selenium']);
  });

  test('the report carries them in s.auto', async () => {
    (window as unknown as Record<string, unknown>).__playwright__binding__ = () => {};
    const r = await buildDeviceRiskReport({ purpose: 'sign_in', browserKey: null });
    expect(JSON.parse(r.body).s.auto).toContain('playwright');
  });
});

describe('traits that cannot all be true (anti-detect browsers, emulators, phones that are desktops)', () => {
  const IPHONE = { os: 'iOS', br: 'Safari', pf: 'iPhone', scr: '852x393', dpr: 3, tp: 5, gpu: 'Apple Inc.|Apple GPU' };
  const ANDROID = { os: 'Android', br: 'Chrome', pf: 'Linux armv81', scr: '915x412', dpr: 2.625, tp: 5, gpu: 'ARM|Mali-G68' };
  const WINDOWS = { os: 'Windows', br: 'Chrome', pf: 'Win32', scr: '1920x1080', dpr: 1, tp: 0, gpu: 'Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)' };
  const touch = { matchMedia: (q: string) => ({ matches: q.includes('coarse') }) } as unknown as Window;
  const mouse = { matchMedia: (q: string) => ({ matches: q.includes('fine') }) } as unknown as Window;

  test('the page knows its own engine (node runs V8)', () => {
    expect(jsEngine()).toBe('v8');
  });

  test('a real iPhone, Android phone and Windows PC say nothing', () => {
    expect(consistencyFindings(touch, IPHONE, ['Helvetica Neue', 'Apple Color Emoji', 'Menlo'], 'jsc')).toEqual([]);
    expect(consistencyFindings(touch, ANDROID, ['Roboto', 'Noto Sans'], 'v8')).toEqual([]);
    expect(consistencyFindings(mouse, WINDOWS, ['Arial', 'Segoe UI', 'Calibri', 'Consolas'], 'v8')).toEqual([]);
  });

  test('an "iPhone" run by Chrome on a desktop (device mode, an anti-detect profile)', () => {
    const fake = { ...IPHONE, gpu: 'Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)', tp: 0, scr: '1920x1080', dpr: 1 };
    expect(consistencyFindings(mouse, fake, ['Segoe UI'], 'v8')).toEqual(['fonts_os_mismatch', 'gpu_os_mismatch', 'mobile_desktop_mismatch', 'ua_engine_mismatch']);
  });

  test('an Android emulator or a desktop posing as Android', () => {
    expect(consistencyFindings(touch, { ...ANDROID, gpu: 'NVIDIA Corporation|NVIDIA GeForce GTX 1660/PCIe/SSE2' }, null, 'v8')).toContain('gpu_os_mismatch');
    expect(consistencyFindings(mouse, { ...ANDROID, tp: 0 }, null, 'v8')).toContain('mobile_desktop_mismatch');
    expect(vmFindings(window, 'Google (Intel)|Android Emulator OpenGL ES Translator (Intel(R) UHD Graphics)')).toContain('emulator');
  });

  test('Windows on Snapdragon shows Adreno and is still Windows; an iPad on the desktop site is still a Mac with touch', () => {
    expect(consistencyFindings(mouse, { ...WINDOWS, gpu: 'Google Inc. (Qualcomm)|ANGLE (Qualcomm, Qualcomm(R) Adreno(TM) X1-85 GPU Direct3D11 vs_5_0 ps_5_0, D3D11)' }, null, 'v8')).toEqual([]);
    expect(consistencyFindings(touch, { os: 'macOS', br: 'Safari', pf: 'MacIntel', scr: '1180x820', dpr: 2, tp: 5, gpu: 'Apple Inc.|Apple GPU' }, null, 'jsc')).toEqual([]);
  });

  test('Firefox that is not Gecko, Safari that is not WebKit, Mac fonts on "Windows"', () => {
    expect(consistencyFindings(mouse, { ...WINDOWS, br: 'Firefox' }, null, 'v8')).toContain('ua_engine_mismatch');
    expect(consistencyFindings(mouse, { ...WINDOWS, os: 'macOS', br: 'Safari', gpu: 'Apple Inc.|Apple M2' }, null, 'v8')).toContain('ua_engine_mismatch');
    expect(consistencyFindings(mouse, WINDOWS, ['Apple Color Emoji', 'Menlo', 'Arial'], 'v8')).toContain('fonts_os_mismatch');
  });

  test('real-tool gaps of 2026-11-24: an iPhone user agent on a Mac\'s Chrome (device mode) is caught three ways', () => {
    const deviceMode = { ...IPHONE, pf: 'MacIntel', gpu: 'Google Inc. (Apple)|ANGLE (Apple, ANGLE Metal Renderer: Apple M5, Unspecified Version)', scr: '852x393', dpr: 3 };
    expect(consistencyFindings(touch, deviceMode, null, 'v8')).toEqual(['gpu_os_mismatch', 'ua_engine_mismatch', 'ua_platform_mismatch']);
    expect(consistencyFindings(touch, { ...IPHONE, pf: 'iPad', scr: '1180x820', dpr: 2 }, null, 'jsc')).toEqual([]);
  });

  test('headless Chrome with the automation flag hidden: its 800x600 frameless window', () => {
    const win = { navigator: { userAgent: 'Mozilla/5.0 (Macintosh)', maxTouchPoints: 0, hardwareConcurrency: 8 }, screen: { width: 800, height: 600 }, outerWidth: 800, outerHeight: 600, innerWidth: 800, innerHeight: 600 } as unknown as Window;
    expect(vmFindings(win, 'Apple|Apple M5')).toContain('headless_window');
    const person = { ...win, screen: { width: 1512, height: 982 }, outerWidth: 1512, outerHeight: 944, innerWidth: 1512, innerHeight: 860 } as unknown as Window;
    expect(vmFindings(person, 'Apple|Apple M5')).not.toContain('headless_window');
  });
});
