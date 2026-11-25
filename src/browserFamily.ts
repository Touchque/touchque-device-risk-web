// src/browserFamily.ts
// Coarse labels of the browser from its user agent: the OS family and the
// browser family with its major version. deviceRisk.ts puts them in every
// report (and re-exports them); agentMarks.ts asks whether the browser is a
// Chromium one. In a file of their own so the two never import each other.

export function osFamily(ua: string, platform: string): string {
  if (/CrOS/.test(ua)) return 'ChromeOS';
  if (/Android/i.test(ua)) return 'Android';
  if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && /Mobile\//.test(ua))) return 'iOS';
  if (/Windows/.test(ua) || /^Win/.test(platform)) return 'Windows';
  if (/Mac OS X|Macintosh/.test(ua) || /^Mac/.test(platform)) return 'macOS';
  if (/Linux|X11/.test(ua) || /Linux/.test(platform)) return 'Linux';
  return 'Other';
}

export function browserFamily(ua: string): { br: string; bv: number } {
  const v = (re: RegExp) => { const m = re.exec(ua); return m ? Number(m[1]) || 0 : 0; };
  if (/Edg(e|A|iOS)?\//.test(ua)) return { br: 'Edge', bv: v(/Edg(?:e|A|iOS)?\/(\d+)/) };
  if (/OPR\/|Opera/.test(ua)) return { br: 'Opera', bv: v(/OPR\/(\d+)/) };
  if (/SamsungBrowser\//.test(ua)) return { br: 'Samsung', bv: v(/SamsungBrowser\/(\d+)/) };
  if (/Firefox\/|FxiOS\//.test(ua)) return { br: 'Firefox', bv: v(/(?:Firefox|FxiOS)\/(\d+)/) };
  if (/Chrome\/|CriOS\//.test(ua)) return { br: 'Chrome', bv: v(/(?:Chrome|CriOS)\/(\d+)/) };
  if (/Safari\//.test(ua) && /Version\//.test(ua)) return { br: 'Safari', bv: v(/Version\/(\d+)/) };
  return { br: 'Other', bv: 0 };
}

/** The browser families built on Chromium (Blink and V8), by browserFamily's names. */
export const CHROMIUM_FAMILIES: readonly string[] = ['Chrome', 'Edge', 'Opera', 'Samsung'];
