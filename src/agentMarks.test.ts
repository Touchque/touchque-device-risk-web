import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { addPageMark, onPageMarks, pageMarks, startAgentMarks, stopAgentMarks, trustedInputSeen } from './agentMarks';

const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Claude/7.37095.0 Chrome/156.0.8078.100 Safari/537.36';
const FIREFOX = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:145.0) Gecko/20100101 Firefox/145.0';
const NEW_CODES = ['claude_agent', 'comet_agent', 'genspark_agent', 'browser_use', 'stagehand', 'skyvern', 'puppeteer',
  'cdp_input', 'input_no_focus', 'insert_text_bulk', 'scripted_click'];

// Events as the browser hands them over (jsdom has no PointerEvent): the test's `trusted` marks them the person's.
function fire(target: EventTarget, type: string, props: Record<string, unknown> = {}) {
  const e = new Event(type, { bubbles: true });
  for (const [k, v] of Object.entries(props)) Object.defineProperty(e, k, { value: v });
  target.dispatchEvent(e);
}
const press = (props: Record<string, unknown>) => fire(document.body, 'pointerdown', { pointerType: 'mouse', button: 0, buttons: 1, ...props });
// The browser announces text it inserts (beforeinput), then inserts it; execCommand('insertText') skips the first.
const typed = (data: string, props: Record<string, unknown> = {}, announced = true) => {
  const event = { inputType: 'insertText', data, isComposing: false, ...props };
  if (announced) fire(document.body, 'beforeinput', event);
  fire(document.body, 'input', event);
};

let clock = 0;
let focused = true;
let heard: string[] = [];
let unsubscribe: () => void = () => {};
const w = window as unknown as Record<string, unknown>;

beforeEach(() => {
  vi.useFakeTimers();
  clock = 1000;
  focused = true;
  heard = [];
  document.head.innerHTML = '';
  document.body.innerHTML = '';
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(CHROME);
  vi.spyOn(document, 'hasFocus').mockImplementation(() => focused);
  stopAgentMarks(window);
  startAgentMarks(window, { trusted: () => true, now: () => clock });
  unsubscribe = onPageMarks(window, (codes) => heard.push(...codes));
});

afterEach(() => {
  unsubscribe();
  stopAgentMarks(window);
  for (const k of ['__claudeElementMap', '__claudeRefCounter', 'GlobalSkyvernFrameIndex', 'globalListnerFlag', 'globalDomDepthMap']) delete w[k];
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('AI agents on the page', () => {
  test("the Claude app's browser: its globals appear when it first reads the page, long after the load", async () => {
    await vi.advanceTimersByTimeAsync(30_000);
    expect(heard).toEqual([]);
    w.__claudeElementMap = new Map();
    w.__claudeRefCounter = 0;
    await vi.advanceTimersByTimeAsync(1000);
    expect(heard).toEqual(['claude_agent']);
    expect(pageMarks(window)).toEqual(['claude_agent']);
  });

  test('Skyvern: its frame index alone, or two of its other globals; one of those alone is a name a page may have', () => {
    w.globalDomDepthMap = new Map();
    expect(pageMarks(window)).toEqual([]);
    w.globalListnerFlag = true;
    expect(pageMarks(window)).toEqual(['skyvern']);
    stopAgentMarks(window);
    delete w.globalListnerFlag;
    delete w.globalDomDepthMap;
    w.GlobalSkyvernFrameIndex = 0;
    expect(pageMarks(window)).toEqual(['skyvern']);
  });

  test('overlays added to the page name the agent, even after they are gone again', async () => {
    const overlays: Array<[string, string]> = [
      ['<div id="claude-agent-stop-container"></div>', 'claude_agent'],
      ['<div id="pplx-agent-overlay"></div>', 'comet_agent'],
      ['<div id="genspark-float-bar"></div>', 'genspark_agent'],
      ['<div data-browser-use-interaction-highlight="true"></div>', 'browser_use'],
      ['<div id="__v3_cursor_overlay__"></div>', 'stagehand'],
      ['<skyvern-control-indicator aria-hidden="true"></skyvern-control-indicator>', 'skyvern'],
      ['<x-pw-glass></x-pw-glass>', 'playwright'],
    ];
    for (const [html, code] of overlays) {
      const holder = document.createElement('div');
      holder.innerHTML = html;
      const el = holder.firstElementChild!;
      // Browser Use's highlight and Playwright's glass pane go on <html>, the others on <body>; both are watched.
      (code === 'browser_use' || code === 'playwright' ? document.documentElement : document.body).appendChild(el);
      await vi.advanceTimersByTimeAsync(0);
      el.remove();
      expect(heard).toContain(code);
    }
    expect(pageMarks(window)).toEqual(['browser_use', 'claude_agent', 'comet_agent', 'genspark_agent', 'playwright', 'skyvern', 'stagehand']);
  });

  test("Claude in Chrome's style left in <head> after a run is not the agent; an overlay deeper than the watch is found when a report is built", async () => {
    document.head.innerHTML = '<style id="claude-agent-animation-styles"></style>';
    await vi.advanceTimersByTimeAsync(0);
    expect(heard).toEqual([]);
    expect(pageMarks(window)).toEqual([]);
    document.body.innerHTML = '<div id="claude-agent-stop-container"></div>';
    await vi.advanceTimersByTimeAsync(0);
    expect(heard).toEqual(['claude_agent']);
    stopAgentMarks(window);
    document.body.innerHTML = '';
    document.head.innerHTML = '';
    document.body.innerHTML = '<main><section><div data-browser-use-interaction-highlight="true"></div></section></main>';
    expect(pageMarks(window)).toEqual(['browser_use']);
  });

  test("a page's own element whose id starts like an agent's, inside its content, is the page's", async () => {
    const content = document.createElement('main');
    content.innerHTML = '<h2 id="claude-agent-sdk">Claude Agent SDK</h2><h2 id="pplx-agent-api">Perplexity</h2><x-pw-demo></x-pw-demo>';
    document.body.appendChild(content);
    // A password widget's own element on <body> ("pw" is the password on a sign-in page): only <html> holds Playwright's.
    document.body.appendChild(document.createElement('x-pw-meter'));
    await vi.advanceTimersByTimeAsync(1000);
    expect(heard).toEqual([]);
    expect(pageMarks(window)).toEqual([]);
  });
});

describe('input only software sends', () => {
  test('cdp_input: a mouse press or drag with no pressure on a Chromium browser; a real mouse has 0.5', () => {
    press({ pressure: 0.5 });
    fire(document.body, 'pointermove', { pointerType: 'mouse', buttons: 0, pressure: 0 });
    fire(document.body, 'pointerdown', { pointerType: 'pen', buttons: 1, pressure: 0 });
    expect(pageMarks(window)).toEqual([]);
    press({ pressure: 0 });
    expect(pageMarks(window)).toEqual(['cdp_input']);

    stopAgentMarks(window);
    startAgentMarks(window, { trusted: () => true });
    fire(document.body, 'pointermove', { pointerType: 'mouse', buttons: 1, pressure: 0 });
    expect(pageMarks(window)).toEqual(['cdp_input']);
  });

  test('cdp_input only on Chromium: other engines report pressure their own way', () => {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(FIREFOX);
    press({ pressure: 0 });
    expect(pageMarks(window)).toEqual([]);
  });

  test('input_no_focus: a press, key or input into a page on screen that is still not focused 100 ms later', async () => {
    // The click that brings a window to the front: focused within the 100 ms.
    focused = false;
    press({ pressure: 0.5 });
    focused = true;
    await vi.advanceTimersByTimeAsync(100);
    expect(pageMarks(window)).toEqual([]);
    // An agent's key into a page that never gets focus.
    focused = false;
    fire(document.body, 'keydown', { key: 'a' });
    await vi.advanceTimersByTimeAsync(99);
    expect(pageMarks(window)).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(pageMarks(window)).toEqual(['input_no_focus']);
  });

  test('a hidden page is not "unfocused input"', async () => {
    focused = false;
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    typed('x');
    await vi.advanceTimersByTimeAsync(200);
    expect(pageMarks(window)).toEqual([]);
    visibility.mockRestore();
  });

  test('insert_text_bulk: text of more than one character in one piece with no key just before', () => {
    // A person: a key, then its character.
    fire(document.body, 'keydown', { key: 'a' });
    clock += 3;
    typed('a');
    // One grapheme in several code points (an emoji picker), IME composing, a paste, autocorrect: not text typed in bulk.
    clock += 2000;
    typed('👨‍👩‍👧');
    typed('日本語', { isComposing: true });
    typed('pasted text', { inputType: 'insertFromPaste' });
    typed('replaced', { inputType: 'insertReplacementText' });
    // A key just before (within 50 ms) and an IME that just finished: still a person's typing.
    fire(document.body, 'keydown', { key: '.' });
    clock += 40;
    typed('. ');
    clock += 2000;
    fire(document.body, 'compositionend');
    clock += 10;
    typed('かな');
    // document.execCommand('insertText') (a writing extension, a text expander, the page itself): no beforeinput.
    clock += 2000;
    typed('Kind regards', {}, false);
    expect(pageMarks(window)).toEqual([]);
    // CDP's Input.insertText: the whole string at once, no key at all.
    clock += 2000;
    typed('Hello Probe 1');
    expect(pageMarks(window)).toEqual(['insert_text_bulk']);
  });

  test('phones and tablets: a QuickType word or the code from Messages, and a tap while the address bar has focus, are a person', async () => {
    const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.1 Mobile/15E148 Safari/604.1';
    const IPAD_DESKTOP = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.1 Safari/605.1.15';
    const ANDROID_TABLET_DESKTOP = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36';
    const ua = vi.spyOn(navigator, 'userAgent', 'get');
    const device = async (agent: string, setup: () => void = () => {}) => {
      stopAgentMarks(window);
      ua.mockReturnValue(agent);
      setup();
      startAgentMarks(window, { trusted: () => true, now: () => clock });
      focused = false;
      clock += 2000;
      typed('123456');
      press({ pointerType: 'touch', pressure: 0.5 });
      await vi.advanceTimersByTimeAsync(200);
      return pageMarks(window);
    };
    expect(await device(IPHONE)).toEqual([]);
    // An iPad asks for desktop sites with a Mac user agent; its touch screen gives it away.
    expect(await device(IPAD_DESKTOP, () => Object.defineProperty(navigator, 'maxTouchPoints', { value: 5, configurable: true }))).toEqual([]);
    delete (navigator as unknown as Record<string, unknown>).maxTouchPoints;
    // An Android tablet asks for desktop sites with a Linux user agent; its main pointer is a finger.
    const coarse = (q: string) => ({ matches: q === '(pointer: coarse)' }) as MediaQueryList;
    expect(await device(ANDROID_TABLET_DESKTOP, () => Object.defineProperty(window, 'matchMedia', { value: coarse, configurable: true }))).toEqual([]);
    delete (window as unknown as Record<string, unknown>).matchMedia;
    // The same on a desktop is an agent's.
    expect(await device(CHROME)).toEqual(['input_no_focus', 'insert_text_bulk']);
  });

  test('a press into one of the page\'s frames (a captcha box, a password manager\'s menu) is the person\'s; leaving the window is not', async () => {
    // Switching to another app: the window blurs and the page has no focus.
    focused = false;
    window.dispatchEvent(new Event('blur'));
    await vi.advanceTimersByTimeAsync(10);
    expect(trustedInputSeen(window)).toBe(false);
    // An element's blur (focus moving inside the page) is not the window's.
    focused = true;
    document.body.innerHTML = '<input id="a">';
    document.getElementById('a')!.dispatchEvent(new Event('blur'));
    await vi.advanceTimersByTimeAsync(10);
    expect(trustedInputSeen(window)).toBe(false);
    // Focus moved into a frame of the page: the browser window keeps it.
    window.dispatchEvent(new Event('blur'));
    await vi.advanceTimersByTimeAsync(10);
    expect(trustedInputSeen(window)).toBe(true);
  });

  test('a person on a plain page: none of the new codes, and the press counts as their input', async () => {
    stopAgentMarks(window);
    // Nobody watching: no evidence either way, so never "no input".
    expect(trustedInputSeen(window)).toBe(true);
    startAgentMarks(window, { trusted: () => true, now: () => clock });
    expect(trustedInputSeen(window)).toBe(false);
    for (let i = 0; i < 10; i += 1) fire(document.body, 'pointermove', { pointerType: 'mouse', buttons: 0, pressure: 0 });
    press({ pressure: 0.5 });
    fire(document.body, 'pointermove', { pointerType: 'mouse', buttons: 1, pressure: 0.5 });
    for (const ch of 'hello') {
      fire(document.body, 'keydown', { key: ch });
      clock += 2;
      typed(ch);
      clock += 120;
    }
    await vi.advanceTimersByTimeAsync(20_000);
    expect(trustedInputSeen(window)).toBe(true);
    const found = pageMarks(window);
    expect(found.filter((c) => NEW_CODES.includes(c))).toEqual([]);
    expect(found).toEqual([]);
  });

  test("events made by the page's own script are never counted", () => {
    stopAgentMarks(window);
    startAgentMarks(window);
    press({ pressure: 0 });
    typed('Hello Probe 1');
    expect(pageMarks(window)).toEqual([]);
    expect(trustedInputSeen(window)).toBe(false);
  });

  test('a code the page decides itself reaches subscribers once', () => {
    addPageMark(window, 'scripted_click');
    addPageMark(window, 'scripted_click');
    expect(heard).toEqual(['scripted_click']);
    expect(pageMarks(window)).toEqual(['scripted_click']);
  });

  test('the poll stops after 15 minutes; the listeners keep watching', async () => {
    await vi.advanceTimersByTimeAsync(15 * 60 * 1000 + 5000);
    expect(vi.getTimerCount()).toBe(0);
    w.__claudeElementMap = new Map();
    await vi.advanceTimersByTimeAsync(5000);
    expect(heard).toEqual([]);
    press({ pressure: 0 });
    expect(heard).toEqual(['cdp_input']);
    // A report still looks for the globals.
    expect(pageMarks(window)).toEqual(['cdp_input', 'claude_agent']);
  });
});
