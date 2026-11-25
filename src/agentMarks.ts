// src/agentMarks.ts
// The marks AI agents and DevTools-protocol (CDP) input leave on a page while
// it is open (@touchque/device-risk 3.2.0). An AI agent reads a page before it
// acts: the Claude app's browser puts its page-reading functions into the page,
// Claude in Chrome, Perplexity Comet, Genspark, Browser Use, Stagehand and
// Skyvern draw their own overlays, and the clicks and typing they send through
// CDP are not a person's. Most of this comes after the identification the page
// made when it loaded, so these watchers keep looking and tell subscribers what
// they find (onPageMarks): the next report carries it in s.auto, and identify
// adds it to the identification it already made (late evidence).
//
// What is watched (codes only; never what is typed, pressed or where):
//   - agent globals: __claudeElementMap and its three siblings (the Claude
//     app's browser, after its first read of the page) -> claude_agent;
//     Skyvern's GlobalSkyvernFrameIndex, or two of its other global* names ->
//     skyvern. Looked up every 250 ms for 10 s, then every second, for 15
//     minutes, and again whenever a report is built (pageMarks);
//   - overlays added to <html>, <head> or <body>: [id^="claude-agent-"]
//     (Claude in Chrome), [id^="pplx-agent"] (Comet), #genspark-float-bar,
//     Browser Use's [data-browser-use-interaction-highlight], Stagehand's
//     #__v3_cursor_overlay__, <skyvern-control-indicator>, and Playwright's
//     x-pw-* glass pane right on <html> (its inspector and recorder: playwright);
//   - cdp_input: a mouse press or drag with no pressure, on Chromium browsers
//     only. CDP's Input.dispatchMouseEvent sends force 0; Chromium gives a real
//     mouse or trackpad 0.5 while a button is down;
//   - input_no_focus: a press, key or input into a page that is on screen but
//     not focused, and still not focused 100 ms later. A person's click focuses
//     the window it lands in; an agent drives a page that never gets focus;
//   - insert_text_bulk: text of more than one character that arrived in one
//     piece with no key pressed just before and no IME composing (CDP's
//     Input.insertText: an agent's typing, Playwright's fill; dictation too,
//     so the server weighs it as a step-up hint only). Only after the
//     browser's own beforeinput for it: document.execCommand('insertText'),
//     which writing extensions, text expanders and pages use, fires none;
//     CDP's insertText does;
//   - whether a press, tap, click or key came from the person's own hardware
//     since the page loaded, a press into one of the page's frames included
//     (the tag calls a form sent without one scripted_click).
// Untrusted events (made by script on the page) are never counted.
//
// input_no_focus and insert_text_bulk are for desktops only (touchFirst):
// a phone's keyboard puts whole words and codes in with no key (QuickType, the
// code from Messages, an email suggestion), its web views and address bar keep
// focus their own way, and the agents these codes are for drive desktop browsers.
//
// No property traps on the agent globals: a trap would make
// `'__claudeElementMap' in window` true on every page, so any other bot check
// on the same page would take every visitor for Claude, and an agent that sets
// the name only when it is missing would break. The poll finds the same globals
// within a second.

import { browserFamily, CHROMIUM_FAMILIES, osFamily } from './browserFamily';

/** AI agents whose marks are on the page (the server's AGENT_TOOLS). */
export const AGENT_CODES: readonly string[] = ['claude_agent', 'comet_agent', 'genspark_agent', 'browser_use', 'stagehand', 'skyvern'];

const CLAUDE_GLOBALS = ['__claudeElementMap', '__claudeElementReverseMap', '__claudeRefCounter', '__generateAccessibilityTree'];
// Skyvern's injected domUtils.js. Its frame index names Skyvern alone; each of the others is a
// name a page could have, so two of them are needed.
const SKYVERN_GLOBAL = 'GlobalSkyvernFrameIndex';
const SKYVERN_GLOBALS = ['GlobalEnableAllTextualElements', 'globalDomDepthMap', 'globalHoverStylesMap', 'globalIncrementalJobCount',
  'globalIncrementalSession', 'globalListnerFlag', 'globalObserverForDOMIncrement', 'globalOneTimeIncrementElements',
  'globalParsedElementCounter'];
/** Agent overlays a selector names exactly, wherever they are. */
const EXACT_OVERLAYS = '[id="genspark-float-bar"],[id="__v3_cursor_overlay__"],[data-browser-use-interaction-highlight],skyvern-control-indicator';
/**
 * With the id prefixes too. The agents add these on <html>, <head> or <body>; a page's own element
 * deeper down may happen to start its id so (a heading anchor "claude-agent-sdk"), so a prefix counts
 * only there. Playwright's x-pw-* elements are found by their tag name's prefix, only right on <html>,
 * where Playwright puts its glass pane: on a sign-in page "pw" is often the password (a page's own
 * <x-pw-meter> on <body>).
 */
const OVERLAYS = `[id^="claude-agent-"],[id^="pplx-agent"],${EXACT_OVERLAYS}`;

const FAST_MS = 250;
const FAST_FOR_MS = 10 * 1000;
const SLOW_MS = 1000;
const POLL_FOR_MS = 15 * 60 * 1000;
const FOCUS_RECHECK_MS = 100;
const KEY_NEAR_MS = 50;

export interface AgentMarksDeps {
  /** Which events came from the person's own hardware (tests). Default: `isTrusted`. */
  trusted?: (e: Event) => boolean;
  /** Milliseconds for the gap between a key and the text it typed (tests). Default: `performance.now`. */
  now?: () => number;
}

interface Watch {
  codes: Set<string>;
  subscribers: Set<(codes: string[]) => void>;
  /** A press, tap, click or key from the person's own hardware since the page loaded. */
  input: boolean;
  /** Stops the listeners, the observer and the poll; null while not watching. */
  stop: (() => void) | null;
}

const watches = new WeakMap<Window, Watch>();

function watchOf(win: Window): Watch {
  let w = watches.get(win);
  if (!w) {
    w = { codes: new Set(), subscribers: new Set(), input: false, stop: null };
    watches.set(win, w);
  }
  return w;
}

/** Adds codes seen; subscribers hear only the new ones. */
function add(w: Watch, codes: string[]): void {
  const fresh = [...new Set(codes)].filter((c) => !w.codes.has(c));
  if (!fresh.length) return;
  for (const c of fresh) w.codes.add(c);
  for (const fn of Array.from(w.subscribers)) {
    try { fn(fresh); } catch { /* a subscriber's problem is its own */ }
  }
}

/** Where an element sits: right on <html> ('html'), right on <head> or <body> ('top'), or deeper (''). */
type Spot = 'html' | 'top' | '';

function spotOf(parent: Node | null, doc: Document): Spot {
  if (!parent) return '';
  if (parent === doc.documentElement) return 'html';
  return parent === doc.head || parent === doc.body ? 'top' : '';
}

/** The agent an element on the page belongs to, or null. `spot`: where it sits (spotOf). */
function overlayCode(el: Element, spot: Spot): string | null {
  try {
    const id = el.getAttribute('id') || '';
    // Claude in Chrome leaves its animation styles on the tab after a run: a person who signs in
    // there later is not the agent. Its Stop button and other overlays exist only while it works.
    if (spot && id.startsWith('claude-agent-') && id !== 'claude-agent-animation-styles') return 'claude_agent';
    if (spot && id.startsWith('pplx-agent')) return 'comet_agent';
    if (id === 'genspark-float-bar') return 'genspark_agent';
    if (id === '__v3_cursor_overlay__') return 'stagehand';
    if (el.hasAttribute('data-browser-use-interaction-highlight')) return 'browser_use';
    const name = String(el.localName || '');
    if (name === 'skyvern-control-indicator') return 'skyvern';
    if (spot === 'html' && name.startsWith('x-pw-')) return 'playwright';
  } catch { /* a form whose control's name shadows a method: not an overlay */ }
  return null;
}

/**
 * A phone or a tablet: an iPhone or Android user agent (or client hints that say mobile), an iPad
 * asking for desktop sites (a Mac user agent with a touch screen), or a touch screen as the main
 * pointer. Anything unreadable counts as one: input_no_focus and insert_text_bulk then stay quiet.
 */
function touchFirst(win: Window): boolean {
  try {
    const nav = win.navigator as Navigator & { userAgentData?: { mobile?: unknown } };
    if (nav.userAgentData?.mobile === true) return true;
    const os = osFamily(nav.userAgent || '', nav.platform || '');
    if (os === 'iOS' || os === 'Android') return true;
    if (os === 'macOS' && (nav.maxTouchPoints || 0) > 1) return true;
    return typeof win.matchMedia === 'function' && win.matchMedia('(pointer: coarse)').matches;
  } catch {
    return true;
  }
}

/** Agent globals on the page now. */
function globalCodes(win: Window): string[] {
  const own = (k: string) => { try { return Object.prototype.hasOwnProperty.call(win, k); } catch { return false; } };
  const out: string[] = [];
  if (CLAUDE_GLOBALS.some(own)) out.push('claude_agent');
  if (own(SKYVERN_GLOBAL) || SKYVERN_GLOBALS.filter(own).length >= 2) out.push('skyvern');
  return out;
}

/** Agent overlays in the document now (a report's check: an overlay deeper than the observer looks, or older than the tag). */
function overlayCodes(doc: Document | undefined): string[] {
  const out: string[] = [];
  try {
    if (!doc) return out;
    for (const el of Array.from(doc.querySelectorAll(OVERLAYS))) {
      const code = overlayCode(el, spotOf(el.parentElement, doc));
      if (code) out.push(code);
    }
    // Playwright's glass pane sits right on <html>; no selector names a tag prefix.
    const root = doc.documentElement;
    if (root) for (const el of Array.from(root.children)) if (overlayCode(el, 'html') === 'playwright') out.push('playwright');
  } catch { /* ignore */ }
  return out;
}

let segmenter: { segment(s: string): Iterable<unknown> } | null | undefined;

/** Graphemes in `s`, counted up to 2 (Intl.Segmenter; without it, letters and digits, so an emoji of several code points is one). */
function graphemes(s: string): number {
  try {
    if (segmenter === undefined) {
      const Seg = (Intl as unknown as { Segmenter?: new (locale?: string, o?: { granularity: string }) => { segment(s: string): Iterable<unknown> } }).Segmenter;
      segmenter = typeof Seg === 'function' ? new Seg(undefined, { granularity: 'grapheme' }) : null;
    }
    if (segmenter) {
      let n = 0;
      for (const segment of segmenter.segment(s)) {
        void segment;
        n += 1;
        if (n > 1) break;
      }
      return n;
    }
  } catch {
    segmenter = null;
  }
  return (s.match(/[\p{L}\p{N}]/gu) || []).length;
}

/**
 * Starts watching `win` for AI agents and CDP input, once per window (a
 * second call does nothing until stopAgentMarks). createDeviceRisk and the
 * script tag call it. Never throws; passive listeners only.
 */
export function startAgentMarks(win: Window, deps: AgentMarksDeps = {}): void {
  try {
    if (!win || typeof win.addEventListener !== 'function' || !win.document) return;
    const w = watchOf(win);
    if (w.stop) return;
    const doc = win.document;
    const trusted = deps.trusted ?? ((e: Event) => e.isTrusted === true);
    const perf = win.performance;
    const clock = deps.now ?? (() => (perf && typeof perf.now === 'function' ? perf.now() : Date.now()));
    const started = Date.now();
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let focusCheck = false;
    let lastKey = -Infinity;
    let lastComposition = -Infinity;
    let before: { data: string; at: number } | null = null;

    // A press or key before the tag started (an async tag can load late) was still the person's.
    try {
      const activation = (win.navigator as Navigator & { userActivation?: { hasBeenActive?: boolean } }).userActivation;
      if (activation?.hasBeenActive === true) w.input = true;
    } catch { /* ignore */ }

    // Blink's pressure rule (0.5 for a held mouse button) is Chromium's; Chrome and Edge on iOS run WebKit.
    const chromium = () => {
      try {
        const ua = win.navigator.userAgent || '';
        return CHROMIUM_FAMILIES.includes(browserFamily(ua).br) && !/CriOS|EdgiOS/.test(ua);
      } catch {
        return false;
      }
    };
    const unfocused = () => {
      try { return doc.visibilityState === 'visible' && !doc.hasFocus(); } catch { return false; }
    };
    // The click that brings a window to the front lands before the window has focus: only a
    // page that is still unfocused 100 ms later counts. Desktops only: a phone's tap on the page
    // while its address bar holds focus moves focus only when the finger lifts.
    const checkFocus = () => {
      if (focusCheck || w.codes.has('input_no_focus') || !unfocused() || touchFirst(win)) return;
      focusCheck = true;
      setTimeout(() => {
        focusCheck = false;
        if (!stopped && unfocused()) add(w, ['input_no_focus']);
      }, FOCUS_RECHECK_MS);
    };

    const onPointer = (e: Event) => {
      if (!trusted(e)) return;
      const p = e as PointerEvent;
      if (e.type === 'pointerdown') {
        w.input = true;
        checkFocus();
      }
      if (p.pressure === 0 && p.buttons > 0 && p.pointerType === 'mouse' && chromium()) add(w, ['cdp_input']);
    };
    const onPress = (e: Event) => { if (trusted(e)) w.input = true; };
    const onKey = (e: Event) => {
      if (!trusted(e)) return;
      w.input = true;
      lastKey = clock();
      checkFocus();
    };
    const onComposition = (e: Event) => { if (trusted(e)) lastComposition = clock(); };
    const onBeforeInput = (e: Event) => {
      const ie = e as InputEvent;
      before = trusted(e) && ie.inputType === 'insertText' && typeof ie.data === 'string' ? { data: ie.data, at: clock() } : null;
    };
    const onInput = (e: Event) => {
      if (!trusted(e)) return;
      checkFocus();
      const ie = e as InputEvent;
      const announced = before;
      before = null;
      if (ie.inputType !== 'insertText' || ie.isComposing || typeof ie.data !== 'string' || ie.data.length < 2) return;
      const at = clock();
      if (!announced || announced.data !== ie.data || at - announced.at > KEY_NEAR_MS) return;
      if (at - lastKey <= KEY_NEAR_MS || at - lastComposition <= KEY_NEAR_MS) return;
      // Desktops only: an iPhone puts a QuickType word, an email suggestion or the code from Messages in this way.
      if (graphemes(ie.data) > 1 && !touchFirst(win)) add(w, ['insert_text_bulk']);
    };
    // A press into one of the page's frames (a captcha box, a "Sign in with…" button, a card field,
    // a password manager's menu) is the person's too, but its events stay in the frame. The page sees
    // its window lose focus while the browser window keeps it (hasFocus stays true); switching to
    // another app or to the address bar blurs the window with hasFocus false.
    const onBlur = (e: Event) => {
      // The window's own blur (an element's passes the window on its way: another target).
      if (e.target !== e.currentTarget || w.input || !trusted(e)) return;
      setTimeout(() => {
        try { if (!stopped && doc.visibilityState === 'visible' && doc.hasFocus()) w.input = true; } catch { /* ignore */ }
      }, 0);
    };

    const Observer = (win as Window & { MutationObserver?: typeof MutationObserver }).MutationObserver;
    let observer: MutationObserver | null = null;
    const observed = new Set<Node>();
    const observe = (node: Node | null | undefined) => {
      if (!node || !observer || observed.has(node)) return;
      observed.add(node);
      try { observer.observe(node, { childList: true }); } catch { /* ignore */ }
    };
    // Records come from <html>, <head> and <body> only: what they add sits right on them (an
    // overlay removed again before the record is read still counts).
    const checkNode = (node: Node, spot: Spot) => {
      if (node.nodeType !== 1) return;
      const el = node as Element;
      const code = overlayCode(el, spot || 'top');
      if (code) add(w, [code]);
      else {
        // An overlay inside what was added (a wrapper around it), by the exact names only.
        try {
          const inner = el.firstElementChild ? el.querySelector(EXACT_OVERLAYS) : null;
          const innerCode = inner ? overlayCode(inner, '') : null;
          if (innerCode) add(w, [innerCode]);
        } catch { /* ignore */ }
      }
      // <head> or <body> parsed after the tag started: watch them too.
      if (el === doc.head || el === doc.body) observe(el);
    };
    if (typeof Observer === 'function') {
      observer = new Observer((records: MutationRecord[]) => {
        for (const r of records) {
          const spot = spotOf(r.target, doc);
          for (const n of Array.from(r.addedNodes)) checkNode(n, spot);
        }
      });
      observe(doc.documentElement);
      observe(doc.head);
      observe(doc.body);
    }

    // Every 250 ms for 10 s, then every second, for 15 minutes: the Claude app's browser adds its
    // globals when it first reads the page, which may be long after the page loaded.
    const poll = () => {
      timer = null;
      if (stopped) return;
      add(w, globalCodes(win));
      const age = Date.now() - started;
      if (age < POLL_FOR_MS) {
        timer = setTimeout(poll, age < FAST_FOR_MS ? FAST_MS : SLOW_MS);
        // Under Node (a test's DOM that imports the library) the poll never keeps the process up.
        (timer as unknown as { unref?: () => void }).unref?.();
      }
    };

    const opts: AddEventListenerOptions = { capture: true, passive: true };
    const listeners: Array<[string, (e: Event) => void]> = [
      ['pointerdown', onPointer], ['pointermove', onPointer], ['mousedown', onPress], ['click', onPress], ['touchstart', onPress],
      ['keydown', onKey], ['compositionend', onComposition], ['beforeinput', onBeforeInput], ['input', onInput], ['blur', onBlur],
    ];
    for (const [type, fn] of listeners) win.addEventListener(type, fn, opts);
    w.stop = () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
      try { observer?.disconnect(); } catch { /* ignore */ }
      for (const [type, fn] of listeners) {
        try { win.removeEventListener(type, fn, opts); } catch { /* ignore */ }
      }
    };
    add(w, overlayCodes(doc));
    poll();
  } catch { /* never break the page */ }
}

/** Stops watching `win` and forgets what was seen there (tests; subscribers stay). */
export function stopAgentMarks(win: Window): void {
  const w = watches.get(win);
  if (!w) return;
  try { w.stop?.(); } catch { /* ignore */ }
  w.stop = null;
  w.codes.clear();
  w.input = false;
}

/**
 * The codes seen on `win` since the watchers started, with the agent globals
 * and overlays there now, sorted. Every report puts them in s.auto. Never throws.
 */
export function pageMarks(win: Window): string[] {
  try {
    const w = watchOf(win);
    add(w, [...globalCodes(win), ...overlayCodes(win.document)]);
    return [...w.codes].sort();
  } catch {
    return [];
  }
}

/** Calls `listener` with each new code seen on `win` (late evidence); returns the unsubscribe. */
export function onPageMarks(win: Window, listener: (codes: string[]) => void): () => void {
  try {
    const w = watchOf(win);
    w.subscribers.add(listener);
    return () => { w.subscribers.delete(listener); };
  } catch {
    return () => {};
  }
}

/** Adds a code the page decided itself (the tag's scripted_click). */
export function addPageMark(win: Window, code: string): void {
  try { add(watchOf(win), [code]); } catch { /* ignore */ }
}

/**
 * Whether a press, tap, click or key from the person's own hardware reached
 * `win` (or one of its frames) since the page loaded. True when nobody watched
 * (no evidence either way).
 */
export function trustedInputSeen(win: Window): boolean {
  const w = watches.get(win);
  return !w || !w.stop ? true : w.input;
}
