# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.2.0] — 2026-11-25

### Added
- **AI agents on the page**, in `s.auto`: the Claude app's browser (`__claudeElementMap` and its three siblings, which
  it adds when it first reads the page) and Claude in Chrome (`[id^="claude-agent-"]`) as `claude_agent`, Perplexity
  Comet (`[id^="pplx-agent"]`) `comet_agent`, Genspark (`#genspark-float-bar`) `genspark_agent`, Browser Use (its
  interaction highlight) `browser_use`, Stagehand (`#__v3_cursor_overlay__`) `stagehand`, Skyvern
  (`GlobalSkyvernFrameIndex`, `<skyvern-control-indicator>`) `skyvern`. `deviceRisk` / `createDeviceRisk` start the
  watchers once per window: the globals are looked up every 250 ms for 10 s, then every second for 15 minutes, and at
  every report; overlays added to `<html>`, `<head>` and `<body>` are seen as they come.
- **Input only software sends**, in `s.auto`: `cdp_input` (a mouse press or drag with no pressure: the DevTools
  protocol sends force 0, a real mouse 0.5; Chromium only), `input_no_focus` (a press, key or input into a page on
  screen that is still not focused 100 ms later), `insert_text_bulk` (text of more than one character in one piece,
  announced by the browser, with no key just before and no IME composing), and from the script tag `scripted_click` (a
  form sent with no press, tap or key from the person since the page loaded; a press into one of the page's frames,
  such as a captcha box or a password manager's menu, counts as the person's). `input_no_focus` and
  `insert_text_bulk` are for desktops only: a phone's keyboard puts whole words and codes in with no key (QuickType,
  the code from Messages, an email suggestion), and a tap moves focus only when the finger lifts. Never a key, a
  character or a position.
- **Late evidence.** An agent reads a page before it acts, so most of this comes after the identification made on
  load. After `identify` succeeds, new codes go to that identification:
  `POST /device-risk/identify { siteKey, requestId, late: { auto } }` (text/plain, codes only, one update per 300 ms
  burst, at most 5 per identification, for 15 minutes). When a form is sent the tag checks once more and sends what is
  new at once (`deviceRisk.flush()`): a beacon to your own `/_tq/` origin; to `api.touchque.com` a keepalive fetch,
  which, like `identify`, sends no cookie. The form field keeps its format.
- Puppeteer is named (`puppeteer`): its `exposeFunction` binding (`puppeteer_*`) and wrapper, its 800x600 viewport with
  the empty brands `setUserAgent` leaves, a `pptr:` evaluate on the stack. Playwright 1.53+, which adds no global by
  default: `__playwright__binding__controller__`, its exact `__pw` names (`__pwClock`, `__pwWebSocketBinding`,
  `__pwWebAuthnBinding`, `__pwSnapshotGlobals`, the recorder's `__pw_recorder*`; never a bare `__pw` prefix, which on
  a sign-in page is often the password), its exposed wrappers, a `UtilityScript` evaluate (code with no URL) on the
  stack, its `x-pw-*` glass pane on `<html>`.
- `headless_chrome` also from the `HeadlessChrome` brand and Chrome's DOM automation globals.
- `pageMarks`, `onPageMarks` and `LATE_EVIDENCE_CODES` are exported.

### Fixed
- `cdp` fires again. Chrome 137+ no longer runs a logged error's own `stack` getter, so the old probe never did. The
  new one asks whether the inspector built a logged error's stack (`Error.prepareStackTrace`) or read its name more
  often than the console alone does. It logs through a fresh blank frame's console at the debug level (hidden by
  default), so the page's Sentry, Datadog or LogRocket wrappers neither swallow nor trigger it, and only while that
  console is the browser's own (an extension's logger in every frame could read the error itself); V8 only,
  everything restored and the frame removed. Checked on Chrome 158: quiet with nothing attached (the name read once
  per log), on under Puppeteer.

### Changed
- `DEVICE_TAG_VERSION` is `3.2.0`. A report can now name more than 10 automation codes: Touchque's server takes 20
  before pages move to 3.2.

## [3.1.0] — 2026-11-25

### Added
- **Touchque's fresh value in every report.** `identify` (and so the script tag) first asks
  `POST /device-risk/identify { siteKey, challenge: true }` for a value Touchque binds to the workspace, the site key
  and the page's network (/24), good for two minutes and once; the report carries it (`ch`) inside what it signs and
  encrypts. Reports can no longer be built ahead of time or asked for on one network and sent from another. Without an
  answer within `timeoutMs` the report goes without one. `DeviceRiskCollectOptions.challenge` passes one to `collect`.
- Every report names the tag's version (`tv`, `REPORT_TAG_VERSION`): Touchque counts a report without a value against it
  only on a workspace whose pages have moved to 3.1, so pages still pinning 3.0 are never flagged.

### Fixed
- `headless_window` only on Chromium browsers (not Brave): an 800x600 frameless Safari or Tor window is not headless Chrome.
- Brave is Brave only when its client-hint brands say so too: a page that just adds `navigator.brave` (Brave's lighter
  matching) is not taken for it.

### Changed
- `DEVICE_TAG_VERSION` is `3.1.0`.

## [3.0.0] — 2026-11-24

First release of `@touchque/device-risk`: Touchque Device Risk is a separate product with its own SDK. Its
versions continue the script tag's line (2.x came with `@touchque/web`, which no longer has Device risk).

### Added
- Everything `@touchque/web` 2.3.0 had for Device risk: `deviceRisk` / `createDeviceRisk` (`identify`,
  `collect`), the script tag (`installDeviceRiskTag`, `touchque-device.global.js`, `dist/device-sri.json`),
  the pointer and input summaries, automation tool marks.
- **Encrypted reports.** `collect` (and so `identify` and the tag) encrypts the report for Touchque:
  `tqe1.<kid>.<epk>.<iv>.<ct>`, ECDH P-256 with Touchque's report key (`REPORT_KEY`, kid `9d8a2f55`),
  HKDF-SHA256 (salt the one-time public key, info `touchque-device-report:v1`), AES-256-GCM with additional
  data `tqe1.<kid>`. Only Touchque opens it; a changed byte makes it unreadable. Without WebCrypto the plain
  report goes. `encrypt: false` gives the plain one. `sealReport` is exported.
- **Traits that cannot all be true** (`consistencyFindings`, in `s.tamper`): `ua_engine_mismatch` (the
  JavaScript engine by the wording of one TypeError: iOS and Safari run JavaScriptCore, Chromium V8, Firefox
  Gecko), `gpu_os_mismatch` (a desktop card on an "Android phone", anything but "Apple GPU" on an "iPhone",
  phone chips on a Mac, Apple/Mali/PowerVR on Windows; Adreno allowed on Windows for Snapdragon),
  `fonts_os_mismatch`, `mobile_desktop_mismatch` (a phone with no touch or a mouse only; an iPhone screen over
  1000 points or under 2x), `ua_platform_mismatch` for an iOS user agent with a Mac platform. In `s.vm`:
  `emulator` (Android Studio, Genymotion, BlueStacks, Nox, LDPlayer, MuMu renderers) and `headless_window`
  (an 800x600 screen with no browser frame: headless Chrome with its automation flag hidden). Checked with
  Puppeteer, Playwright and an Android emulator on 2026-11-24; real Chrome, Firefox and Safari raised nothing.
- **The first-party cookie.** `identify` sends `credentials: 'same-origin'`: through your own `/_tq/` path,
  Touchque's HttpOnly `_tqd` cookie (Path=/_tq, 400 days) goes there and back, and Safari keeps it past its
  7-day limit on script storage. To `api.touchque.com` no cookie is sent.
- `DEVICE_TAG_VERSION` is `3.0.0`.
