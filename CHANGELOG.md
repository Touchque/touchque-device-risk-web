# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
