# @touchque/device-risk

Touchque Device Risk for the browser. It recognises the browser on your sign-in, sign-up, password-reset,
approval and payment pages, gives it a visitor ID of your workspace, and tells bots, emulators, anti-detect
browsers and spoofed phones apart. The same code is the script tag Touchque serves at
`https://cdn.touchque.com/device/vX.Y.Z/script.js`.

Your server reads what Touchque decided with a Device Risk server package: `@touchque/device-risk-node`,
`touchque-device-risk` (Python), `touchque/device-risk` (PHP), `touchque-device-risk-go`, `Touchque.DeviceRisk`
(.NET), `com.touchque:touchque-device-risk` (Java), `touchque-device-risk` (Ruby).

Versions continue the tag's line: 3.0.0 is the first release of this package (the tag's 2.x came with
`@touchque/web`).

## Encrypted reports

Every report is signed by the browser's device-bound key and then encrypted for Touchque
(`tqe1.<kid>.<epk>.<iv>.<ct>`: ECDH P-256 with Touchque's report key, HKDF-SHA256, AES-256-GCM). The page,
its other scripts, browser extensions and the visitor see an opaque string; only Touchque's servers can
open it, and a changed byte makes it unreadable. A person who controls the browser can still change values
before they are encrypted, which is why Touchque checks them against each other, against the request and
against what it saw before. Without WebCrypto (an http page) the report goes unencrypted.
`collect({ encrypt: false })` gives the plain report for debugging.

## What it catches

Besides the visitor ID: automation (WebDriver, headless Chrome, Playwright, Puppeteer, Selenium marks, the DevTools
protocol attached), Android emulators, virtual machines and software graphics, and traits that cannot all be true
(`consistencyFindings`): a JavaScript engine that is not the claimed browser's, graphics or fonts of
another platform, a "phone" with no touch or a desktop screen. How the pointer moved and how the page was
typed into travel as short summaries (counts and milliseconds, never a key or a position).

Since 3.2.0, AI agents that drive the browser: the Claude app's browser and Claude in Chrome, Perplexity Comet,
Genspark, Browser Use, Stagehand and Skyvern by the marks they leave on the page, and input only software sends (a
mouse press with no pressure, a press or key into a page that is not focused, text that arrives whole with no key, a
form sent with no press or key at all). The focus and whole-text checks run on desktops only: a phone's keyboard puts
whole words and one-time codes in with no key. An agent reads a page before it acts, so these often come after the
identification made on load: the page adds them to it for 15 minutes (codes only, at most 5 updates, and once more
when a form is sent), and your server's check weighs them.

## Install on a page
A paid add-on, off until your workspace turns it on (dashboard → Device risk). Every browser that reaches one of
these pages gets a visitor ID of your workspace, like Fingerprint's `visitorId`, and the risk engine decides whether
anything about it asks for more.

### One line on the page, one on your server

```html
<script src="https://cdn.touchque.com/device/v3.0.0/script.js" data-site-key="tqpk_…" data-purpose="sign_in"
        integrity="sha384-…" crossorigin="anonymous" async></script>
```

```typescript
// Your server, when the form arrives (@touchque/device-risk-node; every Device Risk server package has this call):
const verdict = await deviceRisk.check(req.body.touchque_request_id, { event: 'sign_in', externalUsername });
if (verdict.stepUp) { /* ask for more: a number-matched approval, a passkey, your emailed code */ }
```

Pages that already load `…/device.js` (the tag's first name) keep working: the CDN serves the same bytes, with the same
`integrity`, at both names. The dashboard's Device risk → Settings shows the tag with your site key and this version's `integrity` hash
(`dist/device-sri.json` in the package; each version has its own path, so the hash never changes under you). The
tag identifies the browser when the page loads and puts the requestId into a hidden `touchque_request_id` field of
every form on the page, forms added later included. A form's own `data-touchque-purpose="sign_up"` wins over the
tag's `data-purpose` (default `sign_in`). Touchque accepts an identification for 15 minutes and for one account: the
tag takes a new one after 10 minutes, and another after each submit, so a single-page app's next attempt is fresh.
`data-api` points it at another Touchque API host. Allow the script host in `script-src` and your API host in
`connect-src` of your Content-Security-Policy.

**How the pointer moved.** When a form is sent, the tag adds 18 characters after the requestId and a dot: how the
pointer and the fingers moved on the page, as counts computed in the browser (`startPointerSummary`): presses on a
pointer that jumped onto the button and how long they lasted, how close long strokes and swipes came to a ruler line,
how long taps lasted. Never a position, a path or what was pressed. Software that drives a browser (Playwright,
Puppeteer, Selenium, AI browser agents) jumps the pointer and presses for 0 to 3 ms; a hand takes 30 ms and more. Pass
the field to `deviceRisk.check` as it is (45 characters, inside the 64 every server SDK passes on); the risk engine
weighs it as `device_pointer_synthetic`, a number-matched step-up at most, never a refusal, in shadow until you
enforce it. No movement at all (a keyboard, a screen reader) is never a sign; Voice Control and Switch Control move
like software and get the step-up. `data-pointer="off"` on the tag leaves it out. Name it in your privacy notice with
the rest: the numbers serve the sign-in's security, tell no person from another and are not kept apart from the
verdict.

Single-page apps read `window.TouchqueDevice`: `await TouchqueDevice.ready` (the first identification, or null),
`TouchqueDevice.value()` (what to send now: the requestId and the pointer summary), `TouchqueDevice.requestId`,
`TouchqueDevice.refresh()`, and the `touchque:device` event on `document` after each new identification. With npm
instead of the tag: `installDeviceRiskTag({ siteKey, purpose })` does the same.

**What a missing tag gets.** Nothing on the page is trusted. requestIds are made only by Touchque's server, used
for one account, bound to your site's origin and to 15 minutes; your server reads the verdict by requestId and the
risk engine decides. A page without the tag, or with it blocked, sends no requestId: `deviceRisk.check` still
answers (`report: 'missing'`, or `'unknown'` / `'expired'` for one that does not verify) with
`device_identification_missing`. Ad blockers block such scripts for honest people too, so that signal only ever asks
for a number-matched step-up, never refuses, and starts in shadow like the others. Removing or blocking the tag
gets the visitor a step-up at most, never a way past a check.

### From your own domain (first-party)

Ad blockers and browser privacy lists drop scripts and calls to known third-party fingerprinting hosts, for honest
visitors too (they then get `device_identification_missing`, a step-up at most). Big sites serve the tag and its
identify call from their own domain instead, like Fingerprint's proxy integrations: two paths under `/_tq/` on your
site, passed on to Touchque.

| Your path | Goes to |
|---|---|
| `GET /_tq/device/vX.Y.Z/script.js` | `https://cdn.touchque.com/device/vX.Y.Z/script.js` (the same bytes, so the same `integrity`) |
| `POST /_tq/device-risk/identify` | `https://api.touchque.com/device-risk/identify` |

The tag then points at your domain (`data-api` is where it sends the identify call):

```html
<script src="https://www.example.com/_tq/device/v3.0.0/script.js" data-site-key="tqpk_…" data-purpose="sign_in"
        data-api="https://www.example.com/_tq" integrity="sha384-…" crossorigin="anonymous" async></script>
```

Your Content-Security-Policy needs only `'self'` for both (`script-src`, `connect-src`).

**The proxy secret.** Behind your proxy every visitor reaches Touchque from your proxy's address. Send the visitor's
address as `X-Touchque-Client-IP` together with your workspace's proxy secret as `X-Touchque-Proxy-Secret`
(`tqps_…`, dashboard → Device risk → Settings; owners and admins see it, and the API key reads it from
`GET /device-risk/settings`). Touchque then records and scores the visitor's address and counts the per-address
limit (60 identifications a minute) on it instead of on your proxy. Keep the secret on the server like the API key:
an environment variable or a secret store, never in the page or in git. A wrong secret is
`403 proxy_secret_invalid`; rotating the site key makes a new secret. Without the secret the proxy still works, but
every visitor counts against the proxy's one address: fine for small sites only. Also pass the visitor's address as
`clientIp` to `deviceRisk.check` (and `login.request`) on your server. Your own cookies are not needed: drop them
on the way.

**nginx** (in your site's `server` block):

```nginx
location /_tq/device/ {
    proxy_pass https://cdn.touchque.com/device/;
    proxy_ssl_server_name on;
    proxy_set_header Cookie "";
    proxy_set_header Authorization "";
}
location = /_tq/device-risk/identify {
    limit_except POST { deny all; }
    proxy_pass https://api.touchque.com/device-risk/identify;
    proxy_ssl_server_name on;
    proxy_set_header Cookie "";
    proxy_set_header Authorization "";
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Touchque-Proxy-Secret "tqps_…";   # from Device risk → Settings; keep this file out of git
    proxy_set_header X-Touchque-Client-IP $remote_addr;  # behind a load balancer: set_real_ip_from + real_ip_header first
}
```

**Cloudflare Worker** (route `www.example.com/_tq/*`; `wrangler secret put TOUCHQUE_PROXY_SECRET`):

```js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname.startsWith('/_tq/device/')) {
      return fetch('https://cdn.touchque.com/device/' + url.pathname.slice('/_tq/device/'.length));
    }
    if (request.method === 'POST' && url.pathname === '/_tq/device-risk/identify') {
      return fetch('https://api.touchque.com/device-risk/identify', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          Origin: request.headers.get('Origin') || '',
          'X-Touchque-Proxy-Secret': env.TOUCHQUE_PROXY_SECRET,
          'X-Touchque-Client-IP': request.headers.get('CF-Connecting-IP') || '',
        },
        body: await request.text(),
      });
    }
    return new Response('Not found', { status: 404 });
  },
};
```

**Next.js middleware** (`middleware.ts`, on Vercel or your own server; Next.js 16 calls the file `proxy.ts` and the
function `proxy`; `TOUCHQUE_PROXY_SECRET` in the project's environment variables):

```ts
import { NextRequest, NextResponse } from 'next/server';

export const config = { matcher: '/_tq/:path*' };

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (req.method === 'GET' && pathname.startsWith('/_tq/device/')) {
    return NextResponse.rewrite(new URL('https://cdn.touchque.com/device/' + pathname.slice('/_tq/device/'.length)));
  }
  if (req.method === 'POST' && pathname === '/_tq/device-risk/identify') {
    const r = await fetch('https://api.touchque.com/device-risk/identify', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        Origin: req.headers.get('origin') ?? '',
        'X-Touchque-Proxy-Secret': process.env.TOUCHQUE_PROXY_SECRET ?? '',
        // On Vercel the first x-forwarded-for entry is the visitor; behind your own load balancer, its header.
        'X-Touchque-Client-IP': (req.headers.get('x-forwarded-for') ?? '').split(',')[0].trim(),
      },
      body: await req.text(),
    });
    return new Response(r.body, { status: r.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }
  return new Response('Not found', { status: 404 });
}
```

If you already have a middleware, add the two `/_tq/` branches at its top and `'/_tq/:path*'` to its matcher.

**Vercel rewrites** (`vercel.json`, any framework). A rewrite cannot add the proxy secret, so this suits small sites;
at volume, use the middleware above (or a Vercel function doing the same) for the identify path:

```json
{
  "rewrites": [
    { "source": "/_tq/device/:path*", "destination": "https://cdn.touchque.com/device/:path*" },
    { "source": "/_tq/device-risk/identify", "destination": "https://api.touchque.com/device-risk/identify" }
  ]
}
```

A Touchque Login custom domain (verified) serves both paths itself: Device risk → Settings then shows the tag with
`https://login.example.com/_tq`, nothing to proxy. In every case Touchque still checks the page's `Origin` against
your verified domains and listed origins, so pass `Origin` on unchanged (nginx passes it as it came; the Worker and
the middleware set it).

### From your own code

```typescript
import { deviceRisk } from '@touchque/device-risk';

// When the form is sent (purpose: 'sign_in' | 'sign_up' | 'password_reset' | 'approval'):
const id = await deviceRisk.identify({ siteKey: 'tqpk_…', purpose: 'sign_up' });
// id: { visitorId: 'tqv_…', requestId: 'dre_…', confidence: 0.99 }, or null when Touchque could not be reached
form.elements.deviceRiskRequestId.value = id?.requestId ?? '';
```

Never trust the page's copy: your server reads the identification by `requestId` with a server SDK
(`deviceRisk.getEvent(requestId)`: the visitor, how sure, what the page showed, the risk engine's verdict), checks
it for an account on sign-up and password-reset pages (`deviceRisk.check(requestId, { event: 'sign_up',
externalUsername, clientIp })`), and passes it as `deviceRiskRequestId` to `login.request` and `risk.check` on
sign-in and approval pages. An identification serves one account for 15 minutes; another account gets
`device_report_replayed`.

- **The visitor ID** (`tqv_…`) belongs to your workspace only: another Touchque customer sees another one for the
  same browser. It survives cleared site data, private windows where the browser lets its traits be seen, and browser
  updates. `confidence`: 0.99 when the browser's device-bound key sealed the report, 0.95 its stored id, up to 0.9 a
  match of its traits (lower for identical computers of a fleet), 0.5 to 0.6 a first sight.
- **Site key and origins:** the site key (`tqpk_…`) is public; Touchque answers only pages on your organization's
  verified domains and their subdomains (Organization → Domains) and on the origins you list (Device risk →
  Settings). The request is a
  `text/plain` POST, so no CORS preflight; allow your Touchque API host in your Content-Security-Policy `connect-src`.
- **Relay instead:** `deviceRisk.collect({ purpose })` returns the encoded report for your server to pass as
  `deviceRisk`, if your page must not call Touchque itself.
- **With Touchque's 2FA on the same page:** pass the report to `@touchque/web`'s behavioral widget
  (`attachBehavioral(el, { deviceRiskReport: () => deviceRisk.collect({ purpose: 'sign_in' }) })`).
- **What it reads:** coarse traits (OS, browser family and major version, time zone, languages, screen size,
  CPU cores, memory class, touch points, the graphics card's name) and short hashes of how the browser draws a
  test text, plays a test sound, which of 25 common fonts it has, a few Math results and its WebGL limits. And
  findings: browser functions replaced by script, traits that contradict each other (an anti-detect browser or
  a spoofing extension), a virtual machine or software graphics, a headless or automated browser, an AI agent's
  marks and input only software sends (codes only), and a private window where the browser lets that be seen.
- **Sealed:** where the browser has a device-bound key (`browserKey`, the silent sign-in key), the report is
  signed with it (`touchque-device:v1`, a different message from a proof's). Touchque then knows it came whole
  from a browser holding that key, from your page's origin, once. A seal does not make the traits true: script
  on the page can lie to its own report, so Touchque checks them against each other, against the address, and
  against the devices it saw before.
- **What Touchque keeps:** no raw trait. Keyed hashes (HMAC with a key of your workspace alone, so a device is
  never linked across Touchque customers), coarse labels ("Chrome 130 · macOS · laptop"), the account, the
  country and a keyed hash of the address's network, for the 30 to 90 days your workspace sets.
- **What it does:** the risk engine counts per visitor (accounts, sign-ups, countries, stored-id resets), checks the
  browser's clock against the address and decides. Every signal only ever asks for more (a number-matched approval or
  a passkey; on a sign-up, your own extra check). It never lets anyone skip a check and never blocks on its own.
  Signals start in shadow: reported and counted, asking only on visitors your admin marked "Step up always".
- **Never respawned:** the stored id lives in `localStorage` only. A cleared browser is matched back by its traits
  on Touchque's side, not by copying the id between stores.

**Tell your users.** Use it only on sign-in, sign-up, password-reset and approval pages, and say it in your
privacy notice. In Turkey (KVKK) account security can rest on legitimate interest (art. 5/2(f)); in the EU,
reading the device needs consent unless it is strictly necessary for the security of a sign-in the user asked
for (ePrivacy art. 5(3)), and a check that lets a known device do less does not count. Ask your lawyer. A
starting text is on the dashboard's Device risk → Settings tab.
