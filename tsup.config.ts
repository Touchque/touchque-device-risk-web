import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

const { version } = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };

// The script tag's Subresource Integrity hash, published with each version
// (dist/device-sri.json): pages load it with integrity="sha384-…".
async function writeDeviceSri() {
  const file = 'dist/touchque-device.global.js';
  const integrity = `sha384-${createHash('sha384').update(readFileSync(file)).digest('base64')}`;
  const src = `https://cdn.touchque.com/device/v${version}/script.js`;
  writeFileSync('dist/device-sri.json', `${JSON.stringify({ version, src, integrity }, null, 2)}\n`);
}

export default defineConfig([
  // The library: ESM + CJS + types.
  { entry: ['src/index.ts'], format: ['cjs', 'esm'], dts: true, clean: true, treeshake: true },
  // The script tag (served as script.js): one line on the page, no dependency; sets `window.TouchqueDevice`.
  {
    entry: { 'touchque-device': 'src/deviceRiskGlobal.ts' },
    format: ['iife'], dts: false, clean: false, minify: true, treeshake: true, onSuccess: writeDeviceSri,
  },
]);
