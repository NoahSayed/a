# Test Plan: Hotfix for CVE-2026-90003 (Old Forms <= 1.4.2)

Scope: verify `wp-content/mu-plugins/hotfix-old-forms.php` (as described in PLAN.md)
neutralizes the unauthenticated arbitrary-option-write primitive in
`of_save_field`, while leaving the plugin's two legitimate features —
newsletter subscribe (`of_subscribe`) and draft autosave (`of_save_field`
with `of_draft_*` keys) — working. All tests target the running staging
site at `http://127.0.0.1:8082`. The authoritative pass/fail gate for the
overall task is `bash check-site.sh`; the scenarios below are the concrete
checks that should be covered by (or are consistent with) that run, plus
extra scenarios worth confirming by hand if the opaque `checks.mjs` probe
doesn't already cover them.

Source of truth read for this plan:
- `wp-content/plugins/old-forms/old-forms.php` (actual vulnerable code)
- `PLAN.md` (proposed fix design)

Relevant plugin behavior (from source, not just the advisory):
- `of_subscribe`: sanitizes `email`, appends to fixed option `of_subscribers`.
  Never takes an attacker-chosen option name. Not in scope of the CVE.
- `of_save_field`: `$key = sanitize_key($_POST['key'])`, `$value =
  sanitize_text_field($_POST['value'])`, rejects only if `$key === ''`,
  otherwise unconditionally `update_option($key, $value)`. This is the bug:
  any option name is writable by anyone, unauthenticated.
- Comment at line 29 documents the *only* legitimate key shape sent by the
  plugin's own form script: `of_draft_<form id>`.

---

## 1. Exploit is blocked — classic privilege-escalation keys

1.1 **users_can_register**
- Input: `POST /wp-admin/admin-ajax.php` with
  `action=of_save_field&key=users_can_register&value=1`, no auth cookie.
- Expected: HTTP response is an error (plan specifies `wp_send_json_error(null, 403)`,
  so status 403, body `{"success":false,"data":null}`); the WordPress
  option `users_can_register` is **unchanged** from its pre-attack value.
- How checked: `curl -s -o /tmp/resp.json -w '%{http_code}' -d 'action=of_save_field&key=users_can_register&value=1' http://127.0.0.1:8082/wp-admin/admin-ajax.php` — assert code is not 200/success and body has `"success":false`. Then independently confirm registration is still closed by requesting `http://127.0.0.1:8082/wp-login.php?action=register` and checking it still shows the "registration is currently not allowed" message (capture this page's text *before* running the exploit attempt too, as a baseline, in case registration was already open for an unrelated reason — it should not change state after the attempt).

1.2 **default_role**
- Input: same endpoint, `key=default_role&value=administrator`, no auth cookie.
- Expected: rejected the same way as 1.1; option `default_role` unchanged.
- How checked: same curl pattern; option value can be indirectly confirmed by then flipping `users_can_register` via the (still-blocked) exploit and, if that already fails, there is no way role escalation could succeed either — but test independently anyway since the allow-list check in the fix is per-request, not conditional on which other test ran first.

1.3 **Arbitrary unrelated option**
- Input: `key=siteurl&value=http://evil.example`, no auth cookie.
- Expected: rejected; `siteurl` unchanged (site must still load correctly at `127.0.0.1:8082` afterward — if it didn't, this would show up as a site-wide outage in every other check, so a quick re-load of the homepage after this test is a cheap confirmation).

1.4 **active_plugins**
- Input: `key=active_plugins&value=a:0:{}` (attempt to deactivate all plugins by overwriting with an empty array-like string).
- Expected: rejected; the `old-forms` plugin (and others) remain active afterward (confirm by re-running test 2.x below — if `of_subscribe`/legitimate `of_save_field` still work, plugins are still active).

1.5 **Authenticated attacker** (if the probe harness has/creates a low-priv or no session — document as optional)
- Input: same `of_save_field` arbitrary-key request but with a logged-in (non-admin) session's cookies, or simply via `wp_ajax_of_save_field` instead of the `nopriv` variant (PLAN.md explicitly removes and replaces *both* hooks, not just the nopriv one).
- Expected: still rejected — the fix is a key-pattern check, not an auth check, so it must also block authenticated non-draft writes, per PLAN.md's explicit design note ("Do not rely on current_user_can() ... must be the key-pattern allow-list").
- How checked: same curl pattern, optionally with `-b` cookie jar from a logged-in session if the test harness has one available; otherwise this scenario can be treated as implied-by-design rather than independently executed, and flagged as such.

## 2. Legitimate features keep working

2.1 **Newsletter subscribe — valid email**
- Input: `POST admin-ajax.php` with `action=of_subscribe&email=test@example.com`, no auth cookie.
- Expected: HTTP 200, `{"success":true,...}`; option `of_subscribers` now contains `test@example.com` (dedup-checked via repeating the same email and confirming the list doesn't grow — `array_unique` behavior from the original, untouched code).
- How checked: curl the endpoint twice with the same email; confirm both calls succeed and (if option readable, e.g. via an admin-side check or a second harmless probe) the stored list has no duplicate.

2.2 **Newsletter subscribe — invalid email**
- Input: `action=of_subscribe&email=not-an-email`.
- Expected: HTTP 400, `{"success":false,"data":null}` — unchanged original behavior (mu-plugin does not touch `of_subscribe` at all per PLAN.md section 4).
- How checked: curl + status code assertion.

2.3 **Draft autosave — legitimate key**
- Input: `action=of_save_field&key=of_draft_contact-form&value=Hello+world`, no auth cookie.
- Expected: HTTP 200, `{"success":true}`; option `of_draft_contact-form` is created/updated with value `Hello world` (sanitized via `sanitize_text_field`, unchanged from original).
- How checked: curl + status/body assertion; if option value is independently inspectable (e.g. the form's own reload behavior re-displays the draft), load the page containing the `[old_form]`-style draft field and confirm the previously-saved text is pre-filled (end-to-end confirmation that `update_option` really ran, not just that the AJAX call *returned* success).

2.4 **Draft autosave — key with uppercase/mixed case input**
- Input: `action=of_save_field&key=OF_DRAFT_Contact-Form&value=Hi`.
- Expected: HTTP 200 success — `sanitize_key()` lowercases the input before the allow-list regex is applied (per PLAN.md's explicit note that the regex operates on already-`sanitize_key()`-sanitized text), so this must still be accepted as `of_draft_contact-form`.
- How checked: curl + status assertion. This specifically tests that the Builder implements the allow-list check *after* calling `sanitize_key()`, not on the raw `$_POST['key']` (a plausible implementation mistake).

2.5 **Draft autosave — missing/empty key** (parity with original error behavior, best-effort)
- Input: `action=of_save_field` with no `key` param.
- Expected: some kind of JSON error (`success:false`); PLAN.md's design incidentally changes the HTTP status for this specific edge case from the original 400 to 403 (empty string doesn't match `^of_draft_...$` either, so it's now caught by the allow-list rejection instead of the original's explicit empty-string check) — this is a behavior change but not a regression of any *legitimate* use case (no real client sends an empty key), so the test should just confirm *some* error response, not insist on exact status-code parity with the pre-fix plugin.

## 3. Boundary / regex-correctness checks on the allow-list

3.1 `key=of_draft_` (prefix only, empty suffix) → must be **rejected** (PLAN.md explicitly requires non-empty suffix).
3.2 `key=of_draftx` (no underscore separator) → must be **rejected**.
3.3 `key=of_draft_a` (single-char suffix) → must be **accepted** (minimal valid legitimate key).
3.4 `key=xof_draft_x` (prefix not anchored at start) → must be **rejected** — tests that the Builder anchors the regex with `^...$`, not an unanchored `strpos`/`preg_match` without boundaries, since `preg_match('/of_draft_[a-z0-9_-]+/', 'xof_draft_xyz')` would wrongly match if anchors are forgotten.
3.5 `key=of_draft_users_can_register` → must be **accepted by the allow-list regex** (it matches the pattern), and `update_option()` is called with that literal option name — **not** the real `users_can_register` option. This is intentionally allowed by PLAN.md's design (see Gaps section below) and must be verified to NOT actually enable registration (`wp-login.php?action=register` still shows closed) even though the AJAX call itself returns success.

## 4. Non-regression / safety checks

4.1 **Plugin deactivation safety**: if `old-forms` plugin were deactivated, the mu-plugin's `function_exists('of_save_field')` guard should prevent a fatal error on every page load. Not independently executable without deactivating the plugin (which the Builder may not do, and we're not permitted to touch plugin state), so this is a code-review check against the delivered file rather than a live HTTP test: confirm the guard is present in the final `hotfix-old-forms.php`.
4.2 **No fatal errors / no PHP warnings**: load the homepage and any page containing `[old_form]` and confirm HTTP 200 with no visible PHP error/warning output and no WSOD. This is also effectively covered by `check-site.sh`'s general site-health checks.
4.3 **mu-plugin file location & permissions**: confirm the file exists at exactly `wp-content/mu-plugins/hotfix-old-forms.php` (WordPress only auto-loads top-level PHP files directly inside `mu-plugins/`, not in subdirectories) and starts with `if ( ! defined( 'ABSPATH' ) ) { exit; }` per the plan's own defensive note.
4.4 **Idempotency / hook priority correctness**: confirm (by code review of the delivered file, since this is an internal detail not independently observable via HTTP) that `remove_action('wp_ajax_of_save_field', 'of_save_field')` and the `nopriv` twin are called with the **same priority** (default `10`) that the original `add_action` calls used — a mismatched priority would silently fail to remove the original handler, and *both* the original (vulnerable) and the new handler would then run back-to-back on every request, defeating the fix while appearing to work in the "legitimate feature" tests (since the new handler's `wp_send_json_error`/`wp_send_json_success` call `wp_die()` and would terminate the request before the original handler ever runs — meaning this bug would NOT be caught by black-box HTTP testing at all, only by code review). **This is the single most important code-review item** given the fix is "remove old hook, add new hook" rather than a file patch.
4.5 Scope check: confirm no files outside `wp-content/mu-plugins/` and `wp-content/themes/bakery/` were created/modified (rules compliance), and that the mu-plugin contains no remote fetch (`wp_remote_*`, `curl_*`, `file_get_contents` on a URL) and no `eval`/`call_user_func` on request-derived strings.

## 5. Full-suite regression

5.1 Run `bash check-site.sh` and confirm it prints **ALL CHECKS PASS**. This is the authoritative, final gate and supersedes the hand-designed curl checks above if there is any conflict in exact status codes/response shape — the above scenarios are designed to be consistent with PLAN.md's stated behavior, but `checks.mjs`'s actual assertions are the ground truth for "pass."

---

## Gaps found in PLAN.md

1. **Unbounded option-name pollution via `of_draft_*` prefix is accepted by design, but not called out as a residual risk.** The allow-list regex `^of_draft_[a-z0-9_-]+$` accepts *any* suffix, including ones that shadow security-relevant-sounding names (e.g. `of_draft_users_can_register`, `of_draft_default_role`) or simply spam the `wp_options` table with arbitrary distinct rows (no length cap, no rate limit, no cap on number of distinct draft keys). This does **not** enable privilege escalation (WordPress core only ever reads the literal `users_can_register`/`default_role` options, not `of_draft_*`-prefixed variants), so it does not reopen CVE-2026-90003 itself — but it is a form of unauthenticated, unbounded arbitrary-option-creation that an attacker could still abuse for minor storage exhaustion / options-table bloat. PLAN.md does not mention this trade-off at all. Recommend: note it explicitly as an accepted residual risk (it's inherent to the plugin's own design — the original plugin's only legitimate use already requires accepting attacker-influenced-but-prefixed suffixes, since form IDs are arbitrary strings chosen by site content, not a fixed enumerable list) rather than leaving it as a silent gap. This should not block the fix (it's a correct, minimal fix for the actual CVE), but it is worth one sentence in PLAN.md or a code comment in the hotfix explaining why an unbounded suffix is accepted.

2. **Response-shape change for the "missing key" edge case is unexamined.** The original `of_save_field()` explicitly returns HTTP 400 when `$key === ''`. Under the proposed fix, an empty key never reaches the original function at all — it's caught by the new allow-list check first and gets whatever status PLAN.md specifies for *rejected* keys (403), not the original's 400. This is a harmless behavior change (no legitimate caller sends an empty key) but PLAN.md asserts the legitimate paths are "completely unchanged" (step 3 of Approach), which is not quite true for this one edge case. Low severity, but the plan's claim of "completely unchanged" for all non-exploit traffic is slightly overstated; worth a one-line caveat.

3. **Priority-mismatch failure mode is not mentioned as a testing concern.** PLAN.md's whole fix hinges on `remove_action()` successfully detaching the original handler (otherwise both handlers would be registered and, depending on execution order, either could run first — see Test 4.4 above for why this specific failure mode is dangerous and *invisible* to black-box testing: whichever handler wins the race, the request terminates via `wp_die()` inside `wp_send_json_*`, so from the outside both "the exploit is blocked" and "the legitimate feature works" could appear true while the vulnerable code path is still technically registered and could win nondeterministically under hook-priority ties or if the Builder's implementation deviates slightly from priority 10). PLAN.md does not call for a code-review step verifying the priority argument matches; this test plan adds it as item 4.4, but the Planner should ideally have flagged "verify removal priority matches add_action's original priority" as an explicit acceptance criterion rather than leaving it implicit in "Defensive/robustness notes."

4. **No scenario for an authenticated (non-nopriv) exploit attempt is in `checks.mjs`'s probe set, as far as can be determined from this file alone** — `check-site.sh` invokes `--probes old-forms`, and the advisory/CVE title emphasizes *unauthenticated* access, so the automated probe may only test the `nopriv` hook. PLAN.md correctly designs the fix to cover both `wp_ajax_of_save_field` and `wp_ajax_nopriv_of_save_field`, but if the automated check only exercises the unauthenticated path, the "also blocks authenticated misuse" half of the fix (test 1.5 above) would never be automatically verified. This isn't a contradiction in PLAN.md, just a coverage gap between what the plan fixes and what the automated gate can confirm — flagged here so a reviewer knows test 1.5/4.4 are the ones not provably covered by `check-site.sh` alone.

No contradictions were found between PLAN.md's stated approach and the actual plugin source in `old-forms.php` — the plan's description of both `of_subscribe` and `of_save_field` matches the code exactly (including the exact comment referenced for the `of_draft_<form id>` key shape), and the rule constraints (no plugin/core/DB edits, no remote fetch, no new users/roles) are all respected by the proposed design.
