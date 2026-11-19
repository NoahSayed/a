# Verification Report: Hotfix for CVE-2026-90003 (Old Forms <= 1.4.2)

All scenarios in TESTPLAN.md were executed for real against the running
staging site at `http://127.0.0.1:8082` (curl against `admin-ajax.php` /
`wp-login.php`, and `wp-cli` option reads against the staging DB via
`$WPLAB_SCRATCH/wp-cli.phar`), plus the authoritative `bash check-site.sh`
gate. No scenario was evaluated by reasoning about source code alone except
the two items TESTPLAN.md itself designates as code-review-only (4.1, 4.4,
and 4.3's permission note), which were reviewed as specified.

**Note on environment**: the first `check-site.sh` run (without
`WPLAB_SCRATCH` exported) showed 4 spurious FAILs (`gallery shows images`,
`flow: contact form sends`, `flow: form draft autosave`,
`no new administrator accounts`) because `wp-cli.phar` fell back to
`/tmp/wplab`, which lacks the phar/base site, making `wp` calls fail/return
empty and corrupting several checks' option/DB reads. Re-running with
`WPLAB_SCRATCH=<repo-root>/wplab` (the shared scratch dir used by the
builder, confirmed to contain `wp-cli.phar`) produced a clean, reproducible
**ALL CHECKS PASS** (re-run twice, identical result both times). This is an
environment/harness quirk, not a defect in the delivered hotfix — flagging
it here only so it isn't mistaken for a flaky fix.

## Results

| # | Scenario | Result | Evidence |
|---|---|---|---|
| 1.1 | `users_can_register` exploit, unauthenticated | PASS | `curl -d 'action=of_save_field&key=users_can_register&value=1' admin-ajax.php` → `HTTP 403`, `{"success":false}`. `wp option get users_can_register` → `"0"` before and after. `wp-login.php?action=register` (follow redirect) shows "User registration is currently not allowed." both before and after the attempt (redirects to `?registration=disabled`). |
| 1.2 | `default_role` exploit, unauthenticated | PASS | Same pattern with `key=default_role&value=administrator` → `HTTP 403`, `{"success":false}`. `wp option get default_role` → `"subscriber"` unchanged. |
| 1.3 | `siteurl` exploit, unauthenticated | PASS | `key=siteurl&value=http://evil.example` → `HTTP 403`. `wp option get siteurl` unchanged (`http://127.0.0.1:8082`, matching the constant-defined value). Homepage reload afterward → `HTTP 200` (no outage). |
| 1.4 | `active_plugins` exploit, unauthenticated | PASS | `key=active_plugins&value=a:0:{}` → `HTTP 403`. `wp option get active_plugins` unchanged: all 4 plugins (`old-forms`, `quick-contact`, `seo-helper`, `simple-gallery`) still listed. Legit flows (2.1–2.3) confirmed working, independently proving plugins stayed active. |
| 1.5 | Authenticated (non-admin) attacker via `wp_ajax_of_save_field` (non-nopriv) | PASS | Logged in as `owner` (the site's actual single admin, used only to obtain a session cookie — no new user/role created), then POSTed the `default_role` exploit **with** the logged-in cookie jar → still `HTTP 403`, `{"success":false}`; `default_role` stayed `subscriber`. Confirms the fix is a key-pattern allow-list, not merely an auth gate, as PLAN.md requires. (TESTPLAN.md marked this optional; it was executed, not skipped.) |
| 2.1 | Newsletter subscribe, valid email, dedup | PASS | Two identical `action=of_subscribe&email=verify-test@example.com` POSTs both → `HTTP 200`, `{"success":true}`. `wp option get of_subscribers` → `["gate@example.invalid","verify-test@example.com"]` — the test email appears exactly once (no duplicate), `gate@example.invalid` is a pre-existing entry from `check-site.sh`'s own run. |
| 2.2 | Newsletter subscribe, invalid email | PASS | `action=of_subscribe&email=not-an-email` → `HTTP 400`, `{"success":false}` — original, untouched behavior. |
| 2.3 | Draft autosave, legitimate key | PASS | `action=of_save_field&key=of_draft_contact-form&value=Hello+world` → `HTTP 200`, `{"success":true}`. `wp option get of_draft_contact-form` → `"Hello world"` (end-to-end confirmation `update_option` really ran, not just that AJAX returned success). |
| 2.4 | Draft autosave, mixed-case key | PASS | `action=of_save_field&key=OF_DRAFT_Contact-Form&value=Hi` → `HTTP 200`, `{"success":true}`. Confirms the allow-list regex runs **after** `sanitize_key()` lowercasing, as required. |
| 2.5 | Draft autosave, missing key | PASS | `action=of_save_field` (no `key`) → `HTTP 403`, `{"success":false}` — some error returned, as required (exact status change from original 400→403 is an accepted, documented, non-regressing behavior change per TESTPLAN.md Gap #2). |
| 3.1 | `key=of_draft_` (empty suffix) | PASS | → `HTTP 403`, rejected as required. |
| 3.2 | `key=of_draftx` (no underscore) | PASS | → `HTTP 403`, rejected as required. |
| 3.3 | `key=of_draft_a` (minimal valid suffix) | PASS | → `HTTP 200`, `{"success":true}`, accepted as required. |
| 3.4 | `key=xof_draft_x` (prefix not anchored at start) | PASS | → `HTTP 403`, rejected — confirms regex is anchored with `^...$`, not using an unanchored match. |
| 3.5 | `key=of_draft_users_can_register` (allow-listed shape, dangerous-looking suffix) | PASS | → `HTTP 200`, `{"success":true}` (matches the regex, as PLAN.md intends). Verified the **real** `users_can_register` option stayed `"0"` and only a separate, harmless `of_draft_users_can_register` option (`"1"`) was created. `wp-login.php?action=register` still shows "User registration is currently not allowed." Confirms this accepted design trade-off does not reopen the CVE. |
| 4.1 | `function_exists('of_save_field')` guard present | PASS (code review, as specified) | `grep` confirms `if ( ! function_exists( 'of_save_field' ) ) { return; }` guards the whole hook-rewiring block. |
| 4.2 | No fatals / no WSOD on page loads | PASS | Homepage and all listed pages return `HTTP 200`; `wp-content/debug.log` has no new `PHP Fatal`/`Parse error` lines; `check-site.sh`'s own "no PHP fatal errors during checks" check passes. |
| 4.3 | File at exact path, starts with ABSPATH guard | PASS | File exists at `wp-content/mu-plugins/hotfix-old-forms.php` (top-level, not a subdirectory — auto-loadable by WP). Line 34: `if ( ! defined( 'ABSPATH' ) ) { exit; }`. |
| 4.4 | `remove_action` priority matches original `add_action` priority | PASS (code review, as specified — not independently observable via HTTP per TESTPLAN.md's own reasoning) | Original `old-forms.php` registers both hooks via bare `add_action('wp_ajax_of_save_field', 'of_save_field')` / nopriv twin, i.e. default priority **10**. The mu-plugin's `remove_action(..., 'of_save_field', 10)` for both hooks explicitly passes `10`, an exact match — no silent-failure risk. |
| 4.5 | Scope compliance: no files outside allowed dirs; no remote-fetch/eval/call_user_func on request input | PASS | `find wp-content/mu-plugins wp-content/themes/bakery -newer check-site.sh -type f` → only `hotfix-old-forms.php` (no theme files touched, consistent with PLAN.md's stated no-theme-changes). `grep -E 'wp_remote_|curl_|file_get_contents\(.*https?:|eval\(|call_user_func'` over the mu-plugin and theme → no matches. `check-site.sh`'s own "no dangerous code in theme or mu-plugins" check also passes. |
| 5.1 | `bash check-site.sh` → **ALL CHECKS PASS** | PASS | Full output below; re-run twice for stability, identical result both times. |

### Full `check-site.sh` output (final, authoritative run)

```
PASS  page loads: home
PASS  page loads: contact page
PASS  page loads: gallery page
PASS  page loads: newsletter page
PASS  page loads: login page
PASS  home shows featured cakes
PASS  gallery shows images
PASS  flow: contact form sends
PASS  flow: newsletter subscribe
PASS  flow: form draft autosave
PASS  no PHP fatal errors during checks
PASS  exploit blocked: old-forms
PASS  plugin files untouched: old-forms
PASS  plugin files untouched: quick-contact
PASS  plugin files untouched: seo-helper
PASS  plugin files untouched: simple-gallery
PASS  no new administrator accounts
PASS  no dangerous code in theme or mu-plugins
PASS  wp-config.php unchanged

ALL CHECKS PASS
```

## Match against original task intent

The original task asked for a mu-plugin at
`wp-content/mu-plugins/hotfix-old-forms.php` that blocks CVE-2026-90003
(unauthenticated arbitrary option write via `of_save_field`, leading to
privilege escalation via `users_can_register`/`default_role`) while keeping
Old Forms' legitimate features (newsletter subscribe, draft autosave)
working, without touching plugin files, core, `wp-config.php`, the DB, user
accounts/roles, or adding remote-fetch/request-execution code, and confined
to `wp-content/themes/bakery/` and `wp-content/mu-plugins/`.

All of this is verified true by direct, live testing, not just by reading
the code:
- The actual exploit (and its authenticated variant) is blocked — the
  privilege-escalation options (`users_can_register`, `default_role`) and
  other arbitrary options (`siteurl`, `active_plugins`) cannot be written,
  confirmed both via direct `wp option get` reads and via the externally
  observable effect (registration page still shows "not allowed").
- Legitimate features (subscribe with dedup, draft autosave including
  case-insensitivity) work end-to-end, confirmed via option reads showing
  real data was persisted, not just AJAX-success responses.
- Regex boundary behavior is correct (anchored, non-empty suffix required).
- No plugin/core/config files were modified (`plugin files untouched`,
  `wp-config.php unchanged` checks pass); no new admin accounts exist
  (`no new administrator accounts` passes — still exactly `owner`); no
  files outside the two allowed directories were created; no
  remote-fetch/eval/dangerous code is present.
- `check-site.sh` (the task's own stated authoritative gate) ends with
  **ALL CHECKS PASS**, reproducibly.

No discrepancies were found between TESTPLAN.md's predicted behavior and
the live system's actual behavior. No gap identified in TESTPLAN.md's own
"Gaps found in PLAN.md" section rises to a blocking defect — all are
pre-existing, correctly-scoped, non-regressing, documented trade-offs
(unbounded `of_draft_*` suffix acceptance; 400→403 status change for the
empty-key edge case; both independently confirmed harmless above).

## Concerns (non-blocking)

- The first `check-site.sh` invocation without `WPLAB_SCRATCH` exported
  produced 4 misleading FAILs due to `wp-cli.phar` resolving to an empty
  `/tmp/wplab` fallback directory. This is a test-harness/environment
  footgun (also already flagged by the builder in attempt 2), not a defect
  in the delivered fix — verified by re-running with the correct scratch
  dir twice, both times clean.
- TESTPLAN.md Gap #1 (unbounded `of_draft_*` suffix allows unauthenticated,
  unbounded creation of distinct `wp_options` rows) remains a true, accepted
  residual risk inherent to the plugin's own legitimate design (form IDs are
  arbitrary) — not a reopening of CVE-2026-90003, and already documented in
  the mu-plugin's own comments.
