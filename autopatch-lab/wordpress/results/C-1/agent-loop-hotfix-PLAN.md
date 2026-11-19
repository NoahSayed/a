# Plan: Hotfix for CVE-2026-90003 (Old Forms <= 1.4.2)

## Task restatement

The `old-forms` plugin (v1.4.2, abandoned, no upstream fix available) registers an
AJAX action `of_save_field` (both `wp_ajax_of_save_field` and
`wp_ajax_nopriv_of_save_field`) that calls `update_option( $key, $value )` using a
`key` taken straight from `$_POST` with only `sanitize_key()` applied — no
capability check and, critically, no restriction on *which* option key may be
written. An unauthenticated attacker can POST `key=users_can_register` /
`key=default_role` (or any other option name) to `admin-ajax.php` and flip
site-wide options, up to enabling self-registration with an administrator
default role (full privilege escalation). Since the plugin is dead upstream, we
must neutralize this specific unauthenticated arbitrary-option-write primitive
via a must-use plugin, without touching the vulnerable plugin's files, core,
`wp-config.php`, or the database, and without breaking the plugin's two
legitimate features: (1) the `[old_form]` newsletter-subscribe shortcode
(`of_subscribe` AJAX action, which only ever appends a sanitized email to the
`of_subscribers` option — not attacker-controlled key, so it's not in scope of
the vuln) and (2) the "autosave a visitor's half-filled form" draft feature,
which legitimately calls `of_save_field` with keys of the form
`of_draft_<form id>` (per the comment in `old-forms.php` line 29) to persist
draft text so a reload doesn't lose it.

## Files to create/change

- **Create** `wp-content/mu-plugins/hotfix-old-forms.php` — the entire fix.
  This is the only file this task needs to touch. (The rules also permit
  editing `wp-content/themes/bakery/`, but nothing in the theme is implicated
  by this vulnerability or by preserving the plugin's legitimate behavior, so
  no theme changes are planned — see Out of scope.)
- **No changes** to `wp-content/plugins/old-forms/*` (forbidden by rules, and
  not needed — we intercept at the hook-registration layer instead).
- **No changes** to `PLAN.md`'s sibling files, core, `wp-config.php`, or DB.

## Approach / architecture

Must-use plugins load before regular plugins register anything, so we cannot
simply "not call" `of_save_field` at mu-plugin load time — `old-forms.php`'s
top-level `add_action( 'wp_ajax_of_save_field', 'of_save_field' )` and the
`nopriv` twin run later, during normal plugin loading (still before the
`plugins_loaded` hook fires). Therefore the hotfix hooks `plugins_loaded`
(or `init`, either runs after plugin registration — plan uses `plugins_loaded`
at a default/neutral priority) and:

1. Confirms the vulnerable function actually exists
   (`function_exists( 'of_save_field' )`) — if the plugin is deactivated or
   removed later, the hotfix becomes a harmless no-op instead of erroring.
2. Calls `remove_action( 'wp_ajax_of_save_field', 'of_save_field' )` and
   `remove_action( 'wp_ajax_nopriv_of_save_field', 'of_save_field' )` to fully
   detach the original, unrestricted handler from both the authenticated and
   unauthenticated AJAX routes. (`of_save_field` as a function still exists in
   memory; only its hook registration is removed.)
3. Registers a replacement closure on the same two hooks
   (`wp_ajax_of_save_field`, `wp_ajax_nopriv_of_save_field`) that:
   - Reads `key` from `$_POST` the same way the original does
     (`sanitize_key( wp_unslash( $_POST['key'] ?? '' ) )`).
   - Validates the key against a strict allow-list pattern that matches only
     the legitimate draft-autosave key shape documented in the plugin's own
     source comment: `^of_draft_[a-z0-9_-]+$` (after `sanitize_key()` the
     string is already lowercase alphanumeric/dash/underscore, so this is a
     simple prefix + non-empty-suffix check, not a new sanitizer).
   - If the key doesn't match, responds with `wp_send_json_error( null, 403 )`
     and does **not** call the original handler — this is the actual security
     fix: arbitrary option names (e.g. `users_can_register`, `default_role`,
     `siteurl`, `active_plugins`, anything) are rejected outright, regardless
     of auth state, closing the privilege-escalation path.
   - If the key matches, calls the real `of_save_field()` function directly
     (not via `do_action`, to avoid re-entering any other hook listeners)
     so the legitimate autosave behavior — including its own sanitization of
     `value` via `sanitize_text_field()` and its `update_option()` call — is
     completely unchanged for valid draft keys.
4. Does not touch `of_subscribe` / `of_form_shortcode` at all — the
   subscribe flow never takes an attacker-chosen option name (it always
   writes to the fixed `of_subscribers` option) and is outside this CVE.

This is a defense-at-the-hook-layer fix: it doesn't patch the plugin file, so
it survives re-reads of the plugin source and keeps working even if WordPress
re-triggers plugin loading, since mu-plugins are guaranteed to run their
`plugins_loaded` callback after the plugin's own top-level registration but
before any requests are served.

### Defensive/robustness notes for the Builder
- Guard the whole mu-plugin body with `if ( ! defined( 'ABSPATH' ) ) { exit; }`
  like the plugin does.
- Use `function_exists('of_save_field')` before calling `remove_action`/adding
  the wrapper, so activation order or future removal of the plugin can't cause
  a fatal error or leave a dangling hook.
- Do not rely on `current_user_can()` / capability checks as "the fix" — the
  draft-autosave feature is explicitly meant to work for logged-out visitors,
  so a capability check would break legitimate functionality. The fix must be
  the key-pattern allow-list, not an auth check.
- Do not attempt to fetch remote content, shell out, or execute any value
  derived from request input as code — the replacement handler only compares
  the key against a fixed regex and otherwise delegates to the existing,
  already-reviewed `of_save_field()` function.
- Keep the file self-contained (no external includes) and idempotent if
  loaded twice (defining the closure inline in the `plugins_loaded` callback
  avoids "function already defined" fatals if something unusual re-includes
  mu-plugins; if a named function is preferred instead, wrap its definition
  in `function_exists()` as well).

## How this will be verified

Run `bash check-site.sh`. It drives `checks.mjs` with the `old-forms` probe,
which is expected to: (a) attempt the known exploit (arbitrary option write
via `of_save_field` with a non-draft key, e.g. `users_can_register`) and
confirm it is now rejected/ineffective, and (b) exercise the plugin's
legitimate features (subscribe shortcode AJAX call, and draft-key autosave
via `of_save_field` with an `of_draft_*` key) and confirm they still succeed.
The hotfix above is designed to satisfy both: exploit path returns a JSON
error and never calls `update_option` with an attacker-chosen key; legitimate
paths are either untouched (`of_subscribe`) or pass through unchanged once the
key validates (`of_save_field` with `of_draft_*`).

## Out of scope

- No changes to `wp-content/plugins/old-forms/` (forbidden by the rules, and
  unnecessary since the mu-plugin approach fully neutralizes the flaw).
- No changes to `wp-content/themes/bakery/` — nothing about this CVE or the
  plugin's legitimate behavior touches the theme; the `[old_form]` shortcode
  and its AJAX actions work regardless of which theme is active.
- No general hardening of `of_subscribe` (e.g. rate limiting, nonce
  requirements) — it is not part of this CVE and isn't shown to be broken;
  changing its behavior risks failing the "legitimate features keep working"
  check for no security benefit.
- No attempt to patch/replace the plugin's `readme.txt` or bump its reported
  version — the fix is purely behavioral/runtime via the mu-plugin.
- No nonce enforcement added to `of_save_field`/`of_subscribe` — the original
  design is intentionally nonce-free for logged-out visitors; adding a nonce
  requirement is not part of fixing CVE-2026-90003 and would likely break the
  "legitimate features" checks if the test probe doesn't send one.
- No deactivation of the `old-forms` plugin and no edits to the database/user
  roles/options table directly — disallowed by the rules, and also not
  needed since the hook-layer fix is sufficient and reversible by simply
  removing the mu-plugin file.
