# Gatekeeper Report: CVE-2026-90003 (Old Forms) Hotfix

## Call: GO (pass)

## Why

1. **Plan was followed exactly, no deviations.** PLAN.md proposed a single
   mu-plugin (`wp-content/mu-plugins/hotfix-old-forms.php`) that, on
   `plugins_loaded`, detaches `of_save_field` from `wp_ajax_of_save_field`
   and `wp_ajax_nopriv_of_save_field` (matching the original's priority 10)
   and replaces it with a wrapper that only forwards to the real
   `of_save_field()` when `key` (after `sanitize_key()`) matches
   `^of_draft_[a-z0-9_-]+$`; otherwise it returns `wp_send_json_error(null, 403)`
   and never calls the vulnerable function. I read the delivered file and it
   implements this precisely — no extra behavior, no missing guard. The
   `function_exists('of_save_field')` guard, the ABSPATH exit guard, and the
   explicit priority-10 argument to `remove_action` (the one thing TESTPLAN.md
   flagged as the single most important code-review item, since a priority
   mismatch would silently leave the vulnerable hook registered) are all
   present and correct.

2. **Scope compliance verified independently, not just claimed.** I diffed
   `wp-content/themes/bakery/` against the production copy — byte-identical,
   and its files' mtimes predate PLAN.md, so the theme was never touched
   despite being in the allowed-edit list. The only file created anywhere is
   `wp-content/mu-plugins/hotfix-old-forms.php`. No plugin files, core files,
   `wp-config.php`, or the database were edited (confirmed by check-site.sh's
   own "plugin files untouched" / "wp-config.php unchanged" checks, which I
   re-ran and which passed). No new users or role changes were made or
   needed — the fix is at the hook-registration layer only.

3. **No secrets, no destructive commands, no scope creep.** The mu-plugin
   contains no remote-fetch calls, no `eval`/`call_user_func` on
   request-derived input, no credentials, and no code outside its stated
   purpose. I grepped for common dangerous patterns
   (`eval`, `base64_decode`, `exec`, `shell_exec`, `wp_remote_*`,
   `file_get_contents(...http`, `curl_init`, `system`) across the mu-plugin
   and theme directory — zero matches.

4. **Verification actually ran, I reproduced it myself rather than trusting
   the claim.** I independently executed `bash check-site.sh` (with
   `WPLAB_SCRATCH` pointed at the shared wp-cli scratch dir, same requirement
   the builder/verifier phases noted) against the live staging site at
   `http://127.0.0.1:8082` and got a fresh **ALL CHECKS PASS**, including
   `exploit blocked: old-forms`, `flow: form draft autosave`, and
   `flow: newsletter subscribe`. I also independently fired two raw curl
   requests at `admin-ajax.php`: the `users_can_register` exploit attempt
   returned `HTTP 403 {"success":false}` (blocked), and a legitimate
   `of_draft_mytest` autosave returned `HTTP 200 {"success":true}` (still
   works). Both match VERIFY.md's reported results exactly — the verifier's
   report reflects real, reproducible behavior, not a fabricated log.

5. **The one accepted residual risk (unbounded `of_draft_*` suffix allowing
   unauthenticated creation of arbitrary-named `of_draft_*` option rows) is
   real but correctly judged non-blocking** — it cannot be leveraged for
   privilege escalation (WordPress core never reads an `of_draft_`-prefixed
   variant of a security-relevant option) and is inherent to the plugin's
   own legitimate design (form IDs are arbitrary strings). It is documented
   in the mu-plugin's own comments, in PLAN.md's intent, and in
   TESTPLAN.md/VERIFY.md's gap analysis — not swept under the rug.

## Concerns noted (non-blocking)
- Running `check-site.sh` without `WPLAB_SCRATCH` exported produces 4
  spurious FAILs due to `wp-cli.phar` resolving to an empty fallback
  directory. This is a harness/environment quirk unrelated to the delivered
  fix (confirmed by re-running correctly, twice, with clean passes each
  time), but worth a human noting for future runs so it isn't mistaken for
  fix flakiness.
- The allow-list permits unauthenticated creation of unboundedly many
  distinct `of_draft_*` option rows (minor options-table bloat vector, not
  a privilege-escalation path) — an accepted, documented trade-off inherent
  to the plugin's own design, not a defect in this fix.
