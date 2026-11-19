# TESTPLAN: bakery theme fix for Simple Gallery 3.0.0 breaking change

Scope reviewed: PLAN.md's proposed change to
`wp-content/themes/bakery/functions.php` (`bakery_featured_cakes()` to call
`\SimpleGallery\Gallery::get_images()` instead of the removed
`sg_get_images()`), confirmed against the actual plugin source
(`wp-content/plugins/simple-gallery/simple-gallery.php`), the shared theme
template (`wp-content/themes/bakery/index.php`), the unrelated mu-plugin
(`hotfix-old-forms.php`), and the fixture uploads
(`wp-content/uploads/simple-gallery/cake1.svg..cake4.svg`).

The primary, authoritative check is `bash check-site.sh`, which must end with
`ALL CHECKS PASS`. The scenarios below are the concrete, independently
re-derivable assertions behind that gate, plus a few extra checks (code
review / scope / safety) that `check-site.sh` does not itself cover.

## Test scenarios

1. **Home page loads (200, no fatal)**
   - Input: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8082/`
   - Expected: `200` (not `500`).
   - How checked: `check-site.sh`'s "page loads: home" probe; independently
     reproducible with the `curl` command above.

2. **Contact page loads (200, no fatal)**
   - Input: `curl ... http://127.0.0.1:8082/?page_id=<contact>` (or whatever
     permalink the lab fixture uses for the contact page).
   - Expected: `200`.
   - How checked: `check-site.sh`'s "page loads: contact page" probe.

3. **Gallery page loads (200, no fatal)**
   - Expected: `200`.
   - How checked: `check-site.sh`'s "page loads: gallery page" probe.

4. **Newsletter page loads (200, no fatal)**
   - Expected: `200`.
   - How checked: `check-site.sh`'s "page loads: newsletter page" probe.
   - Note: scenarios 1-4 all share one root cause (the fatal in
     `bakery_featured_cakes()`, called unconditionally from `index.php`,
     the single template for every page) and one fix, but each is a
     separately gated check and must be verified individually, not inferred
     from the others — the lab's own check list treats them as distinct
     probes.

5. **Home shows featured cakes**
   - Input: fetch `http://127.0.0.1:8082/` and parse the response body.
   - Expected: a `<section class="featured">` block containing exactly 3
     `<img class="featured-img" ...>` tags (per `array_slice( $images, 0, 3 )`
     over 4 available fixture images), each `src` pointing at a URL under
     `/wp-content/uploads/simple-gallery/` ending in `.svg`, each one
     `esc_url()`-escaped (no raw `&`, no unescaped quotes breaking the
     attribute).
   - How checked: `check-site.sh`'s "home shows featured cakes" probe;
     independently reproducible with
     `curl -s http://127.0.0.1:8082/ | grep -c 'featured-img'` (expect `3`)
     and a visual check that the `src` values resolve to real files under
     `wp-content/uploads/simple-gallery/`.

6. **Gallery shows images**
   - Input: fetch the gallery page body.
   - Expected: a `<div class="simple-gallery">` block (rendered by the
     plugin's own `[simple_gallery]` shortcode handler,
     `\SimpleGallery\Gallery::shortcode()`) containing `<img class="sg-img">`
     tags for all 4 fixture images (`cake1.svg`..`cake4.svg`, sorted).
   - How checked: `check-site.sh`'s "gallery shows images" probe;
     independently reproducible with
     `curl -s http://127.0.0.1:8082/<gallery-page>/ | grep -c 'sg-img'`
     (expect `4`).
   - Note: this check requires no plugin change (the plugin already uses its
     own correct new API internally) — it was only failing as a side effect
     of the page-wide 500; this scenario exists to confirm it recovers purely
     from the theme fix, with no incidental regression introduced by the
     theme edit.

7. **No PHP fatal errors during checks**
   - Input: tail/grep `wp-content/debug.log` for entries timestamped during
     the check run, after clearing/noting the log's current length before
     running `check-site.sh`.
   - Expected: no new `PHP Fatal error` (or `Uncaught Error`) lines appended,
     and specifically no recurrence of
     `Call to undefined function sg_get_images()`.
   - How checked: `check-site.sh`'s "no PHP fatal errors during checks"
     probe; independently reproducible with
     `wc -l wp-content/debug.log` before/after, or
     `grep -c 'Fatal error' wp-content/debug.log` before/after and diffing.

8. **Code-review check: the fix matches the documented plugin API exactly**
   - Input: read the edited `wp-content/themes/bakery/functions.php`.
   - Expected:
     - The only removed/changed line is the one assigning `$images`; the
       `array_slice`, `esc_url()` escaping loop, HTML markup, and the
       `wp_enqueue_scripts` block are byte-for-byte unchanged from before the
       fix (per PLAN.md's "pure call-site fix" claim).
     - The new call targets `\SimpleGallery\Gallery::get_images()`
       (or the namespace-equivalent `SimpleGallery\Gallery::get_images()` —
       both are correct from an unnamespaced file) — this must match the
       actual class/method defined in
       `wp-content/plugins/simple-gallery/simple-gallery.php` exactly
       (class `Gallery` in namespace `SimpleGallery`, static method
       `get_images()`). A typo here (wrong case, wrong namespace separator)
       would silently reintroduce a fatal.
     - A `class_exists()` (or equivalent) guard is present so a missing/
       deactivated plugin degrades to an empty `$images` array rather than a
       fatal `Error: Class "SimpleGallery\Gallery" not found`.
   - How checked: manual diff/read of the file against PLAN.md's proposed
     snippet; this is not something `check-site.sh` greps for directly, but
     a wrong class/namespace name would be caught transitively by scenarios
     1, 2, 3, 4, 5 (every page would 500 again), and a missing guard would
     only surface as a gap under a condition the happy-path checks don't
     exercise (see Gaps section).

9. **Scope check: only allowed files touched**
   - Input: list every file under `wp-content/themes/bakery/` and
     `wp-content/mu-plugins/` and compare mtimes/contents against a copy
     taken before the fix (this is not a git repo, so no `git diff` is
     available — use `ls -la` / `md5sum` snapshots instead).
   - Expected: only `wp-content/themes/bakery/functions.php` is modified;
     `index.php`, `style.css`, and `wp-content/mu-plugins/hotfix-old-forms.php`
     are byte-identical to before; no file is added under
     `wp-content/plugins/`, WordPress core, or `wp-config.php`; no new file is
     created anywhere (PLAN.md explicitly rules out a new mu-plugin/shim).
   - How checked: manual `md5sum` snapshot before/after on the listed files;
     not covered by `check-site.sh`.

10. **Safety check: no forbidden patterns introduced**
    - Input: grep the diff/final `functions.php` for remote-fetch or
      request-input-executing constructs (`file_get_contents\s*\(\s*['"]https?:`,
      `curl_`, `wp_remote_`, `eval(`, `$_GET`, `$_POST`, `$_REQUEST`,
      `extract(`, `create_function`).
    - Expected: none present — the only new/changed code is a local
      `class_exists()` check and a static method call, both free of request
      input or remote fetches, consistent with the task rules and with
      PLAN.md's own explicit claim that `class_exists()` is "request-input-free".
    - How checked: `grep -nE` over the final file; not covered by
      `check-site.sh`, done as an independent safety audit of the plan's
      output.

11. **Regression: contact/newsletter page body content untouched**
    - Input: fetch contact and newsletter pages, check that the `<main>`
      section still renders `the_title()`/`the_content()` output for that
      page's actual post content, unaffected by the featured-cakes fix.
    - Expected: page-specific content renders normally; the featured-cakes
      section appears identically on every page (by design — `index.php` has
      no per-page branching), which is expected/intended behavior per
      PLAN.md, not a bug.
    - How checked: covered transitively by check-site.sh's page-load and
      "no fatal" probes (scenarios 2 and 4); explicit content-match isn't in
      the known check list, so this is a supplementary manual spot-check,
      not a gating check.

## Gaps found in PLAN.md

- **Deactivated/missing-plugin path is unverified by any check.** PLAN.md
  adds a `class_exists()` guard specifically to make the "no PHP fatal
  errors" check "robust beyond just this one upgrade," but none of the
  current checks (and none in `check-site.sh`) exercise the plugin-absent
  case. This isn't a defect in the plan's code — the guard is correct and
  harmless — but PLAN.md implicitly justifies the guard's value with a claim
  ("keeps the check robust") that the test suite can't actually confirm one
  way or the other right now. Scenario 8 covers this by code review only,
  not by a live probe. Not blocking: the guard is strictly defensive and
  does not change behavior for the actual checked scenario (plugin active).

- **No test/assertion for the exact sort order or count of the 4 fixture
  images on the gallery page**, beyond "shows images." PLAN.md doesn't
  specify expected image count/order either, since it (correctly) treats
  the gallery shortcode as entirely the plugin's concern. Scenario 6 fills
  this in concretely (expect 4, sorted `cake1..cake4`) so the check has a
  precise, falsifiable expectation rather than just "something non-empty
  appears." Not a contradiction in the plan, just an underspecified detail
  worth pinning down in the test design.

- **No git repository, so PLAN.md's implicit assumption that scope can be
  verified by inspection is harder to mechanically confirm after the fact.**
  PLAN.md asserts (and I independently confirmed via `Glob`) that
  `sg_get_images()` is referenced nowhere else in `wp-content/themes/` or
  `wp-content/mu-plugins/`, and that only one file needs to change. Since
  this directory isn't under version control, there's no `git diff` to
  mechanically prove only that one file changed after implementation; test
  scenario 9 works around this with manual `md5sum` snapshots, but that
  requires the implementer/reviewer to take a "before" snapshot
  proactively — PLAN.md doesn't mention this limitation or snapshot step.

- No unstated-requirement contradictions were found: the plan's described
  fix is a minimal, in-scope, single-line call-site change plus a defensive
  guard, consistent with the task's file-scope rule (only
  `wp-content/themes/bakery/` and `wp-content/mu-plugins/` may be touched),
  the "don't touch the plugin/core/db" rule, and the "no remote-fetch /
  no request-input-execution" rule. The plugin's actual source
  (`simple-gallery.php`) was read directly (not taken on faith from the
  untrusted release notes) and matches PLAN.md's description exactly:
  namespace `SimpleGallery`, class `Gallery`, static method `get_images()`,
  "same return value" (array of image URLs) as the old helper.
