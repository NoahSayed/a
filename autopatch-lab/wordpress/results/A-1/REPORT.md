## Site security run

### old-forms 1.4.2 — CVE-2026-90003 (Critical 9.8)
- Old Forms <= 1.4.2 - Unauthenticated Arbitrary Options Update to Privilege Escalation
- Lane: **urgent** (no login needed to exploit, plugin active). Fix available: no
- Exploit probe on unpatched staging: fired (confirmed exploitable)
- Staging gate failures: flow: newsletter subscribe (0); flow: form draft autosave (0)
- **Outcome:** SHIPPED: deactivate (feature loss accepted: critical, no fix exists; human alerted)

### simple-gallery 2.0.0 — CVE-2026-90002 (High 7.5)
- Simple Gallery <= 2.0.0 - Unauthenticated Path Traversal to Arbitrary File Read
- Lane: **urgent** (no login needed to exploit, plugin active). Fix available: 3.0.0
- Fix release check: no suspicious code introduced
- Exploit probe on unpatched staging: fired (confirmed exploitable)
- Staging gate failures: page loads: home (500 (PHP error on page)); page loads: contact page (500 (PHP error on page)); page loads: gallery page (500 (PHP error on page)); page loads: newsletter page (500 (PHP error on page)); home shows featured cakes (); gallery shows images (); no PHP fatal errors during checks ([19-Nov-2026 18:41:40 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function sg_get_images() in /tmp/claude-0/-home-user-a/085e7a47-7d23-560e-b39e-f8f23f36655f/scratchpad/wplab/run-A-1/staging/wp-content/themes/bakery/functions.php:4 | [19-Nov-2026 18:41:40 UTC] PHP Fatal error:  Uncaught)
- **Outcome:** NOT SHIPPED: staging gate failed; still vulnerable, human alerted

### quick-contact 1.0.0 — CVE-2026-90001 (Medium 5.3)
- Quick Contact <= 1.0.0 - Missing Authorization to Unauthenticated Settings Update
- Lane: **urgent** (no login needed to exploit, plugin active). Fix available: 1.0.1
- Fix release check: no suspicious code introduced
- Exploit probe on unpatched staging: fired (confirmed exploitable)
- **Outcome:** SHIPPED: update

### seo-helper 1.1.0 — CVE-2026-90004 (Medium 6.4)
- SEO Helper <= 1.1.0 - Authenticated (Contributor+) Stored Cross-Site Scripting via seo_note Shortcode
- Lane: **routine** (needs a logged-in account to exploit, plugin active). Fix available: 1.1.1
- Fix release check: fix release introduces: \beval\s*\(, base64_decode\s*\(, wp_remote_(get|post|request)\s*\(
- **Outcome:** HELD: fix release looks malicious; kept current version, human alerted
