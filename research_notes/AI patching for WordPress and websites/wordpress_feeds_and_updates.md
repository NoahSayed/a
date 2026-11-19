# WordPress Vulnerability Intelligence and Update Mechanics (as of Nov 19, 2026)

Method note: every direct page fetch to wordfence.com, patchstack.com, make.wordpress.org and roots.io failed. The session's network policy blocks those hosts (DNS ENOTFOUND). wordpress.org and wpscan.com were not fetched directly either. The findings below rely on web-search result snippets and on fetches from hosts that were allowed (raw.githubusercontent.com, github.com). Where a figure comes only from a secondary aggregator, I say so. The search tool returns summarized snippets, so treat exact wording as approximate and check exact numbers against the primary page before publishing.

## 1. Where WordPress vulnerability data comes from and how to consume it programmatically

### Takeaway
The best free, machine-readable, commercially usable feed is the Wordfence Intelligence Vulnerability Data Feed v3. It is one bulk JSON file of 117 MB or more, needs a free API key, and v1/v2 were switched off on Mar 9, 2026. WPScan is free only for non-commercial use (25 calls/day); commercial use requires an enterprise quote. Patchstack's API is metered per call (5,000/day on the Standard tier) and its prices are not public. OSV and GitHub advisories barely cover WordPress plugins. Composer users bridge the gap with Roots' "WP Sec Adv", a Composer advisory repository built from Wordfence data.

### Cited Findings
**Wordfence Intelligence (Defiant)**
- v3 has two endpoints. `/api/intelligence/v3/vulnerabilities/production` serves fully analyzed records. `/api/intelligence/v3/vulnerabilities/scanner` holds detection-only data and includes new vulns that are not yet ready for the production feed. Both require a bearer token, which you create under Integrations in a wordfence.com account. "The only change is that Version 3 requires authentication with a free API Key." — [Wordfence v3 docs](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) (via search snippet; fetch blocked)
- Clients that request the feed too often get HTTP 429. The docs give no numeric rate limit. — [Wordfence v3 docs](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) (search snippet)
- Versions 1 and 2 of the feed API "will be disabled on March 9, 2026", and users are told to migrate to v3. — [Wordfence v2 docs](https://www.wordfence.com/help/wordfence-intelligence/v2-accessing-and-consuming-the-vulnerability-data-feed/) / [v3 docs](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) (search snippet)
- The production feed was over 117 MB as of Oct 2025. A PHP client that decodes it in one pass runs out of memory unless you raise the limit (e.g. `php -d memory_limit=512MB`), so streaming or chunked parsing is advisable. — [typisttech/wordfence-api README](https://github.com/typisttech/wordfence-api)
- Data is "free for personal and commercial use". The only limits are attribution: for MITRE-sourced vulns, and for Wordfence's own vulns. Each record carries the data needed to show that attribution in a UI. — [Wordfence blog, Dec 2022 launch](https://www.wordfence.com/blog/2022/12/wordfence-free-vulnerability-database/)
- The current Wordfence Intelligence Terms and Conditions (last updated Jan 26, 2026) say feed access requires an API key generated in a wordfence.com account. Copying the vulnerability info requires a hyperlink to the vulnerability record and keeping Defiant's copyright designation and license. — [Wordfence Intelligence T&C](https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/) (search snippet). Older developer docs said "no authentication" (v1/v2 era); the T&C and v3 docs supersede them.
- Wordfence CLI's vulnerability scanning is powered by this same feed. — [Wordfence CLI 2.0.1 announcement](https://wordfence.com/?p=32490) (search snippet)
- Wordfence has a vendor-facing "Vulnerability Management Portal" with its own terms. — [Wordfence VMP terms](https://www.wordfence.com/threat-intel/vendor/vulnerability-management-portal/terms/)
- Volume, as Wordfence counts it: 8,233 distinct new WordPress vulns published in 2024, of which Wordfence processed 41.7%. Through Apr 28, 2025 there were 4,534 new 2025 vulns, of which Wordfence processed 29%. — [Wordfence blog, Apr 2025](https://www.wordfence.com/blog/2025/04/wordfence-the-worlds-leading-quality-wordpress-vulnerability-intelligence-provider/) (search snippet). Note: Wordfence uses this post to argue it leads on data quality.

**WPScan**
- WPScan's pricing page says the API requires a paid license for commercial use, priced by custom quote. Non-commercial use gets up to 25 API calls/day. Enterprise features include pricing by number of sites, instant email alerts, vuln details by ID, webhooks (Slack/HTTP), and description and PoC data. The WPScan CLI is free to use without the API. — [wpscan.com/pricing](https://wpscan.com/pricing/) (search snippet; the page title says it catalogs "75,549 WordPress core, plugin, and theme vulnerabilities", date of that count unknown)
- Historical terms: the 2019 announcement offered 50 free daily requests, and €25/mo for 250/day. A 2021 archived pricing page listed 25/day free, a 300/day tier and unlimited enterprise. — [WPScan blog 2019](https://wpscan.com/blog/lots-of-wpvulndb-changes/); [archived wpscan.com/api 2021](https://webcf.waybackmachine.org/web/20211006015355/https://wpscan.com/api)
- A third-party listing says there are no self-serve paid plans. — via search summary of [cybersectools.com](https://cybersectools.com/tools/wpscan.md) (secondary)
- User complaints about Jetpack integration limiting the free tier appear in an undated third-party listing. — [10web.io](https://10web.io/wordpress-plugin/wpscan) (secondary, low weight)

**Patchstack**
- The Threat Intelligence API has three tiers. Standard returns vulns for a single version of a plugin, theme or core, capped at 5,000 calls per 24h, and is bought via the Patchstack App. Extended adds bulk multi-plugin calls and more detail endpoints, at custom pricing on request. Beta covers WordPress plus npm and is for selected partners only. — [Patchstack API docs (Netlify deploy-preview mirror)](https://deploy-preview-34--deluxe-meerkat-8daf24.netlify.app/api-solutions/threat-intelligence-api/overview/). Note: this is a preview build, not the canonical docs domain, so treat it as provisional.
- The public database has per-plugin pages, e.g. `patchstack.com/database/vulnerability/<slug>`. — [example](https://patchstack.com/database/vulnerability/wp-mlm)

**WordPress.org Plugin API (closed plugins)**
- `api.wordpress.org/plugins/info/1.2/` returns a bare `{"error": "closed"}` for every closed plugin. It does not say whether the closure is for a security issue, guideline violation, author request, or whether it is permanent. Trac #8214 (Apr 2026, enhancement, status "new") asks for closure reason and permanence in the API. The HTML plugin pages already show this detail. — [Meta Trac #8214](https://meta.trac.wordpress.org/ticket/8214); [wp-meta list, Apr 2026](https://lists.wordpress.org/pipermail/wp-meta/2026-April/062864.html)
- Core's `plugins_api()` turns an error response into `WP_Error('plugins_api_failed')`. — [developer.wordpress.org plugins_api](https://developer.wordpress.org/?p=4897)
- The Composer plugin `typisttech/wp-org-closed-plugin` queries this API to mark closed plugins as abandoned. It does not change composer.lock "since plugin closure might be temporary". — [Packagist](https://packagist.org/packages/typisttech/wp-org-closed-plugin)

**CVE / CNA context**
- The volume of WordPress vulns disclosed has grown steadily since 2022, when several WordPress security companies became CVE Numbering Authorities. — [Wordfence 2024 Annual Report](https://www.wordfence.com/blog/2025/04/2024-annual-wordpress-security-report-by-wordfence/?web=1) (search snippet)
- One CNA's 2025 disclosures: 73.8% of its 3,016 vulns (counted by affected software) were in software with fewer than 1,000 active installs. — [Wordfence blog, Apr 2025](https://www.wordfence.com/blog/2025/04/wordfence-the-worlds-leading-quality-wordpress-vulnerability-intelligence-provider/) (snippet; it does not name the CNA, which appears to be a competitor)

**OSV / GitHub Advisory Database / Composer**
- GHSA imports from GitHub-reported advisories, NVD, npm, FriendsOfPHP, Go, Python, Ruby and RustSec. WordPress plugins are not a listed source or ecosystem. — [GitHub docs: About the GitHub Advisory Database](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/about-the-github-advisory-database)
- Community OSV-format WordPress datasets exist, e.g. `cydave/wphash-vuln-data`. — [GitHub](https://www.github.com/cydave/wphash-vuln-data)
- `composer audit` checks Packagist PHP packages but "has no awareness of WordPress plugin and theme advisories". Roots' **WP Sec Adv** serves Wordfence Intelligence data as a Composer repository and matches advisories to packages by slug. Roots also offers **WP Packages**, a WPackagist replacement it says is "17x faster and updates every 5 minutes". — [Roots: Auditing WordPress vulnerabilities with Composer](https://roots.io/bedrock/docs/auditing-wordpress-vulnerabilities-with-composer/); [Roots: WP Sec Adv](https://roots.io/wp-sec-adv-wordpress-security-advisories-for-composer.md) (search snippets; fetch blocked)

### Inferences
- An auto-patcher's backbone should be a periodic (e.g. hourly) pull of the Wordfence v3 *scanner* feed, used for speed, joined to the *production* feed, used for detail. Match on (software type, slug, installed version) against each site's inventory. Patchstack's per-version API, at 5,000 calls/day on Standard, suits on-demand checks of a single site, not a bulk mirror.
- WPScan's 25-calls/day free tier is non-commercial only, so a commercial AI patching product cannot rely on it without an enterprise contract.
- The closed-plugin API signal (`{"error":"closed"}`) is a cheap way to flag abandoned or security-closed plugins. The reason has to be inferred, e.g. by cross-referencing vuln feeds.
- Coverage differs between vendors, and each vendor publishes stats that favor itself (Wordfence counted 8,233 vulns for 2024; Patchstack counted ~7,966). Using several feeds and deduplicating by CVE gives better recall.

### Gaps
- I could not fetch Wordfence's v3 field schema. Field names (`software[].slug`, `affected_versions`, `patched`, `patched_versions`, `cvss`, `cwe`, `references`, `copyrights`, `informational`) are known from training data on the v1/v2 schema but are **not verified for v3** here.
- I found no current (2026) WPScan prices and no confirmation of Automattic ownership in what I could reach. Background knowledge says Automattic acquired WPScan in 2021, but this is unverified here.
- I found no public Patchstack API prices, nor confirmation of the canonical docs URL.
- I did not confirm whether Roave/security-advisories carries any WordPress-plugin entries. Searches returned nothing.
- I did not confirm which CNAs (Wordfence, Patchstack, WPScan) are currently active, beyond the "several companies became CNAs in 2022" statement.

## 2. Scale and shape of the WordPress vulnerability problem (2024–2026)

### Takeaway
Patchstack counted 11,334 new WordPress-ecosystem vulns in 2025, up 42% from 7,966 in 2024. About 91% were in plugins, about 9% in themes, and core had only a handful. Exploitation is extremely fast: Patchstack reports a 5-hour median from disclosure to mass exploitation for heavily targeted flaws. 2026 brought the first critical unauthenticated core RCE in nearly a decade (wp2shell, July 2026) plus a run of plugin flaws exploited the same day they were disclosed.

### Cited Findings
**Annual counts**
- 2025: 11,334 new vulns, +42% vs 7,966 in 2024. Plugins 91%, themes 9%. "Highly exploitable" vulns rose 113% YoY. Broken Access Control was the most exploited type. — Patchstack *State of WordPress Security in 2026*, as reported by [websiterating.com](https://www.websiterating.com/tools/wordpress-plugin-security-dumpster-fire/), [web60.ie](https://web60.ie/blog/wordpress-plugin-vulnerabilities-surge-2026) and [jorijn.com](https://jorijn.com/en/blog/wordpress-plugins-are-your-biggest-security-risk/). These are secondary sources; the primary is [patchstack.com whitepaper](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2026/) (blocked).
- Core vulns in 2025: one secondary source says 6 (all low risk), another says 2. **The sources conflict.** — via secondary coverage above
- Wordfence count: 8,233 distinct new WordPress vulns published in 2024. 2024 disclosures were up 68% vs 2023. — [Wordfence blog Apr 2025](https://www.wordfence.com/blog/2025/04/wordfence-the-worlds-leading-quality-wordpress-vulnerability-intelligence-provider/); [Wordfence 2024 Annual Report](https://www.wordfence.com/blog/2025/04/2024-annual-wordpress-security-report-by-wordfence/?web=1) (snippets)
- Q3 2025: 1,857 vulns published, down 32.4% QoQ. — [Wordfence Q3 2025 report](https://www.wordfence.com/blog/2025/10/quarterly-wordpress-threat-intelligence-report-q3-2025/) (snippet). A Q4 2025 report exists ([link](https://www.wordfence.com/blog/2026/02/quarterly-wordpress-threat-intelligence-report-q4-2025/)), but I could not extract its figures.
- WPScan's catalog stands at 75,549 core, plugin and theme vulns cumulative, date of count unknown. — [wpscan.com/pricing](https://wpscan.com/pricing/)

**Unpatched at disclosure**
- About 46% of reported vulns did not get a developer patch before public disclosure (2025 data, Patchstack 2026 report). — secondary, per [search summaries of swif.ai / colorlib](https://www.swif.ai/blog/wordpress-security-statistics). The Patchstack 2025 whitepaper (2024 data) reportedly said 52%. — secondary. Neither figure was verified against the primary.
- A Bitdefender analysis reportedly found about 30% of critical WordPress plugin vulns are never patched. — secondary mention only; unverified

**Premium plugins**
- 76% of vulns in premium components were exploitable in real attacks. Patchstack's Zero Day program found 33 highly critical vulns in premium components vs 12 in free ones. Premium components had 3× more Known Exploited Vulnerabilities than free. Premium code gets less scrutiny because researchers have a harder time getting the code. — Patchstack 2026 whitepaper via [digitrendz.blog](https://digitrendz.blog/tech-news/140855/the-state-of-wordpress-security-in-2026-premium-plugin-risks-and-5-hour-exploits/) and [searchenginejournal](https://searchenginejournal.com/report-shows-wordpress-sites-are-getting-hacked-at-faster-rate/568510/) (secondary)

**Time to exploit**
- For heavily targeted, high-impact flaws: median of 5 hours from disclosure to mass exploitation, and 45% exploited within 24h. — Patchstack 2026 report via [jorijn.com](https://jorijn.com/en/blog/wordpress-plugins-are-your-biggest-security-risk/) / [digitrendz](https://digitrendz.blog/tech-news/140855/the-state-of-wordpress-security-in-2026-premium-plugin-risks-and-5-hour-exploits/) (secondary)
- **wp2shell (core, July 2026):** CVE-2026-63030 (REST API batch-route confusion) chained with CVE-2026-60137 (core SQLi) gives pre-auth RCE with no plugin or login needed. Affected versions: 6.9.0–6.9.4 and 7.0.0–7.0.1; the 6.8 branch lacks the full chain. Fixed Jul 17, 2026 in 6.9.5, 7.0.2 and 6.8.6, and force-pushed through core auto-update. Wordfence describes it as "the first critical unauthenticated WordPress core RCE in nearly a decade" and says exploitation began within hours of the patch. Sources conflict on early exploitation status; some report public PoCs within days and a later CISA KEV listing. — [Wordfence wp2shell aftermath, Jul 2026](https://www.wordfence.com/blog/2026/07/wp2shell-aftermath-the-first-critical-unauthenticated-wordpress-core-rce-in-nearly-a-decade/); [The Hacker News](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html); [Expert Insights](https://expertinsights.com/news/wordpress-force-pushes-fix-for-wp2shell); [BleepingComputer](https://bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now); [Indusface](https://www.indusface.com/blog/wp2shell-wordpress-cve-2026-60137-63030-rce/)
- Burst Statistics (CVE-2026-8181): exploitation confirmed the same day as the May 14, 2026 disclosure, and Wordfence blocked over 7,400 attacks in 24h. — [dailysecurityreview](https://dailysecurityreview.com/resources/burst-statistics-cve-2026-8181-draws-7400-attacks-in-24-hours/)
- WP Maps Pro (CVE-2026-8732, admin account creation): 2,858 attacks blocked in the 24h before disclosure per TNW, while another report says 3,600+ in one day. The figures conflict. — [TheNextWeb](https://thenextweb.com/news/wp-maps-pro-wordpress-vulnerability-admin-accounts-cve-2026-8732); [TechRadar](https://www.techradar.com/pro/security/wp-maps-pro-plugin-flaw-to-create-admin-accounts-on-wordpress-sites-saw-3-600-attempts-in-a-single-day)
- Breeze Cache plugin, under active exploitation in May 2026. — [Wordfence, May 2026](https://www.wordfence.com/blog/2026/05/attackers-actively-exploiting-critical-vulnerability-in-breeze-cache-plugin/)
- Super Forms and Elementor Pro RCEs (Aug 2026): more than 440,000 exploit attempts blocked. — [thecybersecguru](https://thecybersecguru.com/?p=24960) (secondary)
- Gravity SMTP (CVE-2026-4020): mass exploitation to steal API keys, about 100k sites exposed. — [TheNextWeb](https://thenextweb.com/news/gravity-smtp-wordpress-plugin-vulnerability-cve-2026-4020-api-keys-exploit)
- Old flaws stay exploited: Wordfence blocked 8.7M attacks on old GutenKit and Hunk Companion flaws. — [SecurityAffairs](https://securityaffairs.com/?p=183876)
- Supply chain: Wordfence PRISM detected a backdoored WordPress plugin within 2 hours of its introduction (Jul 2026). — [Wordfence, Jul 2026](https://www.wordfence.com/blog/2026/07/wordfence-prism-detected-backdoored-wordpress-plugin-within-two-hours-of-it-being-introduced/). The "Essential Plugins" backdoor is cited as one driver of WordPress.org's 2026 update hold (see section 3). — [wpstack substack](https://wpstack.substack.com/p/issue-1-gandalf-at-the-gates)

### Inferences
- With a ~5h median to mass exploitation, an auto-patcher must work in hours, not days. Where no patch exists or the update is held, virtual patching or deactivation has to be a first-class path, not an edge case.
- Most of the volume sits in a long tail of small plugins (73.8% of one CNA's 2025 vulns were in plugins with <1k installs). Most sites will rarely be hit, but popular premium plugins carry outsized real-world risk.
- Premium plugins are both riskier and harder to auto-update (no WordPress.org channel), which makes them a key design problem.

### Gaps
- I could not open the primary Patchstack 2026 whitepaper. All its figures here come from secondary sources and need checking. No 2026 full-year count exists yet (as of Nov 2026). No Wordfence 2025 annual report was found.
- I found no reliable figure for nulled-plugin malware rates in 2025–2026.
- I found no hard count of WordPress.org plugins closed for security reasons per year.

## 3. Mechanics available to apply fixes automatically

### Takeaway
WordPress offers layered auto-update mechanics:
- **Core background updates**, which WordPress.org can force-push (it did for wp2shell, Jul 2026).
- **Per-plugin/theme auto-updates** (UI since 5.5), controlled by the `auto_update_{$type}` filters.
- **Rollback**: failed manual updates since 6.3, failed plugin auto-updates since 6.6.
- **WP-CLI**: granular `update` flags and checksum verification.

A major 2026 change: since Jun 5, 2026, WordPress.org's "Protect The Shire" program holds new plugin/theme releases before they reach auto-updates. Patchstack measured a 24.4h median hold, later cut to about 6h. The hold applies to security fixes too, but manual and WP-CLI updates can bypass it.

### Cited Findings
**Core / plugin auto-updates**
- The filter `auto_update_{$type}` (i.e. `auto_update_plugin`, `auto_update_theme`, `auto_update_core`, `auto_update_translation`) takes a `bool|null $update` and the update offer object `$item`. Common pattern: `add_filter('auto_update_plugin', fn, 10, 2)` that returns true for an allow-list of slugs. — [developer.wordpress.org hook reference](https://developer.wordpress.org/?p=5608); [wp-kama](https://wp-kama.com/2021/auto-updates-in-wordpress)
- `define('AUTOMATIC_UPDATER_DISABLED', true)` in wp-config.php, or the `automatic_updater_disabled` filter, turns off the whole background updater. `WP_AUTO_UPDATE_CORE` controls core updates. Don't put `add_filter()` in wp-config.php, because it conflicts with WP-CLI. — [codex: Configuring automatic updates](https://codex.wordpress.org/es:Configurando_actualizaciones_automaticas); [melapress guide](https://melapress.com/guide-configuring-wordpress-automatic-updates/) (secondary)
- WordPress.org force-pushed the wp2shell fix (6.9.5/7.0.2/6.8.6) through core auto-update. It is unclear whether the push reaches sites with auto-updates disabled, and admins were told to check versions directly. — [Expert Insights](https://expertinsights.com/news/wordpress-force-pushes-fix-for-wp2shell); [Indusface](https://www.indusface.com/blog/wp2shell-wordpress-cve-2026-60137-63030-rce/)

**Rollback**
- WP 6.3 added rollback for failed *manual* plugin and theme updates. — [make.wordpress.org/core, Jul 11 2023](https://make.wordpress.org/core/2023/07/11/new-in-6-3-rollback-for-failed-manual-plugin-and-theme-updates/)
- WP 6.6 merged "Rollback Auto-Update" (Trac #58281, changeset 58128 in `class-wp-automatic-updater.php`). After an automatic plugin update, it makes two loopback requests, one to the dashboard and one to the homepage. If either returns an error, it assumes a PHP fatal and restores the previous version. Auto-updates shouldn't run if loopbacks don't work. Side effects can include deactivated plugins. — [Merge proposal, Apr 19 2024](https://make.wordpress.org/core/2024/04/19/merge-proposal-rollback-auto-update/); [Trac #58281](https://core.trac.wordpress.org/ticket/58281); [changeset 58128](https://core.trac.wordpress.org/changeset/58128)
- False positives happen. In one report a cURL error 18 on the post-update loopback (WP Super Cache environment) caused the update to be rolled back. — [support thread mirror](https://remarpro.com/support/topic/plugin-auto-updates-fail-when-cache-enabled)

**WordPress.org "Protect The Shire" update hold (2026)**
- Announced Jun 5, 2026: a temporary 24h cooldown for plugin and theme releases before auto-updates, during which automated (AI-assisted) review runs. — [WordPress.org News: Protect The Shire](https://wordpress.org/news/2026/06/pts/); [webhosting.today](https://webhosting.today/2026/06/08/protect-the-shire-wordpress-adds-a-24-hour-default-delay-to-plugin-auto-updates/); [HostingAdvice](https://www.hostingadvice.com/blog/wordpress-adds-ai-plugin-reviews-24-hour-delay-to-auto-updates/)
- Patchstack measured a 24.4h median hold across 114 releases. Security fixes were not fast-tracked: of 81 releases patching a disclosed CVE, 49 were held under the 24h window and 32 under a 6h window. Patchstack's Jul 30, 2026 article says the hold was cut to 6h, and a Russian outlet says the cut was not announced. Patchstack recommends exempting or fast-tracking confirmed security fixes. HostingAdvice says 24h remains "indefinitely". **The sources conflict.** — [Patchstack: The WordPress update button isn't telling the truth](https://patchstack.com/articles/the-wordpress-update-button-isnt-telling-the-truth-anymore/); [Patchstack: Protect the Shire solves one problem…](https://www.patchstack.com/articles/protect-shire-solves-one-problem-risks-making-another-worse/); [comnews.ru, Sep 2026](https://www.comnews.ru/content/247228/2026-09-04/2026-w36/1018/novaya-zaschita-wordpress-cepochek-postavok-sozdayot-okno-vozmozhnostey-dlya-khakerov-ekspert-kompanii-gazinformservis) (search snippets)
- Manual dashboard updates are reported to apply instantly: the zip is already the new build, and only the update notice and auto-update pipeline are held. Premium plugins on their own update servers and some managed hosts are not subject to the hold. — [managewp.com](https://managewp.com/wordpresss-24-hour-plugin-update-delay/); [mioritichost](https://mioritichost.com/en/blog/24-hour-delay-wordpress-plugin-updates) (secondary)
- In Sep 2026 WordPress.org added automated plugin reviews that block high-risk updates. — [The Hacker News, Sep 2026](https://thehackernews.com/2026/09/wordpress-adds-automated-plugin-reviews.html); [it-connect](https://www.it-connect.tech/wordpress-now-blocks-high-risk-plugin-updates-automatically-with-ai/)

**WP-CLI (extension-command README, current main)**
- `wp plugin update` / `wp theme update` options: `[<name>...]`, `--all`, `--exclude=<names>`, `--minor`, `--patch`, `--version=<v>`, `--dry-run`, `--format=table|csv|json|summary`, `--insecure`, `--auto-update-indicated` (only items the server flags for auto-update; not combinable with `--version/--minor/--patch`), and `--include-vcs` (VCS-controlled plugins are **skipped by default**). — [wp-cli/extension-command README](https://raw.githubusercontent.com/wp-cli/extension-command/main/README.md)
- `wp plugin auto-updates enable [--all] [--disabled-only]`. `wp plugin deactivate [--uninstall] [--all] [--exclude] [--network]`; `--network` is for multisite network-wide deactivation. — [same README](https://raw.githubusercontent.com/wp-cli/extension-command/main/README.md)
- The hosting handbook recommends `wp plugin update --all --dry-run` before real updates. `wp core verify-checksums` and `wp plugin verify-checksums --all` exist, and plugin checksums only work for WordPress.org-hosted plugins. — [WordPress Hosting Handbook: WP-CLI](https://make.wordpress.org/hosting/handbook/wp-cli/); [developer.wordpress.org: wp plugin verify-checksums](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/)

**Composer-managed WordPress (Bedrock)**
- Bedrock sites manage plugins as Composer packages, sourced from WPackagist or Roots' newer WP Packages mirror (5-minute updates). Advisories come via WP Sec Adv (Wordfence data) for `composer audit`. — [Roots docs](https://roots.io/bedrock/docs/auditing-wordpress-vulnerabilities-with-composer/) (snippet)

### Inferences
- On Composer/Bedrock sites, dashboard and WP-CLI updates are the wrong lever. The patcher should change `composer.json`/`composer.lock` (e.g. `composer update vendor/slug --with-dependencies`), commit, and deploy. On non-git sites, WP-CLI in place is the practical lever. The `--include-vcs` default (skip) protects git-tracked plugins from being overwritten in place.
- `wp plugin update <slug> --version=<patched>` or `--patch` gives the smallest possible fix. Because the WordPress.org hold covers only the auto-update pipeline, an agent that runs WP-CLI or a manual update as soon as a fix is published can get ahead of the 6–24h hold. The trade-off is skipping WordPress.org's supply-chain review window.
- Rollback in 6.6 only detects fatals reachable by loopback. It does not catch functional regressions, so staging tests, backups or snapshots are still needed. Sites where loopbacks are broken (cache/WAF/auth) are both unsafe for auto-updates and prone to false rollbacks.

### Gaps
- I could not confirm whether 6.6 rollback covers themes or only *active* plugins. Background knowledge says it targets active plugins, but this is unverified here.
- I found no sources on premium-plugin update channels (license-key-gated update servers such as EDD Software Licensing, Freemius, or vendor-specific updaters) or how to automate them headlessly.
- I found no documentation of multisite-specific auto-update behavior beyond `--network` on deactivate.
- I found no primary source on the exact current hold duration (24h vs 6h) as of Nov 2026.

## 4. What happens when no fix exists: deactivate, virtual patch/WAF, mu-plugin hotfix

### Takeaway
Roughly half of disclosed vulns lack a patch at disclosure (secondary figures of about 46–52%). The documented fallbacks are:
- **Deactivation/removal** (WP-CLI `wp plugin deactivate`, with `--network` for multisite).
- **Virtual patches**: Patchstack vPatches are site-level firewall rules that use WordPress context; Wordfence Premium firewall rules shipped the same day as disclosure for wp2shell.
- **Swapping closed/abandoned plugins**, which the WordPress.org API flags only as `"closed"`.

### Cited Findings
- A Patchstack vPatch is "a customized firewall rule acting as a virtual shield". Virtual patching "works a lot like a WAF… but runs within the website itself", so it can use context like user authorization and software versions. Example rules block a specific endpoint or action parameter when a permission check is missing, or block a REST endpoint carrying a specific cookie. — [Patchstack: How vPatches protect](https://patchstack.com/?p=19010); [Patchstack FAQ](https://patchstack.com/?p=18985); [Patchstack: What is virtual patching](https://patchstack.com/?p=4818)
- Patchstack also offers "RapidMitigate", described as next-gen vulnerability mitigation. — [Patchstack](https://patchstack.com/articles/rapidmitigate-next-gen-vulnerability-mitigation-for-websites)
- Critique: virtual patching blocks attacks while the vulnerable code stays in place. A competitor (Plugin Vulnerabilities) argues Patchstack "isn't actually patching" and is slower than other firewalls. This is a contested, self-interested view. — [pluginvulnerabilities.com, Feb 2025](https://www.pluginvulnerabilities.com/2025/02/04/patchstack-isnt-actually-patching-vulnerabilities/)
- Hosts and maintenance services ship Patchstack virtual patches, e.g. WP Guardian, Liquid Web/Nexcess, and ManageWP. ManageWP reports blocking 11.9M threats in 6 months with Patchstack. — [jorijn.com: WP Guardian explained](https://jorijn.com/en/blog/wp-guardian-patchstack-explained-extra-protection-when-updates-have-to-wait/); [Liquid Web](https://www.liquidweb.com/blog/what-is-patchstack/); [Patchstack ManageWP case study](https://patchstack.com/articles/case-study-managewp-blocks-11-9m-threats-in-6-months-with-patchstack/)
- For wp2shell, Wordfence Premium users got firewall protection on disclosure day. — [Wordfence wp2shell aftermath](https://www.wordfence.com/blog/2026/07/wp2shell-aftermath-the-first-critical-unauthenticated-wordpress-core-rce-in-nearly-a-decade/) (snippet)
- Secondary: standard hosting defenses reportedly block only about 26% of WordPress-targeted attacks (attributed to Patchstack; not confirmed in the primary). — [search summary of secondary coverage](https://www.searchenginejournal.com/report-shows-wordpress-sites-are-getting-hacked-at-faster-rate/568510/)
- Deactivation tooling: `wp plugin deactivate <slug> [--network] [--uninstall]`. — [wp-cli/extension-command README](https://raw.githubusercontent.com/wp-cli/extension-command/main/README.md)

### Inferences
- A sensible escalation ladder for an AI patcher:
  1. Patched version available: update via WP-CLI or Composer with `--version`, bypassing the WordPress.org hold, after staging and snapshot.
  2. No patch: apply a targeted virtual patch. This can be generated as a must-use plugin (`wp-content/mu-plugins/`), which loads before regular plugins, that blocks the vulnerable route, action or param, or it can be a WAF rule at the edge.
  3. If the risk is critical and actively exploited and no rule is feasible, deactivate the plugin and alert.
  4. If the plugin is closed/abandoned, recommend a replacement.

  The mu-plugin approach is an inference from standard WordPress loading behavior. I found no vendor documentation confirming that Patchstack implements vPatches this way.
- An AI-generated code hotfix (editing plugin source) is fragile: the next update overwrites it, and on WordPress.org plugins it also breaks checksum verification. A virtual patch kept outside the plugin directory is easier to maintain.

### Gaps
- I found no authoritative documentation of mu-plugin-based hotfix patterns, of Patchstack's internal vPatch implementation or load order, or of Wordfence firewall rule distribution mechanics.
- I found no official guidance from WordPress.org on what site owners should do with closed plugins that have unpatched vulns.
