# Vulnerability patching for non-WordPress website stacks (as of 19 Nov 2026)

> **How this was researched:** WebFetch was blocked by the session's network policy for every primary host tried: www.drupal.org, experienceleague.adobe.com and blog.cloudflare.com all failed with ENOTFOUND. So **every finding below comes from search-engine result snippets and the search tool's summaries of them.** I did not read any of these pages in full. Treat specific version numbers and dates as "reported by the cited source" and check them against the vendor page before an automated system relies on them. Some items come from low-authority or unfamiliar sites; those are marked **[UNVERIFIED]**. Statements based on my own background knowledge, with no source fetched this session, are marked **[background, not verified this session]** and kept to the Inferences and Gaps sections.

## 1. Drupal: advisories, machine-readable feeds, Composer and Drush, Automatic Updates and Package Manager, Drupalgeddon

### Takeaway
Drupal has the best machine-readable security data of any CMS here. Its advisories are now published in OSV format and through a JSON PSA feed, which makes "detect" easy to automate. "Apply" is still mostly Composer plus Drush. Core's Package Manager is hidden or experimental but API-stable, and contrib Automatic Updates 4.x requires Drupal 11.2+. Two lifecycle deadlines are close: Drupal 10 reaches end of life on 9 Dec 2026, and Drupal 7 has been EOL since Jan 2025.

### Cited Findings
- **OSV integration:** Drupal security advisories (core and contrib) are now in the OSV database, with IDs like `DRUPAL-CONTRIB-2020-010`. The OSV data is built from a drupal.org API. A repo maintained by the Drupal Security Team, `DrupalSecurityTeam/drupal-advisory-database`, holds the advisories in OSV format. — [drupal.org blog](https://www.drupal.org/blog/drupal-security-advisories-are-now-available-in-osv-database); [GitHub repo](https://github.com/DrupalSecurityTeam/drupal-advisory-database); [osv.dev record](https://osv.dev/vulnerability/DRUPAL-CONTRIB-2020-010); [The DropTimes](https://www.thedroptimes.com/node/64685)
- **Tracking issue:** The drupal.org issue "Provide all security advisories in OpenSSF Vulnerability format for dependency tracking" tracked the OSV work. — [drupalcode issue 3410338](https://git.drupalcode.org/project/drupalorg/-/work_items/3410338)
- **PSA feed:** Drupal publishes a JSON PSA feed at `https://updates.drupal.org/psa.json`, which core and Automatic Updates use to show advisories. The drupal.org REST API also exposes advisories as nodes, for example `https://www.drupal.org/api-d7/node.json?type=sa&status=1`. — [drupal.org: responding to critical security update advisories](https://www.drupal.org/docs/updating-drupal/responding-to-critical-security-update-advisories) (per search snippet)
- **Older Composer mapping:** The community package `webflo/drupal-security-advisories` mapped Drupal SAs to Composer conflicts. — [GitHub](https://github.com/webflo/drupal-security-advisories)
- **Package Manager status:** Package Manager ships in core as a *hidden experimental* module. A drupal.org change notice says it is now considered **API-stable**, with backward-compatible APIs that contrib can rely on. — [drupal.org node 3530905](https://www.drupal.org/node/3530905) (snippet; I could not confirm a date or confirm that it is "stable" for end users)
- **Contrib Automatic Updates:** The 4.x branch was updated 31 Mar 2026, needs Drupal 11.2 or later, and depends on core's Package Manager. Stable releases are covered by the security advisory policy. — [drupal.org/project/automatic_updates](https://drupal.org/project/automatic_updates)
- **Legacy API retired:** drupal.org was to shut down the first-generation (legacy) Automatic Updates API on **4 May 2026**. — [The DropTimes](https://www.thedroptimes.com/node/66329)
- **`drupal_automatic_updater`:** A `drupal/drupal_automatic_updater` package exists on Packagist. — [Packagist](https://packagist.org/packages/drupal/drupal_automatic_updater)
- **Drupal 10 EOL:** Drupal 10 reaches end of life on **9 Dec 2026**, with no Drupal 10 releases after that. Security support for 11.3.x and 10.6.x ends the week of 7 Dec 2026. Drupal 12.0.0 and 11.5.0 are scheduled for that same week. Acquia drops Drupal 10 support on 9 Dec 2026. — [The DropTimes](https://www.thedroptimes.com/node/66487); [Drupal core release schedule](https://drupal.org/about/core/policies/core-release-cycles/schedule); [Acquia FAQ](https://docs.acquia.com/service-offerings/drupal-10x-end-life-faqs)
- **Drupal 7 EOL:** Drupal 7 reached EOL on 5 Jan 2025. One source said "mid-to-late 2026", which conflicts with the official schedule; use the drupal.org date. — [Drupal core release cycle](https://www.drupal.org/core/release-cycle)
- **Drupal 11.2 security support:** Drupal 11.2.x had security support until June 2026, per search results. — [drupal.org/project/automatic_updates](https://drupal.org/project/automatic_updates) (snippet)

### Inferences
- **Feed pipeline:** An AI patcher can ingest Drupal advisories through OSV (ecosystem "Drupal"? exact ecosystem string not verified) or through psa.json. It can then map affected projects against `composer.lock` (packages `drupal/core`, `drupal/<module>`). The fix path is `composer update drupal/<pkg> --with-dependencies`, then `drush updatedb`, `drush cache:rebuild`, and optionally `drush config:export` to check for config drift. **[workflow is background knowledge, not verified this session]**
- **Composer conflicts:** Composer 2.9's default `block-insecure` (section 3) applies to Drupal too, so an outdated Drupal site may fail `composer update` until vulnerable packages are resolved.
- **Lifecycle gotcha:** Around 9 Dec 2026, a "security patch" for many Drupal 10 sites becomes a major-version upgrade to 11. That is not a safe auto-patch: deprecated APIs and contrib compatibility (often handled with Upgrade Status or Rector) will block it. A patcher must classify these sites as "needs a human project", not "auto-patch".
- **Drupalgeddon history:** **[background, not verified this session]** SA-CORE-2014-005 ("Drupalgeddon", Oct 2014, SQL injection) was mass-exploited within hours. Drupal advised that sites not patched within about 7 hours should be assumed compromised. SA-CORE-2018-002 ("Drupalgeddon2", CVE-2018-7600, Mar 2018) and SA-CORE-2018-004 were remote code execution flaws that were also mass-exploited. The lesson: Drupal pre-announces "highly critical" core releases (a PSA a few days ahead, with a fixed release window, typically Wednesday). An automated system should subscribe to the PSA feed and stage a patch run for that window.

### Gaps
- I could not confirm whether Package Manager or Automatic Updates became a *stable, non-hidden* core module in 11.3 or 11.4 during 2026. drupal.org was blocked.
- I could not read the drupal.org page to confirm the OSV ecosystem identifier ("Packagist" with `drupal/` names vs. a separate "Drupal" ecosystem) or the exact psa.json schema.
- I could not verify a Drupalgeddon primary source this session. The search returned nothing on SA-CORE-2018-002.
- Drupal 7 commercial extended support vendors (HeroDevs and others) and their feeds were not researched.

## 2. Other CMSes and commerce platforms: Joomla, Magento / Adobe Commerce, PrestaShop, OpenCart, Ghost, Strapi, Craft CMS

### Takeaway
These platforms vary widely in automation. Joomla now has built-in automated core updates secured with TUF (5.4/6.0, Oct 2025). Adobe Commerce moved to **monthly isolated security patches** in Jan 2026, plus quarterly releases. PrestaShop has a community advisory DB with an API and RSS (Friends-Of-Presta). Ghost, Strapi and Craft use GitHub Security Advisories, so they flow into OSV and npm or Packagist tooling. Commerce platforms (Magento, PrestaShop) carry the highest exploitation risk, and much of it sits in third-party modules.

### Cited Findings
**Joomla**
- **TUF and automated updates:** Joomla 5.1 (Apr 2024) added TUF (The Update Framework) to secure core update delivery. Fully automatic core updates arrived in **Joomla 5.4 and 6.0, released Oct 2025**, built on TUF. — [Joomla Magazine Oct 2025](https://magazine.joomla.org/issues/2025/october-2025/automatic-core-updates-in-joomla); [Joomla Magazine Apr 2024](https://magazine.joomla.org/issues/2024/april-2024/tamper-proof-core-updates-for-joomla-tuf-making-it-into-5-1); [AlternativeTo](https://alternativeto.net/news/2025/10/joomla-6-released-with-automatic-core-updates-new-child-template-and-improved-versioning)
- **Default settings:** Automated updates are on by default for new installs and **off by default for sites upgraded from 5.3 or earlier**. — [mysites.guru](https://mysites.guru/blog/how-to-disable-joomla-automated-upgrades/) (third-party vendor)
- **Security feed:** The Joomla Developer Security Centre publishes resolved-issue announcements with an RSS feed. — [developer.joomla.org security centre](https://developer.joomla.org/security-centre.html?tmpl=.)
- **Sep 2026 release and regression:** Joomla 6.1.4 and 5.4.9 (29 Sep 2026) fixed **16 core security issues**. 5.4.9 introduced a regression: API PATCH requests fataled because of a missing `Doctrine\Inflector\InflectorFactory` import. — [The DropTimes](https://www.thedroptimes.com/node/72589)

**Magento / Adobe Commerce**
- **Monthly isolated patches:** Adobe moved to a **monthly isolated security patch schedule starting January 2026**. Isolated patches are tested only against the *latest security-only patch release* of each release line, so merchants must be on that version first. — [Adobe: monthly isolated security patch policy](https://experienceleague.adobe.com/de/docs/commerce-operations/release/planning/monthly-isolated-security-patches) (German page, snippet); [Swissup Labs Aug 2026](https://swissuplabs.com/blog/is-your-magento-store-up-to-date-august-2026-security-checkup/)
- **Bulletins:** Adobe KB bulletins exist for 2026, such as APSB26-73 and APSB26-153. — [Adobe KB APSB26-73](https://experienceleague.adobe.com/en/docs/experience-cloud-kcs/kbarticles/ka-37421); [Adobe KB APSB26-153](https://experienceleague.adobe.com/en/docs/experience-cloud-kcs/kbarticles/ka-49323)
- **Verification tools:** Adobe Commerce on Cloud merchants can verify an isolated patch with QPT (Quality Patches Tool) status. A newer verification tool installed at `vendor/bin/patch-status` (called "CVT") ships with the **July 2026** isolated patch file and is preferred where available. — [Adobe KB](https://experienceleague.adobe.com/en/docs/experience-cloud-kcs/kbarticles/ka-49323) (snippet; detail is thin)
- **APSB26-138:** A third-party blog describes the Sep 2026 isolated patches (APSB26-138) and a "CVE-2026-77774 / StyleSmuggler hotfix". — [hol.org](https://hol.org/blog/cve-2026-77774-adobe-commerce-magento-apsb26-138-authz) **[UNVERIFIED: not confirmed against an Adobe bulletin]**
- **QPT scope:** QPT is mainly for *quality* patches. Security fixes come through Adobe's security channels (full patch releases, isolated patches, hotfixes). — [OnTap Group](https://www.ontapgroup.com/blog/magento-security-patches)
- **Community patch packages:** Packagist has packages that wrap Magento security patches, such as `disrex/magento-security-patches` and `pushonltd/magento-patchline`. — [Packagist disrex](https://packagist.org/packages/disrex/magento-security-patches); [Packagist pushonltd](https://packagist.org/packages/pushonltd/magento-patchline)
- **SessionReaper (CVE-2025-54236):** CVSS 9.1, an unauthenticated account takeover via the REST API, with remote code execution possible in some configurations. Adobe shipped an out-of-band fix on **9 Sep 2025**. The hotfix had reportedly **leaked about a week before** the official release. Mass exploitation followed in late Oct 2025: Sansec saw about 250 attacks in one day, with PHP webshell payloads uploaded via `/customer/address_file/upload`. The hotfix supports 2.4.4 through 2.4.7. Adobe deployed WAF rules on Cloud and auto-patched Cloud instances, but sources advise applying the hotfix anyway. — [Help Net Security](https://www.helpnetsecurity.com/2025/10/23/adobe-magento-cve-2025-54236-attack/); [SecurityWeek](https://www.securityweek.com/exploitation-of-critical-adobe-commerce-flaw-puts-many-ecommerce-sites-at-risk/); [BleepingComputer](https://www.bleepingcomputer.com/news/security/adobe-patches-critical-sessionreaper-flaw-in-magento-ecommerce-platform/amp); [CrowdSec](https://www.crowdsec.net/vulntracking-report/cve-2025-54236)

**PrestaShop**
- **ps_facetedsearch:** Official notice: ps_facetedsearch 3.0.0 through 4.0.3 is vulnerable, fixed in **4.0.4 (released 3 Jun 2026)**. Third-party trackers describe it as CVE-2026-54159, a PHP object injection leading to remote code execution. It was bundled into PrestaShop 9.1.4 and 8.2.7. — [PrestaShop project news](https://build.prestashop-project.org/news/2026/security-update-faceted-search-module-ps-facetedsearch/); [SecureLayer7](https://securelayer7.net/lab/cve-2026-54159-ps-facetedsearch-php-object-injection-rce); [PrestaShow](https://prestashow.com/en/prestashop-blog/122/prestashop-914-827-aktualizacja-ps-facetedsearch)
- **8.2.6 security release:** PrestaShop 8.2.6 was a security release in 2026. — [PrestaShop project news](https://build.prestashop-project.org/news/2026/prestashop-8-2-6-security-release/)
- **Friends-Of-Presta:** The `friends-of-presta/security-advisories` repo is a community DB for PrestaShop module advisories, with an API and RSS (security.friendsofpresta.org). Many third-party/marketplace modules have critical CVEs, for example Advanced Popup Creator, CVE-2025-69633, CVSS 9.8. — [GitHub friends-of-presta](https://github.com/friends-of-presta/security-advisories); [PT Security dbugs](https://dbugs.ptsecurity.com/vulnerability/PT-2026-8039)
- **Packagist feed:** PrestaShop advisories also appear in Packagist's advisory DB, with PKSA IDs. — [Packagist PKSA-f9zy-1yrp-415w](https://packagist.org/security-advisories/PKSA-f9zy-1yrp-415w)

**Ghost**
- **CVE-2026-26980:** SQL injection affecting Ghost 3.24.0 through 6.19.0, fixed in 6.19.1. A large campaign in **May 2026** exploited it to steal Admin API keys. Patching does not revoke keys already stolen, so keys must be rotated. — [AhnLab ASEC](https://asec.ahnlab.com/en/93954/)
- **SSRF fixes:** CVE-2026-53944 and 53945 (SSRF) are fixed in Ghost 6.21.1 and listed on the npm `ghost` package. — [GitLab advisory DB](https://advisories.gitlab.com/npm/ghost/CVE-2026-53945/)

**Strapi**
- **2026 disclosures:** Strapi published a disclosure covering CVE-2025-64526, CVE-2026-22599 (SQL injection in Content-Type Builder, fixed in 5.33.2 and 4.26.1), CVE-2026-22706 and 22707 (fixed in 5.33.3), and CVE-2026-27886 (critical, relational-field filtering, affecting 4.0.0 through <5.37.0). — [Strapi disclosure blog](https://strapi.io/blog/security-disclosure-of-vulnerabilities-cve-2025-64526-cve-2026-22599-cve-2026-22706-cve-2026-22707-and-cve-2026-27886); [Tenable](https://www.tenable.com/cve/CVE-2026-22599)
- **XSS and v4 support:** CVE-2026-90561 (stored XSS) is fixed in 5.48.1. Strapi **v4 security updates stopped in April 2026**, per search summary. — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-90561/) **[v4 end-of-support date reported only in the search summary; not verified on strapi.io]**
- **May 2026 research:** Research on a "May 2026 admin token oracle / query injection" issue in Strapi. — [Corgea](https://corgea.com/research/strapi-may-2026-admin-token-oracle-query-injection)

**Craft CMS**
- **CVE-2025-32432:** Pre-auth remote code execution (CVSS 10), exploited as a zero-day from mid-Feb 2025 and chained with Yii CVE-2024-58136. Patched in 3.9.15, 4.14.15 and 5.6.17 (Apr 2025). The Mimo group used it for XMRig cryptomining and proxyware. Advisory GHSA-f3gw-9ww9-jmc3. One source says it was added to CISA KEV on 2026-03-20. — [SecurityWeek](https://www.securityweek.com/craft-cms-zero-day-exploited-to-compromise-hundreds-of-websites/); [SOC Prime](https://socprime.com/blog/cve-2025-32432-rce-vulnerability-in-craft-cms/); [SonicWall](https://www.sonicwall.com/de-de/blog/craftcms-vulnerability-exposes-systems-to-pre-auth-rce-now-exploited-in-the-wild-cve-2025-32432-) **[the KEV date reported by one source is unverified]**

### Inferences
- **Detection layer:** For Joomla, Ghost, Strapi and Craft, plus PrestaShop core, advisories reach GHSA, OSV, or Packagist, so a generic lockfile-to-OSV matcher covers detection. Joomla extensions and PrestaShop marketplace modules are the gap. Many are distributed outside Composer or npm and need the Friends-Of-Presta feed or Joomla's Vulnerable Extensions List **[VEL: background, not verified this session]**.
- **Magento auto-patching is version-gated:** isolated patches only apply cleanly on the latest security patch release of each release line. An AI patcher must (a) detect the exact version, (b) choose between "apply isolated patch file" and "full version bump via Composer", then run `bin/magento setup:upgrade`, `setup:di:compile` and `setup:static-content:deploy`, then (c) verify with `vendor/bin/patch-status` or QPT. **[command sequence: background, not verified this session]**
- **Credential rotation:** Ghost CVE-2026-26980 and the Magento SessionReaper webshells show that "patched" ≠ "clean". The pipeline needs post-patch steps: rotate credentials and API keys, and scan for webshells and IoCs.
- **Joomla regressions:** Joomla 5.4.9 broke API PATCH requests. An automated patcher should run smoke tests that include the REST API, not just page loads.
- **Lifecycle risk:** Strapi v4 and Drupal 10 both lose support in 2026. Many "patches" become major migrations.

### Gaps
- **OpenCart:** No 2026 OpenCart advisory data was found; the search did not cover it. OpenCart has historically had a weak advisory process and no auto-update. **[background, not verified this session]**
- **Ghost(Pro):** I did not confirm the update mechanism (`ghost update` CLI for self-hosted) or whether Ghost(Pro) managed hosting patches automatically.
- **Craft CMS:** I did not check whether Craft CMS has built-in auto-update or a security feed beyond GHSA.
- **Adobe sources:** Adobe's official bulletin list for Sep–Nov 2026 and full CVT tool docs could not be read because experienceleague.adobe.com was blocked.

## 3. General application frameworks: PHP (Composer, Laravel, Symfony), Rails, Django/Python, Node/Next.js, static/JAMstack

### Takeaway
For framework apps, detection is a solved problem. Lockfiles plus OSV or GitHub Advisory data (`composer audit`, `npm audit`, `bundler-audit`, `pip-audit`, Dependabot/Renovate) cover it. Composer 2.9 even **refuses to install known-vulnerable versions by default**. Applying the fix is a code change: bump, test, then build and redeploy. That is exactly what an AI patcher can do with PR-based workflows. Next.js and React2Shell show that framework flaws can be pre-auth remote code execution, exploited within hours.

### Cited Findings
**PHP / Composer**
- **Composer 2.9 blocks insecure versions:** From Composer 2.9 (RC1 on 7 Nov 2025), `audit.block-insecure` defaults to **true**. Composer refuses to resolve versions with known advisories. You can opt out globally or ignore specific advisory IDs via `audit.ignore`. `audit.block-abandoned` is opt-in. This **fully replaces `roave/security-advisories`**. — [Packagist blog: Composer 2.9](https://blog.packagist.com/composer-2-9/); [Composer changelog 2.9.0-RC1](https://getcomposer.org/changelog/2.9.0-RC1); [Upsun](https://developer.upsun.com/posts/2025/composer-2.9)
- **Friction:** CI builds broke after 2.9. The Drupal GitLab CI templates issue is titled "Composer 2.9 blocks dependencies which have security advisories". Some constraints became unsatisfiable, and `COMPOSER_NO_AUDIT=1` did not help. — [drupalcode issue 3564269](https://git.drupalcode.org/project/gitlab_templates/-/issues/3564269); [Mage-OS PR](https://github.com/mage-os/github-actions/pull/386)
- **Composer 2.10 policy block:** Composer 2.10 reportedly adds a unified `config.policy` block covering advisories, malware, abandoned packages and custom blocklists. — [nesbitt.io May 2026](https://nesbitt.io/2026/05/29/composer-dependency-policies.html); [myvaultcms](https://myvaultcms.pages.dev/posts/2026-05-28-composer-29-security-repo-management) **[single/low-authority sources; verify against getcomposer.org]**
- **`composer audit`:** `composer audit` reads advisories from Packagist's advisory DB, which aggregates GitHub advisories and FriendsOfPHP. — [Packagist blog](https://blog.packagist.com/discover-security-advisories-with-composers-audit-command/)

**Next.js / React**
- **CVE-2025-29927 (Mar 2025):** A Next.js middleware authorization bypass via a crafted `x-middleware-subrequest` header. Affects about 11.1.4 through 15.2.2. Fixed in **12.3.5, 13.5.9, 14.2.25 and 15.2.3**. The vendor mitigation, if you cannot patch, is to strip that header at the edge or proxy. — [Next.js blog](https://nextjs.org/blog/cve-2025-29927); [Fastly](https://fastly.com/blog/cve-2025-29927-authorization-bypass-in-next-js); [Help Net Security](https://www.helpnetsecurity.com/2025/03/24/critical-next-js-auth-bypass-vulnerability-opens-web-apps-to-compromise-cve-2025-29927/)
- **React2Shell (CVE-2025-55182) is REAL:** The React team disclosed it on **3 Dec 2025**. It has CVSS **10.0**, and is an unsafe deserialization in the React Flight protocol in React Server Components that gives unauthenticated remote code execution. Apps can be exposed even without explicitly defined Server Functions. Affected: Next.js App Router, React Router RSC preview, the Vite RSC plugin and the Parcel RSC plugin. Next.js's CVE-2025-66478 was later marked a duplicate. CISA added it to KEV soon after disclosure. Exploitation by state-linked actors and botnets has been reported. — [Rapid7](https://rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components); [JFrog](https://jfrog.com/blog/2025-55182-and-2025-66478-react2shell-all-you-need-to-know); [NetSPI](https://www.netspi.com/?p=31134); [AhnLab ASEC](https://asec.ahnlab.com/en/91718/)
- **No configuration workaround:** The only reliable fix is to upgrade the packages, then rebuild and redeploy. — [Rapid7](https://rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components)
- **Fake PoCs:** Many public "PoCs" for React2Shell were not verified to work. — [Rapid7](https://rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components)

**OSV ecosystem coverage**
- **Ecosystems:** OSV aggregates ecosystem advisory sources (its data-sources page lists them, including Packagist, npm, PyPI, RubyGems and others). Drupal advisories are now included. — [OSV data sources](https://google.github.io/osv.dev/data); [osv.dev CVE-2025-29927](https://osv.dev/CVE-2025-29927)

### Inferences
- **Recommended detect step:** Parse the lockfiles (`composer.lock`, `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`, `Gemfile.lock`, `requirements.txt`/`poetry.lock`/`uv.lock`) and query the OSV batch API. This covers Laravel, Symfony, Rails, Django, Flask, Next.js, Nuxt, Astro, Gatsby, Strapi, Ghost, Craft and Drupal uniformly.
- **Recommended fix step:** Make a minimal version bump inside the same major (`composer update vendor/pkg --with-dependencies`, `npm install pkg@x.y.z`, `bundle update --conservative gem`, `pip install -U pkg==x`). Then run tests, open a PR, deploy to staging, smoke test, and promote.
- **Static and JAMstack sites:** The *deployed* artifact is static, so the runtime attack surface is small. But build-time dependencies (Node), any SSR, edge or serverless functions, and the hosting platform still need patching. A redeploy is required after the bump. React2Shell hit SSR frameworks specifically.
- **Rails and Django:** **[background, not verified this session]** Rails relies on `bundler-audit` (ruby-advisory-db) and GitHub Dependabot. Django publishes security releases on djangoproject.com with pre-notification. `pip-audit` (PyPA, using the PyPI and OSV advisory DB) is the standard Python checker. All three ecosystems are in OSV.
- **PHP runtime blocking app patches:** A minimal "security bump" sometimes requires a newer PHP than the server runs (see section 5). The patcher must check the `platform` and `php` constraints.

### Gaps
- I did not verify the exact fixed React and Next.js version numbers for React2Shell (believed: React 19.0.1, 19.1.2 and 19.2.1, plus multiple Next.js 15.x/16.x patch lines) **[background, not verified]**. Nor did I verify the follow-up RSC CVEs disclosed in Dec 2025 (DoS and source exposure).
- No 2026 Rails, Django or Laravel incidents were researched, for lack of tool budget.
- I did not confirm the 2026 status of Laravel's own security-advisory process.

## 4. SaaS site builders: Shopify, Wix, Squarespace, Webflow

### Takeaway
On hosted builders, the platform patches the core and infrastructure. The site owner cannot and need not patch it. The owner's residual surface is third-party apps and their OAuth scopes, custom themes and injected code (Liquid, custom JS and embeds), plus account security. An AI system can only *audit and remove or replace*; it cannot patch.

### Cited Findings
- **Shopify shared responsibility:** Shopify secures core infrastructure, hosting and TLS. Merchants are responsible for storefront customizations, app permissions and user access. Shopify scans App Store apps, but cannot control how a third-party app uses the access tokens it was granted. — [Surebright](https://www.surebright.com/blog/shopify-is-secure-your-store-probably-isnt-a-guide-for-shopify-merchants); [Rewind](https://rewind.com/blog/shopify-security-audit-secure-store-protect-data/) (vendor blogs, not Shopify's own policy text)
- **Third-party app incidents:** Shopify attributed a data leak to a compromised third-party app. — [eSecurity Planet](https://www.esecurityplanet.com/trends/shopify-data-leak/)
- **Consentik:** A vulnerability in the Consentik (cookie consent) app exposed hundreds of stores. — [Eva.guru](https://eva.guru/blog/consentik-shopify-security-breach-incident/)
- **Oct 2026 delistings:** A claim that "hundreds of apps were delisted in October 2026 after malicious code incidents" appeared in only one source. — **[UNVERIFIED single-source claim, source not identified in results]**

### Inferences
- **Owner-side work on SaaS builders:**
  - inventory installed apps and scopes
  - flag apps with known advisories or abandoned apps
  - review theme code and third-party `<script>` tags (Magecart-style skimmers)
  - enforce 2FA and staff-account hygiene
  - monitor for client-side script changes
- **Webflow, Wix, Squarespace:** These platforms likewise patch their core. Owner risk is in custom code embeds, Velo backend code (Wix), and third-party integrations. **[background, not verified this session]**
- **No feed to subscribe to:** Machine-readable vulnerability feeds for builder apps essentially don't exist. Detection there means scraping app listings or vendor notices.

### Gaps
- I found no official shared-responsibility documents from Wix, Squarespace or Webflow. The search returned nothing for them.
- No official Shopify security-policy page was retrieved.

## 5. Infrastructure under websites: OS packages, PHP EOL, web servers, containers, managed hosting, control panels

### Takeaway
Much real-world website compromise in 2026 came from below the CMS. Control panels were the prime example: the cPanel/WHM authentication bypass CVE-2026-41940 (CVSS 9.8, in CISA KEV) was exploited for weeks before a patch. The PHP runtime is also reaching EOL: 8.1 ended 31 Dec 2025 and **8.2 ends 31 Dec 2026**. Container images can be patched without a rebuild using Copa and Trivy.

### Cited Findings
**Control panels**
- **CVE-2026-41940 (cPanel/WHM):** An authentication bypass, CVSS 9.8, added to CISA KEV. It was exploited as a zero-day for at least about 30 days before the patch, with attempt indicators back to 23 Feb 2026. Reported late Apr / early May 2026. — [Help Net Security 30 Apr 2026](https://helpnetsecurity.com/2026/04/30/cpanel-zero-day-vulnerability-cve-2026-41940-exploited/); [The Register 1 May 2026](https://www.theregister.com/2026/05/01/critical_cpanel_vuln_hits_cisa/); [Malwarebytes May 2026](https://www.malwarebytes.com/blog/news/2026/05/actively-exploited-cpanel-bug-exposes-millions-of-websites-to-takeover); [Cybersecurity Dive](https://cybersecuritydive.com/news/critical-vulnerability-cpanel-widespread-exploitation/819208)
- **CVE-2026-48172 (LiteSpeed cPanel plugin):** A privilege escalation that any cPanel user can use to run scripts as root. Added to CISA KEV on 26 May 2026. — [search summary; source among cPanel results, e.g. GovInfoSecurity](https://www.govinfosecurity.com/attacks-surge-against-vulnerable-cpanel-whm-software-a-31571) **[exact source of the KEV date not confirmed]**
- **Aug–Sep 2026 privilege escalations:** cPanel (CVE-2026-65643, file creation via parked/addon domains; CVE-2026-58048, a 9.4 root SQL context via database rename) and Plesk for Linux (CVE-2026-67394, customer/reseller to root, fixed in 18.0.79.9 and 18.0.80.5) had privilege escalation fixes. Exploitation status is unconfirmed. — [The Hacker News Aug 2026](https://thehackernews.com/2026/08/critical-cpanel-flaw-could-let-one.html); [The Hacker News Sep 2026](https://thehackernews.com/2026/09/new-cpanel-flaw-lets-hosting-account_0272795595.html); [webhosting.today 24 Sep 2026](https://webhosting.today/2026/09/24/cpanel-patches-a-root-escalation-that-starts-from-an-ordinary-hosting-account/); [privatedevops](https://privatedevops.com/news/cpanel-plesk-root-escalation-august-2026)

**PHP lifecycle**
- **PHP 8.1** reached EOL on 31 Dec 2025.
- **PHP 8.2** is security-only and goes fully EOL on **31 Dec 2026**.
- **PHP 8.3** is security-only since 23 Nov 2025, with EOL on 31 Dec 2027.
- **PHP 8.4:** active support ends 31 Dec 2026, security support until end of 2028.
- **PHP 8.5** was released 20 Nov 2025.
- **After EOL:** Distributions and LTS vendors (e.g. HeroDevs, TuxCare) backport fixes.

Sources for all of the above: [php.watch](https://php.watch/news/2025/12/php-81-eol); [php.net supported versions](https://secure.php.net/supported-versions); [HeroDevs](https://www.herodevs.com/blog-posts/php-end-of-life-dates-support-timeline-for-every-version-2026); [TuxCare](https://tuxcare.com/blog/php-8-2-eol/)

**Containers**
- **Copacetic (copa):** A CNCF Sandbox project from Microsoft, built on BuildKit. It patches OS packages in container images *without a full rebuild*, using a scanner report (Trivy JSON, e.g. `trivy image --vuln-type os --ignore-unfixed -f json`). It adds a patch layer and can handle distroless images.
- **Copa integrations:** copa-action (GitHub Actions), Azure Container Registry Continuous Patching, and Kubescape/Grype integration.
- **Copa limits:** It only fixes OS-package vulnerabilities, not app-level ones (npm, Composer). Post-patch verification is the operator's job.

Sources for the container findings: [Microsoft Open Source blog](https://opensource.microsoft.com/blog/2024/09/18/project-copacetic-quick-and-efficient-container-image-patching/); [Copa quick start](https://project-copacetic.github.io/copacetic/website/quick-start); [LinuxConfig tutorial](https://linuxconfig.org/patch-docker-container-vulnerabilities-with-trivy-and-copa); [DEV/Azure](https://dev.to/azure/automate-container-image-patching-with-copacetic-and-github-actions-4mea)

### Inferences
- **OS auto-patching:** **[background, not verified this session]** Debian/Ubuntu `unattended-upgrades` (security pocket by default) and RHEL/Fedora `dnf-automatic` (`upgrade_type = security`) are mature auto-patchers. Known gotchas:
  - services need restarting (`needrestart`)
  - kernel updates need a reboot or livepatch
  - third-party PPAs and repos are excluded by default
  - PHP from ondrej/sury repos may not be covered
  - nginx and Apache from distro packages get backported fixes, but the version strings stay old, which fools version-based scanners
- **PHP EOL is a blocker for app patches:** Every site still on PHP 8.1 (and from 1 Jan 2027, 8.2) runs an unsupported runtime. App-level security bumps (Drupal 11, Laravel 12, Composer packages) may need a newer PHP. A patcher needs a "runtime upgrade" track that is separate from "dependency bump".
- **Managed and shared hosting:** The site owner usually cannot patch the panel, OS or PHP build. The patcher should detect the host or panel and route to "ask the host / switch the PHP version in the panel".
- **Control panels:** The panel itself (cPanel's `upcp` auto-update tiers, Plesk auto-updates) must be on auto-update. This is high leverage, given CVE-2026-41940. **[upcp/Plesk mechanics: background, not verified this session]**

### Gaps
- No 2026 nginx or Apache httpd CVE data was retrieved.
- No primary docs for unattended-upgrades or dnf-automatic were fetched this session.
- I could not verify the exact CISA KEV entry dates for the cPanel CVEs against cisa.gov.

## 6. Universal fallback: virtual patching via WAF (ModSecurity/OWASP CRS, Cloudflare, AWS WAF)

### Takeaway
Cloud WAFs can ship emergency rules within hours: Cloudflare covered React2Shell on disclosure day, 3 Dec 2025, even on the Free plan. That makes a WAF a useful stop-gap while the real patch is tested. But attackers quickly probe WAF limits such as body-size inspection, and every vendor still says to patch. Open-source OWASP CRS is generic and signature-based; specific coverage depends on rule updates (a CRS-mode rule update for React2Shell landed around 5 Dec 2025, per HAProxy).

### Cited Findings
- **Cloudflare timing:** Cloudflare deployed managed WAF rules for React2Shell, with default action Block, hours before the official advisory. The blog post is dated 3 Dec 2025. The rules were included in the **Free Managed Ruleset** and the standard managed rulesets, so they protect any proxied traffic. — [Cloudflare blog: WAF rules for React vulnerability](https://blog.cloudflare.com/waf-rules-react-vulnerability); [Digit](https://www.digit.in/news/general/cloudflare-says-its-waf-is-already-protecting-users-from-new-react-security-flaws-here-what-it-means.html)
- **Exploitation and bypass attempts:** Cloudflare's threat brief reports scanning and exploitation attempts within hours of disclosure, and attackers trying to bypass WAF inspection limits. Miggo reports Cloudflare temporarily raised inspection limits to 1 MB, then reverted. — [Cloudflare threat brief](https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/); [Miggo](https://www.miggo.io/react2shell)
- **Cloudflare target:** Cloudflare describes a general target of about 12 hours from public PoC to a live rule. — (search summary of Cloudflare materials; [Cloudflare TV](https://cloudflare.tv/event/proactive-waf-vulnerability-protection-firewall-for-ai-multiplayer-chess-demo-in-chatgpt/ea8AYEZR)) **[the "12 hours" figure is Cloudflare self-reporting via search summary; not read directly]**
- **HAProxy / OWASP CRS:** HAProxy Enterprise WAF guidance says CRS-mode protection depends on the rule version, and tells users to update to rules released on **5 Dec 2025**. — [HAProxy](https://cdn.haproxy.com/blog/react2shell-cve-2025-55182-mitigation-haproxy)
- **Kemp:** Kemp says OWASP CRS can block the public React2Shell PoCs. — [Kemp](https://kemptechnologies.com/blog/improve-protection-against-react2shell-vulnerability-using-progress-kemp-loadmaster-waf)
- **CrowdSec:** CrowdSec ships per-CVE "vpatch" rules, for example `vpatch-CVE-2025-55182`. — [CrowdSec](https://www.crowdsec.net/blog/react2shell-overly-spicy-side-of-react-19)
- **Adobe Commerce Cloud:** Adobe deployed WAF protection on Commerce Cloud for SessionReaper, but still told merchants to apply the hotfix. — [Help Net Security](https://www.helpnetsecurity.com/2025/10/23/adobe-magento-cve-2025-54236-attack/)
- **Next.js header strip:** A one-line edge rule (strip the `x-middleware-subrequest` header) was a documented stop-gap for CVE-2025-29927. — [Next.js blog](https://nextjs.org/blog/cve-2025-29927)

### Inferences
- **Recommended pattern for an AI patcher:**
  1. On a new critical advisory, check whether the site sits behind a managed WAF (Cloudflare, Fastly, AWS, Sucuri) and whether a vendor rule exists. If so, enable it or confirm it's in Block mode.
  2. Optionally deploy a narrow custom rule (header strip, path block such as Magento `/customer/address_file/upload`).
  3. Then do the real patch through the normal test-and-deploy pipeline.
  4. Remove temporary custom rules after patching to avoid false-positive drift.
- **Self-hosted WAFs lag:** ModSecurity/CRS lags managed cloud WAFs for CVE-specific coverage, because CRS is generic, community-paced, and the operator has to update it.

### Gaps
- No confirmation of an AWS WAF managed rule group update for React2Shell; only a third-party AWS-style JSON example (Miggo) was found.
- No confirmation of a specific OWASP CRS release (version number) that adds React2Shell coverage.
- There is no systematic data on median time-from-disclosure-to-WAF-rule across vendors.
