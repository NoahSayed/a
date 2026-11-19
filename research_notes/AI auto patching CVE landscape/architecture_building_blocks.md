# Architecture Building Blocks: AI System for CVE Monitoring, Impact Matching, and Auto-Patching (as of Nov 2026)

Research method note (read first): This session ran with a restricted network. WebSearch worked; WebFetch was blocked for nvd.nist.gov, google.github.io (OSV docs), helpnetsecurity.com, csoonline.com and threatbeat.com. Facts below marked **[verified via search, date]** came from search results in this session. Facts marked **[background, not re-verified]** are from the researcher's prior knowledge of stable, well-documented APIs/tools, with the canonical documentation URL given; the report writer should treat them as high-likelihood but should hedge exact numbers. Nothing here was invented; where a figure could not be checked it is listed under Gaps.

## 1. Vulnerability data feeds (NVD, CVE.org, OSV, GHSA, KEV, EPSS, Vulnrichment, EUVD, vendor advisories, CSAF/VEX, exploit sources)

### Takeaway
NVD can no longer be the primary source: since April 15, 2026 NIST enriches (CPE/CVSS) only KEV, federal-software and EO 14028 "critical software" CVEs, and ~29,000 older backlogged CVEs were moved to "Not Scheduled." A 2026 builder should ingest CVE records directly (cvelistV5 + CISA Vulnrichment ADP), use OSV.dev / GHSA for package-level affected-version ranges, layer KEV + EPSS for prioritization, and add EUVD and vendor CSAF/VEX feeds. The CVE program itself survived its 2025 funding scare; a contract renegotiation reported March 10, 2026 removed the March 16, 2026 cliff.

### Cited Findings

**CVE program funding (dated)**
- April 2025: MITRE warned its DHS-funded CVE contract would lapse; CISA's $57.8M contract with MITRE had an option to continue to March 16, 2026, and CISA executed that option (11-month extension) "to ensure there will be no lapse in critical CVE services." — [The Record](https://therecord.media/cisa-extends-cve-program-contract-with-mitre); [The Register, 2025-04-16](https://www.theregister.com/2025/04/16/cve_program_funding_save/); [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/cisa-cve-program-mitre-contract/)
- A MITRE spokesperson said that if the contract lapsed, no new CVEs would be added and the CVE website would eventually go offline. — [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/cisa-cve-program-mitre-contract/)
- CVE Board members were "kept in the dark" about the funding situation; contract terms remained opaque even to the board. — [The Register, 2025-04-25](https://www.theregister.com/2025/04/25/cve_board_funding/)
- Long-time CVE Board members launched the non-profit **CVE Foundation** (April 2025) to pursue long-term independence. — [The Register](https://www.theregister.com/2025/04/16/cve_program_funding_save/); [Senthorus blog](https://blog.senthorus.ch/posts/mitre_cve/)
- Sept 2025: CISA published a CVE program roadmap/"quality era" document saying it was evaluating "potential mechanisms for diversified funding" and that the program should remain publicly maintained and vendor-neutral. — [Help Net Security, 2025-09-12](https://www.helpnetsecurity.com/2025/09/12/cisa-cve-program-future/); [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/cisa-launches-roadmap-cve-program/)
- **March 10, 2026**: CSO Online reported "CVE program funding secured, easing fears of repeat crisis" — CISA and MITRE renegotiated the contract in a way that eliminates the looming expiration. Contract length/terms were not visible in the snippet (page fetch blocked). **[verified via search snippet only]** — [CSO Online](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html); [Threat Beat mirror](https://threatbeat.com/cve-program-funding-secured-easing-fears-of-repeat-crisis/)

**NVD API 2.0 and enrichment backlog (dated)**
- Rate limits: 5 requests per rolling 30-second window without an API key; 50 requests per rolling 30 s with a key. — [NVD Start Here (official, via search)](https://nvd.nist.gov/developers/start-here)
- CVE API `resultsPerPage` maximum is 2,000 (CPE API up to 10,000); NVD separately changed the `/cpematch/` resultsPerPage limit. — [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities-1); [nvd-api Python client](https://kannkyo.github.io/nvd-api/html/_modules/nvd_api/client.html); [NVD news: cpematch resultsPerPage update](https://nvd.nist.gov/general/news/cpematch-resultsperpage-update)
- Date-range parameters (`lastModStartDate`/`lastModEndDate`, `pubStartDate`/`pubEndDate`) are limited to 120 consecutive days (reported by community clients; NVD's own page could not be fetched). — [DEV Community guide](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p)
- Endpoints: `https://services.nvd.nist.gov/rest/json/cves/2.0`, `/cvehistory/2.0` (change history), `/cpes/2.0`, `/cpematch/2.0`; NVD recommends sleeping ~6 s between requests and using `lastModStartDate` deltas for sync; the legacy 1.1 JSON data feeds were retired in 2023. **[background, not re-verified]** — [NVD API workflows](https://nvd.nist.gov/developers/api-workflows)
- **April 15, 2026**: NIST announced it will no longer try to enrich every CVE. Priority enrichment now goes to CVEs in CISA KEV, CVEs in federal-government software, and "critical software" under EO 14028; everything else is "Lowest Priority – not scheduled for immediate enrichment." — [Help Net Security, 2026-04-16](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/); [Socket](https://socket.dev/blog/nist-officially-stops-enriching-most-cves); [CSA Research Note, 2026-04-29](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- ~29,000 backlogged CVEs with NVD publish date before March 1, 2026 were reclassified to "Not Scheduled"; enrichment for a specific CVE can be requested by emailing nvd@nist.gov. Backlog counts vary by source (one reports visible backlog dropping from 33,000+ to ~4,000 after reclassification; another says 27,000+ CVEs have no NVD enrichment). — [Help Net Security](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/); [Black Duck](https://www.blackduck.com/blog/nist-nvd-policy-shift-2026.html); [Strobes](https://strobes.co/blog/nist-nvd-cve-prioritization-update-2026/)
- CSA warns missing CPE data makes a CVE "operationally invisible" to CPE-matching tools, so NVD-only tools may miss or under-rank new CVEs. — [CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- June 2026: a draft Commerce Inspector General review reportedly found NVD severity scores wrong 88% of the time and said NIST lacks sustainable processes to clear the backlog (secondary reporting; IG document not verified). — [TechTimes, 2026-06-02](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm)
- Historical context: CISA launched Vulnrichment in May 2024 when the NVD backlog hit ~10,000. — [Socket](https://socket.dev/blog/cisa-launches-vulnrichment-project-as-nvd-backlog-hits-10-000); [SecurityWeek](https://www.securityweek.com/cisa-announces-cve-enrichment-project-vulnrichment/)

**CVE.org / cvelistV5**
- `github.com/CVEProject/cvelistV5` holds all CVE records in CVE JSON 5.x format, updated continuously (roughly every few minutes) with delta commits plus periodic release zips; CVE Services API (`cveawg.mitre.org/api`) is primarily for CNAs to publish/reserve IDs. Records include CNA container plus ADP containers (e.g., CISA ADP). **[background, not re-verified]** — [cvelistV5 repo](https://github.com/CVEProject/cvelistV5)

**CISA Vulnrichment (ADP)**
- Vulnrichment is the public repo of CISA's enrichment of CVE records through the CISA ADP container; every CVE analyzed has three SSVC decision points (Exploitation, Automatable, Technical Impact); KEV entries get a KEV block; CISA may also add CVSS/CWE/CPE where the CNA did not. Consumers should check the SSVC version string. CISA's guide uses `jq` on the ADP container titled "CISA ADP Vulnrichment." — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment); [CISA: Unlocking Vulnrichment](https://cisa.gov/news-events/news/unlocking-vulnrichment-enriching-cve-data); [heise background](https://heise.de/en/background/CVEs-More-and-better-information-on-vulnerabilities-from-CISA-9845597.html?seite=all)

**CISA KEV**
- Single JSON file at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` with all entries, a `catalogVersion` and `dateReleased`; also mirrored in CSV/JSON at `github.com/cisagov/kev-data`. — [cisagov/kev-data](https://github.com/cisagov/kev-data); [decryptiondigest guide](https://www.decryptiondigest.com/blog/cisa-kev-api-json-feed-automation-guide)
- Entry fields include `cveID`, `vendorProject`, `product`, `dateAdded`, `dueDate`, `requiredAction`, `knownRansomwareCampaignUse`. **[background, not re-verified]** — [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**FIRST EPSS**
- API endpoint `https://api.first.org/data/v1/epss` (FIRST labels it beta); supports `?cve=` (comma-separated), `date=`, `epss-gt=`, `percentile-gt=`, pagination; one client batches 100 CVEs/request (client-side choice, not a documented quota). No official rate limit found. — [api.first.org/epss](https://api.first.org/epss); [vulnera-advisor client](https://docs.rs/crate/vulnera-advisor/0.1.7/source/src/sources/epss.rs)
- EPSS v4 is the current model in the feed; Empirical Security (EPSS maintainers' company) offers an enterprise API with hourly rather than daily updates. — [Empirical Security docs](https://docs.empiricalsecurity.com/models/epss)
- EPSS v4 released March 17, 2025; full daily CSV dumps at `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz`. **[background, not re-verified]** — [FIRST EPSS](https://www.first.org/epss/)

**OSV.dev**
- `POST /v1/querybatch` accepts max 1,000 package-version queries per request (official Swagger). — [OSV Swagger](https://osv.dev/docs/osv_service_v1.swagger.json); [OSV docs: querybatch](https://google.github.io/osv.dev/post-v1-querybatch)
- Data dumps: bucket `gs://osv-vulnerabilities`, per-ecosystem `<ECOSYSTEM>/all.zip`; a July 2026 guide also lists a root `all.zip` (`https://storage.googleapis.com/osv-vulnerabilities/all.zip`), `modified_id.csv` for incremental sync, and `ecosystems.txt` (root all.zip not confirmed in official docs this session). — [OSV data sources](https://google.github.io/osv.dev/data); [OneUptime mirror guide, 2026-07-23](https://oneuptime.com/blog/post/2026-07-23-mirror-update-osv-database/view); [osv.dev issue #2423](https://github.com/google/osv.dev/issues/2423)
- OSV published API latency improvements and revised SLOs. — [OSV blog](https://osv.dev/blog/posts/api-latency-improvements-and-revised-slos)
- Other endpoints: `POST /v1/query` (single package/version or commit hash), `GET /v1/vulns/{id}`, and experimental `determineversion` (C/C++ version from file hashes); OSV aggregates GHSA, PyPA, Go, RustSec, Debian, Ubuntu, Alpine, Chainguard, etc.; no API key required. **[background, not re-verified]** — [OSV API docs](https://google.github.io/osv.dev/api/)
- A 2022 Renovate issue cited the OSV API as rate-limited to ~100 requests/min per IP (old; unverified for 2026). — [renovate issue #6562 / discussion](https://github.com/renovatebot/renovate/issues/6562)

**GitHub Advisory Database (GHSA)**
- Data in `github.com/github/advisory-database` in OSV JSON format, licensed CC-BY-4.0; REST `GET /advisories` (global advisories) and `GET /repos/{owner}/{repo}/dependabot/alerts`; GraphQL `securityAdvisories`/`securityVulnerabilities`; REST primary rate limit 5,000 req/h for authenticated users (15,000 for GitHub Enterprise Cloud apps), 60/h unauthenticated. **[background, not re-verified]** — [advisory-database repo](https://github.com/github/advisory-database); [REST global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories); [REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- Oct 1, 2026: GitHub introduced rate limits for private vulnerability reports (changelog). — [GitHub changelog 2026-10-01](https://github.blog/changelog/2026-10-01-rate-limits-for-private-vulnerability-reports)
- A vendor blog claims GitHub and OSV disagree on 31% of advisories across a 240-repo org (methodology unverified). — [safeguard.sh](https://www.safeguard.sh/resources/blog/renovate-2026-security-mode-field-test)

**EUVD (ENISA)**
- Community clients use base `https://euvdservices.enisa.europa.eu/api` with endpoints such as `/lastvulnerabilities`, `/criticalvulnerabilities`, `/exploitedvulnerabilities`, `/vulnerability?id=`, `/enisaid?id=`, `/advisory?id=`, `/search`; official docs at `euvd.enisa.europa.eu/apidoc`. Endpoint lists differ between client versions. — [euvd Rust crate](https://docs.rs/crate/euvd/0.2.0/source/README.md); [euvd-python-cli](https://pypi.org/project/euvd-python-cli/); [XSOAR integration](https://xsoar.pan.dev/docs/reference/integrations/european-union-vulnerability-database)
- VulnCheck found in May 2025 the API returned 243,969 total vs 264,920 on the website (API may not return all records). — [VulnCheck](https://www.vulncheck.com/blog/enisa-euvd)
- EUVD launched May 2025 under NIS2 Article 12; EUVD IDs (EUVD-YYYY-NNNNN) map to CVE IDs; no API key needed. **[background, not re-verified]** — [Infosecurity Europe explainer](https://www.infosecurityeurope.com/en-gb/blog/future-thinking/how-to-use-euvd-enisa.html)

**Vendor advisories / CSAF / VEX** **[background, not re-verified]**
- Microsoft MSRC: CVRF v3 API `https://api.msrc.microsoft.com/cvrf/v3.0/updates` and `/cvrf/v3.0/cvrf/{YYYY-Mon}` (no API key), Patch Tuesday 2nd Tuesday monthly; MSRC also publishes CSAF. — [MSRC API](https://msrc.microsoft.com/update-guide/); [microsoft/MSRC-Microsoft-Security-Updates-API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API)
- Red Hat: Security Data API `https://access.redhat.com/hydra/rest/securitydata/` and CSAF advisories + VEX files at `https://security.access.redhat.com/data/csaf/v2/` (Red Hat publishes VEX per CVE). — [Red Hat Security Data](https://access.redhat.com/security/data)
- Debian security tracker JSON `https://security-tracker.debian.org/tracker/data/json`; Ubuntu publishes OSV/OVAL and USN data (also in OSV). Android monthly Security Bulletins (source.android.com/docs/security/bulletin); Apple security releases index (support.apple.com/en-us/100100) is HTML-only, no API.
- CSAF 2.0 is an OASIS standard (2022) with a VEX profile; alternative VEX formats are OpenVEX and CycloneDX VEX; vendors publish CSAF via `provider-metadata.json` discovery (e.g., `/.well-known/csaf/`). — [OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html); [OpenVEX](https://github.com/openvex/spec)

**Exploit/PoC sources** **[background, not re-verified]**
- Exploit-DB (`gitlab.com/exploit-database/exploitdb`, `files_exploits.csv` with CVE codes); Metasploit module metadata (`db/modules_metadata_base.json` in rapid7/metasploit-framework); ProjectDiscovery `nuclei-templates` (templates tagged by CVE, MIT); GitHub PoC aggregators `nomi-sec/PoC-in-GitHub` and `trickest/cve`. GitHub PoC repos are a known malware vector — treat as untrusted, never execute outside an isolated sandbox. — [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates); [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)

### Inferences
- Recommended ingestion core (all free): cvelistV5 git pull every 5–15 min (canonical CVE + CNA data + CISA ADP/Vulnrichment), OSV.dev bucket sync via `modified_id.csv` (package/ecosystem affected ranges — the thing you actually match on), GHSA (via OSV or GraphQL), KEV JSON (hourly poll), EPSS daily CSV, EUVD as EU-regulatory cross-check, and vendor CSAF feeds for OS/commercial products. NVD becomes optional enrichment, not a dependency.
- Because NVD CPEs are now missing for most new CVEs, product matching for non-package software (appliances, commercial apps) must rely on CNA-provided `affected` data, vendor CSAF, or LLM extraction from advisory text — this is exactly where an LLM adds value but also where hallucination risk is highest.
- The CVE program's 2025–2026 fragility argues for designing the identifier layer to be multi-ID (CVE, GHSA, OSV, EUVD, vendor IDs) with alias resolution (OSV `aliases` field does this already).

### Gaps
- Exact terms/length of the March 2026 CISA–MITRE renegotiated contract (page fetch blocked); status of CVE Foundation in 2026.
- Official EPSS API rate limit (not documented in sources found).
- Current official OSV API rate limit/SLO numbers (docs blocked).
- Whether NVD published further API changes after April 2026 (none found).
- Current status of GCVE (CIRCL's decentralized alternative) not researched.

## 2. Security news sources and LLM extraction from unstructured news

### Takeaway
News is a leading indicator (zero-days, vendor incidents, big-tech breach reports often precede structured CVE data by hours to days), but it is unstructured and adversary-controllable text. Use RSS + selected social streams, have an LLM extract a strict JSON schema (vendor, product, versions, CVE IDs, exploitation status, fix availability), and always reconcile against structured feeds before acting — never let news text directly drive privileged actions.

### Cited Findings
- Common machine-readable feeds **[background, not re-verified]**: BleepingComputer `https://www.bleepingcomputer.com/feed/`; The Hacker News `https://feeds.feedburner.com/TheHackersNews`; SecurityWeek `https://www.securityweek.com/feed/`; Krebs on Security `https://krebsonsecurity.com/feed/`; Google Project Zero blog (`googleprojectzero.blogspot.com` Atom feed) and Project Zero issue tracker; MSRC blog, Google Online Security Blog, GitHub Security Lab, AWS security bulletins, CISA advisories RSS (`https://www.cisa.gov/cybersecurity-advisories/all.xml`). — [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- Social signals **[background, not re-verified]**: Mastodon (e.g., infosec.exchange) has free streaming/hashtag APIs; Bluesky offers an open firehose/Jetstream; Reddit r/netsec and r/sysadmin via API; X's API is paid and expensive at useful tiers. — [Bluesky Jetstream](https://github.com/bluesky-social/jetstream); [Mastodon streaming API](https://docs.joinmastodon.org/methods/streaming/)
- Time-to-exploit pressure is rising: Google Threat Intelligence Group (Nov 2026) reported an "exploit_agent" system that diffs pre/post-patch code, identifies the likely vulnerability, drafts and runs exploits without humans, shrinking the patch-to-weaponization "grace period." — [TechTarget](https://www.techtarget.com/news/google-finds-ai-agents-autonomously-turning-patches-into-exploits/874837/); [CSA Research Note, 2026-11-18](https://labs.cloudsecurityalliance.org/research/csa-research-note-gtig-exploit-agent-patch-diffing-20261118/)
- Prompt injection via untrusted text entering agent prompts is a confirmed real-world attack class (see section 6); advisory/news text, GitHub issue titles and PoC READMEs are all attacker-writable. — [Aikido PromptPwnd](https://aikido.dev/blog/promptpwnd-github-actions-ai-agents); [CSA Clinejection note](https://labs.cloudsecurityalliance.org/research/csa-research-note-clinejection-prompt-injection-cicd-cache-p/)

### Inferences
- Extraction design: a low-cost model (classifier) filters items as "vulnerability-relevant"; a stronger model extracts into a JSON schema with `evidence_quote` fields per extracted value (forces grounding, lets a validator check the quote exists in source). Map extracted product names to purl/CPE via a curated alias table + OSV/GHSA lookup rather than trusting LLM-produced CPEs.
- The extraction LLM should have no tools and no secrets (a "quarantined" model, dual-LLM pattern); its output is data, schema-validated, and only creates a "watch" signal that raises priority for structured-feed matching — it should never trigger patching by itself.
- Dedup/cluster stories by CVE ID and by embedding similarity; score by source credibility (vendor/CISA > established outlets > social).

### Gaps
- No quantitative source found this session on news-vs-NVD lead time, or benchmarked LLM accuracy for product/version extraction from security news.
- Current X/Twitter API pricing and Reddit API terms for 2026 not verified.

## 3. Matching vulnerabilities to the application (SBOM, scanners, reachability, VEX)

### Takeaway
Generate an SBOM per build (Syft → CycloneDX/SPDX), match with osv-scanner/Grype/Trivy against OSV/GHSA data, then cut noise with reachability (govulncheck for Go; CodeQL/Semgrep/commercial call-graph tools for others) and record "not affected" decisions as VEX so they persist and are machine-consumable.

### Cited Findings
- **[background, not re-verified]** Tools and their roles:
  - Syft (Anchore) generates SBOMs from images/filesystems in CycloneDX and SPDX; Grype matches SBOMs to vulnerabilities and can consume OpenVEX. — [anchore/syft](https://github.com/anchore/syft); [anchore/grype](https://github.com/anchore/grype)
  - osv-scanner (Google) parses 20+ lockfile/manifest formats and container images, queries OSV; v2 (2025) added container-layer scanning and guided remediation (`osv-scanner fix`) for npm and Maven. — [google/osv-scanner](https://github.com/google/osv-scanner)
  - Trivy (Aqua) scans images, filesystems, repos, IaC, k8s; outputs CycloneDX/SPDX and supports VEX inputs (OpenVEX, CycloneDX VEX, CSAF). — [aquasecurity/trivy](https://github.com/aquasecurity/trivy)
  - OWASP Dependency-Check is NVD/CPE-based (requires an NVD API key since v9) — hence most degraded by the 2026 NVD enrichment cutback. — [dependency-check](https://github.com/jeremylong/DependencyCheck)
  - govulncheck uses the Go vulnerability DB's symbol-level data and reports only vulns whose vulnerable functions are reachable from your code (call graph) or present in binaries. — [Go vuln docs](https://go.dev/doc/security/vuln/)
  - Semgrep Supply Chain, Endor Labs, Snyk and others offer function-level reachability for several ecosystems; CodeQL can model data-flow to vulnerable sinks for first-party code.
- CPE-based matching breaks for most new CVEs because NVD no longer assigns CPEs to them. — [CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- Copa consumes a Trivy JSON report of OS-package vulns to patch images (shows scanner output can drive remediation directly). — [Copacetic tutorial](https://github.com/project-copacetic/copacetic/blob/release-0.1/docs/tutorials/patch.md)

### Inferences
- Matching pipeline: (a) SBOM per artifact stored with digest; (b) nightly + on-new-advisory re-match (advisory-triggered re-match against stored SBOMs is far cheaper than rescanning); (c) status per finding = affected / not_affected (with VEX justification: `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, etc.) / fixed / under_investigation.
- LLM role in matching: read advisory + patch commit to identify vulnerable functions when the advisory lacks symbol data, then use a static call-graph tool to check reachability — the LLM proposes, the static tool verifies.
- Run two scanners (e.g., osv-scanner + Grype or Trivy) and union results; disagreement across databases is non-trivial (the unverified 31% GHSA/OSV disagreement claim suggests checking both).

### Gaps
- No benchmark found this session on reachability tools' false-negative rates.
- Exact current osv-scanner/Trivy/Grype version features as of Nov 2026 not re-verified.

## 4. Patch generation (dependency bumps, breaking-change repair, first-party fixes, OpenRewrite, container patching, backports)

### Takeaway
Most fixes (>majority of SCA findings) are dependency version bumps: use Renovate or Dependabot for the mechanical bump, then use an LLM coding agent only to repair build/test breakage. For first-party code, pair a SAST finding (CodeQL/Semgrep) with an LLM fix (GitHub Copilot Autofix and its agentic variant is the mainstream productized version). For containers, Copa patches OS packages without rebuild. Deterministic transformations (OpenRewrite) should be preferred over LLM edits wherever a recipe exists.

### Cited Findings
- Renovate `osvVulnerabilityAlerts` (experimental, added v34.129.0) uses OSV data but only covers direct dependencies; `vulnerabilityAlerts` uses the host SCM's (GitHub) alerts API per repo; OSV API rate-limit-induced PR flapping was addressed via `renovatebot/osv-offline` (v34.142.0). — [Renovate config-options diff](https://git.shivering-isles.com/github-mirror/renovatebot/renovate/-/commit/a91ca62b466b57aa9a18f4e15bd04eb5552278b1.diff); [Renovate discussion #20542](https://github.onedrive11.workers.dev/renovatebot/renovate/discussions/20542); [osv-offline](https://awesome.ecosyste.ms/projects/github.com%2Frenovatebot%2Fosv-offline)
- Copa (Copacetic, CNCF Sandbox, originally Microsoft) patches container images directly from a scanner report (e.g., `trivy image --vuln-type os --ignore-unfixed -f json -o report.json <img>` then `copa patch -i <img> -r report.json -t <tag>`), using BuildKit, without a full rebuild. — [Microsoft Open Source blog](https://opensource.microsoft.com/blog/?p=96360); [linuxconfig guide](https://linuxconfig.org/patch-docker-container-vulnerabilities-with-trivy-and-copa); [Copa tutorial](https://github.com/project-copacetic/copacetic/blob/release-0.1/docs/tutorials/patch.md)
- GitHub Copilot Autofix generates a suggested change for a supported code-scanning alert; agentic autofix (Copilot coding agent) reportedly reached GA for GitHub Enterprise Cloud on Oct 15, 2026, fixing up to 25 alerts in a single PR (another source says public preview since July 10, 2026 — rollout stages conflict). — [GitHub Docs: autofix](https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning); [GitHub responsible-use card](https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning); (GA date from search summary only)
- Google DeepMind CodeMender (announced Oct 2025) had upstreamed 72 security fixes to OSS projects; as of a 2026 comparison it was still not publicly available. — [Datamation](https://www.datamation.com/artificial-intelligence/google-codemender/); [OpenHands blog: 8 best automated remediation tools 2026](https://www.openhands.dev/blog/automated-vulnerability-remediation-tools)
- OpenAI Aardvark (GPT-5-based find-and-fix agent) announced Oct 2025 in private beta; 2026 status unverified. — [The Hacker News](https://thehackernews.com/2025/10/openai-unveils-aardvark-gpt-5-agent.html)
- DARPA AIxCC final (Aug 2025): systems identified 86% of synthetic vulns (77% per MeriTalk) and patched 61% (MeriTalk); average ~$152 per competition task; Trail of Bits spent $39,600 total (~$181/point); teams found 18 real (non-synthetic) vulns and produced 11 real patches; several CRSs open-sourced (e.g., Trail of Bits Buttercup). — [DARPA AIxCC results](https://darpa.mil/news/2025/aixcc-results); [MeriTalk](https://www.meritalk.com/?p=200433); [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/defcon-ai-cyber-challenge-winners/); [Trail of Bits presentation](https://www.trailofbits.com/documents/AIxCC_Main_Stage_Presentation.pdf)
- OpenRewrite: deterministic, type-aware recipes (e.g., Spring Boot / Jackson / Log4j migrations, dependency upgrades) for Java/Kotlin and growing JS/Python support; Moderne runs them at scale. **[background, not re-verified]** — [OpenRewrite docs](https://docs.openrewrite.org/)
- Dependabot security updates open PRs from GHSA alerts and support grouped security updates via `dependabot.yml` `groups` with `applies-to: security-updates`. **[background, not re-verified]** — [Dependabot docs](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates)

### Inferences
- Strategy ladder (cheapest/safest first): (1) minimal semver-compatible bump to the first fixed version (OSV `ranges.events.fixed`); (2) transitive override (npm `overrides`, Maven `dependencyManagement`, Gradle constraints, pip constraints) when the parent hasn't released; (3) major bump + OpenRewrite recipe if available; (4) LLM agent repairs compile/test breakage with the changelog/migration guide in context; (5) vendor/backport a minimal patch (cherry-pick the upstream fix commit, from OSV `references` type FIX) when upgrading is infeasible; (6) mitigating config/WAF rule + VEX "affected, mitigated" as last resort.
- Backporting is where LLMs are uniquely useful: given the upstream fix commit and the pinned older version, have the agent port the diff, then validate with the regression test from the fix commit.

### Gaps
- No authoritative 2026 data on what fraction of real-world CVE fixes are pure bumps vs code changes.
- Copa's current (2026) support beyond OS packages (e.g., language packages) not verified.

## 5. Validation & shipping (tests, PoC/regression, fuzzing, canary, auto-merge, HITL, rollback, agent frameworks, sandboxing, cost per fix)

### Takeaway
"Passes CI" is not enough: a 2026 study found 170 silent failures (patches passing functional checks while keeping or introducing vulns) across seven agent frameworks. Validation must include (a) the project's tests, (b) a vulnerability-specific check (upstream regression test, PoC in a sandbox, or re-scan proving the vulnerable version/symbol is gone), (c) fuzzing for memory-unsafe code, then progressive delivery with auto-rollback. Auto-merge only low-risk classes (patch-level bumps with green CI); everything involving LLM-written code gets human review.

### Cited Findings
- A 2026 study of seven agent frameworks found 170 "silent failures": patches that passed functional checks but retained or introduced vulnerabilities. Vendor fix-accuracy claims (e.g., Snyk 85%) are vendor figures. — [OpenHands blog 2026](https://www.openhands.dev/blog/automated-vulnerability-remediation-tools) (summary via search; underlying study is likely [PatchBench, arXiv 2609.04075](https://arxiv.org/pdf/2609.04075) or [EviRepair, arXiv 2610.13491](https://arxiv.org/pdf/2610.13491) — attribution not confirmed)
- CSA research note on accountability for agentic auto-remediation ("who owns the bad patch?"). — [CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentic-autofix-remediation-accountability/)
- AIxCC cost benchmarks (~$152/task average; $151–$263 per scored point by team) give a rough ceiling for fully autonomous find+patch on C/Java OSS. — [DARPA](https://darpa.mil/news/2025/aixcc-results); [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/defcon-ai-cyber-challenge-winners/)
- Patch-to-exploit windows are shrinking due to AI exploit agents, raising the value of fast but safe rollout. — [CSA, 2026-11-18](https://labs.cloudsecurityalliance.org/research/csa-research-note-gtig-exploit-agent-patch-diffing-20261118/)
- Agent frameworks **[background, not re-verified]**: Claude Agent SDK (Anthropic; programmable agent loop with tools, permissions, hooks, subagents); OpenHands (open-source, MIT, Docker-sandboxed runtime); SWE-agent / mini-SWE-agent (Princeton/Stanford, MIT); LangGraph (stateful graph orchestration with human-in-the-loop interrupts and checkpointing). — [Claude Agent SDK](https://docs.anthropic.com/en/docs/claude-code/sdk); [OpenHands](https://github.com/All-Hands-AI/OpenHands); [SWE-agent](https://github.com/SWE-agent/SWE-agent); [LangGraph](https://github.com/langchain-ai/langgraph)

### Inferences
- Validation gates: (1) build + full test suite in ephemeral sandbox; (2) re-run scanner on the patched lockfile/image — finding must disappear; (3) for code fixes, run the upstream fix's regression test or a generated failing-then-passing test; (4) optional sandboxed PoC (nuclei template or Metasploit module) against a staging deploy, with no egress; (5) for C/C++/Rust-unsafe, short OSS-Fuzz/ClusterFuzzLite-style fuzz run; (6) diff-size and file-scope limits (agent may touch only manifest/lockfile for bump class); (7) LLM-as-reviewer as an additional, not sole, check.
- Auto-merge policy tiers: Tier A (auto-merge): patch/minor bump of a direct dep, CI green, no code changes, not a new maintainer/package (supply-chain check), release age ≥ N days (Renovate `minimumReleaseAge`) unless KEV-listed. Tier B (one human approval): LLM breaking-change repair, transitive overrides, Copa image patches for prod. Tier C (security-team review): first-party code fixes, backports, auth/crypto code.
- Shipping: canary/progressive rollout (Argo Rollouts/Flagger or feature-flag) with automated SLO-based rollback; keep the pre-patch artifact digest pinned for instant revert.
- Sandboxing: run agents in ephemeral containers/microVMs (gVisor/Firecracker), network egress allowlisted to package registries only, no production credentials, read-only repo token; PoCs only in a separate no-egress sandbox.
- Cost per fix (inference): simple bump with no breakage ≈ near-zero LLM cost; LLM breakage repair or code fix ≈ tens of cents to a few dollars per attempt at 2026 frontier-model pricing; AIxCC's ~$150/task is a full find+patch upper reference. Exact numbers were not verified this session.

### Gaps
- Could not confirm the authoritative source of the "170 silent failures" study.
- No public 2026 per-fix cost data from production remediation services found.

## 6. Security of the pipeline itself (prompt injection, auto-merge supply-chain risk, least privilege)

### Takeaway
An auto-patching agent is a privileged CI actor that reads attacker-controlled text (advisories, news, PoC READMEs, issue titles, changelogs of malicious packages). Prompt injection into AI-powered CI is now a confirmed, exploited class (PromptPwnd Dec 2025; Clinejection early 2026; Microsoft observing attempts in the wild). Treat all ingested text as untrusted data, separate read/plan from write/act privileges, and never let an agent auto-merge or hold publishing credentials.

### Cited Findings
- PromptPwnd (Aikido, Dec 2025): GitHub Actions/GitLab CI pipelines that pass untrusted input (issues, PR text, commit messages) into AI agents (Gemini CLI, Claude Code, OpenAI Codex, GitHub AI Inference) let attackers make the agent use privileged tools to leak secrets or alter workflows; described as the first confirmed real-world demonstration of prompt injection compromising CI/CD. — [Aikido](https://aikido.dev/blog/promptpwnd-github-actions-ai-agents); [eSecurity Planet](https://www.esecurityplanet.com/threats/ai-agents-create-critical-supply-chain-risk-in-github-actions/)
- Clinejection: prompt injection in a GitHub issue title enabled CI/CD cache poisoning and supply-chain compromise; CSA says the class has been confirmed in repos of at least five Fortune 500 companies and Google. (Claim that Cline's npm package was tampered on 2026-02-17 is from a less-established source — unverified.) — [CSA Clinejection note](https://labs.cloudsecurityalliance.org/research/csa-research-note-clinejection-prompt-injection-cicd-cache-p/)
- CSA (May 2026) analyzed Copilot Coding Agent, Gemini CLI and Claude Code embedded in GitHub Actions; Microsoft reported observing prompt-injection attempts in public repos using AI-assisted workflows across vendors. — [CSA note, 2026-05-03](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-github-actions-security-20260503-csa-st/); [Microsoft Security blog](https://www.microsoft.com/en-us/security/blog/?p=147931)
- Gemini CLI prompt-injection issues in GitHub workflows reported Oct 2026. — [Cyber Security News](https://cybersecuritynews.com/gemini-cli-prompt-injections-github/)
- Related CI supply-chain incidents: tj-actions/changed-files compromise (March 2025) and Shai-Hulud 2.0 npm worm. — [eSecurity Planet](https://www.esecurityplanet.com/threats/ai-agents-create-critical-supply-chain-risk-in-github-actions/)
- GitHub's own Copilot Autofix responsible-use documentation describes limitations and the need for human review of suggestions. — [GitHub Docs](https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning)

### Inferences
- Controls checklist:
  - Ingestion: strip/escape markup, size-limit fields, wrap untrusted text in clearly delimited data blocks; extraction model has no tools; schema-validate outputs; reject instructions-like content heuristically and log it.
  - Privilege split: "analyst" agent (read-only repo, no secrets) produces a plan; "patcher" agent runs in sandbox with a short-lived, repo-scoped GitHub App token limited to `contents:write` on a bot branch + `pull_requests:write`; never `workflows:write`, never org-admin, never registry publish tokens.
  - Never run agents on `pull_request_target`/`issue_comment` triggers with secrets exposed to untrusted text; pin Actions to commit SHAs; use OIDC for cloud creds; branch protection requiring human or policy-engine approval.
  - Supply chain of the fix itself: before bumping, check new version's provenance (npm/PyPI trusted publishing / Sigstore attestations), maintainer changes, install scripts, and package age; a "security fix" release can itself be malicious (Shai-Hulud-type worms).
  - Egress allowlists for agent sandboxes; tool-call allowlists (no arbitrary curl); audit log of every agent action.

### Gaps
- No primary-source verification of the Clinejection/Cline npm compromise details.
- No published standard (e.g., OpenSSF) specifically for AI auto-remediation pipelines found this session.

## 7. Recommended MVP pipeline (synthesis)

### Takeaway
Build the MVP around free structured data (cvelistV5 + Vulnrichment, OSV/GHSA, KEV, EPSS), standard scanners (Syft + osv-scanner/Grype), Renovate/Dependabot for mechanical bumps, and an LLM agent (Claude Agent SDK, OpenHands or LangGraph-orchestrated) only for triage explanation and breakage repair — with human-approved merges and progressive rollout.

### Cited Findings
- NVD no longer enriches most CVEs, so the MVP must not depend on it. — [Help Net Security](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/)
- OSV querybatch (1,000/req) and bucket dumps support efficient bulk matching. — [OSV Swagger](https://osv.dev/docs/osv_service_v1.swagger.json); [OSV data](https://google.github.io/osv.dev/data)
- Copa + Trivy gives a ready path for container OS-package patching. — [linuxconfig](https://linuxconfig.org/patch-docker-container-vulnerabilities-with-trivy-and-copa)
- AI-in-CI prompt injection is real, so the agent must be sandboxed and least-privileged. — [Aikido](https://aikido.dev/blog/promptpwnd-github-actions-ai-agents)

### Inferences
MVP stages (inference, assembled from the cited building blocks):
1. **Ingest (every 5–15 min):** git pull cvelistV5; OSV `modified_id.csv` delta; KEV JSON; EPSS daily; GHSA via GraphQL `updatedSince`; RSS (10–20 feeds) → normalized `Advisory` table keyed by aliases (CVE/GHSA/OSV/EUVD).
2. **News extraction:** tool-less LLM → JSON schema with evidence quotes → "watch" signals only.
3. **Inventory:** Syft SBOM per build artifact (CycloneDX), stored with commit + image digest; service-to-repo ownership map.
4. **Match:** on each new/changed advisory, re-match against stored SBOMs (osv-scanner/Grype); for Go run govulncheck; otherwise optional reachability tool.
5. **Prioritize:** KEV > EPSS percentile > CVSS/SSVC (Vulnrichment) > reachability > exposure (internet-facing). SLA tiers (e.g., KEV+reachable: 24–72h).
6. **Triage/VEX:** LLM drafts an explanation + proposed VEX status with citations; human confirms "not_affected" (stored as OpenVEX/CycloneDX VEX, fed back into scanners).
7. **Fix:** Renovate/Dependabot bump → if CI fails, agent (sandboxed, no egress beyond registries, scoped token) repairs on bot branch, max N iterations / $ budget; containers via Copa; first-party via CodeQL/Semgrep finding + agent fix.
8. **Validate:** tests + re-scan + regression/PoC-in-sandbox + LLM review summary in PR body.
9. **Ship:** policy-based auto-merge only for Tier A; others human approval; canary + automated rollback; close loop by updating VEX/finding status and metrics (MTTR, fix success rate, $/fix, revert rate).

### Gaps
- No verified 2026 reference architecture from a vendor or standards body to compare against; MVP above is the researcher's synthesis.
