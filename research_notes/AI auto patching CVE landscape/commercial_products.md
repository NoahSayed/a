# Commercial AI Auto-Remediation / Auto-Patching Products: Competitive Landscape (as of 19 Nov 2026)

Method note: Built from about 20 web searches on 19 Nov 2026. Full-page fetches were blocked by the session network policy (for example, thenewstack.io could not be resolved), so most findings come from search-result content. Each source URL is cited. Where the cited page is a vendor or competitor blog, the finding says so. Dates are publication or event dates as reported.

---

## Q1. Platform players: what each does, AI involvement, scope, pricing, status

### Takeaway
By late 2026, every major platform has moved from "suggest a fix" to agentic fix-and-open-PR flows. The main examples are GitHub (agentic autofix, GA Oct 2026; Dependabot-to-agent, Apr 2026), Snyk (Evo Remediation Agent, Oct 2026), Semgrep (Autofix beta for SAST and SCA), Anthropic (Claude Security public beta, May 2026), OpenAI (Aardvark, renamed Codex Security, Mar 2026) and Google (CodeMender public preview, Jul 2026). Almost all of them are scoped to findings from their own scanner. None publicly markets a fully autonomous "watch CVE news, then patch and merge" loop: human review of PRs is the norm.

### Cited Findings

**GitHub (Copilot Autofix + Dependabot + agentic autofix)**
- Apr 7, 2026: Dependabot alerts can be assigned to AI coding agents (Copilot, Claude, Codex), which analyze the vulnerability and open a draft PR. This targets fixes that need more than a version bump, such as breaking API changes, downgrades or complex PRs. It requires GitHub Code Security plus a Copilot plan with coding-agent access. — [GitHub Changelog](https://github.blog/changelog/2026-04-07-dependabot-alerts-are-now-assignable-to-ai-agents-for-remediation/)
- Oct 15, 2026: "Agentic autofix for code scanning alerts" reached GA. It replaces the free "Generate Fix" button with "Assign to Copilot". Up to 25 alerts can be fixed together in one PR, from the alert list or from a security campaign. An enterprise admin enables it with a new "Agentic autofix" policy. It consumes AI Credits from the Code Security budget plus Actions minutes. — [GitHub Changelog](https://github.blog/changelog/2026-10-15-agentic-autofix-for-code-scanning-alerts-general-availability/)
- A public preview of agentic autofix on Jul 10, 2026 is reported only by secondary sources. — [ustechautomations (secondary)](https://ustechautomations.com/resources/blog/agentic-autofix-explained-what-it-changes)
- Classic Copilot Autofix gives one suggested patch per alert and reportedly needs no Copilot subscription on eligible repos. Source is a third party. — [ustechautomations](https://ustechautomations.com/resources/blog/agentic-autofix-explained-what-it-changes)
- Dependabot noise mitigations: grouped updates (one batched PR per ecosystem per month), and a wait of at least 3 days after a release before opening version-update PRs. — [GitHub Blog](https://github.blog/security/supply-chain-security/tame-dependabot-group-your-updates-slow-the-cadence-keep-security-fast/)
- Scope: SCA (Dependabot) and first-party code (CodeQL and third-party SARIF via code scanning). Containers, IaC and cloud were not covered in the sources found.

**Snyk (DeepCode AI Fix → Agent Fix → Evo)**
- Oct 2026: Snyk launched "Evo Agentic AppSec", a team of security agents. The Evo Remediation Agent "runs the full fix loop autonomously and at scale", starting with Snyk Open Source (SCA) issues at launch. Fixes that might break the build are queued for approval rather than merged. — [Yahoo Finance / Snyk PR](https://finance.yahoo.com/technology/ai/articles/snyk-launches-evo-agentic-appsec-120000274.html)
- Sep 17, 2026: The Remediation Agent was in "open preview". Evo accounts for 60% of Snyk's new deal volume, with a 30% increase in average contract value (vendor claim). Evo Continuous Offensive Security was GA in Aug 2026. — [Snyk News](https://snyk.io/news/agentic-ai-security-moves-into-production/); [SD Times](https://sdtimes.com/security/snyks-evo-reaches-60-of-new-deal-volume-as-ai-risks-soar/)
- Snyk claims 85% fix accuracy (vendor figure). It auto-opens fix PRs on new issues and closes them on resolution. — [OpenHands blog (third party)](https://www.openhands.dev/blog/automated-vulnerability-remediation-tools)
- Snyk published a blog positioning Claude Code Security as an "evolution in the remediation loop" rather than a threat. — [Snyk blog](https://snyk.io/blog/claude-code-remediation-loop-evolution/)
- No Snyk acquisition in 2026 was found in searches.

**Sonar (AI CodeFix)**
- In SonarQube Server 2026.1, AI CodeFix is limited to selected rules in Java, JS, TS, Python, HTML, CSS, C# and C++. It produces suggestions, not PRs. — [Augment Code comparison](https://www.augmentcode.com/tools/best-ai-sast-tools)
- Pricing is the only public one among the SAST incumbents: Free (Community Build; Cloud ≤50K LOC), $32/mo (Cloud Team ≤100K LOC), and custom Enterprise pricing. Inclusion of AI CodeFix varies by plan. — [Augment Code / Pixee comparisons](https://www.augmentcode.com/tools/best-ai-sast-tools)

**Veracode Fix**
- Fixes only Veracode's own Pipeline Scan and Platform findings. Veracode claims coverage of more than 70% of detected flaws across 10 languages. "Fix for SCA" was announced in Mar 2026 and is still in Early Access. Fix is licensed separately per developer. — [Pixee: Veracode alternatives (competitor blog)](https://www.pixee.ai/blog/veracode-alternatives); [Pixee: Checkmarx vs Veracode](https://www.pixee.ai/blog/checkmarx-vs-veracode)
- Pricing is not public. Estimates range from a minimum of about $15K/yr to $50K–$250K+/yr for the full platform. — [Pixee comparisons (competitor)](https://www.pixee.ai/blog/checkmarx-vs-veracode)

**Checkmarx (Developer Assist / "agentic AI")**
- Limited to Checkmarx findings. Buyers are told to confirm agent availability and IDE or SCM support. — [Pixee: Checkmarx alternatives (competitor)](https://www.pixee.ai/blog/checkmarx-alternatives)
- Pricing is not public and is per contributing developer. Estimates: a minimum of about $59K/yr (citing Vendr 2026 data), or $200K–$500K/yr for large organizations. — [WeavAI review](https://weavai.app/blog/en/2026/05/06/checkmarx-sast-2026-review-pricing-alternatives/); [Pixee](https://www.pixee.ai/blog/checkmarx-alternatives)

**Semgrep (Assistant / Autofix / MCP)**
- Mar 2026: Autofix entered beta for Semgrep Code. — [Semgrep release notes, March 2026](https://semgrep.dev/docs/release-notes/march-2026)
- Autofix (public beta) now automatically generates fix PRs for both SAST and SCA findings. — [Semgrep blog](https://semgrep.dev/blog/2026/semgrep-mcp-server/)
- Nov 12, 2026: The Semgrep MCP server lets external agents (such as Claude Code) triage findings, generate fixes and file tickets. Opening Autofix PRs requires a token that is not read-only. — [Semgrep blog](https://semgrep.dev/blog/2026/semgrep-mcp-server/)
- Semgrep published "Getting Ready for Mythos with Semgrep", which positions itself alongside frontier-model vulnerability discovery. — [Semgrep blog](https://semgrep.dev/blog/2026/getting-ready-for-mythos-with-semgrep/)

**Aikido Security (AutoFix + Root acquisition)**
- Jan 2026: Series B of $60M at a $1B valuation, bringing total funding to about $85M. — [BankInfoSecurity](https://www.bankinfosecurity.com/aikido-buys-root-for-70m-to-automate-open-source-patching-a-32118)
- Late Jun 2026: Aikido acquired Root (Root.io, the auto-patched containers and backports startup). The price was reported as $70M by [BankInfoSecurity](https://www.bankinfosecurity.com/aikido-buys-root-for-70m-to-automate-open-source-patching-a-32118) and as $70–100M (undisclosed) by [Calcalist](https://www.calcalistech.com/ctechnews/article/hjxak411qzx). Root's tech becomes "Aikido Libraries", which patches CVEs in-place in the OSS version you already run with no forced upgrade. Root's hardened images become "Aikido Images". — [Open Source For You (Jul 2026)](https://www.opensourceforu.com/2026/07/aikido-security-acquires-root-to-enable-in-place-open-source-patching/); [The New Stack](https://thenewstack.io/aikido-acquires-root-security/)
- Aikido says it will backport fixes for CISA KEV vulnerabilities to the community for free. The paid product covers the wider CVE set. — [BankInfoSecurity](https://www.bankinfosecurity.com/aikido-buys-root-for-70m-to-automate-open-source-patching-a-32118)
- Root's prior funding is reported as about $31M by BankInfoSecurity/Calcalist and about $37.6M by [Cybersecurity Market](https://cybersecuritymarket.com/aikido-acquires-root-for-a-reported-70-million-to-patch-open-source-without-forcing-upgrades/). Root had about 25 staff. **Root.io should be flagged as acquired.**

**Wiz (Google)**
- Google closed its acquisition of Wiz on Mar 11, 2026. The headline price was $32B cash. Alphabet's 10-Q puts the finalized purchase price at $29.5B. Wiz keeps its brand and multi-cloud support. — [Cleary Gottlieb](https://www.clearygottlieb.com/news-and-insights/news-listing/google-completes-32-billion-acquisition-of-wiz); [SecurityWeek](https://www.securityweek.com/wiz-joins-google-cloud-as-landmark-acquisition-closes/); [Alphabet 10-Q Q3 2026](https://www.sec.gov/Archives/edgar/data/0001652044/000165204426000084/goog-20260930.htm)
- Wiz bought Dazz (AI remediation) for about $450M in Nov 2024. Dazz had raised about $110M. Dazz was folded into Wiz Code. — [SecurityWeek](https://www.securityweek.com/wiz-buys-dazz-for-450-million/); [Calcalist](https://www.calcalistech.com/ctechnews/article/b1xnec3gjl)
- The Dazz founder (Merav Bahat) has left Wiz after the Google deal. — [Calcalist](https://www.calcalistech.com/ctechnews/article/hyfx11ubwze)
- CodeMender's launch was linked to Wiz / AI Threat Defense, but sources differ on whether the Wiz integration was part of the launch. — [Help Net Security](https://www.helpnetsecurity.com/2026/07/24/google-codemender-ai-agent-code-security/); [Constellation Research](https://www.constellationr.com/insights/news/google-cloud-launches-ai-cybersecurity-agent-codemender)

**Google CodeMender**
- Jul 21–22, 2026: Launched in **public preview** (not GA) on the Gemini Enterprise Agent Platform and as part of AI Threat Defense. It finds vulnerabilities, then verifies and patches them. It can run as a Google Cloud service or in a customer-managed environment (on-prem or other clouds). Google says "hundreds of customers" have used it. Thales has claimed a possible >95% cut in discovery time (vendor-published). — [Help Net Security](https://www.helpnetsecurity.com/2026/07/24/google-codemender-ai-agent-code-security/); [IT Brief](https://itbrief.com.au/story/google-makes-codemender-available-in-its-gemini-security-models); [Constellation Research](https://www.constellationr.com/insights/news/google-cloud-launches-ai-cybersecurity-agent-codemender)
- No public pricing. Consumption (token-based) billing is planned after preview. A "Gemini 3.5 Flash Cyber" tier is limited to governments and trusted partners. Support for third-party frontier models is planned. — [IT Brief](https://itbrief.com.au/story/google-makes-codemender-available-in-its-gemini-security-models)

**OpenAI Aardvark → Codex Security**
- Oct 30–31, 2025: Aardvark was announced as a GPT-5 agentic security researcher in private beta for GitHub Cloud orgs. It scans repos, validates findings in a sandbox and proposes Codex-generated patches. OpenAI claimed 92% recall on known vulns in benchmark repos and 10 CVEs found in open source. — [The Register](https://www.theregister.com/2025/10/31/openai_aardvark_agentic_security); [The Hacker News](https://thehackernews.com/2025/10/openai-unveils-aardvark-gpt-5-agent.html)
- Mar 6, 2026: Aardvark was reportedly rebranded **Codex Security** and integrated into Codex, extending access to ChatGPT Pro, Business, Enterprise and Edu. The source is a wiki, not OpenAI. — [Learn AI wiki](https://ai.miraheze.org/wiki/Aardvark)
- Status is a "research preview". There is no standalone price: scans use included Codex usage and then credits. It reproduces findings in a sandbox and opens a draft PR. A cited per-KLOC price (about $0.018/KLOC) comes from one low-quality source and is unverified. — [eesel.ai](https://www.eesel.ai/blog/codex-security-cloud-pricing); [eesel.ai](https://www.eesel.ai/blog/codex-security-cloud); [Agent Finder](https://agent-finder.co/reviews/codex-security)

**Anthropic Claude Code Security → Claude Security**
- Feb 20, 2026: Claude Code Security launched as a limited research preview for Enterprise and Team customers on Opus 4.6. It scans codebases and suggests targeted patches for human review and does not change code directly. Anthropic said it found more than 500 vulnerabilities in OSS. The launch coincided with a drop in cybersecurity stocks. — [The Hacker News](https://thehackernews.com/2026/02/anthropic-launches-claude-code-security.html); [VentureBeat](https://venturebeat.com/security/anthropic-claude-code-security-reasoning-vulnerability-hunting)
- Apr 30 / May 4, 2026: Renamed **Claude Security** and moved to public beta for Claude Enterprise, on Opus 4.7, from the Claude.ai sidebar. Team and Max access is expected later. — [SiliconANGLE](https://siliconangle.com/2026/04/30/anthropic-announces-claude-security-public-beta-find-fix-software-vulnerabilities/); [Help Net Security](https://www.helpnetsecurity.com/2026/05/04/anthropic-claude-security-public-beta/)
- Claude is also one of the agents that GitHub Dependabot alerts can be assigned to (Apr 2026). — [GitHub Changelog](https://github.blog/changelog/2026-04-07-dependabot-alerts-are-now-assignable-to-ai-agents-for-remediation/)
- False-positive rates were raised as a concern in coverage. — [Cyber Magazine](https://cybermagazine.com/news/will-anthropics-claude-code-security-replace-cyber-tools)

**Endor Labs**
- Series B of $93M (DFJ Growth), Apr 23, 2025. Total funding is reported variously as $163M, $188M or $208M+. Sources say Endor acquired Autonomous Plane in Feb 2026 and launched "AURI" in Mar 2026 (aggregator-sourced, unverified). — [itechguides](https://www.itechguides.com/endor-labs-lands-93m-to-secure-ai-generated-code/); [Tracxn](https://tracxn.com/d/companies/endor-labs/__XfJQQsoW-_uQ984qdxVFeTW_3xfqUB97FR6ibUxH0H4)
- Endor markets reachability analysis plus EPSS and KEV to rank SCA fixes. — [Endor Labs](https://www.endorlabs.com/learn/vulnerability-remediation-automation)

**Datadog, JFrog, Socket, GitLab Duo**: none of my searches returned relevant 2026 auto-remediation results for these (see Gaps). One JFrog-adjacent data point: Seal Security offers a remote repository for JFrog Artifactory, so that "sealed" patched versions resolve transparently. — [Seal Security](https://www.seal.security/)

### Inferences
- Platform fixes are mostly vendor-locked: Veracode, Checkmarx, Sonar and Snyk fix their own findings. GitHub is the exception: it accepts third-party SARIF and lets third-party agents (Claude, Codex) take Dependabot alerts. It is becoming the orchestration layer.
- The frontier labs (OpenAI, Anthropic, Google) all ship "find + validate + propose patch" agents. All are in preview or beta, focus on first-party code reasoning (SAST-like) rather than dependency or container patching, and have usage-based or opaque pricing.

### Gaps
- GitLab Duo vulnerability resolution: no 2026 status or pricing found. From prior knowledge (unverified here), it is an Ultimate + Duo Enterprise add-on that creates an MR for SAST findings.
- Datadog (Code Security / IAST remediation), JFrog (AppTrust / curation, any AI fix), Socket (any AI patching): no sources found.
- Official OpenAI pricing or GA date for Codex Security: not found.
- Snyk Evo Remediation Agent pricing: not public.

---

## Q2. Startups: products, funding, M&A (2025–2026)

### Takeaway
The startup field splits into four groups. (1) AI SAST fixers: Mobb, Pixee, Corgea, ZeroPath, Nullify, DryRun, Amplify. (2) Patched-OSS / backport vendors: Seal Security, Root (now Aikido), Chainguard, Minimus, Echo. (3) ASPM/RBVM remediation-ops platforms: Cycode, Arnica, Seemplicity, Zafran, Vulcan (now Tenable), Dazz (now Wiz). (4) A new 2026 wave of "autonomous remediation" seed companies: QuestorAI, Emphere, Onit, Astelia, Hackuity. Consolidation is under way: Dazz→Wiz→Google, Vulcan→Tenable, Root→Aikido.

### Cited Findings

**Patched open source / containers**
- **Chainguard**: Series D of $356M (Apr 2025) at a $3.5B valuation, then a $280M growth investment from General Catalyst's Customer Value Fund. Total funding is $892M per Sacra, versus $612M per Tracxn (conflict). Factory 2.0 rebuilds more than 1,700 container images every 24h. It patches criticals within 7 days and others within 14. — [Sacra](https://sacra.com/c/chainguard/); [Tracxn](https://tracxn.com/d/companies/chainguard/__lB37xu-JClvYpaTJjeBG6lsnDteO4IwuYq-yf1A2Geg); [Dark Reading](https://www.darkreading.com/application-security/minimal-hardened-updated-daily-new-standard-secure-containers)
- Chainguard controversy (2026): The PHP Foundation said Chainguard released patched PHP images hours before an embargo lifted. Chainguard's CEO cited exploits in the wild. — [Socket blog](https://socket.dev/blog/php-embargo-dispute)
- **Seal Security**: Series A of $13M (Jul 2025), $20M total (tracker data). It calls itself the "AppSec Remediation Agent" and "fix layer for the AI era". It ships backported patches for the exact versions customers run, sometimes before CVE publication. It has an MCP server for Claude Code, Cursor and others, and an Artifactory remote repo. — [Seal Security](https://www.seal.security/); funding: [newmarketpitch / tracker](https://newmarketpitch.com/blogs/news/cybersecurity-funding-deals) (aggregator, verify)
- **Root.io**: acquired by Aikido in Jun 2026 (see Q1).

**AI SAST/code fixers**
- **Pixee (Pixeebot)**: $15M seed (May 2025, tracker). It triages scanner findings and generates context-aware fix PRs. It self-reports up to 95% false-positive reduction and a 76% developer merge rate. — [Pixee](https://www.pixee.ai/resource-center/automated-security-remediation); [OpenHands](https://www.openhands.dev/blog/automated-vulnerability-remediation-tools)
- **Mobb**: A largely vendor-agnostic fix layer that takes findings from several SAST scanners. A Jun 2026 review calls it "a useful fix layer rather than a full detect-and-fix platform". — [Security Boulevard (Jun 2026)](https://securityboulevard.com/2026/06/7-ai-application-security-tools-for-2026/); [Safeguard](https://safeguard.sh/resources/blog/top-sast-auto-fixing-tools)
- **ZeroPath**: Top-10 finalist at the RSAC 2026 Innovation Sandbox. Launched "Zero", a persistent AI agent that runs an AppSec program. Issued a scaling announcement on Mar 13, 2026. — [BusinessWire](https://www.businesswire.com/news/home/20260313797057/en/ZeroPath-Scales-AI-Native-Application-Security-for-the-Modern-Development-Era)
- **Corgea**: AI auto-triage and fix. In Jun 2026 it was described as having "limited public pricing and a smaller deployment footprint". A Q3 2026 update added AI pentesting and triage governance, across 52 releases. — [Security Boulevard](https://securityboulevard.com/2026/06/7-ai-application-security-tools-for-2026/); [Corgea](https://corgea.com/)
- **Nullify**: Finds logic flaws and produces root-cause fix PRs (per competitor Pixee). — [Pixee](https://www.pixee.ai/blog/best-ai-code-security-tools-2026)

**ASPM / remediation operations**
- **Cycode**: Context Intelligence Graph plus "Maestro" agents. Its Remediation Agent opens PR-ready fixes with reasoning. — [Pixee (competitor)](https://www.pixee.ai/blog/best-ai-code-security-tools-2026); [Arnica blog](https://www.arnica.io/blog/top-6-ai-sast-tools-for-2026-the-quick-guide-to-agentic-static-application-security-testing)
- **Arnica**: Agentic pipelineless SAST, SCA, IaC and secrets scanning with automated remediation paths. — [Arnica blog](https://www.arnica.io/blog/top-6-ai-sast-tools-for-2026-the-quick-guide-to-agentic-static-application-security-testing)
- **Seemplicity**: "AI Analysts" for autonomous triage, launched Jun 25, 2026. Also offers a "Find the Fixer" ownership-routing agent and a Remediation agent that gives step-by-step guidance (guidance, not code patches). — [Help Net Security](https://www.helpnetsecurity.com/2026/06/25/seemplicity-ai-analysts-focus-remediation-on-exploitable-risks/); [AppSec Santa](https://appsecsanta.com/seemplicity)
- **Zafran**: Threat-exposure management that aggregates findings across scanners and leans toward *mitigation* via existing WAF, firewall and EDR rather than code patches (per competitor Seemplicity). — [Seemplicity blog](https://seemplicity.ai/blog/zafran-alternative/)
- **Vulcan Cyber**: Acquired by Tenable. One source says the deal completed in Feb 2025 and that Vulcan had raised about $35M. This was single-sourced in my search. — [newmarketpitch exposure mgmt](https://newmarketpitch.com/blogs/news/exposure-management-top-startups-fundraising) (aggregator; verify date and price)
- **Dazz**: Acquired by Wiz in Nov 2024 for about $450M (see Q1).

**New 2026 funding wave (autonomous remediation)**
- **QuestorAI** (Seattle): $3M seed led by Paladin Capital, Oct 2026. Finds vulnerabilities, then generates, validates and applies fixes automatically. — [QuestorAI PR](https://questorai.com/questor-ai-announces-initial-funding-round-to-accelerate-automated-security-remediation-platform/)
- **Hackuity** (Lyon): €16M (about $19M), Sep 2026. Positioned as AI VOC and prioritization, not code patching. — [EU-Startups](https://www.eu-startups.com/2026/09/vulnerability-tsunami-prompts-frances-hackuity-to-land-e16-million-for-automated-cyber-remediation/)
- **Emphere** (Seattle): $2.1M pre-seed (AI2 Incubator, Outsiders Fund), Jun 2026. Analyzes the dependency graph for exploitability and applies fixes automatically. — [SecurityWeek](https://www.securityweek.com/emphere-raises-2-1-million-for-ai-powered-vulnerability-remediation/)
- **Onit Security**: $11M seed, Mar 2026. Agents execute remediation without manual hand-offs, with a claimed MTTR reduction of up to 87% (vendor). — [FinTech Global](https://fintech.global/2026/03/25/onit-security-lands-11m-to-automate-vulnerability-remediation/)
- **Astelia**: $35M Series A led by Index, Feb 2026. Focuses on exposure prioritization and remediation, with scanning planned. — [GovInfoSecurity](https://www.govinfosecurity.com/startup-astelia-secures-35m-for-ai-vulnerability-management-a-30843)
- **Backline**: $9M seed (Jan 2025). An AI agent proposes, implements and tests fixes. — [TechCrunch](https://techcrunch.com/2025/01/30/backline-automatically-remediates-security-vulnerabilities/)

### Inferences
- "Patch without upgrading" (backporting) is now a funded category. Seal is still independent, while Root has been absorbed into Aikido, which gives Aikido the closest bundled offer of AI SAST autofix plus patched libraries plus patched images.
- Vulnerability-management and ASPM vendors (Seemplicity, Zafran, Hackuity, Astelia) mostly automate triage, ownership and ticketing rather than writing code patches. That gap is being filled by agent-native seed companies (QuestorAI, Emphere, Onit).

### Gaps
- No 2025–2026 sourced data found for: Mobb funding, Minimus, Echo (vulnerability-free images), Depshub, Renovate/Mend, Moderne/OpenRewrite, Grit, Xygeni, Konvu, Amplify Security, DryRun Security, Backslash, Socket funding. From prior knowledge (unverified in this session): Grit was acquired by Honeycomb (2025); Minimus launched in 2025 with funding of about $51M. Verify these before use.
- Pricing for nearly all startups is not public. Corgea's pricing is explicitly described as "limited public".
- No confirmed 2026 acquisition of Pixee, Mobb, Seal, ZeroPath or Corgea was found.

---

## Q3. Who ingests threat intel/news (CISA KEV, EPSS, exploit chatter) to prioritize and auto-remediate?

### Takeaway
KEV, EPSS and reachability-based *prioritization* is now standard across SCA and RBVM tools (Endor, Snyk, Seemplicity, Zafran, Astelia, Hackuity). KEV-specific *auto-patching* is explicit only at Aikido/Root, which gives free KEV backports. No vendor I found closes the full "monitor CVE news and exploit chatter → write patch → open PR → merge" loop. Human review of PRs remains the default everywhere.

### Cited Findings
- Common pattern: reachability call-graph analysis, layered with EPSS (probability of exploitation in the next 30 days) and CISA KEV to rank findings, followed by generated fix PRs. — [Endor Labs](https://www.endorlabs.com/learn/vulnerability-remediation-automation); [OpenHands](https://www.openhands.dev/blog/automated-vulnerability-remediation-tools)
- Aikido commits to free backports of KEV-listed vulns for the OSS community. Its paid "Libraries" product covers the wider CVE set. — [BankInfoSecurity](https://www.bankinfosecurity.com/aikido-buys-root-for-70m-to-automate-open-source-patching-a-32118)
- Seal ships patches "sometimes before a CVE is published", which implies it monitors upstream fixes and advisories ahead of NVD. — [Seal Security](https://www.seal.security/)
- Chainguard rebuilds all images every 24h against upstream and pushed PHP patches ahead of an embargo, citing in-the-wild exploits. This shows exploit-signal-driven acceleration. — [Sacra](https://sacra.com/c/chainguard/); [Socket blog](https://socket.dev/blog/php-embargo-dispute)
- Seemplicity's AI Analysts focus remediation on exploitable risk. Zafran prioritizes exploitability and mitigates through existing controls. — [Help Net Security](https://www.helpnetsecurity.com/2026/06/25/seemplicity-ai-analysts-focus-remediation-on-exploitable-risks/); [Seemplicity blog](https://seemplicity.ai/blog/zafran-alternative/)
- Academic work: "KEVGraph" (arXiv, Sep 2026) shows EPSS updates lag KEV additions. Its exploitation-aware ILP remediation plan beat greedy selection on KEV coverage (AUCC 0.997 vs 0.902). — [arXiv 2609.24164](https://arxiv.org/pdf/2609.24164)
- Unverified: a vendor blog claims CISA added "agent-exploited" CVEs to KEV on Aug 27, 2026 and cites a "BOD 26-04" with 3/14/60-day tiers. This could not be confirmed with CISA. — [oometa.ai (unverified)](https://oometa.ai/en/insights/cisa-kev-agent-exploitation-cves-2026)
- Snyk Evo's Remediation Agent runs the full fix loop autonomously. Possibly build-breaking fixes are queued for approval, so it is not a fully autonomous merge. — [Snyk PR](https://finance.yahoo.com/technology/ai/articles/snyk-launches-evo-agentic-appsec-120000274.html)

### Inferences
- Closeness to the "monitor CVE + news → auto-patch my app → open PR" target. These are my ratings, built from the findings above:

| Product | What it fixes | AI involvement | Threat-intel input | PR automation | Closeness (1–5) | Status / pricing |
|---|---|---|---|---|---|---|
| GitHub Dependabot + agent assignment + agentic autofix | SCA, SAST (CodeQL/SARIF) | Copilot/Claude/Codex agents | GitHub Advisory DB; no exploit-news ingestion found | Auto PRs (Dependabot), draft PRs by agent, up to 25 alerts per PR | 4 | GA (Apr / Oct 2026); Code Security + Copilot + AI Credits |
| Snyk Evo Remediation Agent | SCA first (SAST via Agent Fix) | Agentic | Snyk vuln DB, exploit maturity | Autonomous loop, approval for risky fixes | 4 | Launched Oct 2026; pricing not public |
| Aikido AutoFix + Libraries/Images (ex-Root) | SAST, SCA (backports), containers, IaC | AI autofix + backport factory | KEV explicit | PRs / patched artifacts | 4 | Root acquired Jun 2026; Aikido $1B valuation |
| Seal Security | SCA backports (also OS packages per site) | "Remediation agent", MCP | Upstream advisories pre-CVE | Drop-in patched versions | 3–4 | $13M A (2025); pricing not public |
| Chainguard / Minimus / Echo | Container base images | Mostly automation (not LLM-centric) | Upstream; exploit-driven expedites | Image swaps, not app PRs | 2–3 (containers only) | Chainguard $3.5B valuation |
| Semgrep Autofix | SAST + SCA | LLM | Semgrep advisories | Auto PRs (beta) | 3 | Public beta 2026 |
| Endor Labs | SCA | AI + reachability | EPSS + KEV | Upgrade guidance / PRs | 3 | $93M B (2025) |
| Pixee / Mobb / Corgea / ZeroPath / Nullify | SAST (scanner-agnostic for Pixee and Mobb) | LLM | Scanner input only | Fix PRs | 3 | Startups; pricing mostly private |
| Veracode Fix / Checkmarx Assist / Sonar AI CodeFix | Own SAST findings (Veracode SCA in EA) | LLM | Own DB | Suggestions, some PRs | 2 | Enterprise; Sonar from $32/mo |
| Claude Security / Codex Security / CodeMender | First-party code (novel vulns) | Frontier agent | Self-discovery, not CVE feeds | Proposed patches / draft PRs | 2–3 | Beta / research preview / public preview; usage-based |
| Seemplicity / Zafran / Hackuity / Astelia | Cross-scanner triage, cloud/infra | AI triage agents | Exploitability, KEV-style | Tickets, routing, mitigations | 2 | Funded 2026 |
| Wiz (incl. Dazz) | Cloud, code-to-cloud | AI remediation | Threat intel | Remediation guidance / PRs | 3 | Part of Google (closed Mar 11, 2026) |

- The white space is a single agent that combines news and exploit-chatter ingestion (beyond KEV and EPSS) with a code-aware patch across code, dependencies and containers, plus test validation and auto-merge policies. Pieces exist separately: GitHub's orchestration, Aikido's breadth, Seal's and Root's backports, and the frontier labs' reasoning.

### Gaps
- I found no vendor that publicly documents ingesting security *news* or *social/exploit chatter* (as opposed to KEV, EPSS or advisory DBs) as a direct trigger for auto-patching.
- No independent benchmark compares fix acceptance rates across vendors.

---

## Q4. Gaps and complaints (noise, PR fatigue, broken builds)

### Takeaway
The complaints are well documented. Dependency bots flood PRs that often don't touch reachable code. Many fix PRs sit unmerged with failing builds. AI scanners raise false-positive worries. Vendors respond with grouping, cooldowns, reachability, and "queue risky fixes for approval".

### Cited Findings
- Dependabot generated more than 75M PRs in 2022, and developers report alert fatigue. — [arXiv 2502.06175](https://arxiv.org/html/2502.06175v1)
- 11.3% of the studied projects deprecated Dependabot because of notification fatigue or lack of grouping (2022 study). — [arXiv 2206.07230](https://arxiv.org/pdf/2206.07230)
- Filippo Valsorda argued teams should turn Dependabot off because it opens PRs for vulnerable functions that are never called, which trains developers to ignore alerts. A Go maintainer called it a "noise machine". — [Tech Edu Byte](https://www.techedubyte.com/go-library-maintainer-criticizes-github-dependabot-noise/); [Shivam Saraswat blog](https://blog.shivamsaraswat.com/dependabot-sucks/)
- Jan 2026 analysis: NuGet and Gradle bot PRs take 6–7 business days to merge, and more than half of open ones have failing builds. "Bots can't fix breaking changes." — [nesbitt.io](https://nesbitt.io/2026/01/10/16-best-practices-for-reducing-dependabot-noise.html)
- A claim that about 85% of security PRs go unmerged is reported, but the primary source could not be verified. — [Keypup](https://www.keypup.io/blog/dependency-bot-backlog-dependabot-renovate-pull-requests/)
- False-positive rates remain a "critical concern" for Claude Code Security. — [Cyber Magazine](https://cybermagazine.com/news/will-anthropics-claude-code-security-replace-cyber-tools)
- Vendor lock-in: Veracode Fix and Checkmarx Assist only fix their own findings. — [Pixee (competitor)](https://www.pixee.ai/blog/veracode-alternatives)
- Embargo and ethics risk from fast patching: the Chainguard PHP dispute. — [Socket blog](https://socket.dev/blog/php-embargo-dispute)
- Supply-chain risk *from* AI fix agents: a prompt-injection flaw in Claude Code's GitHub Action could expose CI/CD secrets. Microsoft reported it in late Apr 2026, and it was fixed in v2.1.128. — [DevOps.com](https://devops.com/security-flaw-in-claude-code-illustrates-the-risk-of-ai-in-developer-workflows)
- Cost: GitHub's agentic autofix consumes AI Credits and Actions minutes, so large backlogs carry a direct cost. — [GitHub Changelog](https://github.blog/changelog/2026-10-15-agentic-autofix-for-code-scanning-alerts-general-availability/)

### Inferences
- Agentic fixers (GitHub's Dependabot-to-agent, Snyk Evo) explicitly target the "breaking change" PRs that classic bots leave stuck. That is the main pain point, but independent evidence of improved merge rates is not yet available.
- Giving remediation agents write access to repos and CI expands the attack surface, as the Claude Code Action prompt-injection flaw shows.

### Gaps
- No independent 2026 measurement of merge or acceptance rates or build-break rates for AI-generated security PRs. Pixee's 76% and Snyk's 85% figures are self-reported.
- No Gartner or Forrester quotes were retrieved, because fetches were blocked and searches surfaced none.
