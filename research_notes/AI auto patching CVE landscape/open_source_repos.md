# Open-source AI/LLM auto-patching repos (CVE detection → fix), as of 2026-11-19

Method note: Star counts, last-push dates, license (SPDX as GitHub reports it), primary language, archived flag and descriptions were pulled from the GitHub search API (`api.github.com/search/repositories`) on 2026-11-19. The session's GitHub token was invalid, so all queries ran unauthenticated, and repo-scoped endpoints (commits, contributors) were not available. "Push" is GitHub's `pushed_at`, a stand-in for last commit. Feature claims come from each repo's README as fetched the same day, unless a different source is cited. Each fact below links to its repo.

## Q1. What is "artex"? (user's spelling uncertain)

### Takeaway
"artex" almost certainly means **ARTEX**, a Chinese open-source, LLM multi-agent **autonomous penetration-testing** platform by GitHub user Autumn-27 (Go + Next.js, AGPL-3.0). Many forks of it are now the top GitHub results, with roughly 10k stars on the largest. The author deleted or privatized the upstream in October 2026 after reports that it was abused in attacks on South Korean banks. ARTEX is an **offensive black-box pentest tool, not an auto-patcher**: it finds and proves vulnerabilities in running targets and can retest whether a finding is fixed, but it writes no code fixes. Stanford's ARTEMIS is the next most plausible match, and it is also a pentest agent rather than a patcher.

### Cited Findings
- A GitHub search for "artex" returns 1,142 repos. The top ones are all ARTEX forks or derivatives. BaaRai/ARTEX has ~9,755★ (AGPL-3.0, Go, pushed 2026-11-18) and describes itself as "AI autonomous penetration testing system (English translation; upstream: Autumn-27/ARTEX)". Others: jiwoochris/artex-global (~3,991★), RuoJi6/ARTEX (~2,270★, "continuously maintained open-source version"), Hinln/ARTEX (~1,700★, backup of v0.3.15), cskwork/scopeweaver (~1,118★), failsafe-security/artex (~874★), AntiFox-AI/antifox (~778★) — [GitHub search](https://github.com/search?q=artex&type=repositories); [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX)
- What ARTEX does: "a self-hosted, LLM-driven penetration testing platform… a planner splits a goal into intents, workers execute them with real tools", with results kept in an asset graph and an exploration graph. It captures traffic through a MITM proxy and has human-in-the-loop approvals, scope gates and budgets. It ships as one Go binary with an embedded Next.js UI and uses PostgreSQL plus any Anthropic/OpenAI-compatible endpoint or Ollama — [BaaRai/ARTEX README](https://github.com/BaaRai/ARTEX)
- Its closest feature to patching is a **"Vulnerability retest loop"**: a `retester` agent re-runs a finding against an optional fixed version and records "Still reproducible / Fixed / Cannot confirm". It verifies fixes; it does not write them — [BaaRai/ARTEX README](https://github.com/BaaRai/ARTEX)
- Upstream status: "The upstream repository is no longer public" (BaaRai). jaykwok/ARTEX says the original v0.3.15 is commit `e6ec569` dated 2026-10-07, "原仓库已删除" ("the original repository has been deleted"), and that the official Docker image `autumn27/artex` was taken down — [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX); [jaykwok/ARTEX](https://github.com/jaykwok/ARTEX)
- jiwoochris/artex-global: "In October 2026, several Korean news outlets reported that investigators had found indications the upstream ARTEX was used in personal-data breaches targeting Korean financial institutions" — [jiwoochris/artex-global](https://github.com/jiwoochris/artex-global)
- News coverage (seen as search snippets only, not full articles): CrowdStrike reported on 2026-10-07 that an actor used ARTEX plus LLMs against South Korean financial firms. The developer said the tool had been abused and that the project would stop updating and go closed-source. Recorded Future linked related activity to a group it tracks as TAG-217 — [BleepingComputer](https://www.bleepingcomputer.com/news/security/hacker-used-artex-ai-and-claude-agents-to-target-south-korean-banks/); [Digital Today](https://www.digitaltoday.co.kr/en/view/112677/artex-open-source-ai-penetration-testing-tool-goes-private-unrelated-to-hacking-of-korean-financial-firms); [Magica](https://magica.com/news/artex-developer-closes-source-after-south-korean-bank-attacks); [LetsDataScience/Recorded Future](https://letsdatascience.com/news/recorded-future-links-tag-217-to-artex-activity-around-south-b769b66b). Record counts conflict across outlets: a snippet says "8.2 million records" while a BleepingComputer URL slug says "82 million". Neither was verified.
- The same author maintains Autumn-27/ScopeSentry (~2,534★, Go, attack-surface mapping and vulnerability scanning). ARTEX can sync assets from it — [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry); [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX)
- One derivative adds white-box code audit: Ernket/CodeScan-Artex (~343★, AGPL-3.0) is an "LLM multi-agent **static code audit platform**". It is deliberately **read-only**: the agent gets only Read/Write/Edit/LS/Glob/Grep tools, with no Bash or web access. It reports `file:line` findings and dependency reachability but does not auto-patch — [Ernket/CodeScan-Artex](https://github.com/Ernket/CodeScan-Artex)
- An unrelated namesake, IlyassCODEX/ARTEX (~364★, Python, no license, last push 2025-07-24), is a "web application security analysis platform". It is stale — [IlyassCODEX/ARTEX](https://github.com/IlyassCODEX/ARTEX)
- Other candidates:
  - **ARTEMIS** = Stanford-Trinity/ARTEMIS (~552★, Apache-2.0, Rust, last push 2026-04-14), "Automated Red Teaming Engine with Multi-agent Intelligent Supervision… to automate vulnerability discovery". It builds on a Codex (`codex-rs`) binary. It is a pentest agent with no patching — [Stanford-Trinity/ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS)
  - **ARVO** = n132/ARVO (~116★, BSD-2-Clause, last push 2026-09-14), "an Atlas of Reproducible Vulnerabilities in Open source software". It is a dataset/benchmark, not a tool — [n132/ARVO](https://github.com/n132/ARVO)
  - **Aardvark** (OpenAI) has no official OSS repo. The GitHub "aardvark" hits are Netflix-Skunkworks/aardvark (AWS IAM, unrelated) and tiny clones — [GitHub search](https://github.com/search?q=aardvark+security&type=repositories)
  - **Atlantis** = Team-Atlanta/aixcc-afc-atlantis. See Q2.

### Inferences
- The user most likely saw ARTEX, given its star counts (thousands across forks), heavy news coverage in Oct–Nov 2026, and the matching spelling. It fits "find vulnerabilities in my app" (black-box pentest of a running app) but **not** "auto-patch my app". Forks are AGPL-3.0, and the maintainership situation is murky: the upstream is gone, there are dozens of forks, some strip safety gates (jaykwok/ARTEX removed the .gov/.edu asset blocklist), and the tool is linked to real attacks. Recommend against using it as a defensive auto-patcher.

### Gaps
- I could not read Autumn-27's statement or the full news articles directly; the facts above rest on fork READMEs and search snippets.
- I could not confirm whether the user meant something else, such as a private or commercial "Artex" product.

## Q2. Which open-source autonomous vuln-fix agents exist? (catalogue)

### Takeaway
The OSS landscape splits into five tiers:
- **(a) AIxCC Cyber Reasoning Systems (CRSs).** These do real find→patch with fuzzer-validated patches, but only for C/C++/Java projects in OSS-Fuzz format. Their 2025 competition snapshots are mostly frozen; OSS-CRS (OpenSSF), Buttercup and FuzzingBrain are still active.
- **(b) A new 2026 wave of "agentic security harnesses" from big companies.** Google Mantis, Anthropic's defending-code-reference-harness, Visa VVAH and Capital One VulnHunter run discover→verify→patch→re-verify on your own source code with any LLM. These are closest to "AI patches my app".
- **(c) AI pentesters.** Strix, Shannon, PentAGI, PentestGPT, ARTEX, RedAmon and Xalgorix find and prove bugs. A few (Strix skills, RedAmon CodeFix→PR, Logan for Shannon) add fixing.
- **(d) Dependency-CVE remediators.** Renovate, Dependabot, osv-scanner fix, pip-audit --fix, npm audit fix and Copa are deterministic and not AI. Autoremediator and Patchwork add LLM repair.
- **(e) Research prototypes.** PatchAgent, PatchPilot, San2Patch, AutoPatch and SEC-bench are low-star and often stale.

### Cited Findings

#### (a) AIxCC Cyber Reasoning Systems (find + patch; C/C++ and Java, OSS-Fuzz format)
- AIxCC final results (DEF CON 33, Aug 2025): Team Atlanta's Atlantis placed 1st ($4M), Trail of Bits' Buttercup 2nd ($3M) and Theori's RoboDuck 3rd ($1.5M) — [DARPA](https://darpa.mil/news/2025/aixcc-results); [Trail of Bits blog](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)
- **Team-Atlanta/aixcc-afc-atlantis**: ~664★, license NOASSERTION, C, last push 2025-11-25. The README says only "designed to automatically discover and analyze vulnerabilities"; the code is under `example-crs-webservice`. It is a competition snapshot and **stale** (no push for about a year). There is also aixcc-asc-atlantis (~51★, MIT) — [repo](https://github.com/Team-Atlanta/aixcc-afc-atlantis)
- **trailofbits/buttercup**: ~1,757★, AGPL-3.0, Python, **active** (push 2026-11-02). "Buttercup finds and patches software vulnerabilities" with a Fuzzer and a Patcher. It supports "C source code repositories that are OSS-Fuzz compatible" and Java, and needs "Projects that build successfully and have existing fuzzing harnesses". It works best with OpenAI **and** Anthropic keys and has an LLM budget setting. The competition snapshots trailofbits/afc-buttercup (~98★) and asc-buttercup are archived. This is the most usable maintained CRS — [repo](https://github.com/trailofbits/buttercup)
- **theori-io/aixcc-afc-archive** (RoboDuck): ~274★, AGPL-3.0, Python, **archived**, last push 2025-08-05. "Snapshot of the finals release of Theori's CRS". The README warns that the finals had a large LLM budget — [repo](https://github.com/theori-io/aixcc-afc-archive)
- **fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain**: ~152★, Apache-2.0, Python, **active** (push 2026-11-17). It placed 4th at AIxCC. "LLM-powered system that discovers and patches zero-day vulnerabilities… every finding dynamically verified". Its newer v3 "writes and builds its own" fuzz harness for "any C/C++ repo, OSS-Fuzz or not" and runs on "a Claude/ChatGPT subscription, no API key" — [repo](https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain); [paper arXiv 2509.07225](https://arxiv.org/abs/2509.07225)
- **shellphish/artiphishell**: ~143★, MIT, Python, last push 2025-08-27. A competition snapshot (Azure/final.env deployment) and **stale** — [repo](https://github.com/shellphish/artiphishell)
- **42-b3yond-6ug/42-b3yond-6ug-crs** ("BugBuster"): ~31★, GPL-3.0, last push 2025-08-19. **Stale** snapshot — [repo](https://github.com/42-b3yond-6ug/42-b3yond-6ug-crs)
- **siftech/afc-crs-lacrosse**: ~11★, MIT, C++, last push 2025-08-24. A "multi-agent CRS combining fuzzing and symbolic reasoning to find and patch bugs across various C and Java software codebases". **Stale** — [repo](https://github.com/siftech/afc-crs-lacrosse)
- **ossf/oss-crs**: ~187★, MIT, Python, **active** (push 2026-11-18, created 2025-11). It is "a standard orchestration framework for building and running LLM-based autonomous bug-finding and bug-fixing systems". It can ensemble multiple CRSs, cap per-CRS LLM budgets, and target "any project that follows the OSS-Fuzz project structure". This is the post-AIxCC consolidation point under OpenSSF. A related benchmark is sslab-gatech/CRSBench (~10★) — [repo](https://github.com/ossf/oss-crs)
- **google/oss-fuzz-gen**: ~1,452★, Apache-2.0, **archived**, README says "This repository is no longer being maintained." It generated LLM fuzz targets for C/C++/Java/Python and did not patch — [repo](https://github.com/google/oss-fuzz-gen)

#### (b) 2026 agentic "find → reproduce → patch → verify" harnesses for your own codebase
- **google/mantis**: ~2,812★, Apache-2.0, Python, created 2026-06-15, **very active** (push 2026-11-19). "A modular, stack-agnostic toolkit for AI coding agents to autonomously find, reproduce, and patch vulnerabilities". It is a set of skills plus an ADK reference harness. Features from the README:
  - "Patch discovered vulnerabilities, using an adversarial loop to verify the vulnerability is really fixed".
  - Sandboxed dynamic reproduction (Docker/podman), falling back to static-only.
  - A knowledge.db that keeps threat models, findings and prior fixes.
  - SARIF output, an MCP server for `mantis_check_change` diff gating, and a `--scan-mode changed` option for verifying fixes.
  - Any LiteLLM provider (Gemini, Claude, OpenAI).

  Its PR-scan GitHub Action and `mantis-knowledge-refresh` workflow are flagged "untested" end-to-end ("Do not use the action to gate merges"). The README also says "not an officially supported Google product… recommend CodeMender (cloud.google.com/security/codemender)", which makes Mantis the OSS sibling of Google's commercial CodeMender — [repo](https://github.com/google/mantis); [action doc](https://github.com/google/mantis/blob/main/reference/docs/github-action.md)
- **CodeMender itself is not open source.** google-deepmind/codemender is an empty 1★ placeholder. Community repos such as jasonbisson/terraform-google-codemender deploy it as a Google Cloud service — [google-deepmind/codemender](https://github.com/google-deepmind/codemender); [terraform-google-codemender](https://github.com/jasonbisson/terraform-google-codemender)
- **anthropics/defending-code-reference-harness**: ~7,767★, license NOASSERTION, Python, created 2026-05-22, last push 2026-08-06. It provides Claude Code skills `/threat-model`, `/vuln-scan`, `/triage`, `/patch` and `/customize`, plus an autonomous "recon → find → verify → report → patch" pipeline. The pipeline is "configured for finding C/C++ memory vulnerabilities" and is customizable to other languages. The README warns that `/patch` and the pipelines execute code — [repo](https://github.com/anthropics/defending-code-reference-harness)
- **visa/visa-vulnerability-agentic-harness** (VVAH): ~3,094★, Apache-2.0 header (GitHub shows NOASSERTION), Python, created 2026-06-05, push 2026-10-22. "An application security pipeline that discovers, verifies and fixes vulnerabilities in source code, and validates the fixes" — [repo](https://github.com/visa/visa-vulnerability-agentic-harness)
- **capitalone/VulnHunter**: ~1,182★, Apache-2.0, created 2026-07-07, push 2026-10-07. "Attacker-first analysis directly to source code". A separately listed **nealbridges/VulnHunter** (~825★, Apache-2.0, push 2026-11-03) documents a "Hunt → Fix → Verify" loop. `/vulnhunt` finds issues with a falsification pipeline. `/vulnhunter-fix` does TDD remediation: an exploit demo, then a failing security test (RED), then the fix (GREEN). `/vulnhunt-fix-verify` is an independent read-only verifier. It claims "42/42 confirmed findings carried executable exploit tests". The relationship between the two repos (fork or mirror) is unverified — [capitalone/VulnHunter](https://github.com/capitalone/VulnHunter); [nealbridges/VulnHunter](https://github.com/nealbridges/VulnHunter)
- **Lazarus-ai-OSS/clearwing**: ~1,090★, MIT, push 2026-11-05. An agentic source-security pipeline that "optionally generates validated patches", emits SARIF/JSON/Markdown, and has an "N-day exploit pipeline — given CVE IDs, builds the [vulnerable target]… against the patched version to confirm the fix" — [repo](https://github.com/Lazarus-ai-OSS/clearwing)
- **arthurpanhku/dvalincode**: ~121★, MIT, TypeScript, active. "Scan, repair, then prove it". It runs the project's own tests, typecheck and build, and records exit codes as proof that a repair (by its own agent, Claude Code, Codex or a human) holds — [repo](https://github.com/arthurpanhku/dvalincode)
- Agentic SAST that finds but mostly does not patch:
  - agentgg-dev/agentgg (~467★, Apache-2.0; hosted SaaS version)
  - openhackai/OpenHack (~445★, MIT; outputs a "recommended fix" plus Docker exploit verification)
  - utkusen/sast-skills (~1,377★)
  - protectai/vulnhuntr (~2,827★, AGPL-3.0, Python-only, **stale**, last push 2025-02-06)

  Sources: [agentgg](https://github.com/agentgg-dev/agentgg); [OpenHack](https://github.com/openhackai/OpenHack); [vulnhuntr](https://github.com/protectai/vulnhuntr)
- **anthropics/claude-code-security-review**: ~7,010★, MIT, last push 2026-02-11. An AI security-review GitHub Action for PR diffs that detects issues and does not open fix PRs — [repo](https://github.com/anthropics/claude-code-security-review)

#### (c) AI pentest agents (find/prove; some add fixing)
- **usestrix/strix**: ~76,578★, Apache-2.0, Python, very active (push 2026-11-19). "Autonomous AI hackers that find and fix your app's vulnerabilities". It runs code dynamically and validates findings with PoCs. A GitHub Actions PR scan "block[s] insecure code". `npx skills add usestrix/strix` installs "nine skills for running pentests, fixing findings, and CI scanning" for Claude Code, Cursor and Codex. It is the OSS part of a commercial product (Strix Cloud/Enterprise) — [repo](https://github.com/usestrix/strix)
- **KeygraphHQ/shannon**: ~52,058★, AGPL-3.0, TypeScript, active. A white-box AI pentester: "analyzes your source code… executes real exploits… No exploit, no report". It has an experimental `--exp-php2shell` probe to "confirm your PHP apps are patched", an example of CVE-specific verification. It is the OSS core of Keygraph Pro/Enterprise — [repo](https://github.com/KeygraphHQ/shannon)
- **latticelabs-au/logan**: ~3★, AGPL-3.0. A fork of Shannon that "fixes vulnerabilities found by Shannon audits" via a triage → fix plan → parallel fix pipeline. Tiny and immature — [repo](https://github.com/latticelabs-au/logan)
- **samugit83/redamon**: ~3,443★, MIT, active (push 2026-11-14). Its pipeline is "Reconnaissance ➜ Exploitation ➜ … AI Triage ➜ CodeFix Agent ➜ GitHub PR", and it claims 101/104 on the XBOW benchmark. It is one of the few pentesters that opens remediation PRs — [repo](https://github.com/samugit83/redamon)
- Other pentest agents with no auto-fix:
  - vxcontrol/pentagi (~34,579★, MIT, Go)
  - GreyDGL/PentestGPT (~16,506★, MIT, push 2026-07-14)
  - 0x4m4/hexstrike-ai (~13,738★, MIT, MCP server with 150+ tools, push 2026-08-03)
  - xalgorix/xalgorix (~1,373★, Apache-2.0, Go, has a cloud upsell)
  - berylliumsec/nebula (~1,162★, BSD-2)

  Sources: [pentagi](https://github.com/vxcontrol/pentagi); [PentestGPT](https://github.com/GreyDGL/PentestGPT); [hexstrike-ai](https://github.com/0x4m4/hexstrike-ai); [xalgorix](https://github.com/xalgorix/xalgorix); [nebula](https://github.com/berylliumsec/nebula)
- **aliasrobotics/cai** (Cybersecurity AI): ~9,867★, **ARCHIVED**. "No further releases, bug fixes, security patches or support". The last OSS release was 0.5.10 (Dec 2025) and development ran Mar 2025 → Aug 2026; the work moved to a paid successor ("CSI") — [repo](https://github.com/aliasrobotics/cai)
- **projectdiscovery/nuclei**: ~33,100★, MIT, Go. A template-based scanner, not a patcher — [repo](https://github.com/projectdiscovery/nuclei)

#### (d) General coding agents usable for security fixes
- **SWE-agent/SWE-agent**: ~20,831★, MIT. It "takes a GitHub issue and tries to automatically fix it… can also be employed for offensive cybersecurity" (the EnIGMA mode) — [repo](https://github.com/SWE-agent/SWE-agent)
- **OpenHands/OpenHands**: ~93,792★, MIT. A general AI dev agent with no dedicated CVE pipeline found in the repo description — [repo](https://github.com/OpenHands/OpenHands)
- **AutoCodeRoverSG/auto-code-rover**: ~3,105★, NOASSERTION, push 2026-11-01 — [repo](https://github.com/AutoCodeRoverSG/auto-code-rover)
- **patched-codes/patchwork**: ~1,581★, AGPL-3.0, last push 2026-08-24, now described as an "Agentic AI framework for enterprise workflow automation". Its `AutoFix` patchflow "patches vulnerabilities based on a scan using Semgrep" and `DependencyUpgrade` uses semgrep + depscan; both can run in CI and open PRs. It is the OSS part of a commercial product (Patched) — [repo](https://github.com/patched-codes/patchwork)

#### (e) Dependency / container CVE remediation (deterministic baselines, plus AI add-ons)
- **renovatebot/renovate**: ~23,176★, AGPL-3.0 (Mend). It does cross-platform dependency-update PRs; vulnerability-alert PRs are configurable (`vulnerabilityAlerts`, and an OSV-based `osvVulnerabilityAlerts` option per its docs) — [repo](https://github.com/renovatebot/renovate); [docs](https://docs.renovatebot.com/configuration-options/) (option names come from prior knowledge; the docs page was blocked by the proxy in this session)
- **dependabot/dependabot-core**: ~5,851★, MIT, Ruby. "Dependabot's core logic for creating update PRs" — [repo](https://github.com/dependabot/dependabot-core)
- **google/osv-scanner**: ~11,563★, Apache-2.0. "Guided Remediation" (`osv-scanner fix`) is **Experimental** and supports the npm `in-place` lockfile and `relock` strategies and the Maven `override` strategy — [repo](https://github.com/google/osv-scanner); [guided-remediation doc](https://github.com/google/osv-scanner/blob/main/docs/guided-remediation.md)
- **pypa/pip-audit**: ~1,410★, Apache-2.0. "Support for automatically fixing vulnerable dependencies (`--fix`)" — [repo](https://github.com/pypa/pip-audit)
- **npm/cli**: ~10,264★. `npm audit fix` is built in — [repo](https://github.com/npm/cli)
- **project-copacetic/copacetic** (copa): ~1,754★, Apache-2.0, Go, CNCF. It "directly patch[es] container images without full rebuilds" from a Trivy report, covering OS packages — [repo](https://github.com/project-copacetic/copacetic)
- Scanners only, with no fix: aquasecurity/trivy (~39,519★), anchore/grype (~13,297★) and ossf/cve-bin-tool (~1,812★, GPL-3.0) — [trivy](https://github.com/aquasecurity/trivy); [grype](https://github.com/anchore/grype); [cve-bin-tool](https://github.com/ossf/cve-bin-tool)
- **openrewrite/rewrite**: ~3,994★, Apache-2.0. Deterministic mass refactoring and migration recipes, used commercially by Moderne — [repo](https://github.com/openrewrite/rewrite)
- **semgrep/semgrep**: ~17,815★, LGPL-2.1. Its rules support deterministic `fix:` autofix; AI autofix is in the commercial product — [repo](https://github.com/semgrep/semgrep)
- **Rawlings/autoremediator**: ~1★, MIT, TypeScript, created 2026-03, push 2026-11-16. "Agentic remediation for Node.js dependencies":
  - Plan: it takes an audit, a CVE/GHSA ID or a SARIF report.
  - Fix: an upgrade, or a pinned override for transitive dependencies.
  - Repair: an agent fixes code broken by the upgrade, in an isolated copy.
  - Verify: install, tests and typecheck, with rollback on failure.
  - Where no fixed version exists, it can draft a patch for review. It ships as a GitHub Action.

  Conceptually the closest match to "CVE → smart dependency fix", but very low adoption — [repo](https://github.com/Rawlings/autoremediator)
- OSS clients of commercial remediation products:
  - mobb-dev/bugsy (~67★, MIT, push 2026-08-31), "Automatic security vulnerability remediation for your code", the client for commercial Mobb. Mobb's "Vibe Shield" MCP repo was not found under the guessed name mobb-dev/mobb-vibe-shield-mcp.
  - pixee/codemodder-python and codemodder-java (~43/42★, AGPL-3.0, active), the OSS codemod engines behind commercial Pixee.

  Sources: [bugsy](https://github.com/mobb-dev/bugsy); [codemodder-python](https://github.com/pixee/codemodder-python)

#### Research prototypes (mostly low activity)
- cla7aye15I4nd/PatchAgent, USENIX Sec '25: ~126★, Apache-2.0, push 2026-02-25 — [repo](https://github.com/cla7aye15I4nd/PatchAgent)
- ucsb-mlsec/PatchPilot: ~26★, MIT, **stale** (2025-06-05) — [repo](https://github.com/ucsb-mlsec/PatchPilot)
- acorn421/san2patch: ~16★, stale 2025-06 — [repo](https://github.com/acorn421/san2patch)
- ai-llm-research/autopatch, "Multi-Agent Framework for Patching Real-World CVE Vulnerabilities": ~5★, an evaluation-only codebase — [repo](https://github.com/ai-llm-research/autopatch)
- ChrisTimperley/RepairChain (AIxCC semifinal): ~13★, stale 2024 — [repo](https://github.com/ChrisTimperley/RepairChain)
- P2Patch/P2patch (exploit-guided repair plus VulnRepairBench of 101 CVEs): ~3★ — [repo](https://github.com/P2Patch/P2patch)
- Benchmarks:
  - SEC-bench/SEC-bench (~107★, NeurIPS 2025): builds CVE/OSV instances and evaluates PoC plus patching — [repo](https://github.com/SEC-bench/SEC-bench)
  - bountybench/bountybench (~114★, stale): Detect/Exploit/Patch — [repo](https://github.com/bountybench/bountybench)
  - mobb-dev/fix-vuln-code-benchmark: can agents fix disclosed CVEs offline — [repo](https://github.com/mobb-dev/fix-vuln-code-benchmark)
- Curated list: scadastrangelove/awesome-ai-security-tools (~1,763★, active 2026-11-18) lists many of the above with maturity flags — [repo](https://github.com/scadastrangelove/awesome-ai-security-tools)

### Inferences
- For a typical web or app codebase (Python/JS/Go/Java, no fuzz harnesses), the most relevant OSS options in Nov 2026 are the agent-skill harnesses: Google Mantis, Strix's fix skills, Capital One/nealbridges VulnHunter, Anthropic's defending-code-reference-harness and Visa VVAH. Each pairs LLM patching with execution-based verification (an exploit or test re-run). AIxCC CRSs (Buttercup, FuzzingBrain, OSS-CRS) are the most rigorously validated patchers, but they need C/C++/Java targets with OSS-Fuzz-style builds and fuzz harnesses.
- Most of these harnesses date from mid-2026 (created May–July 2026). They have high stars but short track records; Mantis explicitly calls its CI action untested.
- Validation requirements differ by tier:
  - CRSs need fuzz harnesses (FuzzingBrain v3 can generate its own).
  - Mantis, VulnHunter and VVAH want a sandbox (Docker) for dynamic reproduction and degrade to static-only without it.
  - Autoremediator and dvalincode rely on the project's own tests.
  - Logan and Patchwork AutoFix rely only on scanner re-runs and PR review.

### Gaps
- Exact last-commit dates were not available (repo-scoped API access was denied), so `pushed_at` is used as a proxy.
- Supported languages for Visa VVAH and Capital One VulnHunter were not checked in detail.
- Licenses showing NOASSERTION (Anthropic harness, Visa, Atlantis, AutoCodeRover) were not inspected.
- Not located: Theori's continued RoboDuck development and Shellphish/42-b3yond-6ug post-competition maintenance. These repos show no pushes since Aug 2025.
- Not verified this session: whether Strix's "fix" skills open PRs automatically or only edit locally.

## Q3. Which repos combine CVE-feed monitoring (NVD/OSV/GHSA/KEV) with automated code fixes and PRs?

### Takeaway
**No mature OSS project does the full loop** of "watch new CVEs or security news → determine if my app is affected → LLM-patch the code → validate → open a PR". The pieces exist separately:
- **Feed and intel layers.** cve.now (feed + MCP), mukul975/cve-mcp-server, StacklokLabs/osv-mcp and Fazmin/cve-intel.
- **Deterministic dependency-bump bots.** Renovate, Dependabot, osv-scanner fix, pip-audit --fix and npm audit fix. These cover the "new CVE in a dependency" case well; they bump versions but do not fix code.
- **AI fixers.** Mantis, VulnHunter, Strix, Autoremediator and Clearwing's N-day pipeline.

The closest single OSS approximations are **Renovate/Dependabot plus an AI repair step** (Autoremediator does this for Node.js) and **Clearwing's N-day pipeline** (given CVE IDs, it builds and validates against a patched version). Building the full loop means gluing a feed (cve.now RSS/JSON or OSV) to a scanner (osv-scanner/Trivy) to an agent harness (Mantis/Strix) to CI that opens PRs.

### Cited Findings
- **sazabi/cve.now**: ~157★, Apache-2.0, created 2026-10-22. "A free, public vulnerability feed" that merges the CVE List, GHSA, OSV, NVD, EUVD, CISA KEV and EPSS. It offers RSS/Atom/JSON with `filter=kev` and `filter=critical`, Slack subscribe, and a lockfile upload that gives "an RSS feed of only the entries that affect your exact package versions". It also runs a no-auth remote MCP server at `mcp.cve.now/mcp`. It monitors but does not fix — [repo](https://github.com/sazabi/cve.now)
- **mukul975/cve-mcp-server**: ~1,786★, Apache-2.0, push 2026-10-01. An MCP server with 28 tools across NVD, EPSS, CISA KEV, GitHub, Shodan and VirusTotal, plus a `triage_cve` orchestrator ("Should we patch CVE-…?"). It handles triage only — [repo](https://github.com/mukul975/cve-mcp-server)
- Other CVE MCP servers:
  - StacklokLabs/osv-mcp (~44★, Apache-2.0, active)
  - badchars/cve-mcp (~32★, MIT; NVD, EPSS, KEV, GHSA, OSV)
  - roadwy/cve-search_mcp (~110★, stale 2025-07)
  - UPinar/contrastapi (~37★, AGPL; includes "monitoring")
  - devanshkaria88/depshield-mcp (~5★; blocks vulnerable packages before an agent installs them)

  Sources: [osv-mcp](https://github.com/StacklokLabs/osv-mcp); [badchars/cve-mcp](https://github.com/badchars/cve-mcp); [cve-search_mcp](https://github.com/roadwy/cve-search_mcp); [contrastapi](https://github.com/UPinar/contrastapi); [depshield-mcp](https://github.com/devanshkaria88/depshield-mcp)
- **Fazmin/cve-intel**: ~150★, Apache-2.0, Rust, created 2026-10-18. A local desktop app, CLI, REST API and MCP server (42 MCP tools, 46 data sources) that "watches the vendors, products and packages you run". It shows "what changed this week across CISA KEV, EPSS, ENISA" and has a "Remediation Lab" that "ranks the fixes" and gives patch order, plus "Plan fix from a scan". This is CVE monitoring with fix *planning* for what you run, not code patching — [repo](https://github.com/Fazmin/cve-intel)
- **Lazarus-ai-OSS/clearwing**: the N-day pipeline takes CVE IDs, builds the target and confirms the fix against the patched version. It is driven by CVE IDs you supply, not by a feed watcher — [repo](https://github.com/Lazarus-ai-OSS/clearwing)
- **Rawlings/autoremediator**: accepts "a CVE or GHSA id" or audit/SARIF output, applies the fix, agent-repairs breakage, verifies with tests, and ships as a GitHub Action. It is Node.js-only and ~1★ — [repo](https://github.com/Rawlings/autoremediator)
- **google/mantis** has a scheduled `mantis-knowledge-refresh` workflow and a PR-scan Action. Its docs describe these as refreshing the tool's knowledge base and scanning PR diffs, not ingesting CVE feeds, and both are flagged untested — [action doc](https://github.com/google/mantis/blob/main/reference/docs/github-action.md)
- **KeygraphHQ/shannon** ships CVE-specific probes (`--exp-php2shell`) to "confirm your PHP apps are patched". Ademking/php2shell-migration (~10★) is an Agent Skill to "detect, patch and verify PHP apps affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619)". Both show a pattern of one-off, per-CVE agent skills rather than generic feed→patch automation — [Shannon](https://github.com/KeygraphHQ/shannon); [php2shell-migration](https://github.com/Ademking/php2shell-migration)
- **gadievron/cve-env** (~28★, MIT): "given a CVE ID, builds and verifies a Docker environment running the affected application". **qazbnm456/cve-reverser** (~6★): reverses public CVE patches into lab PoCs and Nuclei templates. Both are reproduction-side building blocks — [cve-env](https://github.com/gadievron/cve-env); [cve-reverser](https://github.com/qazbnm456/cve-reverser)
- **Renovate** (OSV-based vulnerability alerts) and **Dependabot** security updates are the mature, non-AI "new advisory → PR" loop for dependencies — [renovate](https://github.com/renovatebot/renovate); [dependabot-core](https://github.com/dependabot/dependabot-core)
- Copa and a small PoC (mario-valente/kubescape-cve-autofix-poc, 0★) show a "CVE autofix" GitHub Action pattern for container images: an in-place copa patch plus a Dockerfile bump — [copacetic](https://github.com/project-copacetic/copacetic); [kubescape-cve-autofix-poc](https://github.com/mario-valente/kubescape-cve-autofix-poc)
- Low-adoption repos that claim the full loop:
  - KyleLJohnson/CVE-Remediator (~2★, C#): "ingests vulnerability alerts… AI-driven agents to patch"
  - bboortz/beaconry (~1★): "CVE scanning + auto-remediation for self-hosted operators"
  - vaniachow/superset-cve-automation (0★): event-driven CVE remediation using the Devin API
  - sandijean90/VulnerabilityAgent (~9★): writes GitHub issues for dependency exploits

  All are hobby-scale — [CVE-Remediator](https://github.com/KyleLJohnson/CVE-Remediator); [beaconry](https://github.com/bboortz/beaconry); [superset-cve-automation](https://github.com/vaniachow/superset-cve-automation); [VulnerabilityAgent](https://github.com/sandijean90/VulnerabilityAgent)
- GitHub keyword searches for "cve monitor auto fix" and "vulnerability autofix llm" returned 1 and 0 relevant results respectively — [GitHub search](https://github.com/search?q=cve+monitor+auto+fix&type=repositories)

### Inferences
- For the user's goal, the practical OSS stack in Nov 2026 has five layers:
  1. Feed: cve.now RSS/JSON with a lockfile filter, or OSV.
  2. Detection: osv-scanner or Trivy in CI.
  3. Dependency CVEs: Renovate or Dependabot opening bump PRs, with an AI repair step for breakage (Autoremediator pattern, or Strix/Mantis skills in Claude Code/Codex).
  4. First-party code vulns or CVE classes: Mantis, VulnHunter or Strix fix-skills with sandbox re-verification.
  5. Containers: Copa.
- Nothing open-source does "read security news (non-structured) → infer impact → patch" end to end. That would need custom glue, for example an MCP feed server plus an agent harness on a schedule.

### Gaps
- I did not find an OSS project that subscribes to KEV/NVD and autonomously opens LLM-generated *code* (not version-bump) PRs at meaningful adoption (>100★). This could be a search blind spot: GitHub search covers names and descriptions only, and README-level content was not code-searched because search/code requires auth.
- Whether Strix Cloud or Shannon Pro offer feed-triggered rescans is a commercial question, out of scope here.
