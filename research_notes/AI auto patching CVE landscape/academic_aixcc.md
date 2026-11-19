# Academic & Competition State of the Art: LLM Automated Vulnerability Repair (AVR) and Autonomous Find+Patch (as of Nov 2026)

Method note (read first): WebSearch worked, but WebFetch was blocked by the session's network allowlist for darpa.mil, team-atlanta.github.io and ironhackers.es, so no primary page was fetched in full. Figures below come from search-result extracts of the cited pages (arXiv abstracts/HTML, vendor blogs, news). Where the extracts were truncated or ambiguous, this is flagged. Several 2026 arXiv items (IDs 26xx.xxxxx) were seen only as abstracts or snippets.

## 1. DARPA AI Cyber Challenge (AIxCC): final results (Aug 2025, DEF CON 33) and 2026 follow-ups

### Takeaway
AIxCC showed that autonomous find-and-patch works on C/C++ and Java OSS-Fuzz-style targets when a crashing PoC (sanitizer oracle) exists. Across the field, 86% of planted bugs were found and 68% patched, and scored patches were about 90% accurate, at roughly $150–$180 per task or point. Independent 2026 re-evaluation shows that PoC-only validation overstates real fix rates by about 1.8x. The open-sourced systems are hard to deploy outside the competition infrastructure.

### Cited Findings
- **Winners (Aug 8–9, 2025):** 1st Team Atlanta (Georgia Tech/KAIST/Samsung/POSTECH), "Atlantis", USD 4M, 392.76 points, more than 170 points ahead of 2nd place. 2nd Trail of Bits, "Buttercup", USD 3M. 3rd Theori, "RoboDuck", USD 1.5M. — [KAIST EE](https://ee.kaist.ac.kr/en/research-achieve/team-atlanta-with-professor-insu-yuns-team-wins-aixcc-final/); [EurekAlert](https://www.eurekalert.org/news-releases/1094256); [The Record](https://therecord.media/darpa-ai-code-competition-winner-def-con); [Trail of Bits blog, 2025-08-09](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)
- **Field-wide synthetic results (DARPA, corrected count):** 54 of 63 planted synthetic vulnerabilities discovered (86%), 43 patched (68%). Early materials used 70 as the denominator (77% found / 61% patched), and both sets of numbers circulate. — [ARPA-H](https://arpa-h.gov/news-and-events/arpa-h-darpa-challenge-showcases-ais-power-secure-americas-health-care); [DARPA results page (not fetched; referenced via search)](https://darpa.mil/news/2025/aixcc-results)
- **Real-world bugs:** 18 real, non-synthetic vulnerabilities found by the finalists, with responsible disclosure to maintainers. 11 viable patches were submitted for them. Team Atlanta's blog says Atlantis contributed 3 of each category of the real bugs (6 C/C++ and 12 Java in total). — [ARPA-H](https://arpa-h.gov/news-and-events/arpa-h-darpa-challenge-showcases-ais-power-secure-americas-health-care); [Team Atlanta blog (via search snippet)](https://team-atlanta.github.io/blog/post-afc/)
- **Cost:** DARPA reported an average cost of about $152 per completed challenge task, including Azure compute and LLM credits. This figure came from secondary coverage; the DARPA page was not fetched. — [ironhackers.es summary of DARPA figures](https://ironhackers.es/en/aixcc-final-defcon-33/); [SoK snippet](https://arxiv.org/html/2602.07666v1)
- **Buttercup (2nd):** 28 vulnerabilities found across 20 CWEs, 19 patches deployed, about 90% accuracy, 219 points at $181 per point, using only non-reasoning LLMs. Its blog table lists about $39.6k total spend for Trail of Bits. Theori spent $31.8k total ($151 per point) and spent about half as much on LLM queries as the top two teams. Column labels in the table were not visible in the snippet. — [Trail of Bits on X](https://x.com/trailofbits/status/1954286988615438474); [Trail of Bits blog](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)
- **Theori (3rd):** about 210.7 points. It had a higher pre-penalty score than Trail of Bits but fell to 3rd, 8.7 points behind, after the accuracy penalty. — [Trail of Bits blog / SoK via search](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/); [AIxCC SoK](https://gts3.org/assets/papers/2026/zhang:aixcc-sok.pdf)
- **Atlantis accuracy and repair rate (ATLANTIS paper):** 91.27% submission accuracy. The paper states Atlantis "patched 31 out of 43 vulnerabilities" (a 72.1% repair rate). Other coverage gives different counts, and the denominators appear to measure different things. — [ATLANTIS paper (ResearchGate)](https://www.researchgate.net/publication/395649167_ATLANTIS_AI-driven_Threat_Localization_Analysis_and_Triage_Intelligence_System); [taesoo.kim PDF](https://taesoo.kim/pubs/2025/kim:atlantis.pdf)
- **SoK: AIxCC (arXiv 2602.07666, Feb 2026):**
  - Field-wide patch accuracy was 91/99 (92%). Bundles from PoC-based patch generation reached 93% accuracy. Patch-SARIF bundles, the only pairing without a PoV, went 1/3.
  - "Incorrect patches remained common even among higher-accuracy systems", and the authors call automated patch accuracy an open problem.
  - Five of seven finalists used less than 25% of their LLM credit budget, so compute and engineering were the bottleneck, not inference spend.
  - The finalist CRSs' resource models and runtime environments "differ substantially from typical deployment settings, posing barriers to post-competition adoption."
  - — [SoK HTML](https://arxiv.org/html/2602.07666v1); [SoK PDF](https://arxiv.org/pdf/2602.07666)
- **Open-sourcing:** all finalist CRSs, challenges and infrastructure are being released, via the AIxCC Competition Archive. Buttercup is fully open source and runs on a laptop. — [SoK](https://arxiv.org/html/2602.07666); [Buttercup page](https://trailofbits.com/buttercup/); [ARPA-H](https://arpa-h.gov/news-and-events/arpa-h-darpa-challenge-showcases-ais-power-secure-americas-health-care)
- **2026 follow-up, OSS-CRS (USENIX WOOT '26):** an OpenSSF sandbox project that ports components from every finalist CRS into a standard orchestration framework. The authors note that each original system was bound to its team's infrastructure, with Atlantis needing heavy infrastructure. Running Atlantis through OSS-CRS found 7 previously unknown bugs (1 high severity) across 6 OSS-Fuzz projects. — [OSS-CRS paper](https://taesoo.kim/pubs/2026/chin:oss-crs.pdf); [USENIX WOOT26](https://www.usenix.org/conference/woot26/presentation/chin)
- **2026 follow-up, OpenSSF (May 12, 2026):**
  - OSS-CRS and FuzzingBrain are now hosted at OpenSSF / Linux Foundation.
  - OpenSSF formed a Cyber Reasoning Systems Special Interest Group.
  - OSTIF was engaged to help close out the bugs found in the competition.
  - — [OpenSSF blog](https://openssf.org/blog/2026/05/12/hack-to-the-future-the-impact-and-legacy-of-the-darpa-aixcc-challenge/); [OpenSSF podcast Feb 2026](https://openssf.org/podcast/2026/02/09/whats-in-the-soss-podcast-53-s3e5-aixcc-part-3-buttercups-hybrid-approach-trail-of-bits-journey-to-second-place-in-aixcc/)
- **Healthcare deployment framing:** ARPA-H co-sponsored the challenge and positioned the CRSs for healthcare software. One trade article is headlined "Now available: AI that finds and provides autonomous patching at scale." — [Healthcare IT News](https://www.healthcareitnews.com/news/now-available-ai-finds-and-provides-autonomous-patching-scale)
- **Independent re-evaluation of the AIxCC systems (PatchBench, arXiv 2609.04075, Sep 2026):**
  - Benchmark of 213 C/C++ tasks across 16 CWEs and 32 projects, testing 11 agents including the top three AIxCC CRSs.
  - PoC-only validation overstates performance by about 1.83x on average.
  - Atlantis passed 92.0% of PoCs but genuinely solved only 48.4% of tasks.
  - The benchmark detects memorized historical patches using a similarity metric and vulnerability transplantation.
  - Evaluating all 11 agents cost about $6,500 in inference.
  - A third-party blog reports that top agents reach 56–59% genuine solve rates and that about 1 in 4 agent fixes is a memorized patch. This was not verified against the paper.
  - — [PatchBench abs](https://arxiv.org/abs/2609.04075); [PatchBench PDF](https://arxiv.org/pdf/2609.04075); [third-party blog](https://codex.danielvaughan.com/2026/09/04/patchbench-vulnerability-patching-agents-memorization-codex-cli/)

### Inferences
- The AIxCC "~90% patch accuracy" is accuracy among submitted patches as judged by the competition's oracle (PoV no longer triggers, functionality tests pass). It is not a measure of semantic correctness. PatchBench suggests the real correct-fix rate of the best CRS is roughly half of its PoC pass rate.
- The key enabler in AIxCC was a reproducible harness: OSS-Fuzz-style builds, a sanitizer crash PoC and functionality tests. An "auto-patch my app on new CVE" product usually lacks a PoC for the app's own code. That puts it closer to the Patch-SARIF case, which scored 1/3 in AIxCC.
- About $150–$180 per task is a reasonable 2025 order-of-magnitude cost for fully autonomous find+patch, on top of substantial compute infrastructure. Patch-only on a known CVE should cost less.

### Gaps
- The official DARPA per-team breakdown (scores for teams 4–7, per-team counts of found/patched/SARIF) could not be fetched because darpa.mil was blocked. The exact definition behind the "$152 per task" figure was not verified against the primary source.
- The Atlantis numbers conflict across sources (31/43 vs 43/54 vs 43/70), and the denominators were not reconciled.
- No evidence was found of 2026 production deployments of AIxCC CRSs beyond the OSS-CRS/OpenSSF work and ARPA-H's healthcare framing.

## 2. Industry systems: CodeMender, Big Sleep, Aardvark, Anthropic, Microsoft, Meta

### Takeaway
Published industry numbers are vendor-reported and mostly about counts: fixes upstreamed, bugs found, recall on seeded bugs. None publish a rigorous patch-correctness rate on an independent benchmark. All of them keep a human review step before patches land.

### Cited Findings
- **Google DeepMind CodeMender (announced Oct 2025):**
  - 72 security fixes upstreamed to OSS over about 6 months, including projects as large as 4.5M LOC.
  - All patches are reviewed by human researchers before upstream submission.
  - An automated critique and validation stage checks that a patch fixes the root cause, is functionally correct, causes no regressions and follows style before it reaches humans.
  - It also proactively rewrites code, for example adding -fbounds-safety annotations to libwebp.
  - It is a research project, not a product. DeepMind will consider a wider release "once reliability is proven."
  - No newer update was found.
  - — [CSO Online](https://www.csoonline.com/article/4068774/google-deepmind-launches-an-ai-agent-to-fix-code-vulnerabilities-automatically.html); [AI Business](https://aibusiness.com/agentic-ai/google-codemender-patches-code-vulnerabilities); [agentsinthewild](https://agentsinthewild.co/use-cases/google-deepmind-codemender)
- **Google Big Sleep:** found a previously unknown critical SQLite flaw before attackers could exploit it. It was described as the first AI to find a memory-safety bug in the wild and get it fixed before the code's official release (Nov 2024). — [The Register / VentureBeat via search](https://www.theregister.com/2025/10/31/openai_aardvark_agentic_security)
- **OpenAI Aardvark (private beta, Oct 30, 2025; GPT-5-based):**
  - Found 92% of known and synthetically introduced vulnerabilities in OpenAI's internal "golden" repositories.
  - Found issues in OSS, 10 of which received CVEs.
  - Pipeline: threat modeling, then commit scanning, then sandbox validation, then a Codex-generated patch for human review.
  - — [OpenAI](https://openai.com/index/introducing-aardvark/); [The Register](https://www.theregister.com/2025/10/31/openai_aardvark_agentic_security); [CyberScoop](https://cyberscoop.com/openai-aardvark-security-and-patching-model-beta/)
- **Anthropic (Claude Opus 4.6 / Claude Code Security, Feb 2026):**
  - Anthropic said it had found and validated more than 500 high-severity vulnerabilities in OSS and was working with maintainers on patches.
  - Critics said not all of these were truly high severity.
  - A Checkmarx Zero test of Claude Code Security found 8 reported vulnerabilities, of which only 2 were true positives.
  - Neither OpenAI nor Anthropic has submitted detection claims to an independent audit.
  - — [The Register, 2026-02-23](https://theregister.com/2026/02/23/claude_code_security_panic); [VentureBeat](https://venturebeat.com/security/anthropic-openai-sast-reasoning-scanners-security-directors-guide); [Techloy](https://www.techloy.com/anthropic-says-its-ai-can-uncover-long-hidden-vulnerabilities-in-open-source-code/)
- **AIxCC sponsors:** Anthropic, Google, Microsoft and OpenAI supported AIxCC with model credits. — [OpenSSF](https://openssf.org/blog/2026/05/12/hack-to-the-future-the-impact-and-legacy-of-the-darpa-aixcc-challenge/)
- **Meta AutoPatchBench (part of CyberSecEval 4):**
  - 136 fuzzing-crash vulnerabilities across 47 projects.
  - Verification combines crash reproduction with an LLDB-based comparison of function states against the ground-truth patch (differential testing). A later paper notes this method can yield both false positives and false negatives.
  - — [CyberGym-E2E paper (describes AutoPatchBench)](https://arxiv.org/html/2606.04460v2)

### Inferences
- Every serious vendor pipeline is "AI proposes, human disposes". No major lab claims unattended merge of security patches.
- Detection claims carry a meaningful false-positive rate in independent tests (the Checkmarx 2/8 result). A product would need its own validation layer, not just vendor scanner output.

### Gaps
- Microsoft: no published AVR success rates were found this session.
- Big Sleep: no aggregate count of findings and no patch statistics were found. From memory, Google reported about 20 Big Sleep findings in Aug 2025 and SQLite CVE-2025-6965 in Jul 2025, but this was not verified this session.
- AutoPatchBench: the best published fix rates from Meta's own release (Apr 2025) were not retrieved.
- Anthropic's red-team blog (red.anthropic.com): no patch-success numbers were retrieved.

## 3. Benchmarks: best reported fix rates and validation method

### Takeaway
Repository-level, execution-validated AVR fix rates were about 20–35% in mid/late 2025 (SEC-bench, PatchEval). Agent scaffolds published in 2026 self-report 70–92% on the same benchmarks. When stricter semantic and security checks are added, real rates fall back to about 50–60% for the best agents, even on C/C++ tasks with PoCs. Benchmark numbers depend heavily on the validation method.

### Cited Findings
- **SEC-bench (arXiv 2506.11791, Jun 2025):**
  - Tasks: PoC generation and vulnerability patching, validated with sanitizer-based PoC oracles in an automated multi-agent pipeline.
  - Best results were 34.0% patching and 18.0% PoC generation, with SWE-agent and OpenHands both above 30% on patching.
  - — [SEC-bench](https://arxiv.org/html/2506.11791v2); [OpenReview](https://openreview.net/pdf?id=QQhQIqons0)
- **SEC-bench Pro:** 183 validated long-horizon instances. — [ResearchGate](https://www.researchgate.net/publication/405317825_SEC-bench_Pro_Can_Language_Models_Solve_Long-Horizon_Software_Security_Tasks)
- **PatchEval (arXiv 2511.11019, Nov 2025):** 1,000 real-world CVEs across 65 CWEs, with a PoC-validated subset for dynamic validation. The best LLM repaired 22.6% and the best agent 23.0%. — [PatchEval](https://arxiv.org/html/2511.11019)
- **ContraFix (arXiv 2605.17450, May 2026):** self-reports 92.0% resolution on SEC-bench and 73.8% on PatchEval using GPT-5-mini, under sanitizer-based oracles. These are self-reported and unverified. — [ContraFix](https://arxiv.org/html/2605.17450)
- **VulnResolver (arXiv 2601.13933, Jan 2026):** a hybrid agent framework for vulnerability issue resolution. Numbers were not retrieved. — [arXiv](https://arxiv.org/pdf/2601.13933)
- **PatchBench (Sep 2026):** PoC-only validation inflates results by 1.83x. Atlantis: 92.0% PoC pass vs 48.4% true solve. — [arXiv](https://arxiv.org/pdf/2609.04075)
- **CyberGym (arXiv 2506.02548, 2025/2026):**
  - Primarily PoC reproduction (finding and triggering) rather than patching. The best result in the original 2025 paper was 17.9%.
  - The 2026 version reports 34 zero-days discovered and 18 historically incomplete patches identified, i.e. upstream fixes that did not fully fix the bug.
  - 2026 leaderboard numbers conflict: Claude Opus 4.8 at 83.1% and GPT-5.5 at 81.8% (self-reported, benchmarklist); Claude Opus 4.6 at 66.6% (per Meta's Muse Spark report) vs 73.8% (benchmarklist). Scaffolding drives the differences.
  - — [CyberGym](https://www.alphaxiv.org/abs/2506.02548); [benchmarklist](https://benchmarklist.com/benchmarks/cybergym/); [datalearner](https://www.datalearner.com/en/benchmarks/cybergym); [Muse Spark report](https://arxiv.org/pdf/2606.12429)
- **CyberGym-E2E (arXiv 2606.04460, 2026):** a repository-level end-to-end benchmark with 920 tasks across 139 projects. — [arXiv](https://arxiv.org/html/2606.04460v2)
- **BountyBench (NeurIPS 2025 D&B, arXiv 2505.15216):**
  - Real bug-bounty systems, with Detect / Exploit / Patch tasks. Patch is validated by the exploit failing and the tests passing.
  - Patch scores: Codex CLI o3-high 90%, Codex CLI o4-mini 90%, Claude Code 87.5%. Custom agents scored 25–60%.
  - Corresponding Exploit scores were 47.5%, 32.5% and 57.5%, so patching a known bug is easier than exploiting it.
  - — [BountyBench](https://papers.nips.cc/paper_files/paper/2025/file/faed4276b52ef762879db4142655c699-Paper-Datasets_and_Benchmarks_Track.pdf); [arXiv](https://arxiv.org/abs/2505.15216)
- **CVE-Bench (ICML 2025):** an exploitation benchmark, not repair. Agents exploit up to 10% of web-app CVEs zero-day and 12.5% one-day. v2.1.0 was revised after benchmark-auditing work found validity issues. — [CVE-Bench](https://arxiv.org/html/2503.17332v4); [PMLR](https://proceedings.mlr.press/v267/zhu25i.html)
- **Vul4J (Java):** in an analysis of 319 LLM-generated patches for 64 Vul4J vulnerabilities, only 24.8% were fully correct. Most failures were semantic misunderstanding, not compile errors. — [Why LLMs Fail, arXiv 2603.10072](https://arxiv.org/html/2603.10072)
- **Multi-language execution-calibrated study (J. Cybersecurity & Privacy, 2026):** covers JS, Python, Go and Java. Even the best model fixes only a minority of vulnerabilities. Over-fixing rates were 7.1–24.1% by model. An LLM-as-judge cannot reliably measure functional preservation. — [JCP 6(5):153](https://doi.org/10.3390/jcp6050153)
- **CWE-bench (arXiv 2610.17020, Oct 2026):** refocuses agentic security benchmarks on defense. Numbers were not retrieved. — [arXiv](https://arxiv.org/html/2610.17020)
- **VulnBump (arXiv 2610.17374, Oct 2026):** a benchmark for fixing vulnerable dependencies while keeping the build and tests green. This is directly relevant to the "upgrade when a CVE drops" product. Numbers were not retrieved. — [arXiv](https://arxiv.org/pdf/2610.17374)
- **General vs specialized patching agents (arXiv 2603.01257):** general-purpose coding agents patch most reliably but at significantly higher token cost than patch-specific agents. — [arXiv](https://arxiv.org/html/2603.01257v1)

### Inferences
- Rough 2025–2026 consensus on validation strength:
  1. PoC no longer crashes + existing tests pass: weakest, inflated by about 1.8x.
  2. Adding hidden or functional tests and differential behavior checks: stronger.
  3. Adding manual or semantic review and memorization checks: strongest.
- Headline numbers above 80% almost always use (1).
- Web-app and bug-bounty (BountyBench) patching of a known, localized bug scores much higher (about 90%) than repository-level C/C++ memory-safety repair (about 25–60%). A product targeting app-level CVEs in managed languages may land at the easier end, but only with an exploit or test oracle.

### Gaps
- No verified Nov 2026 leaderboard for SEC-bench, PatchEval or AutoPatchBench.
- VulnRepairEval and ARVO repair numbers were not retrieved. ARVO is a reproducible OSS-Fuzz vulnerability dataset and underlies AutoPatchBench, but this was not verified this session.
- No SWE-bench security-subset numbers were found.

## 4. Key papers 2023–2026: repair, patch correctness, backporting, dependency upgrades

### Takeaway
Breaking-change repair for dependency upgrades, which is the most product-relevant capability, is weak. On Java/BUMP, about 20–27% of broken builds are fully repaired. Patch-correctness research shows that test-passing ("plausible") patches are frequently overfitted or memorized. Fine-tuned AVR results are inflated by data leakage.

### Cited Findings
- **Byam (arXiv 2505.07522, 2025):**
  - LLM repair of compilation errors caused by breaking dependency updates, evaluated on BUMP (571 breaking Java updates, 243 or 43% of them compile failures; 103 unique updates used).
  - Best result: o3-mini fully repaired 27% of failed builds; DeepSeek V3 repaired 21%.
  - A separate 78% figure refers to individual compile errors, not whole builds.
  - — [arXiv](https://arxiv.org/abs/2505.07522); [KTH slides](https://chains.proj.kth.se/workshop_4_assets/slides/4th_KTH_Chain_2025_Frank_Reyes.pdf)
- **"Automatically Fixing Dependency Breaking Changes" (FSE 2025 / ACM):** up to 23% repair success with an agentic approach vs up to 19% zero-shot. — [ACM](https://dl.acm.org/doi/10.1145/3729366); [UCL PDF](http://www0.cs.ucl.ac.uk/staff/j.krinke/publications/fse25.pdf)
- **BreakGuard (arXiv 2608.20167, 2026):** detects dependency breaking changes using LLM-generated tests. — [arXiv](https://arxiv.org/pdf/2608.20167)
- **Breaking changes in software ecosystems, systematic review (arXiv 2605.24397, 2026).** — [arXiv](https://arxiv.org/pdf/2605.24397)
- **"Repairing vulnerabilities without invisible hands" (arXiv 2507.20977, replication):**
  - Defines a plausible patch as one that passes all available tests.
  - Such patches may be correct, overfitted, or "security-fixing but functionality-breaking".
  - Manual audit is needed to separate these.
  - — [arXiv](https://arxiv.org/html/2507.20977)
- **"Rethinking the Capability of Fine-Tuned LMs for AVR" (arXiv 2512.22633):** fine-tuned AVR models overfit their training sets, and some evaluations use non-disjoint train/test splits. — [arXiv](https://arxiv.org/abs/2512.22633)
- **"Evaluating LLMs for One-Shot Patching of Real and Artificial Vulnerabilities" (arXiv 2511.23408):** LLMs overfit to known vulnerabilities, producing patches that resemble existing fixes rather than addressing the flaw. — [arXiv](https://arxiv.org/html/2511.23408)
- **Reasoning LLMs as static patch-correctness judges (arXiv 2507.22580):** flagged 106 of 109 overfitting APR patches in one evaluation. — [arXiv](https://arxiv.org/pdf/2507.22580)
- **P2Patch: Exploit-Guided Vulnerability Repair (arXiv 2610.20245, Oct 2026).** — [arXiv](https://arxiv.org/pdf/2610.20245)
- **"The History Is the Detector: Executing CVE Patch History, End-to-End" (arXiv 2609.05335, 2026).** Snippet only. — [arXiv](https://arxiv.org/pdf/2609.05335)
- **Human study protocol (arXiv 2606.25973, Jun 2026, Massacci et al.):**
  - A balanced crossover study of LLM-assisted vs manual patching. It hypothesizes faster remediation but more "fake fixes" with LLM help.
  - Small pilot: functional pass rate 56% manual vs 50% LLM-assisted. Fake fixes: 2 manual, 0 LLM-assisted.
  - The full results were not yet published.
  - — [arXiv](https://arxiv.org/abs/2606.25973)

### Inferences
- For a "CVE drops, bump the dependency, fix the breakage" product, the hard part is not the version bump. It is repairing API breakage (about 20–27% fully automatic on Java in 2025) and proving behavior is preserved. Expect most non-trivial upgrades to need human work. Trivial patch-level bumps that need no code change are the easy majority, but the literature did not quantify their share.

### Gaps
- Security patch backporting (PortGPT and similar): no results were retrieved this session.
- Reachability analysis papers (whether a vulnerable function is reachable from app code): none were retrieved this session.
- No VulnBump numbers were retrieved.

## 5. Known failure modes

### Takeaway
The dominant failure modes are well documented:
- Plausible-but-wrong patches: they pass the PoC but do not fix the root cause, or they break functionality.
- Memorized upstream patches.
- Over-fixing, which removes functionality.
- High false-positive rates in AI vulnerability detection.

Prompt-injection risk from ingesting untrusted advisories is real in principle, but no measured study of it in AVR pipelines was found.

### Cited Findings
- **PoC-only validation inflates success by about 1.83x.** Atlantis passed 92% of PoCs but genuinely fixed 48.4%. PatchBench builds memorization detection because agents reproduce historical patches. — [PatchBench](https://arxiv.org/pdf/2609.04075)
- **Incorrect patches remained common even among the best AIxCC systems.** The AIxCC scoring included an accuracy penalty, which cost Theori 2nd place. — [SoK](https://arxiv.org/pdf/2602.07666); [Trail of Bits](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)
- **Patches without a PoV are unreliable:** Patch-SARIF pairing accuracy was 1/3 in AIxCC. — [SoK](https://arxiv.org/html/2602.07666v1)
- **Semantic misunderstanding dominates.** Only 24.8% of 319 Vul4J LLM patches were fully correct. — [arXiv 2603.10072](https://arxiv.org/html/2603.10072)
- **Over-fixing rates of 7.1–24.1%, and LLM-as-judge is unreliable** for checking functional preservation. — [JCP 2026](https://doi.org/10.3390/jcp6050153)
- **Upstream human fixes can also be incomplete:** CyberGym identified 18 historically incomplete patches. — [CyberGym](https://www.alphaxiv.org/abs/2506.02548)
- **False positives and inflated severity in AI vuln finding:** Checkmarx found 2 true positives out of 8 for Claude Code Security, and critics disputed the severity of Anthropic's "500 high-severity" claim. — [The Register](https://theregister.com/2026/02/23/claude_code_security_panic)
- **Benchmark validity issues:** CVE-Bench was revised to v2.1.0 after an audit found evaluation flaws, and fine-tuned AVR evaluations leak data. — [CVE-Bench](https://arxiv.org/html/2503.17332v4); [arXiv 2512.22633](https://arxiv.org/abs/2512.22633)
- **LLM-in-the-loop systems introduce new vulnerability classes**, studied in "Towards Demystifying and Repairing LLM-in-the-Loop Vulnerabilities". Snippet only. — [arXiv 2605.28893](https://arxiv.org/pdf/2605.28893)
- **Operational brittleness:** the AIxCC CRSs are tied to heavy, team-specific infrastructure and are hard to run elsewhere. — [OSS-CRS](https://taesoo.kim/pubs/2026/chin:oss-crs.pdf); [SoK](https://arxiv.org/html/2602.07666)

### Inferences
- A safe product design is: require an executable oracle (PoC, exploit or regression test) and run the full test suite; add differential or behavioral checks and a memorization or similarity check; keep a human approval gate. Pure LLM-judge validation should not be trusted.
- Advisory text (CVE descriptions, GitHub advisories, news) is untrusted input to an agent with write access to the repo, so it is a prompt-injection vector. Treat it as data, sandbox the agent and restrict its tool permissions.

### Gaps
- No measured study was found of prompt injection via CVE advisories or news against AVR or patching agents.
- No study was found that quantifies hallucinated CVE IDs or fabricated advisories in LLM security tooling.
- No production-scale regression-rate data (e.g. rollback rates for auto-merged security PRs) was found for any vendor.
