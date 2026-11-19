# Verdict and Plan: "AI that watches CVEs and security news, then auto-patches my app"

Date: 2026-11-19. Author's stance: opinionated senior engineer. Based on the seven research notes in this folder plus spot-checks (marked **[checked]**). No verify_*.md files existed when I wrote this.

## 0. The short version

- The idea as literally stated ("auto-patch my app from news") is the wrong shape. The part that is valuable is narrower and more boring: **a policy brain that decides *whether and how fast* to patch, on top of tools that already do the patching.**
- (a) Fun OSS project: **worth building**, if you scope it hard.
- (b) Useful for your own apps: **worth building in a thin form (about 2 weekends), a waste if you build the full vision.** Renovate + osv-scanner/Dependabot already cover roughly 80% of the real value for a solo dev.
- (c) Startup: **waste of time as a standalone product.** GitHub, Snyk, Aikido, Semgrep, and every frontier lab are shipping this in 2026 with distribution you cannot match.
- Do not make "reads news and autonomously patches and merges" the headline. Make "explains why this CVE matters to *your* repo, and opens a verified, evidence-carrying PR" the headline. Humans merge.

## 1. Verdict per goal

### (a) Learning / fun OSS project: worth building

Why:
- It touches the live 2026 frontier: agent sandboxing, prompt-injection-safe design, tiered model routing, verification oracles, supply-chain policy. All are portfolio-grade topics.
- There is an audience. The OSS side is full of repos with 1k to 76k stars in adjacent niches (Strix 76k, Shannon 52k, Mantis 2.8k, Anthropic's defending-code-reference-harness 7.8k), which shows appetite for "agentic security" repos.
- The *specific* gap is real and documented in the notes: no OSS project does "feed -> affected? -> verified fix PR" above toy scale. The closest are autoremediator (1 star **[checked]**: Rawlings/autoremediator, MIT, pushed 2026-11-16), Clearwing's N-day pipeline (1.1k, needs you to supply CVE IDs), and hobby repos with 0 to 9 stars. cve.now is feed-only (157 stars **[checked]**).

Caveats:
- "Auto-patch" repos are a crowded narrative. You stand out by honesty and evidence (benchmarks, a failure gallery), not by claims.
- Maintenance is a treadmill. See risks.

### (b) Useful tool for your own apps: worth building thin, not thick

Evidence for thin:
- Dependency CVEs are the common case, and the mechanical part is solved: Renovate (free, `osvVulnerabilityAlerts`, `minimumReleaseAge`), Dependabot (security updates, grouped updates, cooldown, and since Apr 2026 assignable to Claude/Codex/Copilot agents), osv-scanner, `npm audit fix`, `pip-audit --fix`.
- The painful residue is exactly what the notes document: major bumps that break builds and sit unmerged ("bots can't fix breaking changes"), and no urgency/reachability judgment (Valsorda's "Turn Dependabot Off", Feb 2026).
- Research says LLM repair of breaking-change builds is weak: Byam 21 to 27% full-build repair on Java BUMP (2025), FSE'25 up to 23%. Treat it as a minority-case helper, not the core.

Evidence against thick:
- A solo dev with a handful of apps will see maybe a few relevant CVEs a month. A full multi-source news ingestion engine is overkill for that volume; an RSS digest plus a lockfile match gets you the signal.
- GitHub will likely ship most of the glue natively within a year. Dependabot-to-agent already exists (Apr 2026).

Honest rule of thumb: if your apps are on GitHub, turn on Dependabot alerts + Renovate with cooldown and grouped PRs first. Build only the layer that is still missing after that (see section 2).

### (c) Startup / product: waste of time (as a standalone)

- Incumbents with distribution: GitHub (agentic autofix GA Oct 2026), Snyk (Evo Remediation Agent, Oct 2026), Aikido ($1B valuation, bought Root in Jun 2026 for about $70M), Semgrep Autofix, Endor (reachability + KEV/EPSS), Seal (backports), Chainguard ($3.5B).
- Frontier labs ship the agent layer: Claude Security (public beta May 2026), Codex Security, Google CodeMender (public preview Jul 2026).
- 2026 seed rounds ($2M to $11M: QuestorAI, Emphere, Onit) are chasing the same autonomous remediation pitch. A solo dev with no design partners is behind.
- Buyers who pay for this need SOC 2, audit trails, and a vendor to blame. "Cheap Chinese models" is a procurement negative for most Western enterprise buyers (data-residency concerns), not a feature.
- Only plausible commercial angle: OSS core plus a hosted "policy engine as GitHub App" for small teams. Even there, GitHub is the natural acquirer and also the natural killer. Do not quit a job for it. Revisit only if the OSS version gets real adoption and inbound requests.

## 2. What is novel and what is not

### Already done (do not rebuild)

| Capability | Who has it |
|---|---|
| Advisory -> dependency bump PR | Dependabot, Renovate, osv-scanner fix, `npm audit fix`, pip-audit --fix, Snyk, Aikido |
| Agent fixes breaking-change PRs | GitHub Dependabot->Copilot/Claude/Codex agent, Snyk Evo, Autoremediator (Node), Elastic's Renovate+Claude CI pattern |
| KEV/EPSS/reachability prioritization | Endor, Snyk, Seemplicity, Zafran; cve.now and cve-intel in OSS; cve-mcp-server `triage_cve` |
| Feed aggregation | cve.now (CVE, GHSA, OSV, KEV, EPSS, EUVD; RSS; lockfile-filtered feed; MCP), watchvuln (China-centric push bot), OSV |
| Find+fix first-party vulns with sandbox verification | Mantis, VulnHunter, VVAH, Strix skills, Claude Security, CodeMender |
| Backports without upgrading | Seal, Root/Aikido, Chainguard |
| Container OS patching | Copa + Trivy |
| Cooldown (minimumReleaseAge) | Renovate, Dependabot cooldown, pnpm, npm |

### Not done or poorly done (candidate differentiators, ranked by my belief)

1. **Cooldown-vs-urgency policy engine (best bet).** Cooldown is now mainstream advice after Shai-Hulud; GTIG (Nov 2026) says patch-diffing exploit agents compress the window. Nobody in the notes resolves the conflict per update. Policy: hold routine bumps N days; fast-track when (KEV or EPSS high or credible exploit news) AND reachable in your code, but only after provenance/malware checks on the *new* version. This is small, testable, explainable, and genuinely missing. Most defensible novelty.
2. **Reachability-gated, explained triage.** "Why this PR exists / why I did not open one" with evidence. Answers Valsorda directly. Reuse govulncheck (Go), and for npm/Python use call-graph-lite tools plus an LLM that *proposes* vulnerable symbols from the fix commit and a static tool that *verifies*. Honest caveat: reachability for JS/Python is weak; expect false negatives, so reachability should only *lower urgency*, never suppress a KEV item.
3. **News-aware early signal.** Real but overrated. News often precedes structured data by hours to days for big-vendor zero-days, but for a typical app's dependency tree the signal is mostly redundant with GHSA/OSV/KEV within the same day. Treat news as a "watch" escalator only (raises priority, never triggers action). No vendor documents this (notes, commercial Q3), so it is novel, but its marginal value is the least proven. Build it as an experiment with a measured claim: "news flagged X hours before GHSA on N of M cases." If the number is bad, publish that honestly; it is still a result.
4. **Breaking-change repair with a cheap tiered model plus CI loop.** Not novel, but the *cost* angle is: strong open-weight models do bounded repair loops for cents. Novel only if you publish numbers on VulnBump/BUMP-style tasks.
5. **Self-hosted, cheap, tiered models.** A packaging choice, not a moat. Valuable for you; not a differentiator.
6. **Evidence-carrying PRs** (re-scan diff, regression test result, provenance check, cooldown decision log, model/cost footer). Cheap and makes the project feel trustworthy.

I would drop: first-party vuln hunting (crowded, Mantis/Strix/Claude Security own it), C/C++ fuzz-based CRS territory (needs OSS-Fuzz harnesses; Buttercup/OSS-CRS exist), and any "autonomous merge to prod".

## 3. Biggest risks (ranked)

1. **Patch correctness.** PatchBench (Sep 2026): PoC-only validation overstates by about 1.83x; Atlantis passed 92% of PoCs but truly fixed 48.4%. Vul4J: 24.8% fully correct LLM patches; over-fixing 7 to 24%. AIxCC Patch-SARIF (no PoC) 1/3. Your use case lacks a PoC for most CVEs, so you are in the weak-oracle regime. Mitigation: restrict the LLM to the cases where oracles exist (version bump + tests + re-scan; upstream fix commit's regression test for backports). Never let an LLM judge be the sole gate (the multi-language study found LLM-as-judge unreliable for functional preservation). Headline claims above 80% in papers almost always use the weak oracle.
2. **Prompt injection via advisories, news, changelogs, PoC READMEs, issue titles.** PromptPwnd, Clinejection, and the Claude Code Action flaw (fixed v2.1.128) show this is exploited in CI today. News and advisory text is attacker-writable. Mitigation: quarantined extractor model with no tools or secrets, schema-validated JSON with verbatim evidence quotes, output only creates "watch" signals; patcher agent never sees raw news; changelog/release-note text is treated as data in delimited blocks; network egress allowlist; scoped short-lived tokens.
3. **Auto-merge supply-chain risk.** The "fix" release can itself be malicious (Shai-Hulud variants even got legitimate provenance). Fast-tracking a KEV fix bypasses your cooldown, which is exactly when you are most exposed to a poisoned release. Mitigation: provenance + maintainer-change + install-script + package-age checks before any fast-track; pin by hash; auto-merge only Tier A (see gates).
4. **Claude subscription terms [checked via search, status contradictory].** My search shows: Feb 2026 terms restricted subscription OAuth tokens to Claude.ai/Claude Code; Apr 4, 2026 enforcement against third-party harnesses (OpenClaw); mid-May 2026 partial reversal where `claude -p`, Agent SDK, GitHub Actions and third-party tools are allowed but moved to a separate monthly credit pool (reported $20 Pro / $100 Max 5x / $200 Max 20x, effective Jun 15, 2026), with sources disagreeing on whether that split is in force. Third-party apps offering "log in with your Claude subscription" need Anthropic's prior approval. Practical advice: **do not design around a subscription token being driven by a scheduler (Hermes or cron).** Use an API key (or the Agent SDK credit pool) for unattended runs, read the current Anthropic terms/Agent SDK docs yourself before shipping, and never ship an OSS tool that asks users to paste subscription credentials. Also: Hermes has a `claude-subscription-directsdk` plugin in the Nous org (129 stars **[checked]**), which suggests this pattern is common and policy-sensitive; do not rely on it.
5. **Data exposure to Chinese APIs.** Sending private source code, dependency lists, and internal repo structure to DeepSeek/Qwen/GLM/Kimi hosted APIs means that data is under PRC jurisdiction and retention policies you cannot audit. For a hobby app with public code, fine. For anything private or commercial, no. Mitigation: use Chinese models only on (i) public advisory/news text (no private data), or (ii) self-hosted/US-hosted open-weight inference (Together, Fireworks, your own GPU), or (iii) a redaction layer. Keep private code on Claude or locally hosted weights. This is also an honest answer to the cost question: tier by data sensitivity, not just by task difficulty.
6. **Maintenance burden.** Feeds change (NVD enrichment collapsed Apr 2026; EUVD API incomplete: 243,969 vs 264,920 records per VulnCheck), model IDs churn monthly, ecosystems differ. A fun project dies when the owner stops tending feeds. Mitigation: narrow to one ecosystem; reuse OSV/cve.now instead of scraping; pin model aliases in one config file.
7. **Cost runaway / agent loops.** Uber reportedly blew its AI-coding budget. Mitigation: hard per-fix token and dollar caps, max iterations (3), daily ceiling, kill switch.
8. **Legal / ethics.** Embargo/disclosure: acting on pre-disclosure info (Chainguard/PHP dispute). Stay on public advisories. China's 2021 vulnerability regulation (Art. 9: no publishing before vendor fix; no sharing undisclosed vulns with foreign parties) is relevant only if you touch undisclosed vulns or Chinese products; do not ingest or publish undisclosed vulns. Licensing: AGPL components (Renovate, Buttercup, watchvuln-style forks) have copyleft implications if you build a hosted service. Do not integrate ARTEX or its forks (offensive tool, upstream pulled, linked to real attacks). PoCs from GitHub are a known malware vector; never execute them outside a no-egress sandbox. The CSA note on "who owns the bad patch?" is a reminder: your license should disclaim warranty and your PRs should say AI-generated.
9. **Dual use.** Publishing a patch-diffing-friendly pipeline is fine; do not add exploit generation. Stay defensive.

## 4. Phased plan

Guiding principles: one ecosystem, humans merge, every claim measured, every untrusted string treated as data.

### Target ecosystem choice

Pick **npm** or **Python**, not both. My pick: **npm**, because supply-chain incidents (Shai-Hulud) make the cooldown-vs-urgency story most vivid, Renovate/pnpm/npm all have `minimumReleaseAge`, and osv-scanner supports npm lockfile fixes. Counterpoint: reachability tooling is weakest in JS. If you prefer testable reachability, pick **Go** (govulncheck) for a much smaller, cleaner demo; but audience is smaller. Python is the safe middle (pip-audit --fix, good test culture, uv lockfiles). The plan below is written for npm; swap the names for Python.

### Reference repo layout

```
cvepatch/                      # name TBD
  README.md                    # honest positioning, benchmark table, failure gallery
  SECURITY.md                  # threat model, what the bot can and cannot touch
  policy/
    policy.example.yml         # tiers, cooldown days, KEV fast-track, budgets, allowlists
    schema.json
  src/
    ingest/                    # osv_sync, kev, epss, ghsa, cve_now client, rss
    news/                      # quarantined extractor (no tools), schema, evidence-quote validator
    inventory/                 # lockfile/SBOM parsing, repo registry
    match/                     # osv-scanner wrapper, reachability adapters
    decide/                    # policy engine: urgency score, cooldown, tier assignment
    fix/                       # strategy ladder: bump -> override -> repair -> backport
    verify/                    # gates: build, tests, rescan, provenance, diff-scope, reviewer
    deliver/                   # PR writer (evidence body), labels, issue fallback
    agents/                    # prompts, tool allowlists, model routing config
  sandbox/                     # Dockerfile, egress allowlist, runner scripts (no secrets)
  evals/
    cases/                     # frozen historical CVE cases (repo@sha + CVE + expected outcome)
    run_eval.py                # replays pipeline, scores with strict oracle
    results/                   # published numbers, per model tier, with cost
  fixtures/                    # injection corpus: poisoned advisories, changelogs, news
  docs/                        # architecture, policy reference, threat model
  .github/workflows/           # scheduled run, eval CI, injection tests
```

### Verification gates (the part that makes it credible)

Order matters; any fail stops and reports.

0. **Input gate:** only structured sources decide *whether* to act. News creates watch signals only.
1. **Scope gate:** fix class determines which files may change. Bump class: manifest + lockfile only. Repair class: plus source files, capped diff size, no workflow/CI/config/secrets files, no new dependencies.
2. **Supply-chain gate on the target version:** age vs cooldown, provenance/attestation present if prior versions had it, maintainer or publisher change, new install scripts, new network/process code in diff of the package versions (cheap heuristic, plus a model summary as advisory only).
3. **Build + full tests** in an ephemeral sandbox with egress limited to the package registry. Tests must have been green on base before the change (otherwise "not verifiable", route to human).
4. **Re-scan:** the target advisory must disappear and no new advisories of equal or higher severity may appear.
5. **Vulnerability-specific oracle when available:** upstream fix commit's regression test (for backports), nuclei template, or a model-generated failing-then-passing test (flagged "model-written test, weaker").
6. **Second-agent review** using a *different model family* than the patcher, instructed to hunt for over-fixing, removed behavior, dependency additions, and injected text; it gets the diff and the policy, not the raw news. Advisory only; cannot override gates 1 to 5.
7. **Human approval** for everything except Tier A.

Merge tiers:
- **Tier A (auto-merge allowed, off by default):** patch/minor bump of a direct dep, no source change, gates 0 to 4 green, cooldown satisfied or KEV+reachable fast-track with gate 2 clean, repo has tests with a stated coverage floor.
- **Tier B (one human approval):** transitive override, major bump, any LLM repair.
- **Tier C (human plus second reviewer or just do not automate):** first-party code changes, auth/crypto paths, backports.

Report metrics from day one: precision of "affected" calls, PRs opened vs merged, revert rate, time CVE->PR, $/PR.

### Model routing

| Job | Model tier | Why |
|---|---|---|
| News/advisory relevance filter | cheapest open-weight (Qwen small/flash class, DeepSeek flash class) | high volume, no secrets, no tools |
| News/advisory structured extraction | mid open-weight (DeepSeek/Qwen/GLM/Kimi), self-hosted or US-hosted if you care | public text only; schema + evidence quotes |
| Triage explanation, VEX draft, reachability symbol proposal | mid or strong open-weight on public data; Claude if private repo context | needs repo context, so mind data policy |
| Bump + breaking-change repair | Claude Code headless (API key) for private repos; a strong open-weight model in an OpenHands/mini-SWE-agent harness as a cost experiment | actual code edits are where quality matters |
| Second-agent review | different family from patcher | reduces correlated failure |

Check current model names and prices at build time; they will have changed. Keep routing in one YAML file.

### Orchestrator

Hermes Agent (MIT, Nous Research; has a built-in cron scheduler that takes `every 2h` / cron expressions and delivers to chat platforms, per third-party docs; I could not read the official repo from this session) is a reasonable *optional* scheduler and notifier, but it is a **general personal agent**. For this job, a boring scheduler (GitHub Actions cron, systemd timer, or plain cron) plus a deterministic Python pipeline is more auditable and has a smaller attack surface. Do not give a persistent, memory-keeping general agent write access to your repos. If you want Hermes in the story, use it only for notification and human-in-the-loop chat ("approve PR #12?"), not for the privileged patch step. This also keeps you away from subscription-token entanglements.

### Phase 1: Weekend 1 MVP (about 12 to 16 hours)

Goal: one repo, one ecosystem, a deterministic pipeline that opens a *well-explained* PR for a real CVE. No news yet, no auto-merge.

Components:
- Ingest: **OSV via osv-scanner against your lockfile** + CISA KEV JSON + EPSS API. Optionally pull cve.now's lockfile-filtered feed instead of rolling your own.
- Match: osv-scanner (JSON output). Reuse **Renovate** (or `osv-scanner fix`) to produce the bump.
- Decide: a ~150-line policy function: urgency = f(KEV, EPSS, severity, cooldown age). Output "fast-track / normal / hold" with a reason string.
- Fix: bump only. LLM used in one place: when tests fail after the bump, one bounded repair attempt (max 3 iterations, token cap) in a sandbox.
- Verify: gates 1, 3, 4 and a basic version of 2 (age + install-scripts diff).
- Deliver: PR with evidence body (CVE, KEV/EPSS, decision log, test results, rescan diff, model + cost).
- Schedule: GitHub Actions cron (hourly). No Hermes needed yet.

Models: cheap open-weight for explanation text; Claude Code headless on API key for the repair step only if tests fail.

Cost: $0 to $5 per month in LLM spend if you test on your own apps; CI minutes free or low. Dev time is the real cost.

Done when:
- On 3 real or replayed historical CVEs in your repos, the bot opens a PR, tests run, rescan shows the advisory gone, and the PR body explains the urgency decision.
- A deliberately breaking bump is attempted, repaired or cleanly reported "needs human".
- A poisoned advisory text in fixtures cannot change what files the bot touches (first injection test).

### Phase 2: Month 1 (about 3 to 4 weekends)

Goal: the differentiators exist and are measured.

Add:
- **Policy engine v1** with config file, the cooldown-vs-urgency matrix, and a "decision log" artifact per run. Include supply-chain gate 2 properly (provenance, maintainer change).
- **Reachability adapter** for your ecosystem (govulncheck for Go; for npm, an LLM-proposed vulnerable-symbol list from the fix commit + a static usage grep/AST check, clearly labeled low confidence). Reachability lowers urgency, never silences KEV.
- **News watcher v0**: 10 to 20 RSS feeds (CISA, BleepingComputer, THN, Project Zero, vendor blogs) -> relevance filter -> quarantined extractor -> `watch` signal table. Measure lead time vs GHSA/OSV.
- **Eval harness**: 30 to 50 frozen cases (npm CVEs with known fix versions, plus a few breaking-change cases from BUMP-style data; for Python, PatchEval/VulnBump-style cases). Strict oracle: build + tests + advisory gone + no new advisories. Record pass rate and $ per model tier.
- **Injection fixture corpus** and a CI test that must pass.
- Optional: Hermes (or Slack/Telegram) notifier with approve/deny buttons.
- Second-agent reviewer (different family).

Models: open-weight tier for filtering/extraction/triage; Claude (API key) for repair on private repos; compare one open-weight model in the repair slot using the eval harness.

Cost: roughly $10 to $40 per month LLM (mostly eval reruns), plus any self-hosted GPU/inference you choose. Evals dominate cost; cap them.

Done when:
- Eval table published with n, pass rate, $/case for at least two model tiers, with honest failure analysis.
- The policy engine demonstrably separates a KEV+reachable case (fast-tracked) from a routine bump (held) in a replay of a real incident (e.g., a Shai-Hulud-style poisoned release that cooldown would have blocked, and a KEV item that fast-track would have caught).
- News watcher has a measured result (even if "lead time is rarely useful").
- You have run it on your real apps for 2+ weeks with zero unreviewed merges and zero secret exposure.

### Phase 3: Month 3

Goal: harden, widen modestly, decide whether it deserves to live.

Add:
- Second ecosystem *or* container support (Copa + Trivy for image OS packages), not both.
- Backport strategy for one case: no upgrade path -> cherry-pick upstream fix commit, validate with its regression test (Tier C, human review required).
- GitHub App packaging (least-privilege token: contents on bot branches + pull_requests; never workflows:write).
- Tier A auto-merge behind explicit opt-in, with canary/rollback documentation for deploys.
- Public leaderboard of cases and a "run it on your repo in dry-run mode" command.
- Maintenance plan: feed health checks, model-alias pinning, deprecation alerts, a documented "I might stop maintaining this" policy.
- External security review of your own threat model (ask the community, invite injection attempts).

Cost: about $20 to $80 per month for infra/LLM at hobby scale, more if you host a demo.

Done when:
- At least a few external users run it in dry-run and file issues.
- You can state a measured merge rate and revert rate on at least one real codebase over 4+ weeks.
- You make an explicit keep/kill call: if no one but you uses it and Dependabot's agent features have absorbed the policy idea, archive it gracefully with a good write-up. That is a fine outcome.

## 5. What would make it stand out on GitHub

- **Position it as the policy layer, not another agent.** Tagline direction: "Decides when to patch, not just how." Link out to Renovate/osv-scanner/Claude Code instead of competing. One clear sentence in the README about what it is *not* (not a pentester, not a SAST, not auto-merge-by-default).
- **Show the failure gallery.** Cases where it was wrong, refused, or needed a human. In a space full of 90% claims, honesty plus a strict-oracle eval table (cite PatchBench's 1.8x inflation lesson) is the differentiator.
- **Threat model first.** A SECURITY.md that explains the quarantined-extractor design, token scopes, egress allowlist, and the injection fixture corpus. A "try to hack my patch bot" challenge issue invites engagement.
- **Replay demos with real history:**
  - Replay a poisoned-release incident: bot holds the bump (cooldown) while a naive auto-merge bot installs it.
  - Replay a KEV-listed CVE that is reachable: bot fast-tracks within minutes, with a provenance check, while the routine-bump queue stays held.
  - Replay a Valsorda-style noise case: show "no PR opened, here is why" next to Dependabot's PR spam.
- **Cost transparency:** every PR footer shows models used and cents spent; README has a cost-per-fix table across tiers (open-weight vs Claude). The "cheap models for bulk work" idea is a real hook if you show quality/cost numbers.
- **One-command dry run:** `npx cvepatch scan .` or `uvx` equivalent that prints the decision log for your lockfile with no network writes and no LLM calls required.
- **Short screencast or terminal GIF** of the decision log, not of an agent typing.
- **Name ideas (optional):** Triagent, Cooldown, Stitch, Patchwork-style names are taken or crowded (patchwork exists, 1.6k stars). Pick something short and check availability on GitHub and npm/PyPI before attaching to it.
- **Avoid** the words "autonomous", "zero-touch", "AI hacker". Avoid association with ARTEX-like offensive tooling; its upstream withdrawal and links to real attacks make adjacent branding toxic.

## 6. Spot-check log (what I verified vs. relied on)

- **Checked:** autoremediator is 1 star, MIT, pushed 2026-11-16 (GitHub API). cve.now is 157 stars, Apache-2.0 (GitHub API). Hermes Agent exists as NousResearch/hermes-agent with a plugin ecosystem; a Nous-org plugin `claude-subscription-directsdk` exists (129 stars). Direct read of the official hermes-agent repo was denied in this session, so Hermes license/cron details come from third-party pages (MIT, built-in cron scheduler).
- **Checked via web search (contradictory sources):** Anthropic subscription policy timeline for headless/Agent SDK/third-party harnesses in 2026 (Feb terms change, Apr 4 enforcement, mid-May reversal into a separate credit pool, Jun 15 start date disputed). Treat as "must re-read the current official terms before relying on any subscription-based automation."
- **Relied on notes without re-verification:** PatchBench numbers, AIxCC costs, Snyk/GitHub product dates, funding figures, Renovate option names (the notes themselves say the Renovate docs page was unreachable), "170 silent failures" study attribution (unconfirmed in the notes), GTIG exploit_agent report (reported by several outlets in the notes), Spotify auto-merge numbers (snippet only).
- **Known blind spots in the research:** no Reddit/X/HN comment-level sentiment, no independent merge-rate data for AI security PRs, no measured news-vs-GHSA lead time, no official pricing for most commercial products. My claim that news adds little marginal value for dependency CVEs is an inference, not a measured fact; Phase 2 exists to test it.
