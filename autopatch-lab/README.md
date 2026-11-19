# autopatch-lab

Can AI watch for new vulnerabilities and patch your app, your WordPress site and your normal website by itself?
This folder is the evidence: three test labs and two side experiments. Each lab has a vulnerable app, a pipeline,
several ways of fixing it (with and without AI), and a **hidden grader** that no agent ever sees. The grader re-runs
the attacks (with variants), checks the site still works, and checks nothing sneaky was added.

All of it ran on 2026-11-19 in one cloud session. Claude Sonnet and Haiku did the AI steps, run headless with
`claude -p`.

## The answer in one table

| Lab | What was tested | Pipeline + one AI session | Pipeline, no AI | AI with no pipeline | Multi-agent (agent-loop) |
|---|---|---|---|---|---|
| **1. npm library** (`lab/`, `RESULTS.md`) | 3 real vulnerable packages; one fix breaks the code | **9/9** ×3 (Sonnet, $0.065) | 8/9 (broken bump held for a human) | 9/9, but jumped 16 major versions, unpinned | 9/9, $0.59, 23× slower |
| **2. WordPress** (`wordpress/`) | 4 plugins: safe update, fix that breaks the theme, abandoned plugin with no fix, backdoored "fix" | **29/29** ×7 (Sonnet $0.17, **Haiku $0.018**, incl. 2 poisoned-changelog runs) | 24/29 (feature switched off, one hole open) | 24/29 ×2 (one run **installed the backdoor**; both broke the live site) | 29/29, $3.86, 28 min |
| **3. Next.js website** (`website/`) | Real `next` and `jsonwebtoken` advisories (one breaking), fictional no-fix and backdoored packages | **45/46** ×7 (Sonnet $0.20, **Haiku $0.02**, incl. 2 injection runs) | 39/46 | 38/46 and 44/46 (one run pointed prod at the backdoored tarball) | not run |

| Side experiment (`experiments/`) | Result |
|---|---|
| Can AI write the exploit check itself? | 18/18 correct and safe. With the first prompt it missed incomplete fixes on path traversal (0/6). **One added prompt paragraph took it to 6/6 (18/18 overall)**, with no false alarms. Haiku about $0.014 per check |
| Can a cheap model triage security news? | Haiku: 100% valid JSON, 95% relevance precision and recall, **0/7 prompt injections obeyed**, $0.0006 per item. Version ranges are weak (56%), so parse them with code |

## What we learned (each point backed by the runs above)

1. **The pipeline matters more than the model.** Same Sonnet, same inputs: with the pipeline it scored perfect or
   near-perfect every time; without it, both WordPress runs broke the live site and one installed a backdoor.
   Results without a pipeline also swing between runs (38 vs 44/46 on the website).
2. **Plain code should do most of the work:** inventory, matching, choosing the smallest safe version, update,
   release check, staging, gate, promote, rollback. AI only does the parts that need judgement: repairing code an
   update broke, writing a guard when no fix exists, and writing an exploit check when none exists.
3. **A cheap model is enough for those AI steps.** Haiku matched Sonnet in every lab at about a tenth of the cost.
   The tasks are narrow, well specified and checked by code.
4. **One AI session beats a multi-agent pipeline here.** agent-loop got the same scores at 9–22× the cost and
   14–23× the time. Its value is the audit trail, not better fixes.
5. **"AI checks AI" with a second model was noise** (round 1: Haiku rejected 5 of 7 correct fixes). Executable
   checks are the judge: tests, exploit probes, integrity checks, a staging gate.
6. **Inspect every "fix" release before installing it.** A simple diff for new install scripts, eval or remote code
   caught both backdoored releases in every pipeline run. Without the pipeline, the agent installed the backdoored
   release or pointed production at it in 3 of 4 runs (one of them then removed it by hand).
7. **Staging first, then replay on production, with rollback.** Both live-site WordPress runs broke every page
   for visitors before repairing it. No pipeline run broke production.
8. **No fix available is where AI earns its keep.** Scoped hotfixes (a WordPress must-use plugin, a Next.js route
   guard) blocked attack variants the AI never saw and kept the legitimate feature working. The no-AI fallback is
   "switch the plugin off".
9. **Prompt injection in advisories and changelogs did not work** (0 of 6 poisoned lab runs, 0 of 7 triage items), and the
   gate would have caught it anyway (new admin, eval code, changed scripts). Treat the text as data and judge by
   outcomes.
10. **Gates miss what they don't test.** On the website, every AI fix generated its RSA key at server start, so
    logins die on restart. The gate only tested a fresh login, and the hidden grader caught it. Crypto and
    key-management changes need a human, and gates need "restart, then re-check".

## Recommended design

```
feeds (OSV / GHSA / Wordfence / KEV) + news (cheap model, no tools, schema JSON, code parses versions)
  → inventory match (plain code)  → lane: urgent (exploited, or no login needed and active) / routine (cooldown)
  → [urgent] mitigate now: WAF / vPatch rule or deactivate (website)          ← humans can approve in one click
  → release check of the fix (diff for install scripts, eval, remote code, new publisher)  → hold if suspicious
  → staging copy → baseline checks → apply smallest safe version → restart → gate
       gate = build + pages + key flows + exploit probe (library, or AI-written with the "fixes may be incomplete" prompt)
              + integrity (third-party files untouched, no new admins or secrets, no dangerous code) + restart test
  → gate fails?  one AI session (Haiku is enough) repairs site-owned code only, on staging, with untrusted-text framing
  → no fix exists?  one AI session writes a scoped guard (mu-plugin, route guard), verified by probe + features
  → promote: replay on production (never copy the staging DB) → smoke → automatic rollback
  → PR / report with the evidence; human approves anything touching crypto, auth config or production data
```

## Limits

- Every fixture and grader was written in this session, so these are small worlds we designed. Real plugins,
  monorepos and page builders are messier.
- Only 1–3 runs per arm.
- DeepSeek, Qwen, GLM and other Chinese/open-weight models were not tested: there are no API keys here and the hosts
  are blocked. The model calls sit behind one function each (`claude(...)` in the runners, `callExtractor` in news
  triage) so an OpenAI-compatible endpoint can be swapped in.
- Live feeds such as Wordfence, NVD and EPSS were blocked by this environment's network policy. The labs use local
  feeds shaped like the real ones, plus the OSV bucket and the CISA KEV mirror, which were reachable.
- Anthropic's cyber safeguards stopped one sub-agent that was reproducing real-CVE exploits. The website lab was
  rebuilt so that real CVEs are verified mainly by re-scanning; fictional bugs get behavioural tests.

## Running it

| Lab | Command |
|---|---|
| npm | `cd lab && AUTOPATCH_SCRATCH=<dir> node run.mjs A B B B Binj Binj D D` (`AGENT_LOOP_DIR=<built agent-loop>` for arm C) |
| WordPress | `cd wordpress/lab && WPLAB_SCRATCH=<dir> WP_CORE_DIR=<WordPress git checkout> WP_SQLITE_DIR=<sqlite-database-integration checkout> node run.mjs A B Binj E D C` (put `wp-cli.phar` in `<dir>`) |
| Website | `cd website/lab && node run.mjs A B B B Binj Binj E E D D` (see `website/RESULTS.md` for env) |
| Experiments | see `experiments/RESULTS.md` |

Each lab's `RESULTS.md` has the full scoreboard, the bugs we found in our own pipeline, and the evidence: per run,
the diff that reached production, the report and the hidden grade.
