# Verification of GitHub repos named in the AI auto-patching notes

Checked 2026-11-19 against the GitHub search API (unauthenticated, via curl; `gh` had no valid auth in this session). Live values are the search index's `stargazers_count`, `archived`, `license.spdx_id` and `pushed_at`.

## Summary

- Repos checked: 185. These are the owner/name links and bare names in `open_source_repos.md`, `chinese_ecosystem.md` and `architecture_building_blocks.md`, plus names I added for cross-reference (the ARTEX family, the replacement repos for the broken links, and a few bare names).
- Confirmed (match): 179. Every star count the notes give is within 0.5% of the live value, and every license the notes state matches the live value. Counts drifted slightly during the check (e.g. BaaRai/ARTEX 9,788 to 9,795).
- Wrong or missing: 6 (2 mismatch, 4 not found). Mismatches are renamed or archived repos; not-found items are a non-repo label, a wrong owner, and two names that do not resolve.
- Looks hallucinated or mangled: `Clinejection/Cline` is an incident label, not a repo. `Rollouts/Flagger` has the wrong owner (the real project is `fluxcd/flagger`, 5,436 stars). `Autumn-27/ARTEX` (upstream ARTEX) does not exist in the index; user Autumn-27 has 19 repos, none of them ARTEX. The notes' 'deleted upstream' claim is consistent with that, but I could not confirm the deletion itself.
- Stale or omitted facts: `jeremylong/DependencyCheck` is archived and moved to `dependency-check/DependencyCheck`. `ngc660sec/NGCBot` is archived, which the notes do not say. `All-Hands-AI/OpenHands` is now `OpenHands/OpenHands`.
- Not checked: non-GitHub links (Gitee and GitLink: renmingshuai/cve-manager, wuzimo/cve-ease, tuya/gitlink-security-advisory, hocron/AntPatcher) and the gitlab.com exploit-database link. The non-repo pages cited in the notes are also out of scope.
- ARTEX resolution: see the section at the bottom.

## Table

| repo | claimed (from notes) | actual (stars, archived, license, pushed_at) | verdict |
|---|---|---|---|
| `0x4m4/hexstrike-ai` | ~13,738 | 13,738★, archived=false, MIT, pushed 2026-08-03 | match |
| `20020124XZg/ai-code-audit-agent` | named; no stats given | 3★, archived=false, no license, pushed 2026-05-01 | match |
| `404notf0und/CVE-Flow` | ★173 | 173★, archived=false, MIT, pushed 2023-05-22 | match |
| `42-b3yond-6ug/42-b3yond-6ug-crs` | ~31 | 31★, archived=false, GPL-3.0, pushed 2025-08-19 | match |
| `7df-lab/7df_CodeAudit` | named; no stats given | 2★, archived=false, Apache-2.0, pushed 2026-10-10 | match |
| `acorn421/san2patch` | ~16 | 16★, archived=false, MIT, pushed 2025-06-11 | match |
| `Ademking/php2shell-migration` | ~10 | 10★, archived=false, MIT, pushed 2026-10-25 | match |
| `agentgg-dev/agentgg` | ~467 | 467★, archived=false, Apache-2.0, pushed 2026-11-03 | match |
| `ai-llm-research/autopatch` | ~5 | 5★, archived=false, no license, pushed 2025-11-28 | match |
| `aliasrobotics/cai` | ~9,867 (archived) | 9,867★, archived=true, NOASSERTION, pushed 2026-08-22 | match |
| `alibaba/Helios` | named; no stats given | 12★, archived=false, Apache-2.0, pushed 2025-11-03 | match |
| `alibaba/sec-code-bench` | ★137 | 137★, archived=false, Apache-2.0, pushed 2026-10-12 | match |
| `alipay/ant-application-security-testing-benchmark` | ★496 | 496★, archived=false, Apache-2.0, pushed 2026-05-21 | match |
| `All-Hands-AI/OpenHands` | linked under All-Hands-AI | — | mismatch: Renamed: found as OpenHands/OpenHands (93,793 MIT); old owner not in search index. Architecture note link is stale. |
| `anchore/grype` | ~13,297 | 13,297★, archived=false, Apache-2.0, pushed 2026-11-18 | match |
| `anchore/syft` | named; no stats given | 9,925★, archived=false, Apache-2.0, pushed 2026-11-16 | match |
| `antgroup/agent-aegis` | named; no stats given | 201★, archived=false, Apache-2.0, pushed 2026-07-14 | match |
| `antgroup/Agent3Sigma-Canary` | named; no stats given | 41★, archived=false, Apache-2.0, pushed 2026-11-17 | match |
| `antgroup/YASA-Engine` | ★338 | 338★, archived=false, Apache-2.0, pushed 2026-11-03 | match |
| `anthropics/claude-code-security-review` | ~7,010 | 7,011★, archived=false, MIT, pushed 2026-02-11 | match |
| `anthropics/defending-code-reference-harness` | ~7,767 | 7,767★, archived=false, NOASSERTION, pushed 2026-08-06 | match |
| `AntiFox-AI/antifox` | ~778 | 779★, archived=false, AGPL-3.0, pushed 2026-11-17 | match |
| `aquasecurity/trivy` | ~39,519 | 39,519★, archived=false, Apache-2.0, pushed 2026-11-18 | match |
| `arthurpanhku/dvalincode` | ~121 | 121★, archived=false, MIT, pushed 2026-11-19 | match |
| `AutoCodeRoverSG/auto-code-rover` | ~3,105 | 3,105★, archived=false, NOASSERTION, pushed 2026-11-01 | match |
| `Autumn-27/ARTEX` | not in notes as a repo; notes say upstream deleted | — | not found: Upstream ARTEX absent; user Autumn-27 has 19 repos, none ARTEX. Consistent with notes' 'deleted' claim. |
| `Autumn-27/ScopeSentry` | ~2,534 | 2,534★, archived=false, no license, pushed 2026-10-11 | match: Exists; matches notes. |
| `Ayusummer/cve-monitor-wxworkbot` | named; no stats given | 5★, archived=false, MIT, pushed 2024-06-14 | match |
| `BaaRai/ARTEX` | ~9,755 | 9,788★, archived=false, AGPL-3.0, pushed 2026-11-18 | match: ~9,755 claimed; live count 9,788 to 9,795 during this check (drift, under 0.5%). |
| `badchars/cve-mcp` | ~32 | 32★, archived=false, MIT, pushed 2026-09-17 | match |
| `bboortz/beaconry` | ~1 | 1★, archived=false, MIT, pushed 2026-11-17 | match |
| `berylliumsec/nebula` | ~1,162 | 1,162★, archived=false, BSD-2-Clause, pushed 2026-11-18 | match |
| `BlkSword/CTX-Audit` | named; no stats given | 10★, archived=false, Apache-2.0, pushed 2026-11-17 | match |
| `bluesky-social/jetstream` | named; no stats given | 51★, archived=false, Apache-2.0, pushed 2026-10-29 | match |
| `bountybench/bountybench` | ~114 | 114★, archived=false, Apache-2.0, pushed 2025-07-24 | match |
| `BugFor-Pings/CVE_monitor` | named; no stats given | 14★, archived=false, no license, pushed 2025-11-06 | match |
| `bytedance/appshark` | named; no stats given | 1,755★, archived=false, Apache-2.0, pushed 2026-09-16 | match |
| `bytedance/Elkeid` | named; no stats given | 2,704★, archived=false, no license, pushed 2026-11-12 | match |
| `bytedance/PatchEval` | ★237 | 237★, archived=false, Apache-2.0, pushed 2026-10-19 | match |
| `bytedance/vArmor` | named; no stats given | 517★, archived=false, Apache-2.0, pushed 2026-11-11 | match |
| `capitalone/VulnHunter` | ~1,182 | 1,182★, archived=false, Apache-2.0, pushed 2026-10-07 | match |
| `chaitin/MonkeyCode` | ~5,295 | 5,297★, archived=false, AGPL-3.0, pushed 2026-11-19 | match |
| `chaitin/xray` | ~11.8k | 11,797★, archived=false, NOASSERTION, pushed 2024-10-29 | match |
| `ChrisTimperley/RepairChain` | ~13 | 13★, archived=false, Apache-2.0, pushed 2024-07-16 | match |
| `chu0119/Pojun` | ★392 | 392★, archived=false, AGPL-3.0, pushed 2026-11-19 | match |
| `cisagov/kev-data` | named; no stats given | 148★, archived=false, NOASSERTION, pushed 2026-11-18 | match |
| `cisagov/vulnrichment` | named; no stats given | 887★, archived=false, CC0-1.0, pushed 2026-11-19 | match |
| `cla7aye15I4nd/PatchAgent` | ~126 | 126★, archived=false, Apache-2.0, pushed 2026-02-25 | match |
| `Clinejection/Cline` | named as an incident label, not a repo | — | not found: Not a repository; 'Clinejection' is an incident label. No repo by this name in the index. |
| `Clouditera/SecGPT` | ★3,138 | 3,138★, archived=false, Apache-2.0, pushed 2025-06-25 | match |
| `CraigWill/java-env-security-fix` | named; no stats given | 0★, archived=false, no license, pushed 2026-06-26 | match |
| `cskwork/scopeweaver` | ~1,118 | 1,118★, archived=false, AGPL-3.0, pushed 2026-11-18 | match |
| `CVEProject/cvelistV5` | named; no stats given | 3,288★, archived=false, no license, pushed 2026-11-19 | match |
| `dependabot/dependabot-core` | ~5,851 | 5,851★, archived=false, MIT, pushed 2026-11-19 | match |
| `devanshkaria88/depshield-mcp` | ~5 | 5★, archived=false, MIT, pushed 2026-04-03 | match |
| `Ed1s0nZ/PrivHunterAI` | ★405 | 405★, archived=false, no license, pushed 2026-10-07 | match |
| `Ernket/CodeScan-Artex` | ~343 | 343★, archived=false, AGPL-3.0, pushed 2026-11-09 | match |
| `failsafe-security/artex` | ~874 | 874★, archived=false, AGPL-3.0, pushed 2026-11-17 | match |
| `fan-tastic-z/watchvuln-rs` | named; no stats given | 18★, archived=false, no license, pushed 2024-09-20 | match |
| `Fazmin/cve-intel` | ~150 | 150★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `fb0sh/dsh-pentester` | ★104 | 104★, archived=false, NOASSERTION, pushed 2026-10-28 | match |
| `fluxcd/flagger` | not cited (correct Flagger repo) | 5,436★, archived=false, Apache-2.0, pushed 2026-11-16 | match: Not cited by name; the correct Flagger repo (see Rollouts/Flagger). |
| `fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain` | ~152 | 152★, archived=false, Apache-2.0, pushed 2026-11-17 | match |
| `gadievron/cve-env` | ~28 | 28★, archived=false, MIT, pushed 2026-07-12 | match |
| `github/advisory-database` | named; no stats given | 2,561★, archived=false, CC-BY-4.0, pushed 2026-11-19 | match |
| `google-deepmind/codemender` | 1 | 1★, archived=false, no license, pushed 2026-01-05 | match |
| `google/mantis` | ~2,812 | 2,812★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `google/oss-fuzz-gen` | ~1,452 (archived) | 1,452★, archived=true, Apache-2.0, pushed 2026-11-10 | match |
| `google/osv-scanner` | ~11,563 | 11,564★, archived=false, Apache-2.0, pushed 2026-11-18 | match |
| `google/osv.dev` | named; no stats given | 3,073★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `GreyDGL/PentestGPT` | ~16,506 | 16,506★, archived=false, MIT, pushed 2026-07-14 | match |
| `h1kibi/Rcon-OSINT-Assistant` | named; no stats given | 4★, archived=false, MIT, pushed 2026-05-02 | match |
| `haiou-666/haiou2.0-Claude-Code-` | ★991 | 991★, archived=false, MIT, pushed 2026-10-22 | match |
| `hi-KK/VulDB_Spider` | cited (via ecosyste.ms) | 231★, archived=false, no license, pushed 2021-04-28 | match: Cited via ecosyste.ms; exists. Last push 2021-04-28, no license. |
| `Hinln/ARTEX` | ~1,700 | 1,701★, archived=false, AGPL-3.0, pushed 2026-10-08 | match |
| `IlyassCODEX/ARTEX` | ~364 | 365★, archived=false, no license, pushed 2025-07-24 | match: ~364 claimed vs 365 actual (drift). No license, last push 2025-07-24 (as claimed). |
| `iSEngLab/LLM4VulFix` | named; no stats given | 24★, archived=false, no license, pushed 2023-06-02 | match |
| `jasonbisson/terraform-google-codemender` | named; no stats given | 4★, archived=false, no license, pushed 2026-08-06 | match |
| `jaykwok/ARTEX` | named; no stats given | 118★, archived=false, AGPL-3.0, pushed 2026-11-16 | match |
| `jeremylong/DependencyCheck` | linked as OWASP Dependency-Check | 56★, archived=true, Apache-2.0, pushed 2025-09-27 | mismatch: Archived; description says repo moved to dependency-check/DependencyCheck (7,778, Apache-2.0). Link is stale. |
| `jiwoochris/artex-global` | ~3,991 | 3,991★, archived=false, AGPL-3.0, pushed 2026-11-09 | match |
| `Jueze-2019/dsh-redteam-mode` | ★163 | 163★, archived=false, MIT, pushed 2026-11-18 | match |
| `KeygraphHQ/shannon` | ~52,058 | 52,059★, archived=false, AGPL-3.0, pushed 2026-11-18 | match |
| `KyleLJohnson/CVE-Remediator` | ~2 | 2★, archived=false, no license, pushed 2026-05-20 | match |
| `langchain-ai/langgraph` | named; no stats given | 45,142★, archived=false, MIT, pushed 2026-11-19 | match |
| `latticelabs-au/logan` | ~3 | 3★, archived=false, AGPL-3.0, pushed 2026-11-06 | match |
| `Lazarus-ai-OSS/clearwing` | ~1,090 | 1,090★, archived=false, MIT, pushed 2026-11-05 | match |
| `lenaxia/artex` | not cited in notes | 26★, archived=false, AGPL-3.0, pushed 2026-10-07 | match: Not cited in notes. Exists: 26 stars, AGPL-3.0, ARCHIVED, last push 2026-10-07. |
| `lintsinghua/DeepAudit` | ★7,324 | 7,324★, archived=false, AGPL-3.0, pushed 2026-11-16 | match |
| `m4xxxxx/AIxVuln` | ★192 | 192★, archived=false, MIT, pushed 2026-04-25 | match |
| `mario-valente/kubescape-cve-autofix-poc` | 0 | 0★, archived=false, no license, pushed 2026-11-07 | match |
| `microsoft/MSRC-Microsoft-Security-Updates-API` | named; no stats given | 538★, archived=false, MIT, pushed 2025-01-24 | match |
| `mobb-dev/bugsy` | ~67 | 67★, archived=false, MIT, pushed 2026-08-31 | match |
| `mobb-dev/fix-vuln-code-benchmark` | named; no stats given | 1★, archived=false, MIT, pushed 2026-07-22 | match |
| `mobb-dev/mobb-vibe-shield-mcp` | notes: not found under this name | — | not found: Not in index; notes already say not found under this guessed name. |
| `mukul975/cve-mcp-server` | ~1,786 | 1,786★, archived=false, Apache-2.0, pushed 2026-10-01 | match |
| `murphysecurity/murphysec` | ★1,752 | 1,752★, archived=false, Apache-2.0, pushed 2026-04-07 | match |
| `murphysecurity/murphysec-jetbrains-plugin` | named; no stats given | 86★, archived=false, Apache-2.0, pushed 2022-05-18 | match |
| `n132/ARVO` | ~116 | 116★, archived=false, BSD-2-Clause, pushed 2026-09-14 | match |
| `NAXG/ThreatMCP` | named; no stats given | 50★, archived=false, MIT, pushed 2025-06-24 | match |
| `nealbridges/VulnHunter` | ~825 | 825★, archived=false, Apache-2.0, pushed 2026-11-03 | match |
| `Netflix-Skunkworks/aardvark` | named; no stats given | 485★, archived=false, Apache-2.0, pushed 2024-10-25 | match |
| `ngc660sec/NGCBot` | ★3,280 | 3,280★, archived=true, GPL-3.0, pushed 2025-05-25 | match: Stars match. Repo is ARCHIVED (since 2025-05), which the notes do not say. |
| `nomi-sec/PoC-in-GitHub` | named; no stats given | 8,214★, archived=false, CC0-1.0, pushed 2026-11-19 | match |
| `novysodope/yunso` | named; no stats given | 29★, archived=false, no license, pushed 2025-02-13 | match |
| `npm/cli` | ~10,264 | 10,264★, archived=false, NOASSERTION, pushed 2026-11-18 | match |
| `nsvizp/github-cve-monitor` | named; no stats given | 13★, archived=false, no license, pushed 2025-07-24 | match |
| `ok-helloworld/vibe-csa` | ★68 | 68★, archived=false, AGPL-3.0, pushed 2026-09-04 | match |
| `ok-helloworld/vibe-pentest` | ★386 | 386★, archived=false, AGPL-3.0, pushed 2026-09-21 | match |
| `openhackai/OpenHack` | ~445 | 445★, archived=false, MIT, pushed 2026-10-17 | match |
| `OpenHands/OpenHands` | ~93,792 | 93,793★, archived=false, MIT, pushed 2026-11-19 | match |
| `openrewrite/rewrite` | ~3,994 | 3,994★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `openvex/spec` | named; no stats given | 203★, archived=false, CC0-1.0, pushed 2026-10-30 | match |
| `ossf/cve-bin-tool` | ~1,812 | 1,812★, archived=false, GPL-3.0, pushed 2026-11-18 | match |
| `ossf/oss-crs` | ~187 | 187★, archived=false, MIT, pushed 2026-11-18 | match |
| `P2Patch/P2patch` | ~3 | 3★, archived=false, MIT, pushed 2026-10-14 | match |
| `patched-codes/patchwork` | ~1,581 | 1,581★, archived=false, AGPL-3.0, pushed 2026-08-24 | match |
| `pixee/codemodder-java` | ~42 | 42★, archived=false, AGPL-3.0, pushed 2026-11-19 | match: Cited as ~42 stars. Exists, AGPL-3.0. |
| `pixee/codemodder-python` | ~43 | 43★, archived=false, AGPL-3.0, pushed 2026-11-18 | match |
| `polar-easterlies/-111` | named; no stats given | 0★, archived=false, no license, pushed 2025-11-17 | match |
| `project-copacetic/copacetic` | ~1,754 | 1,754★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `projectdiscovery/nuclei` | ~33,100 | 33,101★, archived=false, MIT, pushed 2026-11-18 | match |
| `projectdiscovery/nuclei-templates` | named; no stats given | 13,365★, archived=false, MIT, pushed 2026-11-19 | match |
| `protectai/vulnhuntr` | ~2,827 | 2,827★, archived=false, AGPL-3.0, pushed 2025-02-06 | match |
| `purpleroc/llm_code_audit` | named; no stats given | 17★, archived=false, no license, pushed 2026-07-20 | match |
| `pypa/pip-audit` | ~1,410 | 1,410★, archived=false, Apache-2.0, pushed 2026-11-11 | match |
| `qazbnm456/cve-reverser` | ~6 | 6★, archived=false, MIT, pushed 2026-09-13 | match |
| `Rawlings/autoremediator` | ~1 | 1★, archived=false, MIT, pushed 2026-11-16 | match |
| `renovatebot/osv-offline` | named; no stats given | 25★, archived=false, MIT, pushed 2026-11-19 | match |
| `renovatebot/renovate` | ~23,176 | 23,176★, archived=false, AGPL-3.0, pushed 2026-11-19 | match |
| `roadwy/cve-search_mcp` | ~110 | 110★, archived=false, MIT, pushed 2025-07-26 | match |
| `Rollouts/Flagger` | 'Argo Rollouts/Flagger' (wrong owner) | — | not found: No such repo. Flagger is fluxcd/flagger (5,436, Apache-2.0). Notes' owner is wrong. |
| `RuoJi6/ARTEX` | ~2,270 | 2,270★, archived=false, AGPL-3.0, pushed 2026-11-14 | match |
| `samugit83/redamon` | ~3,443 | 3,443★, archived=false, MIT, pushed 2026-11-14 | match |
| `sandijean90/VulnerabilityAgent` | ~9 | 9★, archived=false, no license, pushed 2025-11-11 | match |
| `sari3l/Poc-Monitor` | ★426 | 426★, archived=false, GPL-3.0, pushed 2026-11-19 | match |
| `savior-only/WatchVuln_Web` | ★46 | 46★, archived=false, MIT, pushed 2026-03-16 | match |
| `sazabi/cve.now` | ~157 | 157★, archived=false, Apache-2.0, pushed 2026-11-11 | match |
| `scadastrangelove/awesome-ai-security-tools` | ~1,763 | 1,763★, archived=false, NOASSERTION, pushed 2026-11-18 | match |
| `SEC-bench/SEC-bench` | ~107 | 107★, archived=false, MIT, pushed 2026-01-27 | match |
| `SecNN/AiScan-N` | ★663 | 663★, archived=false, no license, pushed 2026-09-22 | match |
| `semgrep/semgrep` | ~17,815 | 17,815★, archived=false, LGPL-2.1, pushed 2026-11-19 | match |
| `shellphish/artiphishell` | ~143 | 143★, archived=false, MIT, pushed 2025-08-27 | match |
| `shellsec/watchvuln3` | named; no stats given | 5★, archived=false, MIT, pushed 2026-09-23 | match |
| `siftech/afc-crs-lacrosse` | ~11 | 11★, archived=false, MIT, pushed 2025-08-24 | match |
| `sslab-gatech/CRSBench` | ~10 | 10★, archived=false, MIT, pushed 2026-11-15 | match |
| `sssmmmwww/wxmini-security-audit` | ★424 | 424★, archived=false, no license, pushed 2026-04-03 | match |
| `StacklokLabs/osv-mcp` | ~44 | 44★, archived=false, Apache-2.0, pushed 2026-11-17 | match |
| `Stanford-Trinity/ARTEMIS` | ~552 | 552★, archived=false, Apache-2.0, pushed 2026-04-14 | match |
| `StanleyNull/AutoHunter` | ★558 | 558★, archived=false, Apache-2.0, pushed 2026-10-12 | match |
| `SWE-agent/SWE-agent` | ~20,831 | 20,831★, archived=false, MIT, pushed 2026-11-16 | match |
| `Team-Atlanta/aixcc-afc-atlantis` | ~664 | 664★, archived=false, NOASSERTION, pushed 2025-11-25 | match |
| `Team-Atlanta/aixcc-asc-atlantis` | ~51 | 51★, archived=false, MIT, pushed 2025-08-06 | match: Cited as 'aixcc-asc-atlantis' (no owner). Exists, MIT, 51 stars. |
| `Tencent/AI-Infra-Guard` | ★7,550 | 7,550★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `Tencent/AICGSecEval` | ★667 | 667★, archived=false, NOASSERTION, pushed 2026-05-25 | match |
| `Tencent/VulnGym` | ★370 | 370★, archived=false, NOASSERTION, pushed 2026-10-08 | match |
| `THATYEAR/Artificer` | named; no stats given | 2★, archived=false, no license, pushed 2025-09-19 | match |
| `theori-io/aixcc-afc-archive` | ~274 (archived) | 274★, archived=true, AGPL-3.0, pushed 2025-08-05 | match |
| `tj-actions/changed-files` | named; no stats given | 2,736★, archived=false, MIT, pushed 2026-11-13 | match |
| `TJR181/Cruiser-Agent` | named; no stats given | 25★, archived=false, Apache-2.0, pushed 2026-08-30 | match |
| `trailofbits/afc-buttercup` | ~98 (archived) | 98★, archived=true, AGPL-3.0, pushed 2025-07-14 | match |
| `trailofbits/asc-buttercup` | archived (notes) | 12★, archived=true, MIT, pushed 2025-07-15 | match: Cited as archived. Exists, archived=true, MIT. |
| `trailofbits/buttercup` | ~1,757 | 1,757★, archived=false, AGPL-3.0, pushed 2026-11-02 | match |
| `ucsb-mlsec/PatchPilot` | ~26 | 26★, archived=false, MIT, pushed 2025-06-05 | match |
| `UPinar/contrastapi` | ~37 | 37★, archived=false, AGPL-3.0, pushed 2026-11-19 | match |
| `usestrix/strix` | ~76,578 | 76,581★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `utkusen/sast-skills` | ~1,377 | 1,377★, archived=false, MIT, pushed 2026-10-23 | match |
| `vaniachow/superset-cve-automation` | 0 | 0★, archived=false, no license, pushed 2026-05-20 | match |
| `visa/visa-vulnerability-agentic-harness` | ~3,094 | 3,094★, archived=false, NOASSERTION, pushed 2026-10-22 | match |
| `Vistaminc/AuditLuma` | ★253 | 253★, archived=false, MIT, pushed 2025-08-01 | match |
| `vxcontrol/pentagi` | ~34,579 | 34,579★, archived=false, MIT, pushed 2026-11-13 | match |
| `wgpsec/AboutSecurity` | ★1,944 | 1,944★, archived=false, no license, pushed 2026-10-24 | match |
| `xalgorix/xalgorix` | ~1,373 | 1,373★, archived=false, Apache-2.0, pushed 2026-11-19 | match |
| `XmirrorSecurity/OpenSCA-cli` | ★1,139 | 1,139★, archived=false, Apache-2.0, pushed 2026-05-15 | match |
| `Yean-Sec/StrikeAgent_AtkBrain-Flash` | ★747 | 747★, archived=false, AGPL-3.0, pushed 2026-11-13 | match |
| `yhy0/github-cve-monitor` | ★1,191 | 1,191★, archived=false, MIT, pushed 2023-02-14 | match |
| `Zacarx/AICodeScan` | ★252 | 252★, archived=false, no license, pushed 2025-02-13 | match |
| `zema1/watchvuln` | ★1,922 | 1,922★, archived=false, MIT, pushed 2026-09-07 | match |
| `rapid7/metasploit-framework` | cited, no stats | — | match: Cited in architecture note (bare name). Exists, 39,612 stars, NOASSERTION. |
| `trickest/cve` | cited, no stats | — | match: Cited in architecture note (bare name). Exists, 8,229 stars, MIT. |
| `chaitin/SafeLine` | ★23k | — | match: Notes say 'SafeLine WAF ★23k' (no link): 23,322 actual. |
| `chaitin/PandaWiki` | cited, no stats | — | match: Named in chinese_ecosystem (org link only). Exists, 10,512 stars, AGPL-3.0. |
| `chaitin/OctoBus` | cited, no stats | — | match: Named in chinese_ecosystem (org link only). Exists, 212 stars, GPL-3.0. |
| `argoproj/argo-rollouts` | not cited (Argo Rollouts) | — | match: Not cited by name. Exists, 3,627 stars, Apache-2.0. |
| `dependency-check/DependencyCheck` | not cited (current home) | — | match: Not in notes by this name. Current home of OWASP Dependency-Check. |

## ARTEX resolution

- `artex in:name` (sorted by stars): 1,133 repos total. Top results: BaaRai/ARTEX (9,795, AGPL-3.0, Go, pushed 2026-11-18); jiwoochris/artex-global (3,991, AGPL-3.0); RuoJi6/ARTEX (2,270, AGPL-3.0); Hinln/ARTEX (1,701, AGPL-3.0); failsafe-security/artex (874, AGPL-3.0); bdg9412/artex-ko-plus (279); sharenjun/ARTEX-main (162); Xiao1an/ARTEX-God (123); jaykwok/ARTEX (118); azrielnan/artex-ko-main (113).
- `user:Autumn-27`: 19 repos, including ScopeSentry (2,534), ScopeSentry-Scan (280) and Norma (206). None is ARTEX. The upstream `Autumn-27/ARTEX` is not in the index.
- `lenaxia/artex`: exists, 26 stars, AGPL-3.0, **archived=true**, pushed 2026-10-07. It is an English-UI fork and is not cited in the notes.
- `BaaRai/ARTEX`: 9,795 stars, AGPL-3.0, Go, pushed 2026-11-18. It is the largest fork. Its description says upstream is Autumn-27/ARTEX.
- `jiwoochris/artex-global`: 3,991 stars, AGPL-3.0, pushed 2026-11-09.
- `IlyassCODEX/ARTEX`: 365 stars, no license, Python, pushed 2025-07-24. It is an unrelated web-app analysis platform, as the notes say.
- `Ernket/CodeScan-Artex`: 343 stars, AGPL-3.0, Go, pushed 2026-11-09. It is the read-only audit fork, as the notes say.
- `Stanford-Trinity/ARTEMIS`: 552 stars, Apache-2.0, Rust, pushed 2026-04-14. This matches the notes.
- Bottom line: the artex the user saw is almost certainly the ARTEX pentest family (forks of Autumn-27/ARTEX). The fork with the most stars is BaaRai/ARTEX; the one whose name matches exactly is lenaxia/artex (archived).
