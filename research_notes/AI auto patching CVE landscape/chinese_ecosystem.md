# Chinese Ecosystem: AI Vulnerability Intelligence, CVE Monitoring and Automated Vulnerability Repair (中国 AI 漏洞挖掘 / 漏洞情报监控 / 漏洞自动修复 / 安全大模型), as of Nov 2026

Method note: I searched GitHub with `gh api search/repositories` and `search/code` (star counts and push dates as of 2026-11-19) and used web search. In this session, WebFetch could not reach most Chinese sites or arXiv: secrss.com, qbitai.com, news.qq.com, developer.aliyun.com, wallstreetcn.com, chinalawtranslate.com, gm7.org and arxiv.org all failed DNS resolution through the sandbox proxy. Many findings below therefore come from search-result summaries rather than full-page reads, and they are marked that way where it matters. GitHub-sourced facts (repo names, stars, descriptions, README fragments) are direct.

---

## 1. Chinese open-source projects (GitHub/Gitee/GitLink): CVE monitors, AI pentest and vuln agents, LLM code audit, auto-fix

### Takeaway
China's open-source scene is strongest in two areas: (a) vulnerability-intel collect-and-push bots that send alerts to WeChat (微信), WeCom (企业微信), DingTalk (钉钉) and Feishu (飞书), with zema1/watchvuln as the reference design; and (b) a 2025–26 surge of hobbyist and lab multi-agent AI pentest and code-audit tools (DeepAudit ★7.3k, Pojun, AntiFox, vibe-pentest, AIxVuln). True auto-fix tooling is rare and immature. The most reusable *repair* assets from Chinese organizations are benchmarks (ByteDance PatchEval, Tencent VulnGym, Tencent A.S.E, Alibaba SecCodeBench, Ant xAST) and static-analysis engines (Ant YASA), not fixers.

### Cited Findings

**Vuln-intel monitors and pushers (漏洞情报采集与推送)**
- **zema1/watchvuln** ★1,922, last push 2026-09-07. "一个高价值漏洞采集与推送服务" (high-value vulnerability collection and push service). Its README lists the sources as `avd` (Alibaba Cloud vuln DB 阿里云漏洞库), `ti` (QiAnXin threat intel 奇安信), `oscs`, `seebug` (Knownsec), `threatbook` (微步), `struts2`, `chaitin` (长亭) and `venustech` (启明星辰). It has a configurable polling interval (default 30m), a CVE de-dup across sources (`ENABLE_CVE_FILTER`) and a whitelist filter, and it pushes to DingTalk, WeCom, Feishu, Slack and webhooks — [GitHub zema1/watchvuln README](https://github.com/zema1/watchvuln)
- watchvuln forks and derivatives:
  - **shellsec/watchvuln3** (pushed 2026-09-23) adds KEV as a source, multi-group push, and a local web dashboard. The dashboard can "一键复制分析提示词并跳转 ChatGPT / Gemini / DeepSeek" (one-click copy of an analysis prompt, then a jump to an LLM) — [GitHub](https://github.com/shellsec/watchvuln3)
  - **savior-only/WatchVuln_Web** ★46 adds a web admin console — [GitHub](https://github.com/savior-only/WatchVuln_Web)
  - **fan-tastic-z/watchvuln-rs** is a Rust port — [GitHub](https://github.com/fan-tastic-z/watchvuln-rs)
- **yhy0/github-cve-monitor** ★1,191 (last push 2023). Monitors new CVE repos on GitHub, custom keywords, tool updates and specific researchers' repos, with multi-channel push — [GitHub](https://github.com/yhy0/github-cve-monitor)
- **sari3l/Poc-Monitor** ★426, actively pushed (2026-11-19). GitHub CVE PoC monitoring and push — [GitHub](https://github.com/sari3l/Poc-Monitor)
- **404notf0und/CVE-Flow** ★173. CVE analysis plus an incremental CVE monitor plus "基于深度学习的CVE EXP预测" (deep-learning prediction of whether an exploit will appear), with automated push — [GitHub](https://github.com/404notf0und/CVE-Flow)
- Smaller push bots:
  - BugFor-Pings/CVE_monitor pushes daily CVEs to DingTalk, Feishu and Telegram — [GitHub](https://github.com/BugFor-Pings/CVE_monitor)
  - nsvizp/github-cve-monitor (WeChat, DingTalk, Feishu) — [GitHub](https://github.com/nsvizp/github-cve-monitor)
  - Ayusummer/cve-monitor-wxworkbot (WeCom bot, plus MS vuln info) — [GitHub](https://github.com/Ayusummer/cve-monitor-wxworkbot)
  - novysodope/yunso, a WeChat bot that can plug in an LLM — [GitHub](https://github.com/novysodope/yunso)
- **ngc660sec/NGCBot** ★3,280. A WeChat hook bot that pushes security news (FreeBuf, 先知, 安全客, 奇安信攻防社区), does vulnerability lookups and supports ThreatBook TI queries — [GitHub](https://github.com/ngc660sec/NGCBot)
- LLM-augmented intel aggregators (small):
  - THATYEAR/Artificer collects public vuln intel daily and uses an LLM to "自动生成POC和EXP" (auto-generate PoC/EXP) — [GitHub](https://github.com/THATYEAR/Artificer)
  - h1kibi/Rcon-OSINT-Assistant: NVD/KEV/EPSS/GHSA collection with scoring and AI analysis — [GitHub](https://github.com/h1kibi/Rcon-OSINT-Assistant)
  - NAXG/ThreatMCP is an MCP server wrapping 15 ThreatBook (微步) APIs, including vuln intel — [GitHub](https://github.com/NAXG/ThreatMCP)
- Gitee:
  - **cve-manager** (openEuler community) collects and analyses CVEs, pushes them to users and exposes interfaces to security vendors, under the MulanPSL license — [Gitee](https://gitee.com/renmingshuai/cve-manager) (summary via search)
  - **cve-ease** collects CVE info and notifies by email, WeChat, DingTalk and Feishu bots — [Gitee](https://gitee.com/wuzimo/cve-ease) (summary via search)
  - GitLink hosts **tuya/gitlink-security-advisory**, an Agent Skill for gitlink-cli that queries OSV.dev, grades risk and tracks fixes — [GitLink](https://www.gitlink.org.cn/tuya/gitlink-security-advisory) (summary via search)

**AI pentest and vuln-hunting agents (AI 渗透 / 漏洞挖掘智能体)**
- **lintsinghua/DeepAudit** ★7,324, pushed 2026-11-16. "人人拥有的 AI 黑客战队" (an AI hacker team for everyone). It is a multi-agent pipeline: Recon Agent → Analysis Agent (RAG plus AST) → Verification Agent, which writes a PoC, runs it in a Docker sandbox and self-corrects on failure. It supports Ollama for private deployment. Its README roadmap lists "**自动修复 (Auto-Fix)**: Agent 直接提交 PR 修复漏洞" (the agent opens a PR that fixes the vuln) and incremental PR audit in CI/CD as **not yet done** — [GitHub lintsinghua/DeepAudit](https://github.com/lintsinghua/DeepAudit)
- **chu0119/Pojun (破军)** ★392, pushed 2026-11-19. Autonomous AI pentest / red-team platform with multiple agents and "漏洞情报运营" (vuln-intel operations). Its `vulnintel/` module covers NVD, KEV, GHSA, PoC, a "fast channel", asset linkage and a rate-limit gate. Described as "原百度攻防赛冠军项目独立演进版" (an independent evolution of a Baidu attack-defense competition winner) — [GitHub](https://github.com/chu0119/Pojun)
- **StanleyNull/AutoHunter** ★558: automated SRC bug-bounty (SRC 漏洞挖掘) system combining FOFA asset mapping with multi-worker LLM discovery, review and intel capture — [GitHub](https://github.com/StanleyNull/AutoHunter)
- Other pentest agents:
  - AntiFox-AI/antifox ★778, a fork of ARTEX — [GitHub](https://github.com/AntiFox-AI/antifox)
  - Yean-Sec/StrikeAgent_AtkBrain-Flash ★747 (CTF-focused) — [GitHub](https://github.com/Yean-Sec/StrikeAgent_AtkBrain-Flash)
  - SecNN/AiScan-N ★663 — [GitHub](https://github.com/SecNN/AiScan-N)
  - ok-helloworld/vibe-pentest ★386, which outputs "可落地的整改建议" (actionable remediation advice) but not patches — [GitHub](https://github.com/ok-helloworld/vibe-pentest)
  - DeepSeek-Harness red-team plugins: Jueze-2019/dsh-redteam-mode ★163 — [GitHub](https://github.com/Jueze-2019/dsh-redteam-mode); fb0sh/dsh-pentester ★104 — [GitHub](https://github.com/fb0sh/dsh-pentester)
- **wgpsec/AboutSecurity** ★1,944: a pentest knowledge base "以 AI Agent 可执行的格式沉淀安全方法论" (security methodology captured in agent-executable form) — [GitHub](https://github.com/wgpsec/AboutSecurity)
- **Ed1s0nZ/PrivHunterAI** ★405: a passive proxy that uses Kimi, DeepSeek or GPT to detect authorization/IDOR (越权) bugs — [GitHub](https://github.com/Ed1s0nZ/PrivHunterAI)

**LLM code audit (AI 代码审计)**
- **m4xxxxx/AIxVuln** ★192: LLM multi-agent, end-to-end vuln mining. It sets up project environments for PHP, Java, Python, Go and Node.js, then analyses, verifies and reports — [GitHub](https://github.com/m4xxxxx/AIxVuln)
- **Vistaminc/AuditLuma** ★253 (multi-agent with MCP and Self-RAG, Ollama) — [GitHub](https://github.com/Vistaminc/AuditLuma)
- **Zacarx/AICodeScan** ★252 (sink matching plus AI audit) — [GitHub](https://github.com/Zacarx/AICodeScan)
- **ok-helloworld/vibe-csa** ★68 (static audit plus dynamic verification) — [GitHub](https://github.com/ok-helloworld/vibe-csa)
- **BlkSword/CTX-Audit**: Rust taint/CPG engine that feeds an evidence chain to an LLM via MCP — [GitHub](https://github.com/BlkSword/CTX-Audit)
- **sssmmmwww/wxmini-security-audit** ★424: WeChat mini-program audit built as a Claude Code Agent Teams skill (7 agents) — [GitHub](https://github.com/sssmmmwww/wxmini-security-audit)
- **7df-lab/7df_CodeAudit**: rule SAST plus sandboxed AI agents, with a "VS Code fix" flow — [GitHub](https://github.com/7df-lab/7df_CodeAudit)
- **purpleroc/llm_code_audit** is a curated LLM code-audit resource list — [GitHub](https://github.com/purpleroc/llm_code_audit)

**Auto-fix tooling (漏洞自动修复) — sparse**
- **AntPatcher (hocron/AntPatcher, on GitLink)**. Python CLI with three agents: "安全侦察兵" (scout) runs Bandit, Semgrep and CodeQL; "安全裁决官" (judge) validates and grades; "修复架构师" (fix architect) generates and applies the patch. It re-scans in a loop until clean or until max iterations is reached. No link to Ant Group is evident and no evaluation is published — [GitLink](https://www.gitlink.org.cn/hocron/AntPatcher) (summary via search)
- Small or toy auto-fix repos:
  - CraigWill/java-env-security-fix: rule-based Java dependency/config auto-fix covering 40+ CVEs — [GitHub](https://github.com/CraigWill/java-env-security-fix)
  - 20020124XZg/ai-code-audit-agent (fix suggestions) — [GitHub](https://github.com/20020124XZg/ai-code-audit-agent)
  - polar-easterlies/-111: "基于符号化切片与大模型的跨项目漏洞修复模式挖掘" (cross-project vuln fix-pattern mining via symbolic slicing plus an LLM) — [GitHub](https://github.com/polar-easterlies/-111)
- **ByteDance vArmor Vulnerability Policy Generator** (blog 2026-05-08). An "AI Skill (prompt file)" that takes CVE and PoC info and outputs *mitigation rules* for a specific vulnerability: AppArmor/BPF/Seccomp policy, not a code patch. Framed as "From CVE to Mitigation in Minutes" — [GitHub bytedance/vArmor docs](https://github.com/bytedance/vArmor/blob/main/website/blog/2026-05-08-varmor-vuln-policy-generator/index.md)

**Big-tech open-source assets (reusable)**
- **Tencent/AI-Infra-Guard (A.I.G)** ★7,550, by Tencent Zhuque Lab (腾讯朱雀实验室). A full-stack AI red-teaming platform: Agent Scan, Skills Scan, MCP scan, AI-infra fingerprint/CVE scan, and jailbreak evaluation. Its mcp-scan and skill-scan use LLM-agent pipelines (Info Collection → Code Audit → Vulnerability Review) — [GitHub](https://github.com/Tencent/AI-Infra-Guard)
- **Tencent/VulnGym** ★370: "Real-World, Project-Level Vulnerability Benchmark for White-Box Vulnerability-Hunting Agents" — [GitHub](https://github.com/Tencent/VulnGym)
- **Tencent/AICGSecEval (A.S.E)** ★667: repo-level benchmark for the security of AI-generated code, from the Tencent Wukong Code Security Team (悟空代码安全团队) — [GitHub](https://github.com/Tencent/AICGSecEval)
- **bytedance/PatchEval** ★237: benchmark for LLM vulnerability *patching* (details in §3) — [GitHub](https://github.com/bytedance/PatchEval)
- **bytedance/appshark**: Android static taint analysis — [GitHub](https://github.com/bytedance/appshark)
- **bytedance/Elkeid**: HIDS — [GitHub](https://github.com/bytedance/Elkeid)
- **antgroup/YASA-Engine** ★338: a multi-language static analysis engine on a unified IR, "UAST" — [GitHub](https://github.com/antgroup/YASA-Engine)
- **alipay/ant-application-security-testing-benchmark (xAST)** ★496: an evaluation system for SAST/DAST/IAST tools — [GitHub](https://github.com/alipay/ant-application-security-testing-benchmark)
- **antgroup/Agent3Sigma-Canary** and **antgroup/agent-aegis**: agent-security evaluation and runtime protection for OpenClaw — [GitHub](https://github.com/antgroup/agent-aegis)
- **alibaba/sec-code-bench** (SecCodeBench) ★137: security of LLM-generated code — [GitHub](https://github.com/alibaba/sec-code-bench)
- **alibaba/Helios**: an AI-IDE secure-coding MCP service — [GitHub](https://github.com/alibaba/Helios)
- **Chaitin (长亭)** has no open-source AI vuln agent on GitHub. Its public AI repos are:
  - MonkeyCode ★5,295, described as "企业级 AI 办公工作台" (enterprise AI office workbench) — [GitHub](https://github.com/chaitin/MonkeyCode)
  - PandaWiki — [GitHub](https://github.com/chaitin)
  - OctoBus (an AI agent API gateway) — [GitHub](https://github.com/chaitin)
  - Its security open source: SafeLine WAF ★23k and xray ★11.8k (xray last pushed 2024-10) — [GitHub chaitin/xray](https://github.com/chaitin/xray)
- **murphysecurity/murphysec (墨菲安全)** ★1,752, last push 2026-04-07. Open-source SCA CLI with a vuln DB, plus a JetBrains plugin to "identify and fix open source vulnerabilities" (dependency upgrade) — [GitHub](https://github.com/murphysecurity/murphysec), [plugin](https://github.com/murphysecurity/murphysec-jetbrains-plugin)
- **XmirrorSecurity/OpenSCA-cli (悬镜安全)** ★1,139: open-source SCA — [GitHub](https://github.com/XmirrorSecurity/OpenSCA-cli)
- **Clouditera/SecGPT** ★3,138: the Chinese open "网络安全大模型" (cybersecurity LLM) — [GitHub](https://github.com/Clouditera/SecGPT)

### Inferences
- The watchvuln architecture (pluggable Chinese sources → CVE de-dup → filter/whitelist → IM push) is the de facto pattern. Its source adapters for AVD, QAX TI, OSCS, ThreatBook, Seebug, Chaitin and Venustech are the most directly reusable code for anyone who needs Chinese-language vuln intel. The newest forks add an "LLM analysis prompt" step, but none of them do automated remediation.
- The Chinese OSS community has moved quickly from "find + PoC-verify" agents to production-shaped tools. "Agent opens a fix PR" is still a roadmap item even in the most popular project (DeepAudit), which suggests the open-source repair layer is an open niche.
- Chinese big tech's open-source contribution to *repair* is mostly evaluation infrastructure (PatchEval, VulnGym, A.S.E, SecCodeBench, xAST) rather than fixers. That is directly reusable for anyone building or benchmarking an auto-patcher.

### Gaps
- Most popular repos are not attached to this session, so GitHub's repos API returned 403 and I could not read full READMEs (license, model support, accuracy claims) beyond code-search fragments.
- Gitee search was only possible through web search. Gitee star counts and activity are unverified, and Gitee-only AI auto-fix projects may exist that I could not find.
- I found no open-source auto-fix agent from Chaitin, QAX, 360, Huawei or Alibaba.

---

## 2. Chinese vendors' AI security products — who does vulnerability auto-remediation?

### Takeaway
Chinese vendors are competing hard on AI *vulnerability discovery and reproduction*:
- 360 图龙锋 (Tulongfeng) claims 99.4% on CyberGym.
- Sangfor reports 86.3% on CyberGym; Tencent Xuanwu's Atuin reports 84.8%.
- 360 and Tencent Zhuque report zero-day hauls.

Publicly documented *automated patch generation* is thin. Examples are Tencent's internal CDN red/blue workflow (claimed >99% blue-team fix rate), Alibaba/OpenAnolis kernel hot-patch generation (claimed days → minutes), ByteDance vArmor CVE-to-mitigation-policy generation, and Tophant's "漏洞修补智能体" (vuln-patching agent) concept. The main LLM products (QAX-GPT, Sangfor 安全GPT, NSFOCUS 风云卫, DBAPPSecurity 恒脑, 360 安全大模型) center on SOC alert triage and on discovery plus PoC, not on code patching.

### Cited Findings
- **360 (360 数字安全集团)**
  - Disclosed a "漏洞挖掘智能体体系" (vuln-mining agent system) in April 2026. It found a Windows kernel EoP (CVE-2026-24293) and an Office RCE (acknowledged by MSRC), both reported to the national vuln DB and fixed. It claims "近千个" (nearly 1,000) vulns, with >50 high-severity ones confirmed by CNNVD, CNVD or vendors. It also found 3 vulns in OpenClaw — [China Daily CN](https://cn.chinadaily.com.cn/a/202604/17/WS69e1f066a310942cc49a8243.html); [BAAI hub](https://hub.baai.ac.cn/view/54166) (via search summary; single-source count)
  - Launched the automated vuln-mining agent **图龙锋 (Tulongfeng)** at ISC.AI 2026 (June) and announced an automated defense system **仪天阵** (Yitianzhen). The two are framed as "倚天屠龙", a play on the Heaven-Sword and Dragon-Sabre — [wallstreetcn](https://wallstreetcn.com/articles/3775415); [Sina Finance](https://finance.sina.cn/chanjing/gsxw/2026-06-23/detail-iniekvat8823208.d.html?vt=4) (via search summary)
  - Tulongfeng reported 99.4% vulnerability *reproduction* on CyberGym (3 runs: 99.27%, 99.47%, 99.40%; all 1,507 tasks), on a leaderboard alongside GPT-5.5-Cyber, Claude Mythos Preview and Gemini 3.8 Flash Cyber. One report says Tulongfeng has found 3,432 vulns, 105 of them "监管确认" (regulator-confirmed) — [Xinhua](https://www.news.cn/tech/20261030/9703f5f42a0449b1869f2777c608dbeb/c.html); [qbitai](https://qbitai.com/2026/11/508107.html) (via search summary)
  - Bloomberg framed this as "China's 360 Hunts Software Flaws With AI, Echoing Mythos" (2026-04-22) — [Bloomberg](https://www.bloomberg.com/news/articles/2026-04-22/china-s-360-hunts-software-flaws-with-ai-echoing-mythos)
  - 360's approach is described as "攻防经验蒸馏+智能体蜂群协同" (distilled attack-defense expertise plus an agent swarm), with separate agents for attack surface, code audit, verification and reporting — [qbitai](https://www.qbitai.com/2026/04/405299.html) (via search summary)
  - No technical detail on 仪天阵's patching ability was found.
- **Sangfor 深信服 (安全GPT / Sangfor AI)**
  - CyberGym: 1,301/1,507 tasks (86.3%) with GLM-5.2 (ARVO tasks 87.2%, OSS-Fuzz tasks 77.7%). Sangfor calls it "global #4, top Chinese team". Its architecture is an "Agent Swarm" with "证据治理" (evidence governance) — [Sangfor press](https://www.sangfor.com/es/news-and-press-release/sangfor-ai-ranked-4-on-cybergym-2026); [caiwennews](https://www.caiwennews.com/article/1534687.shtml)
  - 安全GPT 2.0 was in trial with 50+ customers in 2023 — [broker report PDF](https://pdf.dfcfw.com/pdf/H301_AP202306121590849978_1.pdf)
- **Tencent 腾讯**
  - Xuanwu Lab's **Atuin** (玄武 Atuin) scored 84.0% pass@1 on CyberGym L1 with GLM-5.1 (1,265/1,506), then 84.8% with GLM-5.2. The baseline was 68.7% for the same model under Claude Code, and Tencent credits its manager/sub-agent workflow controls for the gap — [Tencent XLab](https://xlab.tencent.com/en/2026/07/02/xuanwu-atuin-cybergym/); [update](https://xlab.tencent.com/en/2026/07/17/xuanwu-atuin-cybergym-glm52/)
  - Zhuque Lab's multi-agent "Blue Team Bot" found **33 zero-days** (OpenClaw, Linux kernel, etc.). All 33 are in disclosure or remediation, and the findings feed AI-Infra-Guard's vuln DB — [Tencent Matrix blog, 2026-04-09](https://matrix.tencent.com/en/2026/04/09/discovering-33-zero-day-vulnerabilities-a-glimpse-into-the-second-half-of-security-attack-and-defense)
  - TencentOS's Corvus AI agent found a Linux kernel bug (CVE-2026-80530 "XFSTango") — [besthub](https://www.besthub.dev/articles/latent-863-days-found-in-72-hours-corvus-ai-discovers-xfstango-kernel-exploit-6c4818f01588) (secondary)
  - **Tencent CDN** runs a 7×24 red/blue agentic workflow: analysis → exploit generation → validation → repair, with deterministic container-topology replay to verify patches. It covers 149 modules, has sent more than 2.6M attack requests and claims a >99% blue-team fix rate — [besthub (secondary write-up)](https://www.besthub.dev/articles/how-tencent-s-cdn-agentic-workflow-automates-24-7-vulnerability-discovery-and-patch-deployment-5e5d783dcafb). Unverified; I could not locate the original post.
- **QiAnXin 奇安信 (QAX-GPT 安全机器人)**: Launched in 2023 and on general sale from March 2024, with new features 智能驾驶舱/智能调查/智能任务/智能报告 (dashboard, investigation, tasks, reports). It is positioned against SOC alert fatigue. I found no public description of vulnerability patch generation — [EqualOcean](https://equalocean.com/news/2024032220666-qax-gpt-security-robot-goes-sale-whole-industry/amp)
- **DBAPPSecurity 安恒 (恒脑 / Hengnao)**: Automates the full flow from code acquisition and logic comprehension to vuln mining, PoC verification and reporting. In January 2026 it entered the 6th 天府杯 (Tianfu Cup) as the first AI contestant and placed top-3 in the vuln-*defense* contest — [qbitai](https://www.qbitai.com/2026/03/383016.html) (via search summary)
- **NSFOCUS 绿盟 (风云卫)**: A security LLM within "智慧安全3.0" (Smart Security 3.0); no auto-patch detail found — [broker report](https://pdf.dfcfw.com/pdf/H3_AP202309271600012510_1.pdf). An NSFOCUS team ("ai小分队") won the 2nd Tencent Cloud Hackathon intelligent-pentest challenge — [gitcode/CSDN](https://gitcode.csdn.net/69fab3390a2f6a37c5a8078b.html) (via search summary)
- **Chaitin 长亭**
  - Its in-house "AI自主渗透智能体" (autonomous AI pentest agent) reportedly won "国内首个AI智能渗透挑战赛" (China's first AI pentest challenge); date and organizer were unspecified — [secrss](https://www.secrss.com/articles/87370) (via search summary)
  - It won 9 national-level honors in Cybersecurity Week 2026, including first place in AI-agent malicious-behavior detection. Its AI products are AI WAF, AI SOC and AI traffic detection — [C114](https://m.c114.com.cn/w241-1317718.html) (via search summary)
- **ThreatBook 微步 (RedAgents)**: Launched 2026-10-16 as a SaaS that runs several AI pentest agents in parallel on one authorized target (Artex Pro, Cyber(YanJi), Yanxun, CyberStrikeAI Enterprise), with all data kept in ThreatBook's environment — [TechNode/PRNasia](https://technode.global/prnasia/threatbook-launches-ai-powered-pentest-aggregator-redagents/); [LetsDataScience](https://letsdatascience.com/news/threatbook-launches-redagents-multi-agent-ai-penetration-tes-f20eac08)
- **Tophant 斗象科技**: CEO Xie Chen (谢忱) pitched a "漏洞修补智能体" (vuln-patching agent) inside a closed loop of 发现→研判→修复→验证 (discover → triage → fix → verify), aimed at "machine-speed" remediation — [gm7.org repost](https://www.gm7.org/archives/161285) (via search summary)
- **Alibaba / OpenAnolis 龙蜥**: Gao Xiangyang (高向阳) of the OpenAnolis ops SIG presented AI-agent generation of Linux kernel hot patches (热补丁) from upstream CVE fixes, cutting the cycle "从天级别压缩至分钟级别" (from days to minutes) — [Alibaba Cloud developer](https://developer.aliyun.com/article/1740905) (via search summary; no success-rate data)
- **ByteDance**: vArmor's CVE→mitigation-policy AI Skill (§1), plus the PatchEval benchmark (§3).
- **Murphysec 墨菲安全 and Xmirror 悬镜**: open-source SCA with dependency-upgrade "fix" in IDE plugins (§1). No public LLM-based code-patch product was found.
- **Other**: Tencent Cloud's vuln-detail API returns CNVD/CNNVD IDs, CVSS and 修复建议 (remediation advice) fields — [Tencent Cloud API](https://cloud.tencent.com/document/api/664/51980). Tencent Cloud WAF promises virtual patches within 12h (high-risk) and 24h (common) — [Tencent Cloud WAF](https://www.tencentcloud.com/product/waf?lang=en)

### Inferences
- Benchmark one-upmanship on CyberGym (360, Sangfor, Tencent Atuin, Zhipu GLM) shows Chinese vendors treat *reproduction and discovery* as the headline metric. Repair has no comparable public Chinese leaderboard except PatchEval.
- Domestic models (GLM-5.x, DeepSeek, Qwen) are the default backbone for vendor agents. That is consistent with procurement and data-residency pressures, and it means Chinese agent scaffolds are tuned for these open-weight models.
- Production auto-remediation in China appears in narrow, verifiable domains (kernel hot patches, WAF/LSM virtual patches, CDN config/code with replay testing) rather than general "agent writes PR to arbitrary repo".

### Gaps
- No primary documentation was found for auto-patch features in QAX-GPT, 360 安全大模型/仪天阵, NSFOCUS 风云卫, Venustech 启明星辰, Huawei, Moan 默安 or Alibaba Cloud Security Center's LLM features.
- The CyberGym figures are vendor self-reports; I could not check the official leaderboard.
- The Tencent CDN workflow numbers are secondary-source only.

---

## 3. Chinese academic work on LLM vulnerability repair, and Chinese teams in competitions

### Takeaway
The most important Chinese-affiliated repair artifact is **PatchEval** (HUST + ByteDance, arXiv 2511.11019). It has 1,000 CVEs in Go/JS/Python and showed the best system fixed only 23% at launch, while a 2026 "Verified" re-test reports up to ~84% for frontier coding agents. Chinese university teams are prominent in AI hacking competitions (Tsinghua RedbudAI won GEEKCON 2026's AI track; Tianfu Cup admitted an AI contestant). However, I found no Chinese AIxCC-style competition dedicated to *automated patching*.

### Cited Findings
- **PatchEval** (arXiv 2511.11019, 2025-11-14; Huazhong University of Science and Technology 华中科技大学 + ByteDance). 1,000 CVEs (2015–2025) across 65 projects in Go, JavaScript and Python, with a 230-case evaluation subset and sandboxed dynamic tests. It found LLM-as-judge unreliable. The best system among 10 LLMs, 1 APR agent, 1 coding agent and 1 commercial agent fixed 23.0% (53/230). Ninety-eight vulns were fixed by at least one system, and only 5 by all — [arXiv](https://arxiv.org/html/2511.11019v1); [GitHub](https://github.com/bytedance/PatchEval); also mirrored on [Gitee](https://gitee.com/ByteDance/PatchEval) and [HF dataset](https://huggingface.co/datasets/ByteDance/PatchEval/blob/main/patcheval_dataset.jsonl)
- **PatchEval-Verified** (README, 2026-07-24) revises the tests to check that the vulnerability is fixed rather than that a specific patch is reproduced. The top entry is 193/230 (83.91%) for a Codex agent on "gpt-5.6-sol" — [GitHub bytedance/PatchEval](https://github.com/bytedance/PatchEval) (via search summary; a different setup from the paper)
- PatchEval is already used as a target by others. EvoRepair (a self-evolving repair agent, arXiv 2605.30105) reports +39.56% over the LoopRepair baseline on PatchEval and +33.50% on SEC-bench — [alphaXiv](https://www.alphaxiv.org/zh/abs/2605.30105) (affiliation not verified)
- **CVE-Bench** (NAACL 2025): benchmark of LLM SE agents repairing real CVEs, with a Tsinghua (清华) co-author (Peiran Wang) and UW–Madison — [ACL Anthology](https://aclanthology.org/2025.naacl-long.212.pdf)
- **LLM4VulFix** (iSEngLab, TDSC 2023): "Pre-trained Model-based Automated Software Vulnerability Repair: How Far are We?" — [GitHub iSEngLab/LLM4VulFix](https://github.com/iSEngLab/LLM4VulFix). iSEngLab is generally associated with Nanjing University (南京大学); this is my recollection, not verified this session.
- "On the Evaluation of LLMs in Multilingual Vulnerability Repair" (arXiv 2508.03470; authors include Dong Wang and Junjie Chen; Chen is likely at Tianjin University, not verified): seven programming languages — [arXiv](https://arxiv.org/abs/2508.03470)
- **Tencent VulnGym** (arXiv 2608.02001): 23 repos, 184 advisories and 408 line-annotated vulnerability entries, pinned to vulnerable commits. 71.2% of advisories are business-logic flaws, and the best agent/model reportedly reaches only 22.58% advisory recall on hard tasks — [arXiv](https://arxiv.org/pdf/2608.02001); [besthub](https://besthub.dev/articles/ai-era-vulnerability-benchmark-revamp-3-632-cve-insights-vulngym-release-ff507a4f3327) (numbers via secondary write-ups)
- Peking University's Xiong Yingfei (熊英飞), a leading Chinese APR researcher, has 2025 ChinaSoft slides on program analysis/repair in the LLM era — [slides PDF](https://xiongyingfei.github.io/slides/2025ChinasoftAnalysis.pdf) (not read)
- Other 2025–26 agentic vuln-repair arXiv papers (Chinese affiliation **not verified**, because arxiv.org was unreachable): Knowledge-Enhanced Agentic Vulnerability Repair (2607.00820), MemRepair (2605.17444), EviRepair (2610.13491), RAVEN (2606.22647; 86.75% on 83 Java vulns), PatchIsland (2601.17471) — [arXiv 2607.00820](https://arxiv.org/pdf/2607.00820); [arXiv 2605.17444](https://arxiv.org/pdf/2605.17444); [arXiv 2610.13491](https://arxiv.org/pdf/2610.13491); [alphaXiv RAVEN](https://www.alphaxiv.org/zh/abs/2606.22647)
- A ZTE (中兴) presentation reportedly showed the vuln fix ratio rising from 40.9% to 69.2% with LLM assistance (context missing) — via search summary; source not identified
- **Competitions**
  - GEEKCON 2026 added its first "AI黑客极限挑战赛" (AI hacker extreme challenge) for LLMs, agents and automated attack-defense. **Tsinghua's RedbudAI (清华大学网络研究院)** won. The track focused on discovery and exploitation, not repair — [Tsinghua News](https://www.tsinghua.edu.cn/info/1176/129069.htm)
  - 天府杯 (Tianfu Cup) 2026: 安恒恒脑 was the first AI contestant and placed top-3 in the vulnerability-*defense* contest — [qbitai](https://www.qbitai.com/2026/03/383016.html) (via search summary)
  - The 2nd Tencent Cloud Hackathon 智能渗透挑战赛 (intelligent pentest challenge) was won by NSFOCUS's team — [gitcode](https://gitcode.csdn.net/69fab3390a2f6a37c5a8078b.html) (via search summary)
  - Cruiser-Agent targets the "TSec Benchmark" CTF evaluation platform — [GitHub TJR181/Cruiser-Agent](https://github.com/TJR181/Cruiser-Agent)
  - 360 AI 安全研究院 (360 AI Security Research Institute) report (2026-06-23): AI vuln mining is moving "从模型能力展示进入真实系统中的工程化验证阶段" (from model capability demos to engineering validation on real systems) — [Sina Finance](https://finance.sina.cn/chanjing/gsxw/2026-06-23/detail-iniekvat8823208.d.html?vt=4) (via search summary)

### Inferences
- PatchEval's two numbers (23% → ~84% "Verified") show that test-oracle design dominates measured repair rates. A builder should adopt PatchEval-Verified's "is it fixed?" oracle rather than patch-similarity scoring.
- Chinese competitions so far reward offense and discovery. Strong Chinese repair research is mostly in benchmarks and arXiv papers, not in contests.

### Gaps
- No evidence found of a 强网杯 (QWB) AI vuln-mining or auto-repair track, or of a Chinese government AIxCC-equivalent dedicated to auto-patching.
- Affiliations for most 2026 agentic-repair arXiv papers were unverified because arxiv.org was blocked in this session.

---

## 4. Chinese vulnerability databases and feeds; regulation affecting auto-disclosure

### Takeaway
The official databases (CNVD, CNNVD, MIIT NVDB) have no documented public developer APIs. Practical machine access is via scraping (watchvuln-style), cloud-vendor APIs that cross-reference CNVD/CNNVD IDs, or commercial TI. The 2021 **网络产品安全漏洞管理规定** (Regulations on the Management of Network Product Security Vulnerabilities) constrains auto-disclosure through:
- the 2-day reporting duty for product providers;
- a ban on publishing before the vendor's fix;
- a ban on giving undisclosed vulns to foreign organizations;
- a filing (备案) regime for collection platforms (2023), with the first approved list in 2026 and an industry self-discipline pact on 2026-11-10.

### Cited Findings
- **Feeds used in practice** (watchvuln source list): `avd` (阿里云漏洞库 avd.aliyun.com), `ti` (奇安信威胁情报 / QAX TI, NOX), `oscs` (OSCS 开源软件供应链安全社区, run with Murphysec), `threatbook` (微步), `seebug` (知道创宇/Knownsec), `chaitin` (长亭 vuln intel/Stack), `venustech` (启明星辰), `struts2` — [watchvuln README](https://github.com/zema1/watchvuln)
- I found no public API docs for CNNVD or CNVD. Third-party scrapers such as VulDB_Spider (NVD/CNVD/CNNVD) exist but are stale. Cloud APIs from Tencent Cloud, Alibaba Cloud Security Center and Huawei Cloud HSS return `cnvd_id`/`cnnvd_id` fields usable for ID mapping — [Tencent Cloud API](https://cloud.tencent.com/document/api/664/51980); [Alibaba Cloud DescribeVulDetails](https://www.alibabacloud.com/help/zh/security-center/developer-reference/api-sas-2018-12-03-describevuldetails); [Huawei HSS ShowCmsVulDetail](https://support.huaweicloud.com/intl/en-us/api-hss2.0/ShowCmsVulDetail.html); [VulDB_Spider](https://repos.ecosyste.ms/hosts/GitHub/repositories/hi-KK%2FVulDB_Spider)
- OSCS publishes weekly reports and poisoning (投毒) intel; no public API docs were found — [OSCS](https://zhi.oscs1024.com/tag/%e6%bc%8f%e6%b4%9e/page/11) (via search summary)
- **网络产品安全漏洞管理规定** (MIIT, CAC and MPS, 工信部联网安〔2021〕66号; effective 2021-09-01) — [CAC](https://www.cac.gov.cn/2021-07/13/c%5F1627761607640342.htm):
  - **Art. 7**: network product providers must report vuln info to the **MIIT 网络安全威胁和漏洞信息共享平台** (Cybersecurity Threat and Vulnerability Information Sharing Platform, NVDB) **within 2 days**, covering product, version, technical characteristics, harm and scope. They must also notify upstream component providers.
  - **Art. 9** (publishing rules), as quoted in multiple reposts: no publishing before the provider releases fixes, and no exaggeration. Item (7): "不得将未公开的网络产品安全漏洞信息向网络产品提供者之外的境外组织或者个人提供" (undisclosed vuln info must not be given to overseas organizations or individuals other than the product provider).
  - **Art. 4**: no illegal collection, sale or publication of vuln info.
  - Sources: [secrss](https://www.secrss.com/articles/48440); [Jiemian](https://m.jiemian.com/article/6352810.html); [China Law Translate](https://www.chinalawtranslate.com/?p=16895) (via search summary)
- **网络产品安全漏洞收集平台备案管理办法** (Filing Measures for Vulnerability Collection Platforms, 工信部网安〔2022〕146号, effective 2023-01-01). The first approved batch, published in 2026, includes NVDB, 补天 (Butian), 漏洞盒子 (Vulbox) and 360漏洞云. On **2026-11-10** NVDB and the platforms signed a 《网络产品安全漏洞收集平台自律公约》 (Self-Discipline Pact for vulnerability collection platforms). NVDB also named 2026 "专业库" (specialized sub-database) support units, including an AI-products sub-database — [news.qq (360 入选首批备案)](https://news.qq.com/rain/a/20260521A096J400); [secrss](https://www.secrss.com/articles/95532) (via search summary)
- **Enforcement**: during "护网-2025" (HW-2025, the national attack-defense exercise), police penalized a vuln collection platform under the Cybersecurity Law for publishing vuln details before the vendor fix — [Jiemian/secrss](https://www.secrss.com/articles/84750) (via search summary)
- 360's AI-found vulns are reported as routed through CNNVD, CNVD and the "national vuln DB" before or alongside vendor fixes (e.g., CVE-2026-24293) — [China Daily CN](https://cn.chinadaily.com.cn/a/202604/17/WS69e1f066a310942cc49a8243.html)

### Inferences
- For an AI system operating in China, or on Chinese products, that auto-files or auto-publishes findings:
  - auto-publication before the vendor patches is prohibited;
  - sending undisclosed findings to foreign entities, including a foreign-hosted LLM API or a foreign coordinator, is plausibly restricted under Art. 9(7);
  - product vendors have a 2-day clock to NVDB.
- In practice this forces in-country models and data residency (consistent with ThreatBook's "data never leaves" pitch) and pushes disclosure through CNVD, CNNVD, NVDB or filed platforms.
- A builder outside China should not depend on CNVD or CNNVD as machine-readable sources. AVD, OSCS and vendor TI feeds via watchvuln-style scrapers are the practical route.

### Gaps
- I could not confirm whether CNNVD, CNVD or NVDB currently offer any registered-member API or data-export program.
- I could not verify whether Art. 9(7) has been interpreted to cover cloud LLM API calls.
- The full text of the November 2026 自律公约 was not read.

---

## 5. Community discussion (知乎, FreeBuf, 先知, 看雪, 安全客, CSDN, WeChat official accounts)

### Takeaway
Chinese community sentiment in 2025–26 holds that AI vuln *discovery* has become real and commoditized. The "Mythos moment" of April 2026 triggered a domestic race ("中国版 Mythos", a Chinese Mythos), with 360, Tencent and Sangfor responding. The consensus bottleneck is verification, prioritization and safe patching, and practitioners are wary of hallucinated or incomplete patches. Practical write-ups center on LLM-assisted triage and on pushing remediation in 甲方 (enterprise/in-house security) operations, not on fully autonomous patching.

### Cited Findings
- Media framed 360's push as "当漏洞正被AI重新定价 360想打造中国版Mythos" (as AI reprices vulnerabilities, 360 wants to build a Chinese Mythos) — [wallstreetcn](https://wallstreetcn.com/articles/3775415)
- 36Kr: "别怪 Anthropic 不开放新模型 Mythos，它实在太危险了" (don't blame Anthropic for not opening up Mythos; it really is too dangerous) — [36Kr](https://www.36kr.com/p/3759023216476928)
- A 安全牛 (aqniu) piece argued AI bug-finding is not new; what is new is that the whole industry is now taking it seriously — [secrss](https://www.secrss.com/articles/89320) (via search summary)
- Taiwanese vendors' views:
  - DEVCORE (戴夫寇尔): Opus 4.6 has already lowered the bar for finding and exploiting vulnerabilities.
  - CyCraft (奧義智慧): AI patching is already showing results.
  - Source: [iThome TW](https://www.ithome.com.tw/news/175398) (via search summary)
- Prof. Li Qi (李祺, BUPT 北京邮电大学) argues LLMs restructure all three stages — discovery, verification, repair. He warns that security models risk turning "漏洞分析工具" (vuln-analysis tools) into "漏洞生成助手" (vuln-generation assistants) — [secrss](https://www.secrss.com/articles/94082) (via search summary)
- A Tencent Cloud developer-community practice article covers using LLMs to speed up vuln review and to push remediation in enterprise security operations (黑白灰运营, black/white/grey operations) — [Tencent Cloud Dev](https://cloud.tencent.com/developer/article/2522228)
- Chinese coverage of foreign agents (OpenAI Aardvark, Google CodeMender) describes the pipeline: threat modeling → discovery → sandbox validation → fix → human review → PR — [secrss](https://www.secrss.com/articles/84521); [36Kr](https://36kr.com/p/3532537301458049); [qbitai](https://www.qbitai.com/2025/10/347735.html)
- Tophant's CEO pitched "让漏洞修复以机器速度进行" (machine-speed remediation) — [gm7](https://www.gm7.org/archives/161285)
- Cautionary data widely recirculated: 1Password found generative AI more likely to produce exploitable or incomplete patches on complex CVEs; the overall fully-fixed rate was 47% — [CyberScoop](https://cyberscoop.com/ai-code-patching-security-risks)
- GitHub activity reflects the community mood. The most-starred Chinese AI security repos of 2025–26 are offensive and audit agents: DeepAudit 7.3k, AI-Infra-Guard 7.5k, AboutSecurity 1.9k. A popular config pack, "海鸥 2.0" (haiou-666, ★991), is promoted as making Claude Code act as a Chinese security researcher who "直接给代码不给免责声明" (gives code directly, without disclaimers) — [GitHub haiou-666](https://github.com/haiou-666/haiou2.0-Claude-Code-)

### Inferences
- The community appetite is for offense, audit and PoC automation. Auto-patching is discussed mainly as a vendor vision (Tophant, 360 仪天阵) and as an unsolved problem, which creates an opening for verifiable, test-gated repair tools.
- Concern about dual use ("漏洞生成助手") and the regulatory disclosure rules shape how Chinese vendors present AI vuln work: they stress reporting to CNNVD and CNVD and regulator confirmation (监管确认).

### Gaps
- I could not access 知乎 (Zhihu), FreeBuf, 先知 (xz.aliyun.com), 看雪 (Kanxue) or 安全客 (Anquanke) directly, and search did not surface specific threads on AI auto-patching. The sentiment above therefore comes from secondary media (secrss, 36Kr, qbitai, iThome) rather than forum posts.
- No WeChat official-account (公众号) articles were retrievable.
