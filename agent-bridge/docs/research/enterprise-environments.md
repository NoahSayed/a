# agent-bridge in corporate and regulated environments

Research date: 2026-11-19. Scope: what agent-bridge must do to be usable and approvable inside corporate networks and
externally regulated firms (banks, brokers, payment companies, fintech).

**How to read the confidence markers.** "Verified" means I read the vendor page itself. "Snippet" means the claim came from
a search-result summary of an official page that I could not open in full (learn.microsoft.com was not reachable for
direct fetch from this environment). "Unconfirmed" means I could not find a source and the text is my inference.
Vendor-blog and law-firm sources are labelled as such. Nothing here is legal advice; compliance teams decide what counts as
a record.

## Executive summary

1. **Egress is the first blocker.** agent-bridge uses Node's global `fetch` with no proxy code. It only works behind a corporate
   proxy on Node 22.21+/24.5+ with `NODE_USE_ENV_PROXY=1`, but `package.json` says Node >= 22.13. PAC files, NTLM and Kerberos
   proxies are not supported by Node's built-in proxy support (no source says they are; Claude Code's own docs point NTLM/Kerberos
   users to an LLM gateway).
2. **TLS interception is mostly a documentation problem.** Node honours `NODE_EXTRA_CA_CERTS` and, from 22.19/24.6,
   `NODE_USE_SYSTEM_CA=1`. The bridge needs to document these, pass them through `.mcp.json`, and report TLS failures clearly.
3. **Admins approve MCP servers by exact command line.** Claude Code's `allowedMcpServers` matches `serverCommand` as the exact
   command plus arguments; `env` is not compared. A fixed, argument-free launch command with all config in `env` is therefore
   approvable, and `managed-mcp.json` makes a project-level `.mcp.json` (what `init` writes) irrelevant.
4. **`init --hook` will not work under a locked-down policy.** `allowManagedHooksOnly` blocks user and project hooks. The bridge
   must work with no hook (`wait_for_message`, `/loop`) and ideally ship a managed-hook snippet admins can deploy.
5. **Slack is approvable but a poor fit for regulated records.** It needs one admin-approved app per agent, and records capture
   depends on the firm's existing Slack archiving/Discovery setup. Teams and Symphony are where banks live, but bot-to-bot message
   delivery is unconfirmed on both, and Teams bots normally need an inbound HTTPS endpoint.
6. **A self-hosted relay is the strongest answer for regulated firms.** Data stays on-prem, there is one audit surface, and no
   third-party (DORA) ICT provider is added. It must then meet the table in section 5.
7. **Record-keeping rules are real but their application to agent chatter is a compliance decision.** SEC 17a-4, FINRA 4511/3110
   and MiFID II Art. 16(7) cover business communications; agent messages that only coordinate code may fall outside, messages
   containing client, order or trading content may not. Ship the capability (export, retention, hold), not a position.
8. **Chat is not a place for card data or secrets.** PCI DSS 4.2.2 requires strong cryptography if PAN goes over messaging, and 3.3
   forbids storing sensitive authentication data after authorization. Server-side DLP (card numbers via Luhn, IBANs, key patterns)
   is the feature most likely to turn a "no" into a "yes".
9. **Today's design already has good bones**: per-agent tokens stored hashed, sender identity derived server-side, 0600 token
   files, no telemetry, two runtime dependencies, `redirect: "error"`. Missing: proxy/CA support, audit export, DLP, retention
   holds, Windows support, signed/pinned releases.
10. **Windows laptops and internal npm mirrors are routine.** The hook is POSIX-shell only and `chmod 0600` is meaningless on
    NTFS; install must work from an Artifactory/Nexus mirror with a lockfile and no postinstall scripts.

---

## 1. Corporate networks

### 1.1 What the environment looks like
Typical: all egress through an authenticated HTTP(S) proxy (often selected by a PAC file), TLS inspection with a corporate root
CA, no inbound connections to laptops, outbound allowlisted by domain, npm via an internal mirror, no local admin rights.
Claude Code itself documents the same shape: `HTTPS_PROXY`/`NO_PROXY`, basic auth in the proxy URL, no SOCKS, a custom CA via
`NODE_EXTRA_CA_CERTS`, and a recommendation to use an LLM gateway for NTLM/Kerberos proxies
([Claude Code network config](https://code.claude.com/docs/en/network-config.md), verified). It also lists the hosts an admin must
allowlist, which is the precedent for agent-bridge publishing its own host list (Slack: `slack.com`; Supabase: the project host).

### 1.2 What Node needs (verified against the Node docs)
| Need | Mechanism | Versions |
|---|---|---|
| Proxy for built-in `fetch`/`http(s)` | `NODE_USE_ENV_PROXY=1` or `--use-env-proxy`; reads `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (lowercase wins) | Added v24.5.0 and v22.21.0 |
| Programmatic equivalent | `http.setGlobalProxyFromEnv()` (covers `fetch` and `http.request`) | same line of releases |
| Proxy auth | `http://user:pass@host:port` in the URL; `https://` proxies allowed | same |
| No-proxy lists | `*`, host, `.suffix`, `*.suffix`, IP, IP range, `host:port` | same |
| Extra trusted CA | `NODE_EXTRA_CA_CERTS=file` (PEM, read once at process start; ignored if `ca` option is passed) | v7.3.0 |
| OS trust store | `--use-system-ca` or `NODE_USE_SYSTEM_CA=1` | flag v23.8.0 (non-Win/mac support v23.9.0); env var v24.6.0 and v22.19.0 |
| OpenSSL store | `--use-openssl-ca`, `SSL_CERT_FILE`/`SSL_CERT_DIR` | v6.11.0 |

Sources: [Node CLI docs](https://nodejs.org/api/cli.html), [Node http docs, Built-in Proxy Support](https://nodejs.org/api/http.html#built-in-proxy-support),
[v22.21.0 release notes](https://nodejs.org/blog/release/v22.21.0) (snippet: lists `--use-env-proxy` and "http proxy for fetch under NODE_USE_ENV_PROXY").
Node marks the feature "1.1 Active development".

Implications:
- **Not supported by the built-in feature (unconfirmed absence, not stated by Node):** PAC files, NTLM, Kerberos/Negotiate, SOCKS.
  Node's docs describe only static proxy URLs. A PAC-only shop needs a local forwarder (e.g. CNTLM/px-style) or an allowlisted
  direct route to the relay.
- **Env vars must reach the MCP child process.** Claude Code applies its own proxy variables to itself; whether it forwards them to
  stdio MCP children is not something I confirmed. `init` should write `NODE_USE_ENV_PROXY`, `HTTPS_PROXY`, `NO_PROXY`,
  `NODE_EXTRA_CA_CERTS` into the `.mcp.json` `env` block when they are set.
- **Do not suggest disabling verification.** `NODE_TLS_REJECT_UNAUTHORIZED=0`/`strict-ssl=false` is the usual forum "fix"
  ([guide](https://linuxize.com/post/fix-npm-unable-to-get-local-issuer-certificate/), blog) and will fail any security review.
- A third-party undici `ProxyAgent` can be passed as `dispatcher`, but one report says a version different from Node's bundled
  undici broke built-in `fetch` (search snippet, unverified). Prefer Node's own mechanism and a minimum-version check.
- Claude Code reads the OS cert store only on Node 22.15+ or the native installer
  ([network config](https://code.claude.com/docs/en/network-config.md)); the bridge process is a separate Node process, so it needs its own setting.

### 1.3 npm mirrors, no admin rights, Windows
- npm honours `registry`, scoped `@scope:registry`, `cafile`, `proxy`/`https-proxy`, `noproxy` in `.npmrc`
  ([npm-config guide, blog/secondary](https://linuxize.com/post/fix-npm-unable-to-get-local-issuer-certificate/)). Lockfile `resolved`
  URLs that point at `registry.npmjs.org` can break `npm ci` against a mirror (unconfirmed; verify against npm docs).
- Claude Code docs list `registry.npmjs.org` as needed for `npx`-launched MCP servers unless mirrored
  ([network config](https://code.claude.com/docs/en/network-config.md)). A bridge that runs `npx -y agent-bridge` makes admins
  allowlist a floating install; a pre-installed, pinned path is easier to approve (see section 4).
- Without admin rights: no global installs, no writing to `/etc` or `C:\Program Files`. The bridge must run from a user-writable
  directory and keep state under `~/.agent-bridge` (it does).
- Windows: README says the hook is written for macOS/Linux shells; `cli.js` uses POSIX single-quoting for the hook command and
  `chmod 0600` for tokens, which does not restrict access on NTFS. `AGENT_NAME=human node cli.js send` in the README is bash
  syntax. Not met today.

---

## 2. Approved chat/collaboration platforms

Summary first, detail below. "Bot-to-bot" = agent A reading what agent B posted in the same channel.

### 2.1 Slack (Enterprise Grid)
- **Approval:** Grid org owners can require that every app is approved by an owner/app manager
  ([Slack updates](https://slack.com/help/articles/115004846068-Slack-updates-and-changes), snippet). agent-bridge's Slack mode needs
  **one app per agent**, so N approvals; an admin will ask why. A shared single-app design with a per-agent signing identity would
  reduce approvals but lose "Slack vouches for the sender".
- **Compliance surface:** Discovery APIs for eDiscovery/archiving/DLP by approved third-party apps, legal holds, DLP connectors that
  can quarantine content ([Discovery APIs](https://slack.com/help/articles/360002079527-A-guide-to-Slacks-Discovery-APIs),
  [legal holds](https://slack.com/help/articles/4401830811795-Create-and-manage-legal-holds), snippets). Bot posts are ordinary
  messages, so the firm's existing Slack archiver should capture them (unconfirmed for bot-authored messages; ask the Slack admin).
- **Keys and residency:** EKM is an Enterprise Grid add-on, customer keys in AWS KMS, revocable at several granularities; some
  metadata stays under Slack-held keys ([EKM](https://slack.zendesk.com/hc/en-us/articles/360019110974-Slack-Enterprise-Key-Management)).
  Data residency picks the at-rest region; usage/account data is still processed in the US ([data management](https://slack.com/trust/data-management)).
- **Rate limits:** Slack cut `conversations.history` to 1 req/min and 15 messages for commercially distributed non-Marketplace
  apps; internal customer-built apps are exempt ([Slack changelog](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps)).
  The README's claim matches this. Risk: a firm may register the apps differently.
- **Transport:** outbound HTTPS to `slack.com`; no inbound. Good for corporate networks.

### 2.2 Microsoft Teams (most common in banks)
- **Receiving without @mention:** a bot that declares RSC permission `ChannelMessage.Read.Group` can receive all channel messages
  in teams where it is installed; team owners consent at install; supported in GCC/GCC-High/DoD
  ([MS Learn: all channel messages with RSC](https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/conversations/channel-messages-with-rsc), snippet).
  Reports say shared and private channels behave differently (community posts, unverified).
- **Bot-to-bot:** I found no source saying a Teams bot is delivered another bot's channel messages. Treat as **unconfirmed, likely
  not supported**. The documented pattern is bot receives user messages.
- **Graph polling alternative:** reading channel messages via Graph with app-only `ChannelMessage.Read.All` needs tenant-admin
  consent and approval via the Teams *protected APIs* request form; RSC `ChannelMessage.Read.Group` avoids the form for specific
  teams (Microsoft Q&A, snippets: [Q&A](https://learn.microsoft.com/en-us/answers/questions/524535/issue-with-running-get-command-within-graph-explor),
  [Graph protected APIs page, cited but not opened](https://learn.microsoft.com/en-us/graph/teams-protected-apis)). Developers report weeks-long approvals (anecdotal).
- **Inbound requirement:** Bot Framework/Teams bots receive activities by Microsoft POSTing to the bot's HTTPS messaging endpoint
  (general knowledge, not sourced here). That breaks "no inbound connections" for laptop-based agents; Graph polling does not.
- **Incoming webhooks:** Office 365 connectors were retired (final switch-off window May 2026 per Microsoft's dev blog) in favour of
  Workflows; webhook posts cannot customise bot name/icon ([MS dev blog](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/), snippet). Post-only, so it cannot carry replies.
- **Auth:** Entra ID app registration (client secret or certificate) plus Bot Framework registration; admin must allow custom apps.
- **Verdict:** feasible only with substantial Entra/Teams admin work; not a quick backend. Defer.

### 2.3 Symphony
- Bots authenticate as **service accounts** with RSA key pairs (JWT signed with the private key); only a pod admin can create the
  account and upload the public key; keys can be replaced/revoked in the Admin Portal
  ([RSA auth](https://docs.developers.symphony.com/bots/authentication/rsa-authentication),
  [creating a bot user](https://docs.developers.symphony.com/bots/getting-started/creating-a-bot-user), snippets).
- **Topology:** for enterprise customers the Agent and Key Manager run on-premise, the Pod is cloud, and the bot must be on-prem
  too ([REST architecture](https://docs.developers.symphony.com/bots/overview-of-rest-api/rest-api-architecture), snippet). A
  laptop-resident agent would need a route to the on-prem Agent. Key Manager tokens last up to two weeks.
- **Bot-to-bot:** not found in any source; unconfirmed. The BDKs ([Java BDK](https://symphony-bdk-java.finos.org/authentication.html)) are
  the integration route.
- **Verdict:** good fit for banks that already archive Symphony, but needs a pod admin and a per-firm integration; defer.

### 2.4 Mattermost, Rocket.Chat, Matrix (self-hosted)
- **Mattermost:** bot accounts authenticate with personal access tokens; only System Admins/plugins create bots; tokens do not
  expire by default but can be cycled via the REST API ([bot accounts](https://docs.mattermost.com/developers/integrate/reference/bot-accounts), snippet).
  Websocket (`/api/v4/websocket`) delivers posts only for channels the bot belongs to (community driver docs). Bot-to-bot
  visibility: unconfirmed but plausible (ordinary posts). Pure outbound HTTPS to an internal host; good air-gapped fit.
- **Rocket.Chat:** dedicated integration user or personal access token (long-lived until regenerated/removed); creating tokens
  needs the `create-personal-access-tokens` permission and 2FA on the generate endpoint
  ([Rocket.Chat auth docs](https://developer.rocket.chat/apidocs/introduction-to-authentication), snippet). Bot-to-bot unconfirmed.
- **Matrix/Synapse:** access tokens or appservice registration; encryption for bots is the sore point. Appservice/sync-less
  encryption needs experimental MSCs and "encrypted appservices do not work yet" per some notes
  ([Hookshot encryption docs](https://matrix-org.github.io/matrix-hookshot/latest/advanced/encryption.html), snippet). Use
  unencrypted rooms (server-side archive) or accept that E2EE and server-side audit conflict.
- **Common caveat:** each adds an adapter to maintain, and in an air-gapped shop the relay is simpler than operating a chat server
  just for agents.

### 2.5 Platform feasibility table
| Platform | Agents can talk? | Identity model | Admin approval needed | Notes |
|---|---|---|---|---|
| Slack (Grid) | Yes, implemented (bots read channel history) | One bot app per agent; Slack vouches for sender | App approval per agent; private channel; scopes | Outbound only; relies on firm's Slack archiver; non-Marketplace rate limits exempt for internal apps |
| Teams | Unconfirmed bot-to-bot; Graph polling possible | Entra app / Bot Framework identity | Custom-app policy, RSC consent or tenant consent + protected-API form | Bot Framework needs inbound endpoint; webhooks are post-only; high effort |
| Symphony | Unconfirmed bot-to-bot | Service account + RSA key | Pod admin creates account/keys | On-prem Agent/Key Manager; bot must reach it |
| Mattermost | Likely (REST + websocket) | Bot account + PAT | System admin creates bot; add to channel | Fully self-hosted; good air-gapped fit |
| Matrix | Yes in unencrypted rooms | Access token / appservice | Server admin | E2EE for bots immature |
| Self-hosted relay | Yes (designed for it) | Per-agent token (+ optional mTLS) | Internal security review of the relay; no vendor approval | Full control of audit, retention, DLP, residency |

---

## 3. Regulatory and compliance controls

### 3.1 Do they apply to agent-to-agent messages?
My assessment (judgement, not a legal opinion): the rules attach to **business communications of a regulated entity**, not to the
medium. Messages between coding agents that discuss a build, an API shape or a migration are plausibly internal engineering
traffic. They become in scope when they carry or relate to client orders, trading, advice, or customer data, or when a firm's
policy defines "all employee-directed tooling traffic" as retained. Because agents act for a named employee and humans can post
into the channel (Slack mode), a firm's compliance team will probably default to "retain it" rather than carve out an exception.
The practical consequence is that the bridge should make retention possible and cheap, not decide scope.

| Regime | What it says (sourced) | Plausibly applies to agent messages? | Features that help |
|---|---|---|---|
| SEC Rule 17a-4 (US broker-dealers) | Electronic records must be kept in WORM format or with a complete time-stamped audit trail; the 2022 amendments added the audit-trail option and let a firm designate a third party or an executive officer for undertakings ([Davis Polk](https://www.davispolk.com/insights/client-update/crawling-modernity-sec-amends-worm-recordkeeping-requirements-broker-dealers), law-firm summary) | If content is a business communication | Append-only log with timestamps, export, no silent edit/delete |
| SEC off-channel enforcement | About 95 actions and $2.3bn in penalties from FY2022 for unpreserved off-channel communications ([Hunton via iplum](https://www.iplum.com/blog/sec-enforcement), secondary); the SEC has since deprioritised stand-alone cases, but the rules are unchanged ([MirrorWeb](https://www.mirrorweb.com/blog/off-channel-enforcement-the-rules-remain-the-same), vendor); FINRA is still active ([Advisor Perspectives](https://www.advisorperspectives.com/articles/2026/05/13/finra-took-secs-baton-channel-penalties)) | An unsanctioned agent channel carrying business content is the exact pattern | Run on an approved, archived channel (Slack with archiver, or the relay with export); do not add a side channel |
| FINRA 4511 / 3110 | 4511 requires records in a 17a-4-consistent format, default six years where no period is specified; 3110.09 covers retention of correspondence and internal communications; FINRA lists failure to retain/review non-email electronic communications on approved channels as a finding ([FINRA 2026 report, books and records](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/books-and-records)). One vendor says three years; sources conflict, check per record type | Same test | Retention config, supervisory read access (read-only reviewer role) |
| MiFID II Art. 16(7) (EU/UK) | Records of communications relating to client orders/transactions kept five years, up to seven if the regulator asks ([ESMA Q&A](https://www.esma.europa.eu/node/204124), [FCA SYSC 10A](https://handbook.fca.org.uk/handbook/SYSC/10A/1.html)) | Only if related to those activities | Retention >= 5 y configurable, extendable by hold |
| PCI DSS v4.0.1 | PAN sent over end-user messaging (chat, email, IM) must be protected with strong cryptography (4.2.2); sensitive authentication data must not be stored after authorization (3.3) ([Secureframe summary](https://secureframe.com/blog/pci-dss-4.0.1), vendor; check PCI SSC text) | Yes if an agent pastes test or production card data, logs or DB dumps | Server-side detection (Luhn PANs, CVV patterns), block or redact; TLS in transit; encryption at rest |
| GDPR | Chat content and conversation logs are personal data; processor contract (Art. 28), storage limitation (log deletion schedule), Chapter V for transfers outside the EU ([Art. 28 text](https://gdpr-text.com/hu/read/article-28/), [summary, vendor](https://www.legiscope.com/blog/article-28-gdpr.html)). I did not find a source on Schrems II / DPF status; not covered here | Yes, bodies can contain names, emails, IDs | Self-host or EU-region; retention/purge; delete-agent; data minimisation |
| EU DORA | Applies since 17 Jan 2025; register of information for ICT third-party arrangements (Art. 28), mandatory contract terms (Art. 30), exit strategy for critical/important functions ([AFM](https://www.afm.nl/en/sector/themas/europese-wet--en-regelgeving/dora/derde-aanbieders), regulator; others are vendor blogs) | Using Supabase or Slack makes each an ICT third party for the firm | A self-hosted relay adds no new third party; if SaaS backends are used, document data flows so the firm can fill its register; exit = export + switch backend |
| SOC 2 (customer ask) | Criteria are principle-based; auditors expect individual attribution in logs, periodic access reviews, a defined key-rotation schedule with evidence; no AICPA-mandated interval ([practitioner blogs](https://goteleport.com/blog/soc2-non-human-identities/)) | A bank will ask the same of a vendor or internal tool | Per-agent identity, admin audit log, token rotation/expiry, list-who-has-access command |

### 3.2 Features this implies
- **Immutable, exportable audit log** (who/what/when, hash-chained or append-only, export to JSONL/CSV to a firm's archive).
- **Retention policy and legal hold** (configurable minimum, purge refuses to delete held data).
- **DLP on send**: reject or redact PANs (Luhn-valid 13-19 digits), CVV-looking fields next to PAN, IBANs (mod-97), private keys,
  `xoxb-`/`sb_secret_`/AWS key patterns; log the block event without the content.
- **Data location control**: on-prem relay, or EU-region SaaS, and no hidden third-party calls.
- **Read-only reviewer role** for supervision/compliance, separate from agent tokens and admin.
- Complementary evidence on the Claude side: Claude Code can emit OpenTelemetry events that record MCP server and tool names when
  `OTEL_LOG_TOOL_DETAILS=1` ([managed-mcp docs](https://code.claude.com/docs/en/managed-mcp.md)); that gives the firm a second record of what the agent sent.

---

## 4. Claude Code enterprise controls and what an admin needs from an MCP server

### 4.1 Controls (verified in [managed-mcp](https://code.claude.com/docs/en/managed-mcp.md), [settings](https://code.claude.com/docs/en/settings.md), [network config](https://code.claude.com/docs/en/network-config.md))
- **Managed settings** (system `managed-settings.json`, MDM/registry, or server-managed from the admin console) are the top of the
  precedence stack; user, project and `--settings` cannot override them.
- **MCP control patterns:** `managed-mcp.json` gives exclusive control (users cannot add or use other servers; `--mcp-config` makes
  Claude Code exit); `managedMcpServers` pushes HTTPS-only remote servers (no `command`, no `${VAR}`); `allowedMcpServers` +
  `allowManagedMcpServersOnly` is an approved catalogue. Paths: `/etc/claude-code/managed-mcp.json`,
  `/Library/Application Support/ClaudeCode/managed-mcp.json`, `C:\Program Files\ClaudeCode\managed-mcp.json`.
- **Matching:** `serverCommand` = exact command and arguments, in order; the `env` block is **not** compared. `serverUrl` supports
  wildcards. `serverName` is explicitly "not a security control". Managed-mcp.json entries need no allowlist entry unless they use
  `${VAR}` expansion outside `env`. Don't put credentials in a managed file (readable by all users); use per-user env expansion or `headersHelper`.
- **Hooks:** `allowManagedHooksOnly` loads only managed, SDK and force-enabled plugin hooks and blocks user/project hooks
  ([settings reference, via search snippet](https://code.claude.com/docs/en/settings-reference)).
- **Sandbox network:** `sandbox.network.allowedDomains`/`deniedDomains`, `allowManagedDomainsOnly` (same source, snippet). I could not
  confirm whether the sandbox constrains stdio MCP server processes; assume MCP servers run outside it and need their own egress controls.
- **Third-party model providers:** with Amazon Bedrock, Google's Agent Platform (Vertex) or Microsoft Foundry, model traffic goes to
  the provider, not `api.anthropic.com`; the Datadog telemetry hosts are never contacted in those modes; `DISABLE_TELEMETRY` and
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` exist for the direct API ([network config](https://code.claude.com/docs/en/network-config.md)).
  Regulated firms commonly choose these routes; agent-bridge must not assume `api.anthropic.com` reachability.
- **Monitoring:** OTel export lists which MCP servers/tools are used ([managed-mcp](https://code.claude.com/docs/en/managed-mcp.md)).

### 4.2 What this means for agent-bridge (admin approval checklist)
| Admin expectation | Implication |
|---|---|
| Fixed, reviewable launch command | Ship one entry point, e.g. `node /opt/agent-bridge/server.js`, **no per-agent arguments**; per-agent identity via `env` (`AGENT_NAME`, token file path) which the allowlist ignores. Provide a `managed-mcp.json` template and a `managed-config` CLI command that emits it |
| `.mcp.json` from `init` is irrelevant under lockdown | Under `managed-mcp.json`, project `.mcp.json` servers do not load; document the admin path as primary |
| No auto-update, pinned version | Release tarball with checksum or npm provenance, exact version in the lockfile, `engines` check, no self-update code (none exists today) |
| No telemetry, no surprise egress | State plainly: outbound calls are only to the configured backend. A test that fails if any other host is contacted gives reviewers evidence |
| Source review is feasible | ~1,700 lines of JS, two runtime dependencies (`@modelcontextprotocol/sdk`, `zod`), lockfile present. Keep that; publish an SBOM |
| Secrets not in config | Token files (0600 on POSIX, ACL on Windows) referenced by path; never in `.mcp.json`. Already true |
| Works without hooks | Under `allowManagedHooksOnly` the `init --hook` file is ignored; rely on `wait_for_message`, `/loop`, or ship the hook as a managed hook snippet |

---

## 5. Air-gapped and no-SaaS environments: what a self-hosted relay must offer
Evidence base here is mostly the above sources plus general practice; there is no single regulator checklist. Items are my
recommendations; where a standard backs one, it is linked.

- **Transport:** TLS 1.2+ with operator-supplied certificate and key (PEM), reloadable without downtime; optional **mTLS** for agent
  clients (Claude Code itself supports client certs, so firms already run this pattern:
  [network config](https://code.claude.com/docs/en/network-config.md)). Plain HTTP only on loopback, and refused by default for non-loopback.
- **Runtime:** runs as non-root, read-only root filesystem, a single data volume, listens on a configurable port, no outbound calls
  at all (no update checks, no telemetry, no DNS lookups beyond its own bind). Offline-installable: container image with pinned digest,
  plus a plain `node` tarball for hosts with no container runtime.
- **Operations:** `/healthz` and `/readyz` endpoints, structured JSON logs to stdout, graceful shutdown, documented backup/restore
  (consistent SQLite or Postgres snapshot) and a schema-migration path that never runs implicitly.
- **Identity and admin separation:** per-agent tokens, stored hashed, with expiry, rotation, revocation and last-used time; a
  **separate admin credential** that cannot send as an agent and a **read-only auditor credential**; admin actions written to the audit log.
  agent-bridge's Supabase mode already splits the publishable key + agent token from the secret key; the relay should copy that.
- **Audit and retention:** append-only log, export, retention + legal hold, size and rate limits (the existing per-sender limits).
- **DLP:** inline scan on `send_message`, configurable action (block/redact/allow-and-flag), with the rule set auditable.
- **Network posture:** documented ports and flows; supports sitting behind a reverse proxy/load balancer; honours `X-Forwarded-*` only from configured proxies.
- **Time:** server-side timestamps only (agents' clocks are untrusted); NTP dependency documented.
- **Supply chain:** reproducible-ish build, signed artifacts, vulnerability policy; Node 22 LTS (22.x is in maintenance, plan for Node 24 -- check the Node release schedule).
- **Multi-tenancy:** separate "bridges" (namespaces) so two business lines (e.g. a desk and a payments team) cannot see each other's agents.

---

## 6. Prioritised requirements for agent-bridge

"Today" is judged from `README.md`, `stores/*.js`, `server.js` and `cli.js` in `/home/user/a/agent-bridge`.

| # | Requirement | Why (environment / regulation) | Priority | Meets today? |
|---|---|---|---|---|
| 1 | Honour `HTTPS_PROXY`/`NO_PROXY` (incl. proxy auth); fail fast with a clear error if unsupported; raise/enforce Node floor (22.21+) or document `NODE_USE_ENV_PROXY=1` | Corporate egress proxies | Must | **No.** Global `fetch` only (`stores/supabase.js:34`, `stores/slack.js:66`); no env-proxy handling; `engines` says >=22.13, which predates 22.21 |
| 2 | Work behind TLS interception: document `NODE_EXTRA_CA_CERTS` / `NODE_USE_SYSTEM_CA=1`, pass them through `init`, and print the TLS error cause; never suggest disabling verification | Corporate root CA | Must | **Partly.** Node honours the variables natively; nothing in code/README mentions them. Errors surface `e.cause.code`, which helps |
| 3 | Self-hosted relay with TLS (custom cert), mTLS option, non-root container, health checks, no outbound calls | Air-gapped, banks, DORA | Must | **Not yet** (relay in progress) |
| 4 | Append-only audit log with export (JSONL/CSV), attributable to agent and timestamped by the server | SEC 17a-4, FINRA 4511/3110, MiFID II, SOC 2 | Must (regulated) | **Partly.** Supabase/SQLite keep messages and `cli.js log`/`tail` print them; no export format, no tamper evidence, `delete-agent` and `purge` delete rows, local SQLite has no auth boundary |
| 5 | Retention policy with legal hold; purge refuses held data; configurable minimum retention | FINRA 4511 (6 y default), MiFID II (5-7 y), GDPR storage limitation | Must (regulated) | **Partly.** `cli.js purge N` exists for Supabase; no hold, no minimum retention, nothing for Slack (history lives in Slack's own retention) |
| 6 | Server-side DLP on send: block/redact PAN (Luhn), IBAN, private keys, known token formats; audit the block | PCI DSS 3.3/4.2.2, GDPR minimisation, secret hygiene | Must (PCI/bank), else Should | **No.** Only server instructions telling the agent "never send secrets" (`server.js:78`) |
| 7 | Stable, argument-free launch command; config entirely via `env`; `managed-mcp.json` generator + docs for admins | Claude Code allowlist matches exact command/args, ignores env | Must | **Partly.** `server.js` is configured by env; `init` only writes project `.mcp.json` with absolute paths and a hook the managed policy may block |
| 8 | Works with no hook and no `.mcp.json` write access (managed hooks only) | `allowManagedHooksOnly`, `managed-mcp.json` exclusivity | Must | **Partly.** `wait_for_message` and `/loop` work without the hook; README presents the hook as a main option |
| 9 | Per-agent identity, token rotation, revocation, expiry, last-used, separate admin and read-only auditor credentials | SOC 2 CC6, access reviews, key-rotation evidence | Must for relay | **Partly.** Supabase: hashed tokens, rotate/revoke/delete, secret key separate; no expiry, no auditor role; SQLite trusts the `AGENT_NAME` env; Slack delegates to Slack |
| 10 | Pinned, reviewable supply chain: lockfile, 2 runtime deps, signed release/checksum, SBOM, no postinstall, no self-update, no telemetry | Admin MCP approval, DORA third-party review | Must | **Mostly.** Lockfile, 2 deps, no telemetry, no update logic, `redirect: "error"`; not published or signed yet |
| 11 | Installable from an internal mirror and runnable without admin rights; documented offline install | Artifactory/Nexus, locked-down laptops | Should | **Mostly.** No native builds, state under `~`; no documented offline/mirror path |
| 12 | Windows support: hook written for Windows, token file ACLs, README commands | Windows laptops | Should | **No.** Hook is POSIX single-quoted; `chmod 0600` only; README examples are bash |
| 13 | Document data flows and egress hosts per backend (a one-page "network and data sheet") | Firewall allowlisting, DORA register, GDPR transfers | Should | **No** (only scattered statements in README) |
| 14 | Optional message classification/labels and a per-bridge namespace | Chinese-wall separation between desks/teams | Should | **No** |
| 15 | Fail-closed on non-HTTPS backend URLs (except loopback) | TLS requirement, PCI 4.2.2 | Should | **Unknown.** I found no scheme check in `stores/supabase.js`/`slack.js`; not verified exhaustively |
| 16 | Hash-chained log or periodic signed checkpoints | Stronger 17a-4 audit-trail evidence | Could | No |
| 17 | Encryption at rest for local SQLite / relay store (or documented disk encryption) | Bank endpoint standards, GDPR | Could | No (0600 file only) |
| 18 | Mattermost / Rocket.Chat / Matrix adapters | Air-gapped shops that already run one | Could | No |
| 19 | Teams and Symphony adapters | Bank-standard chat | Could (blocked on unconfirmed bot-to-bot and admin effort) | No |
| 20 | PAC-file / NTLM / Kerberos proxy support (or a documented local-forwarder recipe) | Large-bank proxies | Could | No |

---

## 7. Gaps in this research
- learn.microsoft.com could not be fetched directly; Teams statements rest on search-result summaries and community Q&A.
- Bot-to-bot message visibility on Teams, Symphony, Mattermost and Rocket.Chat is **unconfirmed**; test each with a real pair of
  bots before committing to an adapter.
- Whether Claude Code forwards proxy variables to stdio MCP children, and whether its sandbox covers MCP processes, are
  unconfirmed.
- Regulatory sources are mostly law-firm or vendor summaries; check the SEC release, FINRA rules, ESMA Q&A, PCI SSC document and
  EUR-Lex text before quoting in a security questionnaire. I did not research Schrems II / EU-US DPF status, or non-EU/US regimes
  (e.g. MAS, APRA, BaFin BAIT/MaRisk).
- PAC/NTLM/Kerberos limits of Node's proxy support are inferred from the documented feature set, not from an explicit statement.
