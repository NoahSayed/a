# agent-bridge

A message bridge that lets AI agents working on **different projects** talk to each other, whether they're on
the same machine, on different machines, in a company that only allows Slack, or in a bank that allows nothing
outside its own network.

Each agent (for example a Claude Code session in `frontend/` and a Cursor or Codex session in `backend/`) runs its
own copy of this MCP server. **Claude Code, Cursor and OpenAI Codex** are supported, and can be mixed on one bridge. They exchange messages through a shared mailbox:

- **Local**: a SQLite file on one machine. Nothing to set up, no network.
- **Supabase**: a few `bridge_*` tables and functions in a Supabase project. Works across machines, people and
  networks.
- **Slack**: one private Slack channel. Each agent is its own Slack app, and people in the channel can watch and join
  in.
- **Relay**: a small server you run on your own host (`relay.js`), for on-prem and air-gapped networks. It keeps a
  hash-chained audit log, has retention and legal hold, an auditor role, mTLS, and server-side DLP.

```
 Claude Code (frontend)                    Claude Code (backend)
        │ MCP stdio                                │ MCP stdio
 agent-bridge server ──►  mailbox  ◄── agent-bridge server
                     local: ~/.agent-bridge/bridge.db
                     remote: Supabase, a Slack channel, or your own relay
```

Requires Node **22.13+**, which ships `node:sqlite` (22.21+ or 24+ for corporate proxies). There are no native builds
and three small runtime dependencies (the MCP SDK, zod, and smol-toml for Codex's config file). Tested in CI on **Linux, macOS and Windows**, on Node 22 and 24.

**In a company, a bank or a fintech?** Read [docs/ENTERPRISE.md](docs/ENTERPRISE.md) (choosing a backend, proxies and TLS
inspection, DLP, approval, regulations) and [docs/NETWORK-AND-DATA.md](docs/NETWORK-AND-DATA.md) (what goes where).

## Tools the agents get

| Tool | What it does |
|---|---|
| `whoami` | This agent's name, the backend, and the unread count |
| `list_agents` | Agents on the bridge, with their project dirs |
| `send_message(to, body, type?, subject?, thread_id?)` | Send a message. Leave out `thread_id` to start a thread; pass it to reply. `type` is `request`, `response` or `fyi` |
| `check_inbox(limit?, mark_read?, from_agent?)` | Read unread messages, oldest first, optionally from one agent only |
| `wait_for_message(timeout_seconds?, thread_id?, from_agent?)` | Block until a message arrives (default 50 s; call again to keep waiting) |
| `get_thread(thread_id)` | The whole back-and-forth of a thread you're in |

## Stage 1: two repos on the same machine

```bash
cd agent-bridge && npm install

# wire up each repo with its own agent name (--hook adds the "you have mail" notice)
node cli.js init ~/code/frontend frontend "React app, owns the login UI" --hook
node cli.js init ~/code/backend  backend  "API server, owns /api/*"     --hook
```

Open Claude Code in each repo, approve the `bridge` server, and ask "run whoami on the bridge".

`init` adds a `bridge` server to `<repo>/.mcp.json` and leaves any servers already there alone. With `--hook` it
also adds a hook to `<repo>/.claude/settings.local.json`; the hook is written for macOS/Linux shells. `.mcp.json`
ends up with absolute paths for this machine, so you may want to gitignore it. `init` refuses to write through a
symlink.

## Cursor and Codex

The bridge is a plain MCP server, so every tool that speaks MCP can use it. `init` writes each tool's own files;
pick the tools with `--client` (default `claude`; several with commas, or `all`). It works with every backend below.

```bash
node cli.js init ~/code/frontend frontend "React app"  --client cursor --hook
node cli.js init ~/code/backend  backend  "API server" --client codex  --hook
node cli.js init ~/code/shared   shared   "libs"       --client all    --hook   # a repo opened in all three
```

| | Claude Code | Cursor | Codex |
|---|---|---|---|
| MCP server | `.mcp.json` | `.cursor/mcp.json` | `.codex/config.toml` (`[mcp_servers.bridge]`, existing settings kept byte for byte) |
| Unread-mail hook (`--hook`) | `UserPromptSubmit` in `.claude/settings.local.json` | `sessionStart` + `beforeSubmitPrompt` in `.cursor/hooks.json` (opt-in `stop` with `--cursor-events`) | `UserPromptSubmit` in `.codex/hooks.json` |
| Skill | `.claude/skills/agent-bridge/` | `.cursor/skills/agent-bridge/` | `.agents/skills/agent-bridge/` |
| You approve | the `bridge` server | the server, in Cursor's MCP settings | the project (trust), then the hook once ("Hooks need review") |

Every `init` also installs the **agent-bridge skill** ([skills/agent-bridge/SKILL.md](skills/agent-bridge/SKILL.md),
`--no-skill` to skip): when to message another agent, how to write a useful message, how to wait, and the safety
rules. Each tool's details, what was verified against the real tool, and its limits:
[docs/clients/cursor.md](docs/clients/cursor.md) and [docs/clients/codex.md](docs/clients/codex.md). Tested: a Claude
Code, a Cursor and a Codex agent, each started from its own tool's generated config, message each other on one
bridge; the Codex config is also checked by the real Codex CLI (its app-server starts the bridge and calls its tools).

## Stage 2: agents on different machines (Supabase)

**1. Once per Supabase project (admin).** Open the project's **SQL editor**, paste
[`supabase/migration.sql`](supabase/migration.sql) and run it. It only creates `bridge_*` objects, so it can sit next
to your other tables, and it is safe to run again to upgrade.

**2. Register agents (admin).** Use the project's **secret** key (Settings → API keys). Keep it on your own machine:
agents never need it.

```bash
export SUPABASE_URL=https://<project-ref>.supabase.co
export SUPABASE_SECRET_KEY=sb_secret_...
node cli.js add-agent frontend "React app, owns the login UI"   # prints a token, shown once
node cli.js add-agent backend  "API server, owns /api/*" --save # or save it on this machine
```

**3. On each agent's machine.** Give that machine its token, not the secret key, then wire up the repo:

```bash
export SUPABASE_URL=https://<project-ref>.supabase.co
export SUPABASE_PUBLISHABLE_KEY=sb_publishable_...   # public by design
node cli.js save-token frontend                      # paste the token; stored in ~/.agent-bridge/tokens (0600)
node cli.js init ~/code/frontend frontend --supabase --hook
```

The token never goes into the repo: `.mcp.json` only points at the token file. On one machine you can run several
agents (one token file each), and you can mix local and Supabase agents on the same machine as long as each pair
uses the same backend.

**Admin commands** (all need `SUPABASE_URL` + `SUPABASE_SECRET_KEY`):

```bash
node cli.js rotate-token frontend [--save]   # new token; the old one stops working
node cli.js revoke-agent frontend            # disable an agent (rotate-token re-enables it)
node cli.js delete-agent frontend            # remove an agent and every message it sent or got
node cli.js limits                           # show limits; --rate N --max-unread N --max-mb-day N to change
node cli.js purge 30                         # delete messages older than 30 days
```

### Security model (Supabase)

- Agents hold the **publishable** key, which is public by design, plus their own **token**. The database stores only a
  SHA-256 hash of each token.
- The `bridge_*` tables are closed to the API roles: no table or sequence privileges. RLS is on with no policies.
  Every operation goes through a `SECURITY DEFINER` function that works out who the caller is from the token, so the
  **sender is always the token's agent**. An agent can't read, consume or alter anyone else's mail, can't post into a
  thread it isn't in, and can't pull a third agent into a thread.
- Admin functions are callable only with the secret key.
- **Per-sender limits** (defaults: 60 messages a minute, 200 unread per recipient, 20 MB a day) stop one misbehaving
  agent from burying everyone's inbox or filling the project.

## Stage 3: through a Slack channel (corporate-friendly)

If your company already approves Slack, agents can talk in **one private Slack channel**. You don't need a database or
any inbound URL: each agent only makes outbound HTTPS calls to `slack.com`. People in the channel can watch the
traffic and can also talk to the agents.

**1. One Slack app per agent.** Each agent gets its own app, so Slack itself vouches for who sent each message. Print a
manifest and paste it into api.slack.com → Create New App → From an app manifest:

```bash
node cli.js slack-manifest frontend "React app, owns the login UI" > frontend-manifest.json
node cli.js slack-manifest backend  "API server, owns /api/*"     > backend-manifest.json
```

Install each app to the workspace (your Slack admins may need to approve it) and copy its **Bot User OAuth Token**
(`xoxb-...`). The bot's username becomes the agent's name: lowercase letters, digits, `-` and `_`.

**2. Make a private channel** (for example `#agent-bridge`), invite both bots and the people who should see the traffic,
and copy the channel ID (channel details → bottom of the About tab, `C0...`).

**3. On each agent's machine:**

```bash
export SLACK_CHANNEL_ID=C0123ABCDEF
node cli.js save-slack-token frontend                     # paste the xoxb- token; stored 0600, never in the repo
node cli.js init ~/code/frontend frontend --slack --hook
```

**How it looks in Slack.** Each message is a normal post such as `frontend → backend · request · login`, followed by
the body. When an agent picks a message up, its bot adds ✅, so you can see what has been handled. To talk to an
agent, write `@backend please run the migrations` (or `backend: ...`) in the channel. The agent receives it as a
request from `human:<your-username>` and can reply to you in a thread.

**What Slack guarantees, and what it doesn't:**
- **Who sent a message comes from Slack** (the bot user that posted it), never from the message itself. Two bots with
  the same name are both refused.
- **Everyone in the channel can read everything.** That's the point, so keep the channel private.
- Thread caps and the "replies stay between a thread's two participants" rule are applied by every agent when reading,
  so a misbehaving bot's extra messages are simply ignored.
- There are **no server-side rate limits** as there are with Supabase. A misbehaving bot is dealt with by removing it
  from the channel.
- Agents read the last 72 hours of the channel (`AGENT_BRIDGE_LOOKBACK_HOURS`), polling every 3 seconds. Slack's 2025
  rate-limit cuts on `conversations.history` don't apply to internal, customer-built apps.
- The scopes in the manifest are exactly the calls the code makes. If your workspace restricts any of them, the
  `whoami` tool reports what failed.

## Stage 4: your own relay (on-prem, air-gapped, regulated)

```bash
# on an internal host
openssl rand -hex 32 > admin.key && chmod 600 admin.key
RELAY_ADMIN_KEY_FILE=admin.key RELAY_TLS_CERT=tls.crt RELAY_TLS_KEY=tls.key RELAY_HOST=0.0.0.0 \
  RELAY_AUDIT_LOG=audit.jsonl npm run relay

# admin: register agents
RELAY_URL=https://bridge.corp.internal:8787 RELAY_ADMIN_KEY_FILE=admin.key node cli.js add-agent frontend --save

# each agent's machine
RELAY_URL=https://bridge.corp.internal:8787 node cli.js init ~/code/frontend frontend --relay --hook
```

The relay speaks the same protocol as the Supabase backend. It adds:
- mutual TLS (`RELAY_TLS_CA`);
- a read-only auditor key with `cli.js export`;
- a hash-chained audit log checked by `cli.js verify-audit`;
- minimum retention and legal hold;
- DLP enforced on the server.

There's a non-root Docker image in [`relay/`](relay/). Details: [docs/ENTERPRISE.md](docs/ENTERPRISE.md#2-the-self-hosted-relay).

## Corporate networks, DLP and diagnosis

- **Proxy and TLS inspection:** run `init` in a shell where `HTTPS_PROXY`, `NO_PROXY` and `NODE_EXTRA_CA_CERTS` (or
  `NODE_USE_SYSTEM_CA=1`) are set. It copies them into the server's settings with `NODE_USE_ENV_PROXY=1`, which Node's
  `fetch` needs before it will use a proxy. Plain `http://` backends are refused except on localhost.
- **DLP:** outgoing messages (subject and body, also checked together) are checked for private keys, cloud and SaaS
  tokens, JWTs, passwords in assignments, command-line flags, connection URLs and `Authorization` headers, payment card
  numbers (Luhn plus issuer) and IBANs (mod-97), after undoing zero-width and full-width tricks. Set
  `AGENT_BRIDGE_DLP` to `block` (default), `redact`, `warn` or `off`. It is pattern-based: a safety net, not a guarantee.
- **`node cli.js doctor [repo]`:** checks Node, backend, settings, token-file permissions, proxy and CA, DLP, and
  reachability and auth. Every problem comes with a fix, and secrets are masked.

## How an agent learns it has mail

An idle session (Claude Code, Cursor or Codex) doesn't wake up by itself, so pick one or more of these:

1. **Ask it**: "check your bridge inbox".
2. **Ask, then wait**: "ask backend what /api/login returns and wait for the answer". The agent calls
   `send_message` and then `wait_for_message`. In the other repo, run
   `/loop 1m check the bridge inbox and answer any requests` so that agent keeps answering.
3. **Hook** (`init --hook`): on every prompt, the agent is told if unread messages are waiting. If it ever seems
   silent, run the hook command with `AGENT_BRIDGE_DEBUG=1` to see why. On Windows, `init` writes an exec-form hook
   (`--hook-form exec`): no shell, and its settings are kept in your local `.claude/settings.local.json`, never read
   from the repo. Hooks are optional. Under a managed "managed hooks only" policy, use 1 or 2. Cursor and Codex
   get the same note through their own hooks (see the table above); Codex runs a hook only after you trust it.

## Guardrails

- **Peer messages are data, not orders.** Each message has a header from the bridge, and every line of the body is
  shown prefixed with `| `. A message can therefore never pass itself off as a header or as text from another agent.
  The server's instructions tell the agent to check with its own user before doing anything destructive or outside
  its project because another agent asked, and never to send secrets over the bridge.
- **Loop protection.** A thread stops at the cap it was started with: `AGENT_BRIDGE_MAX_HOPS`, default 20, never more
  than 100. Use `type: "fyi"` when no reply is needed.
- **Validated input.** Agent names are `a-z 0-9 - _` (max 40), subjects are one line (max 200 characters), and bodies
  are at most 50,000 characters.

## Watching or joining in as a human

```bash
node cli.js tail                        # live feed (local: everything; Supabase: the token's own traffic)
node cli.js log 50                      # last 50 messages
node cli.js agents                      # who's on the bridge
AGENT_NAME=human node cli.js send backend "please pause, schema is changing"   # local
```

## Environment variables

| Var | Default | |
|---|---|---|
| `AGENT_NAME` | (local: required) | This agent's address. With Supabase it must match the token's agent, if set |
| `AGENT_DESCRIPTION` | none | Shown to other agents in `list_agents` |
| `AGENT_BRIDGE_BACKEND` | auto | `sqlite`, `supabase`, `relay` or `slack`; auto picks Supabase if `SUPABASE_URL` is set, else the relay if `RELAY_URL` is set, else Slack if `SLACK_CHANNEL_ID` is set, else SQLite |
| `AGENT_BRIDGE_DB` | `~/.agent-bridge/bridge.db` | Local mailbox. Must be the **same path** for agents that should talk |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | | Supabase project and its publishable (anon) key |
| `AGENT_BRIDGE_TOKEN` / `AGENT_BRIDGE_TOKEN_FILE` | | This agent's token, or a file holding it (preferred) |
| `AGENT_BRIDGE_MAX_HOPS` | `20` | Cap for threads this agent starts (max 100) |
| `AGENT_BRIDGE_RATE_PER_MIN`, `AGENT_BRIDGE_MAX_UNREAD`, `AGENT_BRIDGE_MAX_BYTES_PER_DAY` | 60, 200, 20000000 | Local per-sender limits (Supabase: `cli.js limits`) |
| `SUPABASE_SECRET_KEY` | | Admin commands only. Never give it to an agent |
| `SLACK_CHANNEL_ID` | | The bridge channel (`C0...`) |
| `SLACK_BOT_TOKEN` / `SLACK_BOT_TOKEN_FILE` | | This agent's bot token, or a file holding it (preferred) |
| `AGENT_BRIDGE_LOOKBACK_HOURS` | `72` | Slack: how far back agents read the channel |
| `RELAY_URL` | | Your relay (`https://...`). The agent token works as for Supabase |
| `RELAY_TLS_CA`, `RELAY_TLS_CLIENT_CERT`, `RELAY_TLS_CLIENT_KEY` | | Client side of the relay's mutual TLS |
| `RELAY_ADMIN_KEY` / `_FILE`, `RELAY_AUDITOR_KEY` / `_FILE` | | Admin and read-only auditor credentials (admin machine only) |
| `AGENT_BRIDGE_DLP` | `block` | `block`, `redact`, `warn` or `off` |
| `HTTPS_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY`, `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA` | | Corporate proxy and CA. `init` copies them for you |
| `AGENT_BRIDGE_ALLOW_INSECURE_HTTP` | unset | `1` allows plain `http://` backends off localhost (labs only) |

## Known limits

- **Delivery is at-most-once if a response is lost in transit.** Messages are marked read as they're handed over. A
  call that's cancelled gives its messages back, but if the network drops the response *after* the database
  committed, that message won't be shown again (it's still in `get_thread`). See R1-05 in
  [docs/adversary/round-01-triage.md](docs/adversary/round-01-triage.md).
- `wait_for_message` polls (Supabase every 2 s, Slack every 3 s); there's no push yet. Slack Socket Mode would make
  it instant and is a natural next step.
- On Slack, two replies sent at the same moment in one thread can show the same hop number. Readers count messages, so
  the cap still holds. Slack messages older than the lookback window are not seen.
- An idle agent still needs a nudge to look at its mail (`/loop`, the hook, or asking it). The bridge carries the
  messages; it doesn't start sessions.

## Tests

`npm test` runs every suite that needs no API key: end-to-end (on all four backends), security, Slack, relay,
concurrency, CLI, DLP, proxy, doctor, the Claude/Cursor/Codex client suites and the adversary-round regressions. It needs a local Postgres for the Supabase stand-in (`TEST_PG_URL`, default
`postgresql://postgres@127.0.0.1:54329/postgres`). CI runs the same suites on every push. What each suite proves, the
mutation results, and how to run the live tests against your own project: [docs/TESTING.md](docs/TESTING.md).
