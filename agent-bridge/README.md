# agent-bridge

A message bridge that lets AI agents working on **different projects** talk to each other, whether they're on
the same machine or on different ones.

Each agent (for example a Claude Code session in `frontend/` and another in `backend/`) runs its own copy of
this MCP server. They exchange messages through a shared mailbox:

- **Local**: a SQLite file on one machine. Nothing to set up, no network.
- **Supabase**: a few `bridge_*` tables and functions in a Supabase project. Works across machines, people and
  networks.

```
 Claude Code (frontend)                    Claude Code (backend)
        │ MCP stdio                                │ MCP stdio
 agent-bridge server ──►  mailbox  ◄── agent-bridge server
                     local: ~/.agent-bridge/bridge.db
                     remote: Supabase (publishable key + per-agent token)
```

Requires Node **22.13+**, which ships `node:sqlite`. There are no native builds.

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

## How an agent learns it has mail

An idle Claude Code session doesn't wake up by itself, so pick one or more of these:

1. **Ask it**: "check your bridge inbox".
2. **Ask, then wait**: "ask backend what /api/login returns and wait for the answer". The agent calls
   `send_message` and then `wait_for_message`. In the other repo, run
   `/loop 1m check the bridge inbox and answer any requests` so that agent keeps answering.
3. **Hook** (`init --hook`): on every prompt, the agent is told if unread messages are waiting. If it ever seems
   silent, run the hook command with `AGENT_BRIDGE_DEBUG=1` to see why.

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
| `AGENT_BRIDGE_BACKEND` | auto | `sqlite` or `supabase`; auto means Supabase when `SUPABASE_URL` is set |
| `AGENT_BRIDGE_DB` | `~/.agent-bridge/bridge.db` | Local mailbox. Must be the **same path** for agents that should talk |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | | Supabase project and its publishable (anon) key |
| `AGENT_BRIDGE_TOKEN` / `AGENT_BRIDGE_TOKEN_FILE` | | This agent's token, or a file holding it (preferred) |
| `AGENT_BRIDGE_MAX_HOPS` | `20` | Cap for threads this agent starts (max 100) |
| `AGENT_BRIDGE_RATE_PER_MIN`, `AGENT_BRIDGE_MAX_UNREAD`, `AGENT_BRIDGE_MAX_BYTES_PER_DAY` | 60, 200, 20000000 | Local per-sender limits (Supabase: `cli.js limits`) |
| `SUPABASE_SECRET_KEY` | | Admin commands only. Never give it to an agent |

## Known limits

- **Delivery is at-most-once if a response is lost in transit.** Messages are marked read as they're handed over. A
  call that's cancelled gives its messages back, but if the network drops the response *after* the database
  committed, that message won't be shown again (it's still in `get_thread`). See R1-05 in
  [docs/adversary/round-01-triage.md](docs/adversary/round-01-triage.md).
- With Supabase, `wait_for_message` polls every 2 seconds; there's no push.

## Tests

`npm test` runs every suite that needs no API key: end-to-end, security, concurrency, CLI and the adversary-round
regressions. It needs a local Postgres for the Supabase stand-in (`TEST_PG_URL`, default
`postgresql://postgres@127.0.0.1:54329/postgres`). CI runs the same suites on every push. What each suite proves, the
mutation results, and how to run the live tests against your own project: [docs/TESTING.md](docs/TESTING.md).
