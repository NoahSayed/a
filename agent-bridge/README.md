# agent-bridge

A local message bridge that lets AI agents working on **different projects** talk to each other.

Each agent (for example a Claude Code session in `~/code/frontend` and another in `~/code/backend`) runs
its own copy of this MCP server with a different `AGENT_NAME`. Both point at the same SQLite file, which
acts as a shared mailbox.

```
 Claude Code (frontend)            Claude Code (backend)
        │ MCP stdio                        │ MCP stdio
 agent-bridge AGENT_NAME=frontend   agent-bridge AGENT_NAME=backend
        └──────────►  ~/.agent-bridge/bridge.db  ◄──────────┘
```

Requires Node **22.13+**, which ships `node:sqlite`. No native builds and no cloud services.

## Tools the agents get

| Tool | What it does |
|---|---|
| `whoami` | This agent's name, the DB path, and the unread count |
| `list_agents` | Agents that have connected, with their project dirs |
| `send_message(to, body, type?, subject?, thread_id?)` | Send a message. Omit `thread_id` to start a thread; pass it to reply. `type` is `request`, `response` or `fyi` |
| `check_inbox(limit?, mark_read?)` | Read unread messages, oldest first |
| `wait_for_message(timeout_seconds?, thread_id?)` | Block until a message arrives (for "ask, then wait for the answer") |
| `get_thread(thread_id)` | Full back-and-forth history of a thread |

## Setup

```bash
cd agent-bridge && npm install
```

In **each** project, add a `.mcp.json` at the project root. Use a different `AGENT_NAME` per project
and an absolute path to `server.js`:

```json
{
  "mcpServers": {
    "bridge": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/agent-bridge/server.js"],
      "env": {
        "AGENT_NAME": "frontend",
        "AGENT_DESCRIPTION": "React app; owns the login UI",
        "AGENT_BRIDGE_DB": "~/.agent-bridge/bridge.db"
      }
    }
  }
}
```

Restart Claude Code in each project and approve the `bridge` server. To check it worked, ask the agent
to run `whoami` / `list_agents`.

### Environment variables

| Var | Default | |
|---|---|---|
| `AGENT_NAME` | (required) | This agent's address on the bridge |
| `AGENT_DESCRIPTION` | none | Shown to other agents in `list_agents` |
| `AGENT_BRIDGE_DB` | `~/.agent-bridge/bridge.db` | Must be the **same path** for agents that should talk |
| `AGENT_BRIDGE_MAX_HOPS` | `20` | Max messages per thread (loop protection) |

## How an agent learns it has mail

An idle Claude Code session doesn't wake up by itself, so pick one or more of these:

1. **Ask it**: "check your bridge inbox".
2. **Ask, then wait**: in the sending project, say "ask backend what /api/login returns and wait for the
   answer". The agent calls `send_message` and then `wait_for_message`. In the other project, run
   `/loop 1m check the bridge inbox and answer any requests` so that agent keeps answering.
3. **Hook (automatic notice)**: add a `UserPromptSubmit` hook to the project's `.claude/settings.json`.
   On every prompt it tells the agent if unread messages are waiting:

   ```json
   {
     "hooks": {
       "UserPromptSubmit": [
         { "hooks": [{ "type": "command",
           "command": "node /ABSOLUTE/PATH/TO/agent-bridge/cli.js peek frontend" }] }
       ]
     }
   }
   ```

## Watching or joining in as a human

```bash
node cli.js tail                       # live feed of all messages
node cli.js log 50                     # last 50 messages
node cli.js agents                     # who's connected
node cli.js send human backend "please pause, schema is changing"
```

Set `AGENT_BRIDGE_DB` in your shell if you're not using the default path.

## Guardrails built in

- **Peer messages are data, not orders.** Every message is shown with a header saying it comes from a peer
  agent, and the server's instructions tell the agent to check with its own user before doing anything
  destructive or outside its project because another agent asked.
- **Loop protection.** A thread stops accepting messages after `AGENT_BRIDGE_MAX_HOPS`. Use `type: "fyi"`
  for messages that need no reply.
- **No self-messages**, and replies must go to a thread that exists.

## Tips

- Keep a shared contract (an OpenAPI spec, shared types, a `CONTRACT.md`) that both projects can read.
  Use the bridge to *negotiate changes* to it, not as the only place the truth lives.
- Agents on **different machines** can't share a local SQLite file. All storage is in `store.js`, so for
  cross-machine use you'd swap it for a hosted database such as Postgres or Supabase and keep the same tools.

## Test

```bash
npm test   # spins up two MCP clients ("frontend" and "backend") and runs a full conversation
```
