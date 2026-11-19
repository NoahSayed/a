# Network and data sheet

What agent-bridge sends where, what it stores, and who can read it, backend by backend. It's written for the security
review that comes before approving the tool in a corporate or regulated environment (firewall allowlists, the DORA ICT
third-party register, GDPR transfer assessments, PCI scoping). Background and sources:
[research/enterprise-environments.md](research/enterprise-environments.md).

## What runs where

- **The MCP server** (`server.js`). Each agent's Claude Code session starts one as a child process over stdio. It
  listens on no port and accepts no inbound connections. It only connects out to the configured backend.
- **The CLI** (`cli.js`). Run by a person for setup, admin and watching traffic. Same egress as the server.
- **No telemetry, no update checks, no other hosts.** The code calls `fetch` in exactly two places: `stores/supabase.js`
  and `stores/slack.js`, both to the configured URL, with `redirect: "error"` so a response can't send a request (and
  its credentials) anywhere else.

## Per backend

| | Local (SQLite) | Supabase | Slack |
|---|---|---|---|
| **Egress** | none | `https://<project-ref>.supabase.co` (443): one host | `https://slack.com/api/*` (443): one host |
| **Inbound** | none | none | none (no Events API, no webhook URL) |
| **Calls** | file I/O only | `POST /rest/v1/rpc/bridge_*` (JSON) | `auth.test`, `conversations.members`, `users.info`, `conversations.history`, `chat.postMessage`, `reactions.add`, `reactions.remove` (form-encoded) |
| **Credentials on the agent's machine** | none (identity is `AGENT_NAME`; trusts the local user) | publishable key (public by design) + per-agent token in a 0600 file | per-agent Slack bot token (`xoxb-`) in a 0600 file |
| **Admin credential** | none | Supabase secret key: admin's machine only, never given to agents | Slack workspace admin approves each app |
| **Where messages are stored** | `~/.agent-bridge/bridge.db` (0600, directory 0700) | `public.bridge_messages` in the Supabase project's region | the Slack channel, under the workspace's retention and archiving settings |
| **Who can read messages** | anyone who can read the file as that OS user | the sending and receiving agent only (enforced in SQL); project admins | every member of the channel (by design: people watch and join in) |
| **Who decides the sender** | the local `AGENT_NAME` (cooperative) | the database, from the token's hash | Slack, from the posting bot user |
| **Retention** | until deleted | until `cli.js purge N` / `delete-agent` | the workspace's Slack retention policy (agents read only the last 72 h) |
| **Third party for DORA / GDPR** | none | Supabase (processor; pick the region) | Slack/Salesforce (processor; Enterprise Grid data residency where needed) |

## What a message contains

| Field | Notes |
|---|---|
| `from_agent`, `to_agent` | agent names (`[a-z0-9_-]`, max 40), or `human:<slack-username>` on Slack |
| `type` | `request`, `response` or `fyi` |
| `subject` | optional, one line, max 200 characters |
| `body` | free text, max 50,000 characters (30,000 on Slack): **whatever the agent writes**. This is the field to worry about: code, logs and config can end up here |
| `thread_id`, `hop`, `max_hops` | conversation bookkeeping |
| `created_at`, `read_at` | server timestamps (Slack: the message `ts`; ✅ reaction = read) |

No file attachments, no images, no repository contents unless an agent pastes them into a body.

## Proxies and TLS inspection

Node's built-in `fetch` uses `HTTPS_PROXY` / `NO_PROXY` only when the process starts with `NODE_USE_ENV_PROXY=1`
(Node 22.21+ / 24.5+). A corporate root CA is added with `NODE_EXTRA_CA_CERTS=/path/ca.pem`, or with
`NODE_USE_SYSTEM_CA=1` (Node 22.19+ / 24.6+) to trust the OS store. These must be in the MCP server's `env` (`init` writes
them for you once the hardening work lands). **Never set `NODE_TLS_REJECT_UNAUTHORIZED=0`.**

## Allowlist summary for a firewall team

| Backend | Allow |
|---|---|
| Local | nothing |
| Supabase | `<project-ref>.supabase.co:443` |
| Slack | `slack.com:443` |
