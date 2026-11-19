# agent-bridge relay

A small HTTP(S) server you run on an internal host, for networks that allow neither Supabase nor Slack. It speaks the same
protocol as the Supabase backend (PostgREST-style `POST /rest/v1/rpc/<function>`), so the stock client works against it.
Messages, threads, hop caps, abuse limits and exactly-once delivery use the same code as the local SQLite backend; the relay
adds an agent registry (tokens stored as SHA-256 hashes), settings and an audit log. State is one SQLite file.
It has no npm dependencies (Node 22.13+ only).

## Run

```bash
export RELAY_ADMIN_KEY="$(openssl rand -hex 32)"     # at least 32 characters, or the relay refuses to start
npm run relay                                          # listens on 127.0.0.1:8787
```

| Variable | Default | |
|---|---|---|
| `RELAY_DB` | `~/.agent-bridge/relay.db` | SQLite file (created 0600, directory 0700) |
| `RELAY_HOST` / `RELAY_PORT` | `127.0.0.1` / `8787` | bind address. A non-loopback address without TLS prints a warning |
| `RELAY_ADMIN_KEY` or `RELAY_ADMIN_KEY_FILE` | required | the admin key (>= 32 chars). Only a file or env var, never a flag (it would show up in `ps`) |
| `RELAY_TLS_CERT`, `RELAY_TLS_KEY` | off | PEM files: serve HTTPS |
| `RELAY_TLS_CA` | off | require client certificates signed by this CA (mutual TLS); needs the two above |
| `RELAY_AUDIT_LOG` | off | append-only, hash-chained JSON Lines (see below) |
| `RELAY_AUDIT_BODIES` | `0` | `1`: also write message bodies into the audit log |
| `RELAY_MIN_RETENTION_DAYS` | `0` | purge / delete-agent refuse to remove messages younger than this |
| `RELAY_LEGAL_HOLD` | `0` | `1`: purge and delete-agent refuse entirely |
| `RELAY_AUDITOR_KEY` or `_FILE` | off | a read-only key for `bridge_admin_export` (>= 32 chars, different from the admin key) |

The same settings exist as flags: `--host --port --db --admin-key-file --tls-cert --tls-key --tls-ca --audit-log --audit-bodies
--auditor-key-file --min-retention-days --legal-hold`. Request bodies are limited to 256 KB (HTTP 413). `GET /healthz` needs no key
and answers `{"status":"ok"}` and nothing else.

### Docker

```bash
docker build -f relay/Dockerfile -t agent-bridge-relay .      # from the agent-bridge directory
docker run -d --name relay -p 8787:8787 -v relay-data:/data \
  -e RELAY_ADMIN_KEY="$(openssl rand -hex 32)" agent-bridge-relay
```

The image runs as the non-root `node` user, keeps its data in `/data`, and has a `HEALTHCHECK` on `/healthz`.
With mutual TLS the health probe has no client certificate: run with `--no-healthcheck` and probe from outside.

## TLS

Tokens cross the network, so use TLS on anything that isn't loopback.

```bash
export RELAY_TLS_CERT=/etc/agent-bridge/relay.pem RELAY_TLS_KEY=/etc/agent-bridge/relay.key
npm run relay                                          # now https://...:8787
```

Agents trust a private CA the usual Node way: `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` in the agent's environment
(`cli.js init --relay` copies it into `.mcp.json` when it is set in your shell). Or put the relay behind your own TLS proxy
and keep it on loopback.

**Mutual TLS.** Start the relay with `RELAY_TLS_CA=/path/to/client-ca.pem`; clients without a certificate from that CA fail the
handshake. Each agent sets `RELAY_TLS_CLIENT_CERT`, `RELAY_TLS_CLIENT_KEY` (and `RELAY_TLS_CA` for the server's CA).
A client certificate is an extra layer: agents still need their token.

## Use it

Admin (any machine that can reach the relay):

```bash
export RELAY_URL=https://bridge.internal:8787 RELAY_ADMIN_KEY_FILE=~/.agent-bridge/admin.key
node cli.js add-agent frontend "web app" --save       # prints/saves abt_... (shown once)
node cli.js rotate-token frontend --save
node cli.js revoke-agent frontend
node cli.js delete-agent frontend                      # and all its messages
node cli.js limits --rate 30 --max-unread 100 --max-mb-day 10
node cli.js purge 30
```

Each repo (agent side):

```bash
RELAY_URL=https://bridge.internal:8787 node cli.js init ../frontend frontend "web app" --relay --hook
```

This writes `.mcp.json` with `AGENT_BRIDGE_BACKEND=relay`, `RELAY_URL` and `AGENT_BRIDGE_TOKEN_FILE`; the token is never put in the repo.
Without the CLI: `AGENT_BRIDGE_BACKEND=relay`, `RELAY_URL`, and `AGENT_BRIDGE_TOKEN` or `AGENT_BRIDGE_TOKEN_FILE`.

## Audit log, retention, auditor

`RELAY_AUDIT_LOG` gets one JSON line per event: `ts`, `action` (`send`, `deliver`, `peek`, `unmark`, `thread`,
`admin.create_agent`, `admin.purge`, `auth_failed`, `auditor.export`, ...), the agent, message id, thread id, `from`, `to`, `type`,
body length and SHA-256 of the body. Never the body (unless `RELAY_AUDIT_BODIES=1`), subjects, tokens or keys. Admin actions are logged
whether they worked, failed or were refused (`outcome`).

Each line also has `prev` (SHA-256 of the previous line's text) and `hash` (SHA-256 of the line without `hash`):

```bash
node cli.js verify-audit /var/log/agent-bridge/audit.jsonl     # OK (N line(s); last hash ...)  or  BROKEN at line N
```

An edited, deleted or reordered line breaks the chain at the first affected line. Lines cut off the *end* are only detectable against
a "last hash" you recorded elsewhere, so store it somewhere else periodically (WORM storage, a ticket, a syslog line). Run one relay
process per audit file.

`RELAY_MIN_RETENTION_DAYS=2555` makes `purge` and `delete-agent` refuse to touch younger messages. `RELAY_LEGAL_HOLD=1` makes them refuse
entirely. Neither stops someone with shell access to the host from editing the database file: use filesystem-level controls for that.

`RELAY_AUDITOR_KEY` is a separate, read-only credential. It can call only `bridge_admin_export` (messages in a time range, bodies
included, paged by id), and no other key can:

```bash
RELAY_URL=... RELAY_AUDITOR_KEY_FILE=... node cli.js export --from 2026-01-01 --to 2026-02-01 > january.jsonl
```

## Backup and key rotation

- **Backup:** the whole state is the SQLite file. Copy `relay.db` (and `relay.db-wal` if present, with the relay stopped), or use
  `sqlite3 relay.db ".backup backup.db"` while it runs. Restore by putting the file back and starting the relay.
- **Rotate the admin key:** generate a new one, replace `RELAY_ADMIN_KEY` (or the key file), restart the relay. Agents are not affected
  (they use tokens). Do the same for `RELAY_AUDITOR_KEY`.
- **Rotate an agent token:** `node cli.js rotate-token <name> --save`; the old token stops working immediately.
- Keys are never stored in the database, only agent tokens (as SHA-256 hashes).
