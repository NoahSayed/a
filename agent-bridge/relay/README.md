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
| `RELAY_AUDIT_BODIES` | `0` | `1`: also write message bodies into the audit log. Switches accept `1/true/yes/on` and `0/false/no/off` (any case); anything else refuses to start |
| `RELAY_AUDIT_REQUIRED` | `0` | `1`: fail closed. A request whose audit line can't be written is refused (HTTP 503) and has no effect; needs `RELAY_AUDIT_LOG` |
| `RELAY_MIN_RETENTION_DAYS` | `0` | purge / delete-agent refuse to remove messages younger than this |
| `RELAY_LEGAL_HOLD` | `0` | on (`1/true/yes/on`): purge and delete-agent refuse entirely. A value that is neither on nor off refuses to start |
| `RELAY_AUDITOR_KEY` or `_FILE` | off | a read-only key for `bridge_admin_export` (>= 32 chars, different from the admin key) |
| `RELAY_DLP` | `block` | the relay's own server-side check of every message: `block`, `redact`, `warn` or `off`. Validated at startup (a typo refuses to start); `warn` and `off` print a warning. The relay does **not** read `AGENT_BRIDGE_DLP` (that is the clients' setting; if it is set in the relay's environment the relay says it is ignored), so a stray shell variable can't weaken the server |

The same settings exist as flags: `--host --port --db --admin-key-file --tls-cert --tls-key --tls-ca --audit-log --audit-bodies
--auditor-key-file --min-retention-days --legal-hold`. Request bodies are limited to 256 KB (HTTP 413). `GET /healthz` needs no key
and answers `{"status":"ok"}` and nothing else (HTTP 503 `{"status":"audit log failing"}` while the audit log can't be written).

Settings that are present but empty (`RELAY_TLS_CA=`, `RELAY_TLS_CERT=`, `RELAY_TLS_KEY=`, `RELAY_ADMIN_KEY_FILE=`, `RELAY_AUDITOR_KEY_FILE=`, `RELAY_AUDIT_LOG=`),
unreadable or empty key/certificate files, and a key given both as a variable and as a `_FILE` all refuse to start. The effective posture is printed at
startup: `TLS`, `mTLS`, `legal hold`, `minimum retention`, `audit`, `auditor key`, `DLP` and the `connections` limits.

Connection limits (defaults suit an internal service; put the relay behind a proxy that also limits connections if it faces anything less trusted):

| Variable | Default | |
|---|---|---|
| `RELAY_HEADERS_TIMEOUT_MS` | `10000` | time allowed to send the complete request headers (not longer than the next one) |
| `RELAY_REQUEST_TIMEOUT_MS` | `30000` | time allowed to send the complete request |
| `RELAY_IDLE_TIMEOUT_MS` | `30000` | a socket that sends nothing for this long is closed (also before a TLS handshake) |
| `RELAY_KEEPALIVE_TIMEOUT_MS` | `5000` | idle keep-alive connections |
| `RELAY_MAX_CONNECTIONS` | `512` | more simultaneous connections are dropped. Keep it below the process's file-descriptor limit |
| `RELAY_MAX_CONNECTIONS_PER_IP` | `32` | one source address's share of `RELAY_MAX_CONNECTIONS` (an IPv6 address counts as its whole /64, an IPv4-mapped one as IPv4); more are dropped, so one client holding idle sockets can't lock out the others. A client that pools connections can briefly hold more sockets than it has requests running |
| `RELAY_AUTH_FAIL_AUDIT_MAX` / `_WINDOW_MS` | `10` / `60000` | failed authentications logged per source IP and scope per window; the rest are counted in an `auth_failed.summary` line. At most 10,000 sources are tracked at once: when the table is full the oldest is evicted (with its own summary line), so a new source is always logged under its own address, even after a spray from thousands of other addresses |

Behind a reverse proxy (or any NAT) every client shares the proxy's address: the per-address share, the auth-failure attribution and the audit
`ip` field then name the proxy. Limit connections per client at the proxy, and raise `RELAY_MAX_CONNECTIONS_PER_IP` for it.

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
whether they worked, failed or were refused (`outcome`). Reads are recorded with the ids of the messages they disclosed (`peek`, `recent`, `thread`).
Failed authentications are rate-limited per source (see above), so unauthenticated traffic can't grow the log without bound.
Export timestamps (`--from`, `--to`) need an explicit zone (`2026-01-01T00:00:00Z`, `...+01:00`) or are a UTC date (`2026-01-01`); a date-time without a zone is refused.

Each line also has `prev` (SHA-256 of the previous line's text) and `hash` (SHA-256 of the line without `hash`):

```bash
node cli.js verify-audit /var/log/agent-bridge/audit.jsonl     # OK (N line(s); last hash ...)  or  BROKEN at line N
```

An edited, deleted or reordered line breaks the chain at the first affected line. Lines cut off the *end* are only detectable against
a "last hash" you recorded elsewhere, so store it somewhere else periodically (WORM storage, a ticket, a syslog line). Run one relay
process per audit file.

If a write is cut short (disk full, crash), the next start (or the next write) ends the partial line and records a `chain.repair` entry
that continues the chain; `verify-audit` accepts that junk line only when it is directly followed by the repair entry that covers it.
With `RELAY_AUDIT_REQUIRED=1` the relay doesn't go on without its audit trail: sends are taken back, reads return nothing (claimed
messages are handed back), admin changes are written down before they happen, and `/healthz` reports 503 until the log is writable again.
If the line that records an admin change's *outcome* can't be written after the change was made, the answer is not "refused": it is HTTP 500,
code `AB001`, "the change was applied, but its outcome could not be written to the audit log", with `details: {"applied": true, "result": ...}`
(for `create_agent` and `rotate_token` the new token is in `result`, so it isn't lost). Don't repeat the request; the log holds the attempt
line (and an `applied_unaudited` line if it can be written), so the trail shows what was intended and that the outcome is unrecorded.

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
