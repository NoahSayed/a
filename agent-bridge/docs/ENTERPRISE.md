# Running agent-bridge in a company, a bank or a fintech

This is the operator's guide for networks that are locked down: egress through a proxy, TLS inspection, an approved list
of SaaS, security review before anything is installed, and, in regulated firms, record-keeping and data-protection
rules. The research behind it, with sources, is in [research/enterprise-environments.md](research/enterprise-environments.md).
What leaves each machine, and where it goes, is in [NETWORK-AND-DATA.md](NETWORK-AND-DATA.md).

## 1. Pick the backend your environment allows

| Your environment | Backend | Why |
|---|---|---|
| One developer, one machine | **Local (SQLite)** | No network at all. A file in your home directory |
| Regulated (bank, broker, payments), air-gapped, or "no new SaaS" | **Relay (self-hosted)** | Runs on your own server. Data stays on-prem, there's one audit trail, and it adds no new ICT third party under DORA. Server-side DLP, retention and legal hold, read-only auditor access |
| Slack is approved and archived (Enterprise Grid with an archiver) | **Slack** | Outbound HTTPS to `slack.com` only. People can watch and join in, and records go to the firm's existing Slack archive |
| Startup or scale-up, cloud is fine | **Supabase** | Managed Postgres. Pick the region for data residency |

You can switch backend later; the tools the agents see are the same everywhere. Teams and Symphony are common in banks,
but whether two bots can read each other's messages there couldn't be confirmed, so no adapter exists yet. The relay is
the answer there.

## 2. The self-hosted relay

The relay is one Node process (`relay.js`, Node built-ins only) with one SQLite file. It speaks the same protocol as the
Supabase backend, so agents use the same tested client.

**Run it** (on an internal host; see [`relay/README.md`](../relay/README.md) and [`relay/Dockerfile`](../relay/Dockerfile), which runs
as a non-root user with a health check):

```bash
openssl rand -hex 32 > /etc/agent-bridge/admin.key && chmod 600 /etc/agent-bridge/admin.key
RELAY_ADMIN_KEY_FILE=/etc/agent-bridge/admin.key \
RELAY_HOST=0.0.0.0 RELAY_PORT=8787 \
RELAY_TLS_CERT=/etc/agent-bridge/tls.crt RELAY_TLS_KEY=/etc/agent-bridge/tls.key \
RELAY_AUDIT_LOG=/var/log/agent-bridge/audit.jsonl \
RELAY_MIN_RETENTION_DAYS=2190 \
node relay.js
```

| Setting | What it does |
|---|---|
| `RELAY_ADMIN_KEY` / `_FILE` | Admin credential (32+ characters; the relay refuses a weaker one). Registers, rotates, revokes and deletes agents, and changes limits |
| `RELAY_AUDITOR_KEY` / `_FILE` | Read-only credential for compliance: it can export messages in a time range, and nothing else |
| `RELAY_TLS_CERT`, `RELAY_TLS_KEY` | HTTPS with your internal CA's certificate |
| `RELAY_TLS_CA` | Mutual TLS: only clients holding a certificate from this CA can connect. Clients set `RELAY_TLS_CLIENT_CERT` / `_KEY` |
| `RELAY_AUDIT_LOG` | Append-only JSON Lines, **hash-chained**. `node cli.js verify-audit <file>` prints OK or the first edited, deleted or reordered line. Bodies are recorded as length plus SHA-256 unless `RELAY_AUDIT_BODIES=1` |
| `RELAY_MIN_RETENTION_DAYS` | `purge` and `delete-agent` refuse to remove anything younger. FINRA 4511's default is six years; MiFID II five to seven |
| `RELAY_LEGAL_HOLD=1` | Nothing can be purged or deleted. Refused attempts are audited |
| `GET /healthz` | Liveness, reveals nothing |

**Register agents and wire up repos:**

```bash
export RELAY_URL=https://bridge.corp.internal:8787 RELAY_ADMIN_KEY_FILE=/etc/agent-bridge/admin.key
node cli.js add-agent payments-api "Payments API, owns /v2/charges" --save   # or hand the printed token to its owner
node cli.js init ~/code/payments-api payments-api --relay                    # on the agent's machine
```

**Compliance export:** `RELAY_URL=... RELAY_AUDITOR_KEY_FILE=... node cli.js export --from 2026-01-01T00:00:00Z --to 2026-02-01T00:00:00Z`.

**Backups:** copy the SQLite file, plus its `-wal`, while the relay is stopped, or use `sqlite3 relay.db ".backup ..."`.
Back up the audit log, and record its last hash (`verify-audit` prints it) somewhere separate: that is what detects lines
removed from the end.

## 3. Corporate proxy and TLS inspection

Node's built-in `fetch` ignores `HTTPS_PROXY` unless the process **starts** with `NODE_USE_ENV_PROXY=1` (Node 22.21+ or
24+). TLS-inspecting proxies need their root CA trusted: `NODE_EXTRA_CA_CERTS=/path/corp-root.pem`, or
`NODE_USE_SYSTEM_CA=1` (Node 22.19+ / 24.6+) to use the OS store.

You don't have to wire this up by hand. Run `init` in a shell where `HTTPS_PROXY`, `NO_PROXY` and `NODE_EXTRA_CA_CERTS`
are set, and it copies them into the MCP server's settings together with `NODE_USE_ENV_PROXY=1`. It makes the CA path
absolute and warns if a proxy URL contains credentials. If a proxy is configured but not active, the server says so on
startup and in `whoami`.

Never set `NODE_TLS_REJECT_UNAUTHORIZED=0`. Plain `http://` backends are refused except on loopback; the escape hatch for
labs is `AGENT_BRIDGE_ALLOW_INSECURE_HTTP=1`.

NTLM, Kerberos and PAC-file proxies aren't supported directly. Use a local forwarding proxy (the approach Claude Code's
own docs suggest for those).

## 4. DLP: secrets and card data stay out of messages

Every outgoing message, on every backend, is checked before it leaves (`AGENT_BRIDGE_DLP`, default `block`). The check
finds:
- private keys (also JSON-escaped or cut short);
- cloud and SaaS tokens (AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, Anthropic, OpenAI, npm, SendGrid, Twilio);
- JWTs;
- this project's own tokens and keys;
- passwords: `password = ...` style assignments, `--password X` / `-pX` flags, `user:pass@` in connection URLs,
  `Authorization: Bearer|Basic|Token` headers;
- **payment card numbers** (Luhn-valid and in a real issuer range, any grouping);
- **IBANs** (correct length for the country, mod-97 valid, any case or grouping).

The subject and body are checked separately and together (a secret split across them is found). Zero-width characters,
full-width digits and similar tricks are undone before checking. It is pattern-based, so it is a safety net, not a
guarantee: a bare password with no label, or a vendor format it doesn't know, gets through. The list of known gaps is in
[adversary/round-03-triage.md](adversary/round-03-triage.md).

| Mode | Behavior |
|---|---|
| `block` | The message isn't sent. The error names the kind of data, never the data |
| `redact` | Each match is replaced with `[REDACTED:<kind>]` and the message is sent |
| `warn` | The message is sent, and the agent is told what was found |
| `off` | No checking |

On the **relay** the same check also runs **server-side**, so a client that skips it can't get around it. The relay's
mode is its own setting, `RELAY_DLP` (default `block`, shown in its startup line; a typo stops it from starting). On Supabase
and Slack the check runs in agent-bridge's client. Someone calling those APIs directly with a stolen token isn't
checked, which is one more reason the relay is the choice for PCI-scoped teams.

## 5. Getting it approved

| A reviewer will ask | Answer |
|---|---|
| What does it connect to? | Only the configured backend: one host. The code has exactly two `fetch` call sites, plus the mTLS client. No telemetry, no update checks |
| What does it install? | Two runtime dependencies (`@modelcontextprotocol/sdk`, `zod`), a lockfile, no native builds, no postinstall scripts |
| Where are secrets kept? | In token files (0600 on POSIX; the user-profile ACL on Windows), referenced by path. Never in `.mcp.json` or the repository |
| How is it tested? | Every suite runs in CI on Linux, macOS and Windows on Node 22 and 24. Two fresh-context attack rounds so far, each finding fixed with a regression test that failed first, and mutation testing on every guard. See [TESTING.md](TESTING.md) and [adversary/](adversary/) |
| Does it work with our Claude Code policy? | It works with no hooks at all (`wait_for_message`, `/loop`), so `allowManagedHooksOnly` is fine. Under `managed-mcp.json`, project `.mcp.json` files are ignored. Admins add one fixed entry: `node /opt/agent-bridge/server.js` with settings in `env`, which the allowlist doesn't compare. With `AGENT_BRIDGE_NAME_FROM=project` each agent is named after its project folder, which must already be a valid agent name (capitals are lower-cased; anything else is refused, and so is an `AGENT_NAME` that differs from the folder) |
| And with Codex or Cursor? | Codex: admins can allowlist the server in `requirements.toml` (`[mcp_servers.bridge.identity]`, matched on the launch command; anything else is disabled), and `allow_managed_hooks_only` turns project hooks off; the bridge works without hooks. Codex also loads a repo's `.codex/` only for a trusted project and runs a hook only after the user trusts it. Cursor: hooks and MCP can be set machine-wide (`/etc/cursor`, `/Library/Application Support/Cursor`, `C:\ProgramData\Cursor`). Details and what is verified: [clients/codex.md](clients/codex.md), [clients/cursor.md](clients/cursor.md) |
| Is it diagnosable? | `node cli.js doctor [repo]` checks Node, backend, settings, token file permissions, proxy and CA, DLP, and reachability and auth, and prints a fix for every failure, with secrets masked |

## 6. Regulations: what helps, and what remains your decision

Whether agent-to-agent messages count as business communications is a compliance decision. Coding chatter probably
doesn't; anything about clients, orders or trading probably does. These features help either way:

| Rule | What agent-bridge gives you | What stays with you |
|---|---|---|
| SEC 17a-4, FINRA 4511/3110 | Relay: append-only hash-chained audit log with server timestamps, minimum retention, legal hold, read-only auditor export | WORM storage or a designated third party; supervisory review; retention periods per record type |
| MiFID II Art. 16(7) | Retention and hold as above; Slack via your archiver | Deciding which threads relate to client orders |
| PCI DSS (3.3, 4.2.2) | DLP blocks card numbers by default (server-side on the relay); TLS in transit; mTLS available | Disk encryption on the relay host; keeping real card data out of agent contexts in the first place |
| GDPR | Self-hosting or region choice, purge, delete-agent, DLP to reduce what's sent | Your processor agreements and transfer assessments |
| DORA | The relay adds no new ICT third party; [NETWORK-AND-DATA.md](NETWORK-AND-DATA.md) lists each backend's data flows for your register | The register entry, exit plan and testing |
| SOC 2 | Per-agent identity, token rotation and revocation, admin and auditor separation, audited admin actions (including refused ones) | Access reviews and evidence collection |

## 7. Known limits (be honest with your reviewers)

- **Delivery** is at-most-once if a response is lost after the server has marked the message read. Cancelled calls give
  their messages back.
- **Local SQLite** trusts the OS user: anyone who can run as you can read and write your mailbox.
- **Slack:** everyone in the channel reads everything, by design. Thread rules are enforced by every reader, not by a
  server. History is limited to the lookback window.
- **Relay:** retention and legal hold stop deletion **through the API**. Someone with shell access to the host can still
  edit the files. That's what the audit chain, and a separately recorded last hash, are for.
- **DLP** is pattern-based. It misses encoded or split secrets and can flag a Luhn-valid order number.
- An idle agent still needs a nudge (`/loop`, the hook, or asking it) to read its mail.
