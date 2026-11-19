# Relay: a self-hosted backend for networks without Supabase or Slack

Status: built and tested. Everything below was run on the commit this note ships with (see the end for the numbers).

## What was built

`relay.js` is a small HTTP(S) server (Node built-ins only, no new dependencies) that speaks the **Supabase backend's protocol**
(`POST /rest/v1/rpc/<function>`, JSON object of named arguments, `apikey` header, 204 for void, errors as
`{code,message,details,hint}`, 404 `PGRST202` for an unknown function or argument). `stores/supabase.js` talks to it unchanged.
The 9 agent functions and 6 admin functions of `supabase/migration.sql` are implemented with the same names, arguments, defaults,
status codes and error messages the clients and tests match on.

| File | What |
|---|---|
| `relay.js` | the server, config, RPC table, argument coercion, request handling |
| `relay-audit.js` | hash-chained audit log writer and verifier |
| `stores/tls-fetch.js` | tiny `fetch` over (mutual) TLS for the client (Node's `fetch` can't take a client certificate without undici) |
| `store.js`, `stores/supabase.js` | backend `relay`; `label` option so `whoami` says `relay:<url>` |
| `cli.js` | admin commands against a relay, `init --relay`, `verify-audit`, `export` |
| `relay/Dockerfile`, `relay/README.md` | image (node:22-alpine, non-root, `EXPOSE 8787`, `HEALTHCHECK`), run/TLS/backup/rotation docs |
| `test/relay.js`, `test/backends.js` (`relay-local`), `test/mutations.js` (`RL ` prefix) | tests |

## Design decisions

- **Messages reuse `SqliteStore`.** One `SqliteStore` ("core") owns the database connection. Each request builds a per-call view with
  `Object.create(core, { agent, limits })`, so the store's own `send / inbox / unmark / thread / recent / unreadSummary` run unchanged
  (thread rules, hop caps, abuse limits, `BEGIN IMMEDIATE` claims) with the caller's identity and the *current* limits. **`SqliteStore` was not modified.**
  The relay adds `relay_agents` (name, description, project_dir, `token_hash` = SHA-256 hex, created/last_seen/revoked) and `relay_settings`
  tables to the same file. The store's own `agents` table is unused (the relay's registry is authoritative and `list_agents` shows only registered, non-revoked agents).
- **SQL parity beyond the store:** unknown/revoked recipient -> `Unknown agent "x". Use list_agents ...` (the local backend queues for unknown agents); `limit` and
  `max_hops` are clamped exactly like SQL (0 -> 1, not "default"); `p_from` that can't be a name returns `[]`; arguments are type-checked like Postgres would
  (`22P02` -> 400, not 500); the thread id is lower-cased; admin name/description checks mimic the check constraints; limits are range-checked like `bridge_settings`.
- **Auth:** agent calls are authenticated by `p_token` only (the `apikey` is ignored, the client sends `relay`). Tokens are `abt_` + 64 hex, stored as SHA-256, looked up by hash.
  Admin functions need the admin key in `apikey`, compared by `timingSafeEqual` of SHA-256 digests (constant time, no length leak). Admin key as a token -> 403
  `invalid agent token`; any token or wrong key on an admin function -> 401 `42501`.
- **Wire hygiene:** only `POST /rest/v1/rpc/<name>` and `GET /healthz` exist; everything else is a generic 404/405. Body limit 256 KB (413, input drained so the client can read the answer);
  a body that isn't a JSON object is refused (400 `PGRST102`); errors never include stacks, paths or SQL (internal errors log a short message to stderr, never tokens);
  SQLite busy -> 503 (the client retries reads). Request/headers timeouts set.
- **Config** is env or flags; keys are never flags. `RELAY_ADMIN_KEY` < 32 chars is refused at start. A non-loopback bind without TLS prints a warning.
- **Audit log** (`RELAY_AUDIT_LOG`): JSON Lines, opened append-only 0600. Events: `send`, `deliver` (claimed), `peek`, `unmark`, `thread`, admin actions (with `outcome` ok/failed/refused),
  `auth_failed` (scope + function + IP, never the credential), `auditor.export`. Message events carry id, thread, from, to, type, byte length and SHA-256 of the body; the body only with `RELAY_AUDIT_BODIES=1`.
  Subjects are never logged.
- **Regulated-environment additions (orchestrator's addendum):**
  1. *Tamper evidence:* each line has `prev` (SHA-256 of the previous line's text; 64 zeros first) and `hash` (SHA-256 of the line without `hash`). The chain continues across restarts.
     `node cli.js verify-audit <file>` prints `OK (...; last hash ...)` or `BROKEN at line N`. Edits, deleted lines (including the first) and reordering are detected at the first affected line.
  2. *Retention / legal hold:* `RELAY_MIN_RETENTION_DAYS` (purge `older_than` must be >= it; delete-agent refuses while any of the agent's messages is younger) and `RELAY_LEGAL_HOLD=1`
     (both refuse always). Refusals are HTTP 400 with a clear message and are audited as `outcome: "refused"`.
  3. *Auditor key:* `RELAY_AUDITOR_KEY(_FILE)` opens only `bridge_admin_export(p_from, p_to, p_after_id, p_limit)` (messages with bodies, oldest first, paged by id, read-only, audited).
     The admin key and agent tokens don't work for it, the auditor key works for nothing else, and with no auditor key configured export is closed to everyone. `cli.js export` pages through it.
  4. *mTLS:* `RELAY_TLS_CA` makes the server require client certificates from that CA. The client side takes `RELAY_TLS_CA`, `RELAY_TLS_CLIENT_CERT`, `RELAY_TLS_CLIENT_KEY`.

## How to run

See `relay/README.md`. Short form: `RELAY_ADMIN_KEY=$(openssl rand -hex 32) npm run relay`, then
`RELAY_URL=... RELAY_ADMIN_KEY=... node cli.js add-agent frontend --save`, `RELAY_URL=... node cli.js init ../frontend frontend --relay`.
Tests: `node test/e2e.js relay-local`, `node test/security.js relay-local`, `node test/concurrency.js relay-local`, `node test/relay.js` (`npm run test:relay`; `npm test` includes them).

## Test adaptations (existing suites)

- `test/security.js`: "no apikey -> 401" accepts 401 or 404 for the relay and asserts the body names nothing (it has no table endpoints); the "Authorization: Bearer new-style key"
  test is skipped for the relay (it checks Supabase's gateway; the relay ignores `Authorization`). The two `b.pool` (Postgres-only) tests skip themselves as before.
- `test/harness.js`: `RELAY_*` env vars are stripped from child environments like `SUPABASE_*`.
- `relay-local` has `kind: "relay"` (whoami prints `relay:<url>`), `registered: true`, `tokenVar`, `urlVar: RELAY_URL`, `badToken`; it runs `relay.js` as a **child process** on a random port.

## Test and mutation results

Every suite was run twice on the final code, with identical results both times (local Postgres 16 for `supabase-local`):

| Command | Result (run 1 / run 2) |
|---|---|
| `node test/e2e.js sqlite supabase-local slack-local relay-local` | 81/81 / 81/81 (relay-local alone: 21) |
| `node test/security.js supabase-local` | 19/19 / 19/19 |
| `node test/security.js relay-local` | 16/16 / 16/16 |
| `node test/slack.js` | 17/17 / 17/17 |
| `node test/concurrency.js sqlite supabase-local slack-local relay-local` | 12/12 / 12/12 |
| `node test/cli.js` | 24/24 / 24/24 |
| `node test/regressions-r1.js` | 29/29 / 29/29 |
| `node test/relay.js` (new) | 39/39 / 39/39 (incl. TLS and mTLS with openssl-generated certificates) |

**Fail-first.** Before `relay.js` existed, `node test/e2e.js relay-local` died with `MODULE_NOT_FOUND`. `test/relay.js` was written before the audit-chain,
retention, auditor, mTLS and CLI features and run against the core relay: **22/39 passed, 17 failed** (all the new-feature tests; the 413 and TLS-helper failures were test bugs
that were then fixed: the 413 test exposed a real problem, the relay closed the connection before the client read the 413, now it keeps draining). With the features: 39/39.

**Mutations** (`node test/mutations.js "RL "`): **24/24 killed**: weak admin key accepted; admin functions accept any apikey; export open to the admin key when no auditor key is set;
auditor key opens admin functions; body limit off; non-object JSON accepted; store-rule text sent with a stack; healthz reveals more; tokens stored in clear; revoked agents still authenticate;
send to unregistered agents; unknown arguments ignored (sender spoofing); abuse limits not applied; audit log writes bodies; audit chain not linked; chain not continued after restart;
verify-audit ignores hashes; verify-audit ignores the chain; purge ignores retention; delete-agent ignores retention; purge ignores legal hold; delete-agent ignores legal hold;
refused admin actions not audited; mTLS doesn't require a client certificate. (Not mutation-testable: the constant-time comparison, see open issues.)

## Open issues / not done

- **Audit tail truncation:** removing lines from the *end* of the log (or the whole file) can't be detected by the chain alone; `verify-audit` prints the final hash so it can be anchored externally.
  One relay process per audit file (two writers would fork the chain).
- **Audit is best effort:** a failed audit write (disk full) is logged to stderr and the request still succeeds. For a hard "no audit, no service" rule the write would have to precede the commit.
- **No brute-force throttling** on the admin/auditor key (a 32+ character key is the defence). A per-IP failed-auth limit would be a small addition; failures are audited with the source IP.
- **Retention is policy in the relay, not in storage:** anyone with shell access to the SQLite file can still change it. Use filesystem/WORM controls for SEC 17a-4-style immutability; this feature only stops the *API* from deleting.
- **Single process:** one SQLite connection serialises everything; fine for dozens of agents, not a horizontally scaled service. Several relays on one file would work (BEGIN IMMEDIATE) but would break the audit chain.
- **Docker image is untested here:** no Docker daemon in this environment. The health-check command was run by hand against a live relay. The healthcheck can't pass with mTLS (no client cert).
- **Client mTLS** uses a small `https`-based fetch (`stores/tls-fetch.js`); it doesn't pool beyond keep-alive and has no proxy support.
- R1-05 (a lost HTTP response *after* a claim commits loses the message) applies to the relay exactly as to Supabase; the same `unmark` mitigation is available.
- `p_older_than` accepts `N seconds|minutes|hours|days|weeks` only (what `cli.js purge` sends), not the full Postgres interval grammar.
- The constant-time comparison can't be mutation-tested (the mutant is behaviourally identical); it is covered by review only.
