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
- (Round 2 changed some of the above: the audit log can now fail closed and heal a torn write, failed-auth lines are rate-limited, and there are connection limits. See the next section.)

## Round 2 fixes

Findings R2-01, 02, 03, 04, 05, 09, 10, 13, 14 and 15 of [round-02.md](../adversary/round-02.md) (the relay and its audit log). The rest of round 2
(Slack, hooks, token file handling) is handled elsewhere. Tests: `test/regressions-r2-relay.js` (`node test/regressions-r2-relay.js`), written first and run on the
code the round attacked: **0 of 24 passed** (two of them, in the R2-02 and R2-05 groups, reach into the new `relay.audit` / `relay.core` handles and so can only fail there on
the API; the other 22 failed on the behaviour itself, e.g. `RELAY_LEGAL_HOLD="true": purge was 200`, `11 of 11 half-open sockets were still open after 6 s`, `340 connections were held open at once (cap 60)`,
`bridge_whoami.p_token: 500`, `120 auth_failed lines`, `{"ok":false,"line":3,"reason":"not valid JSON"}`, `TZ=UTC p_to="2026-11-19T18:33:01" -> 200`). Two tests were added while fixing (a silent connection on the TLS
port, a stalled request body), so the suite has 26 tests. Two test-side lessons: a client socket nobody reads from never notices that the server closed it (the tests call `resume()`),
and the connection-burst check looks for up to a second instead of at one instant, so a loaded machine can't fail it.
Mutations are named `R2-xx ...` in `test/mutations.js` (`node test/mutations.js "R2-"`).

| id | fix | test | mutations |
|---|---|---|---|
| R2-01 | `RELAY_LEGAL_HOLD`, `RELAY_AUDIT_BODIES`, `RELAY_AUDIT_REQUIRED` are parsed by one strict function: `1/true/yes/on` (any case, trimmed) is on, `0/false/no/off/empty` is off, anything else is a `RelayConfigError` naming the variable. The startup line `relay: security posture: TLS: .., mTLS: .., legal hold: ON/off, minimum retention: N day(s), audit: .., auditor key: ..` is printed before `listening on`. | every spelling of on (purge and delete-agent refuse), every off spelling, garbage refused, `RELAY_AUDIT_BODIES=true`, posture line | exact-`1` parse (hold, bodies), unknown value taken as off, posture not printed, posture hides the hold |
| R2-03 | `RELAY_TLS_CERT/KEY/CA`, `RELAY_ADMIN_KEY_FILE`, `RELAY_AUDITOR_KEY_FILE`, `RELAY_AUDIT_LOG` set but empty refuse to start (so does an unset compose variable that expands to nothing, and `--tls-ca ""`). Certificate, key and CA files must be readable, non-empty and contain a PEM block. An empty auditor key file used to silently disable export; now it is an error. The posture line says `mTLS: required` or `off`. | empty/blank/missing/empty-file/non-PEM for each of the TLS settings, flag form, empty key files, posture | empty check removed; empty and PEM checks removed together (double guard); posture says off; empty auditor file accepted |
| R2-10 | If both `RELAY_ADMIN_KEY` and `RELAY_ADMIN_KEY_FILE` are set (and the same for the auditor key), the relay refuses to start; the `--admin-key-file` flag no longer deletes the environment key behind your back, it conflicts with it. A *blank* `RELAY_ADMIN_KEY=` next to a key file is not a key and is ignored (the file is used). | both set (env+file, flag+env, auditor env+file); each alone starts | check removed |
| R2-15 | `headersTimeout` 10 s, `requestTimeout` 30 s, socket idle `timeout` 30 s (also `handshakeTimeout` before a TLS handshake), `keepAliveTimeout` 5 s, `connectionsCheckingInterval` <= 2 s (Node only enforces the header/request timeouts at this interval; its default is 30 s), `maxConnections` 512. All overridable (`RELAY_HEADERS_TIMEOUT_MS`, `_REQUEST_`, `_IDLE_`, `_KEEPALIVE_`, `RELAY_MAX_CONNECTIONS`); nonsense values refuse to start. | half-header, silent and one-byte sockets all closed within the timeout; a header-dripping client is cut; 40 idle connections leave `/healthz` at 200, a burst of 300 is held to the cap and fully reaped, `/healthz` recovers; a silent socket on the TLS port is dropped; sane defaults | no idle timeout, no header timeout, no checking interval, no cap, no handshake timeout, defaults off/huge |
| R2-13 | Error messages no longer `JSON.stringify` the offending value: a depth-limited `preview()` (3 levels, 5 items) plus a try/catch. Deeply nested arguments are a 400 `22P02`. | 100,000-deep array and 40,000-deep object in `p_token`, `p_body`, admin `p_name` and `p_older_than`; no "internal error" on stderr; `/healthz` still up | unbounded stringify (preview and try/catch are a double guard; the mutation removes both) |
| R2-02 | Intervals above 100 years (36,500 days) are `22008` 400. Every failure of an admin function is audited (`outcome: failed`, or `refused` for policy), not only `RpcError`s; an unexpected error is audited with `reason: "internal error"` and answered with the generic 500. | the three absurd intervals, rows unchanged, three `failed` audit lines, a normal 36,000-day purge still works; an admin call that hits a closed database is audited | cap removed, audit only for `RpcError` |
| R2-04 | `auth_failed` is rate-limited per source IP and scope: the first `RELAY_AUTH_FAIL_AUDIT_MAX` (10) per `RELAY_AUTH_FAIL_AUDIT_WINDOW_MS` (60 s) are logged, the rest counted, and an `auth_failed.summary` line (`ip`, `scope`, `logged`, `suppressed`, `since`) is written when the window ends (by a timer, and when the relay stops). At least one line per source per window. Memory is bounded (10,000 sources, then one shared counter per scope). | 240 failed requests from one address (agent and admin scope) give at most 10 lines per scope plus a summary, kept + suppressed adds up to 120 per scope, the log has < 40 lines and verifies | every failure audited, no summary, no line kept, summary only at shutdown |
| R2-05 | **Fail closed:** `RELAY_AUDIT_REQUIRED=1` (needs `RELAY_AUDIT_LOG`). When an audit line can't be written: a send is taken back (the stored row is deleted), an inbox read hands its claimed messages back and returns nothing, `peek`/`recent`/`thread` return nothing, admin changes write an `outcome: "attempt"` line first and are refused if that fails, and the answer is 503 `55000`. `/healthz` is 503 while the log is failing (and tries to write a recovery line, so it recovers by itself); this also applies without the switch. **Repair:** `AuditLog` finds a torn last line at startup (and after a failed write, by comparing the file size), ends it with a newline and records `chain.repair` (`prev` = hash of the junk, `after` = hash of the last good line); `verify-audit` accepts junk only if the next entry is the matching repair entry, and reports `repairs`. `writeSync` is looped so a short write is finished rather than ignored. | torn tail at startup, short write at run time, junk without a covering repair, repair that doesn't continue from the last good line (it can't hide a deleted line), required mode with a failing writer (send, inbox, peek, recent, thread, admin delete, healthz, recovery, verification), best-effort mode, config checks | seal at open, seal before write, resync, verifier accepts any junk, verifier ignores `after`, required off, strict off, send kept, claim kept, attempt line, healthz, 500 instead of 503, required without a log |
| R2-09 | Date-times without `Z` or an offset are a 400 `22007` with a hint; a date alone is a UTC date. The parser is hand written (no `Date.parse`, so `TZ` can't matter, and 31 February is refused). The export audit line keeps the typed text as `from_raw`/`to_raw` next to the normalised instant. | run with `TZ=UTC` and `TZ=America/Los_Angeles`: four zone-less spellings refused for `p_from` and `p_to`; `Z`, `+00:00`, `+02:00`, `-08:00`, date-only, and the audit line | zone check removed, offset applied backwards, raw text dropped |
| R2-14 | `bridge_recent` is audited (`recent`: agent, count, ids); `peek` and `thread` entries carry `ids`. | ids of every disclosed message in all three | recent unaudited, ids dropped from peek / thread |

### Left open

- **Audit-before-commit for `deliver`:** in required mode a claim that can't be audited is handed back, but lines for messages audited earlier in the same batch stay in the log
  (they say `deliver` for a message the caller never saw). The SQLite claim and the audit write are not one transaction.
- **A crash between the commit and the audit write** (power loss, not a write error) still loses that audit line; only a write-ahead record per request would close it. Admin changes have one (`attempt`), messages don't.
- **Torn-write repair assumes one writer per file** (as before) and a regular file. A hole in the middle of the file (not a torn tail) is reported by `verify-audit`, not repaired. `verify-audit`'s CLI output doesn't print the repair count yet (the verifier returns `repairs`; `cli.js` is not part of this change).
- **The auth-failure limiter is per source address**: behind a proxy every client shares the proxy's address (one noisy client can use up the 10 lines for all of them; the summary line still counts everything). The 10,000-source memory bound has no test (it needs 10,000 addresses).
- **`maxConnections` is global**, so a client that fills the cap locks others out until its sockets time out (at most `RELAY_IDLE_TIMEOUT_MS`). A per-address limit would need trusting proxy headers; put a proxy in front if that matters. The cap does not know the process's file-descriptor limit; keep it well below `ulimit -n`.
- `RELAY_AUDIT_LOG=` set but empty is now an error (it used to silently turn the audit off); to run without an audit log, leave it unset.
- The `Dockerfile` healthcheck is unchanged; it now sees 503 when the audit log is failing, which is intended.
