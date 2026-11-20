# Round 2 triage

Round 2 was run by a fresh-context agent against commit `cc67aa3`. It covered the Slack backend, the self-hosted relay, and
the unread-mail hook (shell and exec form). Its findings are in [round-02.md](round-02.md): **15, all confirmed by running
them**, 0 critical, 0 high, 5 medium, 10 low.

Two Sonnet agents fixed them, split by file so they wouldn't collide, and the orchestrator reviewed and merged their work.
Each fix has a regression test that failed on the code the round attacked, and mutations that remove the fix.

| Suite | On the attacked code | Now |
|---|---|---|
| [`test/regressions-r2-relay.js`](../../test/regressions-r2-relay.js) | 0 of 24 | 26 of 26 (two tests were added while fixing) |
| [`test/regressions-r2-client.js`](../../test/regressions-r2-client.js) | 1 of 20 (the one pass guards something that already held, see below) | 20 of 20 |

Per-finding detail: [notes/relay.md § Round 2 fixes](../notes/relay.md) and [notes/round2-client.md](../notes/round2-client.md).

| id | severity | outcome | what changed |
|---|---|---|---|
| R2-01 | medium | FIXED | `RELAY_LEGAL_HOLD`, `RELAY_AUDIT_BODIES` and `RELAY_AUDIT_REQUIRED` are parsed strictly. `1/true/yes/on` turns the setting on and `0/false/no/off/empty` turns it off. Anything else stops the relay from starting. The relay prints a "security posture" line at startup |
| R2-02 | low | FIXED | Purge intervals over 100 years get a 400, not a 500. Every failed admin call is audited, whatever the error |
| R2-03 | medium | FIXED | An empty `RELAY_TLS_CERT`, `RELAY_TLS_KEY` or `RELAY_TLS_CA` (or an empty key file, or an empty `RELAY_AUDIT_LOG`) stops the relay from starting. Certificate files must contain PEM. The posture line says whether mTLS is required |
| R2-04 | low | FIXED | Failed-login audit lines are capped per source and scope at 10 per minute; the rest go into a summary line. Memory use is bounded |
| R2-05 | low | FIXED | A torn last line is sealed with a `chain.repair` entry, which `verify-audit` accepts only if it continues from the last good line. `RELAY_AUDIT_REQUIRED=1` fails closed: an action that can't be audited is undone or refused (503), and `/healthz` reports 503 while the audit log fails |
| R2-06 | low | FIXED | `init --hook` removes only agent-bridge's own entries inside a matcher group, so the user's other hooks and the group's matcher survive |
| R2-07 | medium | FIXED | Slack scans the whole lookback window (up to 500 pages, configurable) and waits out 429s. A scan that is cut short says so in `whoami`, `check_inbox`, `wait_for_message`, the hook and `doctor`, and never reports "Inbox empty". Readers enforce per-sender limits (60 a minute, 200 unread) and count what they ignore |
| R2-08 | low | FIXED | A Slack username shared by two people is ambiguous: the message is ignored and reported, never attributed to `human:<name>` |
| R2-09 | medium | FIXED | Export timestamps without a time zone get a 400, from a hand-written parser that ignores `TZ`. A date on its own means a UTC date |
| R2-10 | low | FIXED | Setting both `RELAY_ADMIN_KEY` and `RELAY_ADMIN_KEY_FILE` (or both auditor equivalents) stops the relay from starting |
| R2-11 | low | FIXED | Before any network call, a token must look like a token: `abt_` plus 64 hex characters, or `xoxb-...`. The token file must be a small regular file that other users can't read. `doctor` applies the same checks |
| R2-12 | low | FIXED | Exec-form hooks work behind a proxy and a private CA. `peek` re-runs itself once with the proxy and CA settings in the child's environment (allowlisted keys only, never `NODE_OPTIONS`, with a guard against loops) |
| R2-13 | low | FIXED | Deeply nested arguments get a 400 instead of a 500 (error messages use a depth-limited preview) |
| R2-14 | low | FIXED | `bridge_recent` is audited, and `peek` and `thread` entries carry message ids |
| R2-15 | medium | FIXED | The relay has header, request, idle and keep-alive timeouts (also during the TLS handshake), a connection cap of 512, and a checking interval of 2 seconds or less. All are configurable |

## Counts

| | |
|---|---|
| Fixed | 15 |
| Rejected | 0 |

## Still open (stated in the notes, not hidden)

- **Relay audit:** a `deliver` line written for a message that was later handed back in the same batch stays in the log.
  A crash between commit and audit write (power loss, not a write error) loses that line; admin changes have an
  `attempt` line first, messages don't.
- **Connection cap:** it is global, and the auth-failure limiter is per source address. Behind a proxy, every client
  shares one address. Put a reverse proxy in front if per-client fairness matters.
- **Slack scan:** it is stateless, so a very busy channel can cost many history calls per poll. Lower
  `AGENT_BRIDGE_LOOKBACK_HOURS` if that becomes too heavy. Slack has no server-side daily byte budget, so a flood stays
  visible in the channel even though readers ignore it.
- **One client test passed on the old code:** the R2-12 test checks that `peek --set` still refuses
  `NODE_OPTIONS`. That guard already held; the test stays so R2-12 can't loosen it.

## What the round taught

- Every medium finding was a **misconfiguration that failed open** (`true` instead of `1`, an empty CA path) or a
  **resource left unbounded** (sockets, scan pages). Neither kind shows up in tests written by the person who wrote the
  feature, because they always configure it correctly. Round 3 therefore aims at configuration handling too.
- The fix agents needed **`mutations.js --check`**, which the orchestrator added between rounds. Merging their work
  showed that refactors had moved or **duplicated** some mutation targets, so a mutation could mutate the wrong copy and
  "survive" or be "killed" for the wrong reason. `--check` now fails on missing and on ambiguous targets, and runs in CI.
- A sub-agent that hits a usage limit mid-mutation-run leaves a mutated file behind. Before merging such a branch,
  `git status` it and restore the file from its last commit.
