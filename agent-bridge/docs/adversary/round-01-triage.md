# Round 1 triage

Round 1 was run by a fresh-context agent against commit `3d2f469` (stage 2 work in progress). Its findings are in
[round-01.md](round-01.md). It reported **15 findings, every one confirmed by running it**: 0 critical, 2 high, 4 medium, 9 low.

Possible outcomes for each finding:
- **FIXED**: code changed, with a regression test that failed on the old code first and passes now, plus a mutation check showing
  the test notices when the fix is removed.
- **PARTLY FIXED**: what remains is written down below.
- **ACCEPTED**: a known limit, with the reason.

The regression tests are in [`test/regressions-r1.js`](../../test/regressions-r1.js). Run on the code the round attacked, they scored
**0 of 26**. With the fixes they score **29 of 29**: the 26, plus three added afterwards (a raw-SQL subject check, a daily byte budget,
and the R1-08 lock test rewritten to lock a fresh database). The mutation results are in [TESTING.md](../TESTING.md#mutation-testing).

| id | severity | outcome | what changed | test |
|---|---|---|---|---|
| R1-01 | medium | FIXED | The next hop number is `max(hop)+1`, not `count(*)+1`. Purged rows can no longer make a hop number repeat. | `R1-01 purge never wedges a thread that spans the cutoff` |
| R1-02 | medium | FIXED | A reply inside a thread may only go to someone who is already in the thread (both backends). To bring someone new in, start a new thread. | `R1-02 a thread member can't pull a third agent into the thread` |
| R1-03 | high | FIXED | Per-sender limits, enforced in SQL under a per-sender advisory lock so parallel sends can't overshoot: 60 messages a minute, 200 unread per recipient, 20 MB a day. Admins change them with `cli.js limits` (`bridge_admin_set_limits`); SQLite reads `AGENT_BRIDGE_RATE_PER_MIN` and friends. `check_inbox` and `wait_for_message` gained a `from_agent` filter, so spam can't bury a real message. New `cli.js delete-agent` cleans up after a revoked agent. | `R1-03` x4 (rate, backlog, byte budget, sender filter) |
| R1-04 | high | FIXED | Every body line is shown prefixed with `\| `, so a body can never start a line, and so can never fake a header or a `from:` line. Subjects must be one line (client check plus a SQL `CHECK`), and agent names are validated everywhere. | `R1-04` x3 (body, subject via client, subject via raw SQL) |
| R1-05 | medium | PARTLY FIXED | `wait_for_message` looks first and claims only if the caller is still there. `check_inbox` and `wait_for_message` hand claimed messages back (`bridge_unmark`) when the call was cancelled meanwhile. The default wait is now 50 s, under the MCP SDK's 60 s request timeout. **Still open:** if the HTTP response to the claim itself is lost after the database committed, the message is marked read and never shown again. Closing that needs an explicit acknowledgement protocol (deliver, then ack by id); that is scheduled for a later round. | `R1-05 a cancelled wait doesn't lose the message it was about to deliver` |
| R1-06 | low | FIXED | The hook command quotes every value with POSIX single quotes, so nothing in a path or URL is expanded. Re-running `init` also replaces a hook written in the old double-quoted format instead of stacking a second one; that came up while fixing this. | `R1-06 …`, cli `upgrading replaces a stage-1 hook …` |
| R1-07 | medium | FIXED | The mailbox file is created 0600 (SQLite gives `-wal`/`-shm` the same mode), an existing mailbox owned by you is tightened to 0600, and a directory the bridge creates is 0700. A directory you chose yourself is left alone. | `R1-07 the local mailbox is private to its owner` |
| R1-08 | low | FIXED | `peek` opens SQLite with a 1.5 s busy timeout, so a locked mailbox can't hold a prompt for 10 s. | `R1-08 the hook answers quickly even when the local DB is locked` |
| R1-09 | low | FIXED | Local agent names (`AGENT_NAME`, recipients, `from_agent` filters) must match `^[a-z0-9][a-z0-9_-]{0,39}$`, the same rule as Supabase. | `R1-09 local agent names are validated` |
| R1-10 | low | FIXED | Every message carries its thread's `max_hops`; replies use the thread's value, never the sender's. | `R1-10 a thread keeps the cap it was started with` |
| R1-11 | low | FIXED | The test database is UTF8 like Supabase, and the client counts code points the way `char_length` does. Two test-side bugs turned up while fixing this: the fake PostgREST corrupted multi-byte text split across request chunks, and SQL_ASCII had hidden it. | `R1-11 length limits count characters the same way on every layer` |
| R1-12 | low | FIXED | `fetch(..., { redirect: "error" })`, and any 3xx is refused with a clear message. | `R1-12 the client never follows a redirect` |
| R1-13 | low | FIXED | A malformed `thread_id` is refused right away, and `wait_for_message` only waits out `NetworkError`s (unreachable, timeout, 5xx). Every other error is reported immediately. | `R1-13 wait_for_message with a malformed thread_id fails fast` |
| R1-14 | low | FIXED | `init` refuses to write through a symlinked `.mcp.json`, `.claude` or `.claude/settings.local.json`. | `R1-14 init refuses to write through a symlink` |
| R1-15 | low | FIXED | The migration revokes all sequence privileges on `bridge_messages_id_seq` from `public`, `anon` and `authenticated`. | `R1-15 API roles have no privileges on the message id sequence` |

## Counts

| | |
|---|---|
| Fixed | 14 |
| Partly fixed (rest scheduled) | 1 (R1-05: a lost response *after* the claim commits) |
| Rejected | 0 |

## What the round taught

- The two high findings had nothing to do with the database's access control, which the round attacked hard and which held (see
  "Tried and held" in round-01.md). They came from the edges: what the receiving *model* reads (R1-04), and what one valid token can do
  inside its own permissions (R1-03). The next round should start there.
- Fixing the round surfaced four bugs in our own test setup, each of which had been hiding something:
  1. A SQL_ASCII test database hid the real length limits.
  2. The fake PostgREST corrupted text split across request chunks.
  3. An unhandled `pg` pool error crashed a suite after it had passed, which looked like flakiness.
  4. Our own quoting fix (R1-06) broke hook de-duplication. The existing CLI suite caught it.
- Defence in depth makes single-guard mutations survive. In R1-05 and R1-13, two independent guards each block the failure, so removing
  one alone changes nothing. Those mutations remove both together, and the docs say so.
