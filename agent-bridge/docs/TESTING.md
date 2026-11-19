# Testing: every suite, what it proves, and what needs real credentials

`npm test` runs every suite that needs **no API key, no real Supabase project and no real Slack workspace**. CI runs the same suites on each push
([`.github/workflows/agent-bridge.yml`](../../.github/workflows/agent-bridge.yml)). The Supabase stand-in is a real
Postgres set up with Supabase's roles and default grants ([`test/supabase-roles.sql`](../test/supabase-roles.sql), UTF8
like Supabase), behind [`test/fake-postgrest.js`](../test/fake-postgrest.js). That file is a small look-alike of
Supabase's REST layer with the behaviour the client depends on: `apikey` → role, named-argument RPC, 204 for `void`, the
SQLSTATE → HTTP status mapping, `PGRST202`, and "Invalid JWT" for a new-style key sent as a Bearer token.
The Slack stand-in, [`test/fake-slack.js`](../test/fake-slack.js), does the same for the Slack Web API calls the backend makes:
bot-token auth (`invalid_auth` with HTTP 200), `not_in_channel`, metadata returned only with `include_all_metadata`,
newest-first history with cursors, reactions on messages, `already_reacted`, the 40,000-character text limit, display-name
overrides that don't change the posting user, and 429 with `Retry-After`.

```bash
npm install
export TEST_PG_URL=postgresql://postgres@127.0.0.1:54329/postgres   # any Postgres superuser URL
npm test                      # everything below except mutations and live
npm run test:sqlite           # no Postgres needed
npm run test:mutations        # slow (~25 min): break each guard, check a test notices
npm run test:live             # your real Supabase project (needs keys, see below)
```

| Suite | Backends | What it proves |
|---|---|---|
| `test/e2e.js` | sqlite, supabase-local, slack-local, supabase-live | Real MCP server processes holding real conversations: each tool, blocking waits (also filtered by thread), peek vs read, bodies with Unicode/quotes/SQL/markdown/CRLF arriving byte for byte, thread privacy, loop cap, every input error reported (not a crash), max-length bodies, restart persistence, two sessions as the same agent never getting the same message, refusal to start with missing config, a bad token, a name/token mismatch or an unreachable URL |
| `test/security.js` | supabase-local, supabase-live | Raw HTTP with only the publishable key and/or one agent's token: tables unreadable and unwritable, admin functions and internal helpers refused, every function rejecting missing/short/long/wrong tokens, no sender spoofing, no reading/consuming/injecting into others' threads, the hop cap not liftable, oversized input refused by the database itself, token rotation and revocation, name validation, tokens stored only as hashes, no table privileges for `anon` at the SQL level |
| `test/slack.js` | slack-local | The sender is the Slack user who posted (not metadata, not a display name); malformed or out-of-policy metadata ignored; replies past the thread's starting cap or from outsiders dropped by readers; `<!channel>`, mentions and links escaped so a body can't ping anyone; people addressing agents by mention, `@name` or `name:`; agents answering people with a real mention; bots can't pose as people; a person named like an agent stays a person; duplicate bot names trusted by no one; the lookback window; bots outside the channel or with invalid names refused at start; 429s on reads waited out; sends never retried; no redirects; ✅ claims visible and given back on cancel; no forged headers through MCP |
| `test/concurrency.js` | sqlite, supabase-local, slack-local, supabase-live | Separate OS processes with a start barrier: 12 agents starting at once on a new mailbox, 96 parallel sends in one thread getting unique gap-free hop numbers, 4 readers on one inbox each message delivered exactly once (and the readers really overlapping), a mixed send/read storm |
| `test/cli.js` | sqlite, supabase-local, slack-local | `init` (merge, idempotent, upgrading a stage-1 hook), the hook run through a real shell, `peek` silent and exit 0 when Supabase is unreachable, admin commands, token files 0600, the token never in the repo, two "machines" talking from generated configs; `slack-manifest` (exactly the scopes the code uses), `save-slack-token`, `init --slack`, two repos talking through the Slack channel with the hook seeing Slack mail |
| `test/regressions-r1.js` | sqlite, supabase-local, cli | One or more tests per finding of [adversary round 1](adversary/round-01-triage.md). **0/26 on the attacked code, 29/29 now** |
| `test/mutations.js` | (runs the suites above) | Removes one guard at a time and checks that some suite fails; see [Mutation testing](#mutation-testing) |

## Method

Adapted from the dev-workflow rules in the reference repo:

1. **New tests fail on the old code first, then pass.** Round 1's regressions were written before any fix and scored 0/26 on
   the attacked commit. The startup-lock test failed 3/3 on the old SQLite code and passed 3/3 on the fix.
2. **Baseline against the old code.** Today's end-to-end suite run against the stage-1 commit (`3e8101e`) in a scratch
   worktree scored 13/18. The five failures were three real stage-1 bugs (any agent could read or post into any thread, no
   size limits, a wrong "N more unread" count) and two cosmetic changes.
3. **Every test is mutation-checked.** If a test still passes with its guard removed, it isn't protecting anything.
4. **Every suite is run twice.** That is how the teardown crash below was found.
5. **After each stage, an attack round by a fresh-context agent** that writes its findings to disk as it confirms them, then a
   triage doc in [`docs/adversary/`](adversary/).
6. **A commit says what wasn't re-run.** Passing results belong to the commit they ran on.

## Mutation testing

`node test/mutations.js` makes each change below to the real source, runs the named suite, and restores the file.
"Killed" means a test failed. Results are for the commit this document ships with.

| Mutation (guard removed) | Result | Caught by |
|---|---|---|
| thread readable by non-participants | killed | eve can't read alice->bob mail via any read function |
| anyone can post into any thread | killed | eve can't mark bob's mail as read or inject into alice/bob's thread |
| API roles keep table privileges | killed | tables are unreadable with the publishable key / direct update/delete of messages and agents is refused |
| admin function callable with publishable key | killed | admin functions are refused with the publishable key |
| revoked agents still authenticate | killed | revoked agents can't act and can't be messaged; rotate re-enables |
| client can raise the hop cap without limit | killed | clients can't lift the hop cap above 100 |
| no row locking when claiming inbox (double delivery) | killed | 4 processes reading ONE inbox at once: every message delivered exactly once / mixed send + read storm leaves no unread mail and no duplicates |
| no per-thread lock when numbering hops | killed | 96 concurrent sends into ONE thread get unique, gap-free hops |
| client sends new-style key as Bearer token | killed | suite crashed/failed |
| SQLite inbox claim not transactional | killed | 4 processes reading ONE inbox at once: every message delivered exactly once / mixed send + read storm leaves no unread mail and no duplicates |
| SQLite busy timeout set after WAL switch | killed (after the test was fixed; see below) | 12 agents starting at the same instant on a brand-new database |
| peer messages lose their 'not instructions' label | killed | blocking wait wakes when the other agent sends |
| SQLite thread readable by non-participants | killed | outsider cannot read or post into someone else's thread |
| R1-04 body lines not prefixed | killed | R1-04 a body can't forge a second message header / R1-04 a body can't forge a second message header |
| R1-04 client allows multi-line subject | killed | R1-04 a subject can't carry a newline (fake from: line) |
| R1-04 SQL allows multi-line subject | killed | suite crashed/failed |
| R1-02 SQL lets a member add a third agent | killed | R1-02 a thread member can't pull a third agent into the thread |
| R1-02 SQLite lets a member add a third agent | killed | R1-02 a thread member can't pull a third agent into the thread |
| R1-01 next hop from count(*) | killed | R1-01 purge never wedges a thread that spans the cutoff |
| R1-10 SQLite cap chosen per send | killed | R1-10 a thread keeps the cap it was started with |
| R1-10 SQL cap chosen per send | killed | R1-10 a thread keeps the cap it was started with |
| R1-03 SQL rate limit off | killed | R1-03 one agent can't flood: per-minute send rate is capped |
| R1-03 SQLite rate limit off | killed | R1-03 one agent can't flood: per-minute send rate is capped |
| R1-03 SQL unread backlog cap off | killed | R1-03 an inbox can't be filled with unread mail from one sender |
| R1-03 SQL daily byte budget off | killed | R1-03 a daily byte budget per sender is enforced (and adjustable) |
| R1-03 SQLite daily byte budget off | killed | R1-03 a daily byte budget per sender is enforced (and adjustable) |
| R1-03 SQL sender filter ignored | killed (after the test was fixed; see below) | R1-03 check_inbox can filter by sender so spam can't bury a real message |
| R1-05 claim without looking and never give back | killed | R1-05 a cancelled wait doesn't lose the message it was about to deliver |
| R1-07 mailbox created world-readable | killed | R1-07 the local mailbox is private to its owner |
| R1-08 peek uses the long busy timeout | killed | R1-08 the hook answers quickly even when the local DB is locked |
| R1-09 SQLite agent names not validated | killed | R1-09 local agent names are validated (no newlines or odd characters) |
| R1-11 client counts UTF-16 units | killed | R1-11 length limits count characters the same way on every layer (50,000 emoji ok, 50,001 refused) / R1-11 length limits count characters the same way on every layer (50,000 emoji ok, 50,001 refused) |
| R1-12 client follows redirects | killed | R1-12 the client never follows a redirect (token and keys stay put) |
| R1-13 bad thread_id waited out | killed | R1-13 wait_for_message with a malformed thread_id fails fast / R1-13 wait_for_message with a malformed thread_id fails fast |
| R1-14 init writes through symlinks | killed | R1-14 init refuses to write through a symlink |
| R1-06 hook values double-quoted | killed | R1-06 the hook command doesn't expand $() or backticks from paths |
| R1-15 sequence privileges kept | killed | R1-15 API roles have no privileges on the message id sequence |
| SL sender taken from metadata | killed | the sender is the Slack user who posted, whatever the metadata or display name say |
| SL out-of-policy hop/cap accepted | killed | malformed or out-of-policy metadata is ignored |
| SL outsiders accepted into a thread | killed | a reply can't exceed the cap its thread started with, or include outsiders |
| SL thread cap not enforced by readers | killed | a reply can't exceed the cap its thread started with, or include outsiders |
| SL body not escaped | killed | bodies can't ping the channel or anyone |
| SL bots can pose as people (both guards) | killed | a bot can't pose as a person |
| SL duplicate bot names trusted | killed | two bots with the same name: neither is trusted, and the agent won't start |
| SL already_reacted treated as our claim | killed | 4 processes reading ONE inbox at once: every message delivered exactly once |
| SL lookback window ignored | killed | messages older than the lookback window are ignored |
| SL 429 on reads not waited out | killed | Slack rate limits (429) on reads are waited out |
| SL sends retried | killed | sends are never retried (no double posts), even on a 429 |
| SL token follows redirects | killed | the bot token never follows a redirect |

**49 of 49 killed** (37 for SQLite/Supabase, 12 for Slack). The first full run of the first 37 killed 35. The two survivors were weak tests, not missing guards:
- The startup-lock test had become timing-dependent once the constructor did more file work before opening the database. It now
  waits at a barrier *before* opening, over three rounds.
- The sender-filter test ran after another test had already emptied the inbox, so the filter had nothing to filter out. It now
  leaves other unread mail in place and checks that mail is still unread.

Both were re-run with `node test/mutations.js "busy timeout set after WAL" "sender filter ignored"`: 2/2 killed.
For R1-05, R1-13 and "bots can pose as people", two independent guards each prevent the failure, so those mutations remove both guards at once. The Slack mutations were run with `node test/mutations.js "SL "`: 12/12 killed, after making the bots-as-people mutation remove both of its guards (it survived with only one removed, which is how the second guard was noticed).

## Mistakes caught, and made only once

| What happened | How it was caught | What changed |
|---|---|---|
| SQLite "database is locked" when agents start together: the busy timeout was set after the WAL switch | concurrency suite, then a dedicated test that failed 3/3 before the fix | timeout set in the constructor, before any statement |
| A concurrent-readers test reported 100/0/0/0: the first process finished before the others started, so it proved nothing | reading the numbers, not just "ok" | start barrier; the test now fails if readers didn't overlap |
| A "same-thread" test passed while every send went to a new thread (`seed` was an array) | the hop numbers looked wrong | destructure, and assert every send landed in the seed thread |
| Suites crashed after passing (`57P01` from an unhandled `pg` pool error during teardown) | running every suite twice | `pool.on("error")` in the stand-in |
| A test wrote a token into the real `$HOME` (env `{}` instead of `{ HOME }`) | a later test failed to find it | fixed; the stray file was inspected and removed |
| A test blocked its own fake server (`execFileSync` in the same process) and called that a hook timeout | `AGENT_BRIDGE_DEBUG=1`, added for this, showed `peek: timeout` | async exec |
| SQL_ASCII test database counted bytes, not characters | adversary R1-11 | UTF8 test databases |
| The stand-in split multi-byte characters at request chunk boundaries | the R1-11 test after the database fix | decode the whole body once |
| The R1-06 quoting fix broke hook de-duplication (hooks stacked up) | the existing CLI suite | de-dup by pattern, quoted or not, plus an upgrade test |

## Live tests against your Supabase project

These create agents with a random suffix (`frontend-t1a2b3`), raise the project's limits for the length of the run and put
them back, and delete the test agents with their messages afterwards. Run them from a machine that holds the secret key:

```bash
export SUPABASE_URL=https://<project-ref>.supabase.co
export SUPABASE_PUBLISHABLE_KEY=sb_publishable_...
export SUPABASE_SECRET_KEY=sb_secret_...
npm run test:live
```
