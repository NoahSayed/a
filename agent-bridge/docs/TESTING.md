# Testing: every suite, what it proves, and what needs real credentials

`npm test` runs every suite that needs **no API key and no real Supabase project**. CI runs the same suites on each push
([`.github/workflows/agent-bridge.yml`](../../.github/workflows/agent-bridge.yml)). The Supabase stand-in is a real
Postgres set up with Supabase's roles and default grants ([`test/supabase-roles.sql`](../test/supabase-roles.sql), UTF8
like Supabase), behind [`test/fake-postgrest.js`](../test/fake-postgrest.js). That file is a small look-alike of
Supabase's REST layer with the behaviour the client depends on: `apikey` → role, named-argument RPC, 204 for `void`, the
SQLSTATE → HTTP status mapping, `PGRST202`, and "Invalid JWT" for a new-style key sent as a Bearer token.

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
| `test/e2e.js` | sqlite, supabase-local, supabase-live | Real MCP server processes holding real conversations: each tool, blocking waits (also filtered by thread), peek vs read, bodies with Unicode/quotes/SQL/markdown/CRLF arriving byte for byte, thread privacy, loop cap, every input error reported (not a crash), max-length bodies, restart persistence, two sessions as the same agent never getting the same message, refusal to start with missing config, a bad token, a name/token mismatch or an unreachable URL |
| `test/security.js` | supabase-local, supabase-live | Raw HTTP with only the publishable key and/or one agent's token: tables unreadable and unwritable, admin functions and internal helpers refused, every function rejecting missing/short/long/wrong tokens, no sender spoofing, no reading/consuming/injecting into others' threads, the hop cap not liftable, oversized input refused by the database itself, token rotation and revocation, name validation, tokens stored only as hashes, no table privileges for `anon` at the SQL level |
| `test/concurrency.js` | sqlite, supabase-local, supabase-live | Separate OS processes with a start barrier: 12 agents starting at once on a new mailbox, 96 parallel sends in one thread getting unique gap-free hop numbers, 4 readers on one inbox each message delivered exactly once (and the readers really overlapping), a mixed send/read storm |
| `test/cli.js` | sqlite, supabase-local | `init` (merge, idempotent, upgrading a stage-1 hook), the hook run through a real shell, `peek` silent and exit 0 when Supabase is unreachable, admin commands, token files 0600, the token never in the repo, two "machines" talking from generated configs |
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

MUTATION_RESULTS

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
