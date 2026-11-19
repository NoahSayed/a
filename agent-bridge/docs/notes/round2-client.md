# Round 2, client side: R2-06, R2-07, R2-08, R2-11, R2-12

Findings are in [../adversary/round-02.md](../adversary/round-02.md). The relay findings (R2-01 to R2-05, R2-09, R2-10,
R2-13 to R2-15) are fixed elsewhere. README.md, docs/TESTING.md, relay.js and relay-audit.js were not touched.

Regression tests: `node test/regressions-r2-client.js` (20 tests). Run on the code the round attacked (the original `b7159a8`
sources with only the new test files and the extended fake Slack copied in) it scored **1 of 20**: every test failed except
the one that checks `peek --set` still refuses `NODE_OPTIONS` (that guard already held; the test exists so the R2-12 change can't
loosen it). On the fixed code it passes 20 of 20. Mutations: `node test/mutations.js "R2-06" "R2-07" "R2-08" "R2-11" "R2-12"`.

| id | outcome | fix | tests | mutations |
|---|---|---|---|---|
| R2-06 | FIXED | `init --hook` filters the hooks *inside* each matcher group and drops a group only if it ends up empty; the group's `matcher` and every other hook survive | `R2-06 ...` x2 (shell and exec form): a group `[user hook, old shell hook, lint hook, old exec hook]` keeps exactly the user's two; an all-ours group goes; unrelated groups are untouched | drops the whole group; loses the matcher |
| R2-07 | FIXED | see below | 7 tests | 13 |
| R2-08 | FIXED | a username shared by several channel members makes a sender ambiguous: the message is ignored, counted and reported (never `human:<name>`) | `R2-08 ...` | accepted as one human; ignored silently |
| R2-11 | FIXED | token shape and file checks before any request, see below | 6 tests | 5 |
| R2-12 | FIXED | `peek` re-runs itself once with the settings in the child's environment, see below | 4 tests | 4 |

## R2-07: Slack scan completeness and reader-side limits

* **Whole window, higher cap.** `scan()` pages through `conversations.history` until Slack says there is no more, up to
  `AGENT_BRIDGE_SLACK_MAX_PAGES` pages (default **500** x 200 = 100,000 messages; was a hard 20). The attacker's 4,100 posts are 21 pages.
* **429.** Each history call is retried 4 times and honours `Retry-After` (up to 30 s). If Slack keeps rate-limiting after the first
  page, the scan stops there and counts as cut short (it does not throw away what it read); a 429 on the very first page is an error as before.
* **Cut short is loud.** `SlackStore.scanWarnings()` returns the problems with the latest scan. `whoami` gets a `warnings` array (only
  when non-empty), `check_inbox` appends `WARNING: ...` lines and, when nothing was found, says *"No unread messages in the part of
  the channel that was scanned."* instead of `Inbox empty.`; `wait_for_message` appends them too; the `peek` hook prints them;
  `doctor` runs a scan and reports `Slack channel scan` (OK with the page and message counts, or WARN with the text). The text names the
  oldest timestamp covered (the window start, or the oldest message actually read when the cap/429 cut the scan) and the variable to raise.
* **Replies whose thread start is out of reach.** A reply (hop > 1) whose thread start is older than what the scan covers, and that
  involves this agent, is counted and reported ("N message(s) in threads that started before ... were ignored"). A reply to a thread
  that never existed (start inside the covered range) is still dropped silently, as before: that is a forgery, not a loss.
* **R1-03 limits on Slack, applied by every reader**, oldest first, before the thread rules so an ignored message never starts a thread:
  * per sender, at most `AGENT_BRIDGE_RATE_PER_MIN` (default 60) accepted messages in any 60 s window;
  * per sender and recipient, at most `AGENT_BRIDGE_MAX_UNREAD` (default 200) accepted messages the recipient has not claimed (✅ by
    the recipient's bot). Because claimed messages stop counting, the backlog drains: after the recipient reads 100 of 250, 150 are visible.
    Mail to a person is not limited by backlog (nobody claims it), only by rate;
  * ignored messages are counted per sender and reported (`Ignored 50 message(s) from eve: more than 200 unread ...`).
  The daily byte budget of R1-03 is not applied on Slack (Slack's own 40,000-character message limit and the 30,000 body limit stay).
  The limits are the reader's view: unlike a server they cannot refuse the post, so a flood stays visible in the channel for people.
* Claim (✅) and identity semantics are unchanged; `test/slack.js` passes unmodified.

## R2-11: only a token is sent as the token

`readSecret(env, name, { shape })` in `store.js`. For the agent token (`AGENT_BRIDGE_TOKEN`, used by the Supabase and relay backends) the value
must match `^abt_[0-9a-f]{64}$`; for the Slack bot token `^xoxb-[A-Za-z0-9-]+$`. This applies to the variable and to the file. A token file must also be a regular file of at most
4 KiB, and on POSIX must not be accessible to "other" users (`mode & 0o007`): it is **refused** (not just warned), the same bar at which `doctor`
reports FAIL (group-readable stays a doctor WARN and works). Windows has no POSIX bits; the check is skipped there as in `doctor`.
Errors name the variable and path, never the contents, and happen in `createStore`, i.e. before any request, in the server, `peek`,
the CLI and `doctor`. `doctor` now uses the same readers for its probe, FAILs on a token of the wrong shape (was WARN) and does not
probe with a file it would refuse. `readSecret` without `shape` (admin and auditor keys) is unchanged.
Consequence for users: a token file that is 0644 now stops the server with `... is accessible by other users ... chmod 600`.
Two existing tests wrote token files with the default mode and were changed to 0600 (`test/cli.js` custom token file), and
`test/doctor.js` expects FAIL instead of WARN for a malformed token file.
Not done (suggested in the finding, optional): refusing non-loopback `http://` (already done by `assertSecureUrl` since the hardening round) and
requiring token files to live under `~/.agent-bridge/`.

## R2-12: exec-form hooks behind a proxy and a private CA

Node reads `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA` and `NODE_USE_ENV_PROXY` once at start, so `process.env` assignments inside `peek` do not
work. Options checked on Node 22.23.5: `http.setGlobalProxyFromEnv` does **not exist** (it arrived in 24.14 / 25.4, outside the supported
floor of 22.13); `tls.setDefaultCACertificates` exists from 22.19 / 24.5 only. Neither covers the whole supported range, and neither
covers `fetch()`'s proxy on 22.13-22.20 either, so `peek` re-runs itself:

* `PEEK_ENV_KEYS` is unchanged. A second, separate list `PEEK_PROCESS_KEYS` holds `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`,
  `NODE_USE_ENV_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy`, `http_proxy`, `NO_PROXY`, `no_proxy`. `peek --set` accepts keys from
  either list and nothing else (`NODE_OPTIONS`, `LD_PRELOAD`, `AGENT_BRIDGE_TOKEN` and the guard variable are refused, and the whole peek stays silent).
* If any process key was set and `AGENT_BRIDGE_PEEK_REEXEC` is not `1`, `peek` runs `spawnSync(process.execPath, [cli.js, ...same args], { env: { ...process.env, ...those keys, AGENT_BRIDGE_PEEK_REEXEC: "1" }, timeout: 9000 })`
  once, forwards its output and exits 0. The child sees the guard and does not spawn again. Without process keys (or on shell-form hooks, which already
  carry them as an env prefix) nothing changes and there is no extra process.
* `init --hook-form exec` now writes these keys into the hook's `--set` arguments (they come from the shell's proxy settings that `init` already
  copies into `.mcp.json`).
* Test: a TLS-inspecting forward proxy (`test/forward-proxy.js`, extracted from `test/proxy.js`, which now imports it) in front of the fake Slack, a
  private CA made with openssl, `init --slack --hook --hook-form exec`, and the hook spawned the way Claude Code does with an environment that has
  no proxy or CA. It prints the unread note and the proxy saw the requests. Dropping the CA from the arguments, dropping the proxy
  settings, or presetting the guard each make it silent with no (or no successful) request. Skipped with a reason without openssl or on a Node without `NODE_USE_ENV_PROXY` (< 22.21).

## Left open / notes

* The re-exec guard cannot be mutation-tested: a mutant that ignores it makes `peek` spawn itself without end, so there is none. The test that
  presets the guard (no re-exec, no request) covers the behaviour; the loop is bounded in practice by the guard being set in the child's environment.
* Doctor and `peek` build the Slack store without the server's `identify()` retries; a 429 there is reported like any other network error.
* R2-06: the dedup pattern still matches any hook command that contains `cli.js peek <name>` (e.g. an `echo` that mentions it). Tightening it would stop
  replacing hooks written by older installs from other paths, so it was left.
* The Slack reader limits are per scan (stateless), so a very busy channel costs up to 500 history calls per poll; `wait_for_message` polls every 3 s.
  If that is too heavy for a big channel, lower `AGENT_BRIDGE_LOOKBACK_HOURS`. An incremental scan with a cursor in memory would be the next step.
* Windows/macOS were not run (Linux only): the POSIX mode checks are skipped on win32, the exec-form hook test uses `execFile` and `baseEnv`/`homeEnv`.
