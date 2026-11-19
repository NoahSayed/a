# Portability notes (Linux, macOS, Windows; Node 22 and 24)

Written on Linux only. Windows and macOS behaviour below is from reading the code, the Node and Claude Code docs, and
reasoning; the CI matrix is what will prove it.

## How Claude Code runs hook commands (researched)

From the Claude Code hooks reference (code.claude.com/docs/en/hooks):

- A hook `command` in **shell form** is run with `sh -c` on macOS/Linux, **Git Bash on Windows**, or **PowerShell when
  Git Bash is not installed**. A per-hook `"shell": "bash" | "powershell"` field chooses explicitly.
- A hook with an **`args`** array is **exec form**: `command` is resolved as an executable and spawned directly, no shell.
  On Windows `command` must be a real executable (`node.exe` is; `.cmd` shims are not).
- There is **no per-hook `env` field**. Hooks inherit Claude Code's environment.

So the old hook (`AGENT_X='..' '/path/node' '/path/cli.js' peek name`) is POSIX-only: under PowerShell it is a syntax
error, and the quoting is only right for sh/Git Bash. Env assignments in front of a command have no portable form.

Fix: `init` has `--hook-form shell|exec`. Default is `shell` on macOS/Linux (unchanged, R1-06 quoting kept) and `exec`
on Windows. Exec form writes
`{ command: process.execPath, args: [cli.js, "peek", name, "--mcp", <repo>/.mcp.json] }`. `peek --mcp` reads
`mcpServers.bridge.env` from that file (string values only, `AGENT_DESCRIPTION` ignored) and uses it as the bridge
environment, exactly what the server itself is launched with. No env is inlined into settings, no shell is involved, so
there is nothing to expand (R1-06 holds by construction). Re-running `init` replaces a hook of either form (dedup matches
`command + args`). Tests: cli `--hook-form exec ...`, `switching hook form ...`, `peek --mcp ...`; regressions R1-06 runs
for both forms (shell form POSIX-only).

Caveat: exec form needs a Claude Code version that understands `args` (the docs do not say which). An older version
would ignore `args` and run bare `node` on Windows. `--hook-form shell` is available as an override (works under Git Bash).

## Issues found

| # | Where | What breaks | Fix |
|---|-------|-------------|-----|
| 1 | `cli.js` init hook (was ~l.309-313) | POSIX env-prefix + single quotes do not work in PowerShell (Windows without Git Bash) | exec form above |
| 2 | `store.js` `expandHome` | `p.startsWith("~")` also expanded `~foo` to `<home>foo`; `~\x` was handled by accident on Windows only | only `~`, `~/x` (and `~\x` on win32) expand; test `expandHome: ...`, mutation added |
| 3 | `test/cli.js`, `test/regressions-r1.js`, `test/harness.js` | tests set only `HOME`; on Windows `os.homedir()` reads `USERPROFILE`, so token files would be written to the real profile | `homeEnv()`/`baseEnv()` set both; `runCli` adds `USERPROFILE` whenever `HOME` is given |
| 4 | tests spawning with `env: { PATH, HOME }` | on Windows a child without `SystemRoot` can fail (sockets, crypto) | `baseEnv()` passes `SystemRoot` |
| 5 | `test/cli.js` / `regressions-r1.js` `statSync().mode` asserts (0600/0700) | NTFS has no POSIX bits (mode reads as 0666) | assert on POSIX; print a `skip` line with the reason on win32 |
| 6 | `test/cli.js` / R1-06 ran hooks via `bash -c` | on Windows runners `bash` on PATH can be the WSL launcher, not Git Bash; shell form is not what Windows writes anyway | `runHook` spawns exec-form hooks directly and uses `bash -c` only for shell-form hooks; R1-06 shell variant is POSIX-only |
| 7 | test cleanup `rmSync` | Windows keeps just-closed SQLite files / killed children's files busy (EBUSY/EPERM) | `rmrf()` with `maxRetries`/`retryDelay` |
| 8 | R1-14 symlink test | `symlinkSync` needs privilege on Windows | EPERM is reported as skipped (GitHub's Windows runner is admin, so it should run) |
| 9 | `cli.js` `process.exit()` after `console.log` | on some platforms piped stdout can be cut off by an immediate exit | `flush()` (empty write callbacks on stdout/stderr) before every exit. Not testable on Linux, hardening only |
| 10 | Line endings | a Windows checkout with `autocrlf` turns sources and `migration.sql` into CRLF | `agent-bridge/.gitattributes`: `* text=auto eol=lf`. Token files and `.mcp.json` read back are `trim()`med; `save-token` test feeds `\r\n` |

## Checked, no change needed

- `stores/sqlite.js`: `chmodSync`/`mkdirSync(mode)` do not throw on Windows (mode is mostly ignored); `process.getuid?.()`
  is `undefined` there and `statSync().uid` is 0, so the "tighten an existing mailbox" branch never runs. The mailbox lives in
  the user profile (`%USERPROFILE%\.agent-bridge`), protected by its inherited ACL; the bridge does not set ACLs.
- `Atomics.wait` sleep in `stores/sqlite.js` is allowed on the main thread in Node (only browsers forbid it), on all platforms.
- `node:sqlite`: unflagged from 22.13; still printing an ExperimentalWarning on 22/24, which `process.emitWarning`
  filtering (matches "SQLite") suppresses. `DatabaseSync({ timeout })` only exists from 22.16, but the code also sets
  `PRAGMA busy_timeout` explicitly so 22.13-22.15 behave the same.
- `.mcp.json`: `command: process.execPath`, `args: [server.js]` are JSON strings; backslashes and spaces are fine. No code
  splits paths on `/` (checked `grep split("/")`). `HERE` comes from `fileURLToPath`.
- No signal handling in `server.js`; tests end servers by closing stdin or `kill()` (TerminateProcess on Windows is fine for
  the one place it is used, R1-08's lock holder).
- Temp dirs use `os.tmpdir()`, nothing assumes `/tmp`.

## Could not verify (needs CI)

- Everything on macOS and Windows, and Node 24 (only Node 22.23 was available).
- That `bash` is not needed anywhere on Windows now (exec-form hooks only); on macOS `bash` is used for shell-form hooks.
- R1-08 (hook answers fast while another process holds an EXCLUSIVE lock) on Windows: mandatory file locking may make
  `peek` fail at open instead of at the first statement; it is expected to still exit 0 within the limit.
- The 16-process "brand-new database" race and the concurrent-reader suites on Windows SQLite WAL.
- Real Claude Code on Windows: exec-form hook support by version, and whether Claude Code needs `${CLAUDE_PROJECT_DIR}`
  style paths (we write absolute paths).

## CI matrix

`.github/workflows/agent-bridge.yml`, `fail-fast: false`, npm cache on, Node 22 and 24:

- **test-linux** (`ubuntu-latest`, Postgres 16 service, 20 min): e2e `sqlite supabase-local slack-local`, security,
  slack, concurrency `sqlite supabase-local slack-local`, cli, regressions. Same as before.
- **test-portable** (`macos-latest`, `windows-latest`, 30 min, `AGENT_BRIDGE_TEST_NO_PG=1`): e2e `sqlite slack-local`,
  slack, concurrency `sqlite slack-local`, cli, regressions.

`AGENT_BRIDGE_TEST_NO_PG=1` (read in `test/backends.js` as `NO_PG`): `test/cli.js` skips its Supabase section,
`test/regressions-r1.js` runs only its sqlite section plus the CLI regressions, and requesting `supabase-local` by name
throws instead of silently skipping. The Linux job never sets it. `test/security.js` is Postgres-only and not run
off-Linux. Postgres-free replacements for the token-file / `init --supabase` checks live in cli's
"portability" section so macOS/Windows still cover them.
