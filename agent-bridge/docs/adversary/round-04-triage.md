# Round 4 triage

Round 4 was run by a fresh-context agent against commit `313359c`, in a separate clean checkout. It covered the new
multi-client code: the Claude Code, Cursor and Codex writers, the skill, `peek` as a Cursor/Codex hook, `doctor <repo>`
per client, and the tool annotations. Findings: [round-04.md](round-04.md), **13, all confirmed by running them** (R4-12 at
string level only: no PowerShell here): 0 critical, 0 high, 5 medium, 8 low. Repro scripts:
[round-04-scripts/](round-04-scripts/).

**All 13 are fixed.** Tests: [test/regressions-r4.js](../../test/regressions-r4.js), **1/15 on the attacked code** (the one
pass is the "a mailbox under ~/.agent-bridge is still checked" guard, which should pass before and after), **15/15 now**.

| id | severity | fix | mutations |
|---|---|---|---|
| R4-01 | medium | `init` plans every tool's files (and skills) into one transaction and writes only when every step succeeded; each file goes to a temporary name and is renamed into place. The "wrote ..." lines are printed after the writes | each tool writes at once |
| R4-02 | medium | `doctor <repo>` opens (and so creates, chmods, converts) the mailbox only if the repo's path is under `~/.agent-bridge/` and isn't a symlink; otherwise it says it skipped it and how to check it from the shell | opens a mailbox anywhere |
| R4-03 | medium | One `isSecretSupabaseKey` (an `sb_secret_` key or a JWT whose role is `service_role`) used by `init`, `managed-config` and `doctor`; `init --supabase` refuses before writing anything. This also closes R3-07's JWT half | init writes the key; JWT not recognised |
| R4-04 | medium | Every writer lists hooks and MCP servers it didn't write, in a WARNING ("read them before you trust the project"). No more "Trust all": the user is told to trust the agent-bridge hook by its command. Codex approvals in the bridge entry (`default_tools_approval_mode`, `[mcp_servers.bridge.tools.*]`) are dropped, with a note | approvals kept; foreign entries not reported |
| R4-09 | medium | `list_agents` caps descriptions (500) and project dirs (300) when stored and when shown; its tool description, the server's instructions and the skill say these are peer data, not instructions | no display cap; no peer-data label |
| R4-05 | low | Every client's `readServerEnv` returns `{ error }` instead of throwing, so another tool's unreadable file doesn't stop `init` | readServerEnv throws |
| R4-06 | low | One `readText` for repo config files: refuses symlinks and non-regular files, opens with `O_NOFOLLOW`/`O_NONBLOCK`, re-checks the opened file, reads at most its `fstat` size | (four independent layers; no single removal is observable, see below) |
| R4-07 | low | The Claude writer checks shapes like the others (`.mcp.json`, `mcpServers`, `hooks`, `UserPromptSubmit`); a SKILL.md that differs from ours is kept as `SKILL.md.bak` | three |
| R4-08 | low | Repo config files over 1 MiB are refused before parsing; errors from the TOML editor (a `RangeError` from 100,000 dotted keys) are reported like parse errors | no size cap |
| R4-10 | low | `docs/clients/codex.md` and `init`'s message now say what Codex really asks (only `send_message`), and the regression test checks the doc against that | (doc test) |
| R4-11 | low | `resolveIdentityEnv` no longer uses an inherited `CURSOR_PROJECT_DIR`. As a Cursor hook, `peek` passes the absolute workspace folder from Cursor's hook input as `AGENT_BRIDGE_PROJECT_DIR` | inherited variable names the agent; relative workspace used |
| R4-12 | low | One shared PowerShell quoting function (`psq` in `clients/common.js`) for Cursor and Codex: typographic single quotes doubled, `"` and control characters refused | typographic quotes not doubled |
| R4-13 | low | `--name=value` works for every value option; an unknown or misspelled option is an error (except for `peek`, which runs as a hook and must never fail loudly) | both |

Mutations: 30 new or retargeted for this round, **all killed** after two test gaps the first run exposed were closed
(a `{"hooks":[]}` settings file, and a description stored by another client bypassing the server's own cap). The
R4-06 layers have no individual mutations: removing any one of the four leaves the others refusing the file, and a
device reads as 0 bytes because the read is bounded by the opened file's size.

## What the trend says

| Round | Critical | High | Medium | Low |
|---|---|---|---|---|
| 1 | 0 | 2 | 4 | 9 |
| 2 | 0 | 0 | 5 | 10 |
| 3 (new code: DLP, proxy, doctor, managed) | 0 | 2 | 7 | 10 |
| 4 (new code: Cursor, Codex, skill) | 0 | 0 | 5 | 8 |

The attacker found no way to execute code through the new writers: POSIX quoting of every hook form held, the TOML
editor survived 21 merge shapes, hook output is always JSON-encoded, and R3-04's fix held. What it found was about
**trust boundaries around files a cloned repo controls** (what init keeps, what doctor opens, what a hook reads) and about
being exact with users (wording, flags). Round 3's open items (DLP gaps and the rest, see
[round-03-triage.md](round-03-triage.md)) are still open, except R3-07's service_role half, closed here.
