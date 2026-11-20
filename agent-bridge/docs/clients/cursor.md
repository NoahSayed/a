# Cursor

agent-bridge works in Cursor the same way it does in Claude Code: a project MCP server (`bridge`) plus an optional hook that
tells the agent when it has unread mail. Cursor's own docs (cursor.com) were not reachable while this was written, so every
fact below is marked **verified** (read in code Cursor ships, or in Cursor's own repositories, or exercised by
`test/clients-cursor.js`) or **reported** (from write-ups and issue threads, not confirmed here). The sources are at the end.

## Setup

```bash
node cli.js init ~/code/web web "React frontend" --client cursor --hook
# both tools in one repo:
node cli.js init ~/code/web web "React frontend" --client claude,cursor --hook
```

This writes, in the repo:

| File | What |
|---|---|
| `.cursor/mcp.json` | `mcpServers.bridge = { command, args, env }`, the same entry Claude gets in `.mcp.json` (absolute paths for this machine; the env carries token **file** paths, never a token) |
| `.cursor/hooks.json` | with `--hook`: `{"version": 1, "hooks": {...}}` with our unread-mail hooks (see below) |

Re-running `init` replaces only our entries: your other servers, other hooks, `version` and unknown keys stay; running it again
changes nothing. `.cursor`, `mcp.json` and `hooks.json` are never written through a symlink, and nothing is written if either
file has a shape we can't merge into (the error names the file and what is wrong; Cursor tolerates comments in `hooks.json`,
we don't, so a commented file has to be cleaned first).

**What you must do in Cursor** (init prints this as its `next (Cursor):` line):

1. Open the repo in Cursor. Go to **Cursor Settings > Tools & MCP** (older versions: **MCP**) and switch the `bridge` server on.
   Cursor does not start a project server until you do. *(reported; the menu name has changed between versions)*
2. Start a **new chat**. Hooks and MCP servers are picked up per chat/session. *(reported)*
3. Add `.cursor/mcp.json` and `.cursor/hooks.json` to `.gitignore` if you don't want machine-specific paths committed.

To remove it: delete the `bridge` entry from `.cursor/mcp.json` and the entries whose command contains `cli.js peek <name>` from
`.cursor/hooks.json`.

## The hooks, and why these events

Cursor runs a hook's `command` and expects **JSON on stdout** (verified: the hook engine parses stdout as JSON; plain text is
not an answer). `peek --format cursor --event <event>` therefore always prints one line of valid JSON and exits 0, whatever
happens: a broken bridge, an unreachable Slack, a bad `--set`, a dead proxy re-run all give the no-op answer, never an error and
never a block.

| Event | Default | Output | Status |
|---|---|---|---|
| `sessionStart` | on | `{"continue":true,"additional_context":"<unread note>"}` | `additional_context` verified in the hook engine and reported in Cursor's docs; fires when a new chat starts. Reported: fire-and-forget, not run in cloud agents |
| `beforeSubmitPrompt` | on | `{"continue":true,"additional_context":"<unread note>"}` | `continue` is documented. `additional_context` is **verified in the engine** (validator accepts it, the merge step collects it, it is attached to the user message) but the public docs list only `continue` / `user_message` for this event, and reports disagree about the IDE. If the IDE ignores it the hook is harmless and `sessionStart` still works. |
| `stop` | **off** (`--cursor-events sessionStart,beforeSubmitPrompt,stop`) | `{"followup_message":"..."}` only after a completed turn with unread mail | verified (below) |

Output with no mail: `{"continue":true}` (`sessionStart`, `beforeSubmitPrompt`) or `{}` (`stop`).

**Why `stop` is opt-in.** A follow-up makes the agent act on bridge mail without the user typing anything. That is what some
setups want ("when you finish, check your inbox") and a surprise for others, and mail comes from other agents. It is capped three
ways: Cursor's own `loop_limit` (written into `hooks.json` as `2`; Cursor's default is 5, `null` is unlimited), `peek` checks the
input's `loop_count` itself, and it only fires when `status` is `completed` (not after the user pressed stop, not after an
error) **and** an unread note exists (a Slack scan warning alone never wakes the agent). Reading the mail marks it read, so the
loop ends when the agent calls `check_inbox`. Without readable stdin there is no follow-up.

**Timeouts.** Each hook entry has `timeout: 10` (seconds; Cursor's default is 60). `peek` itself gives up on the bridge after 4 s.

Choose events with `--cursor-events` (comma-separated; unknown names are refused before anything is written). Re-running with a
different list removes our hooks from events no longer wanted.

### If the repo also has Claude Code set up

Cursor imports Claude Code hooks (Settings > Agents > Third-party imports; on by default, *reported*). Verified in the engine:
it reads `.claude/settings.json`, **`.claude/settings.local.json`** (where our Claude hook lives) and `~/.claude/settings.json`,
maps `UserPromptSubmit` to `beforeSubmitPrompt`, and runs them with the same JSON-on-stdin protocol. Our Claude hook prints
plain text; Cursor's engine treats that as an invalid answer and ignores it (reported: the IDE shows a parse error).

So `peek` detects Cursor: when it is run **without `--format`** and Cursor's environment variables (`CURSOR_PROJECT_DIR` or
`CURSOR_VERSION`, which Cursor's hook runner sets) are present, it reads the hook's JSON from stdin, and if that is Cursor's
(an event name like `beforeSubmitPrompt`, or `cursor_version`), it answers in Cursor's format. If `.cursor/hooks.json` already runs
our Cursor hook for that event, the imported one stays quiet (`{"continue":true}`) so the note isn't delivered twice. Claude
Code itself is untouched: without Cursor's variables `peek` never reads stdin, and if they leak into Claude's environment (a
terminal started by Cursor) Claude's own stdin (`hook_event_name: "UserPromptSubmit"`) is not mistaken for Cursor's.
Stdin reads are bounded: never a terminal, 300 ms, 4 MiB, never an error.

### Windows

*Verified in the engine:* on Windows Cursor does not use a POSIX shell. It builds a PowerShell script (`@'...'@ | & <command>`) and
sends the JSON input through it; on macOS/Linux it runs `<command> <<'CURSOR_HOOK_EOF' ... ` in a POSIX shell. *Reported:* imported
Claude hooks are wrapped in PowerShell but have been seen running under bash.

`hooks.json`'s `command` is one string, so there is no separate exec form. `init` therefore defaults to `--hook-form exec` on
Windows: no `VAR='x'` prefix, settings passed as `--set K=V` arguments, every word quoted for PowerShell (single quotes, doubled
inside), so a path like `C:\Users\O'Brien` works. On macOS/Linux the default is the shell form (POSIX single quoting; `exec`
there also works and is just env-free). **Untested on a real Windows Cursor:** `test/clients-cursor.js` checks the PowerShell
quoting as strings (and everything else on Linux/macOS); nothing here ran PowerShell. If the hook doesn't fire on Windows, run the
command from `.cursor/hooks.json` by hand in PowerShell first. Cursor also has an unverified special case for Windows where the
first word of the command is looked up with `.exe`/`.cmd` suffixes; we always give the full path of `node`.

## Naming the agent after the project folder (managed installs)

Everything above writes an explicit `AGENT_NAME`. For a machine-wide setup where the agent is named after the folder
(`AGENT_BRIDGE_NAME_FROM=project`, see README), the server needs the folder:

```json
{ "mcpServers": { "bridge": { "command": "node", "args": ["/opt/agent-bridge/server.js"],
  "env": { "AGENT_BRIDGE_NAME_FROM": "project", "AGENT_BRIDGE_PROJECT_DIR": "${workspaceFolder}" } } } }
```

`${workspaceFolder}` (and `${env:NAME}`) interpolation in `mcp.json` is *reported* in Cursor's docs; the interpolation code in the
SDK handles `${env:NAME}` and `${NAME:-default}` only and has no `workspaceFolder`, so verify it on your Cursor version. Without
`AGENT_BRIDGE_PROJECT_DIR` the server falls back to `CLAUDE_PROJECT_DIR`, then **`CURSOR_PROJECT_DIR`** (new; Cursor sets both for
hooks, *verified*; whether the IDE sets either for MCP servers is unverified), then the working directory.

## Limits

- **Tool timeout.** *Reported:* the Cursor CLI/ACP cuts an MCP tool call at about 60 s and it isn't configurable; the IDE allows
  longer calls. `wait_for_message` defaults to 50 s (max 600) and its description already says to keep `timeout_seconds` under the
  client's tool timeout, so the default is fine; in Cursor CLI don't ask for more than ~55. The SDK reads a per-server
  `startupTimeoutSec` (connect time only, max 300 s), nothing for tool calls.
- Hook context is text added to the conversation; the agent decides whether to call `check_inbox`. `sessionStart` only reaches a
  new chat, so in a long chat the mail note depends on `beforeSubmitPrompt` (if your IDE ignores `additional_context` there, enable
  `stop`, or tell the agent to poll `check_inbox`).
- `peek` for SQLite needs the agent name on the command line (`init` writes it); a nameless machine-wide hook is silent there.
- If `--client claude,cursor` hits a symlink in the Cursor files, Claude's files have already been written (each client is checked
  just before its own write; `--cursor-events` is validated first).

## Team and enterprise

*Verified in the engine's loader:* hooks come from, in order, enterprise (`/Library/Application Support/Cursor/hooks.json` on
macOS, `/etc/cursor/hooks.json` on Linux, `C:\ProgramData\Cursor\hooks.json` on Windows), team (distributed by the dashboard),
user (`~/.cursor/hooks.json`), project (`.cursor/hooks.json`), then the three Claude files above. A Claude-imported hook identical
(same event, same command string) to a Cursor one is dropped; ours differ, hence the stdin detection. Cursor refuses to load a
config whose path contains a symlink. Hooks may set `failClosed`; we never do (a broken bridge must not block anyone). An admin
who wants the hook everywhere can put the `command` from a generated `hooks.json` into the enterprise or team file, but note it
holds a per-machine path and agent name (not tested end to end; there is no `managed-config` for Cursor yet). MDM-managed
`mcp.json` (the loader has an enterprise location) and Cursor's team MCP allow-lists (a server's command line is matched against a
policy) were seen in the code but not exercised; if your team blocks unlisted servers, the allow-list must contain the
`node .../server.js` command line.

## Why there is no Cursor plugin

A plugin (`.cursor-plugin/plugin.json`, `mcp.json`, `hooks/hooks.json`, `skills/`) would install without `init`. It can't be made
correct today: our server must be launched with an absolute path to `node` and `server.js` on *this* machine, and a plugin is
fetched into a Cursor-managed directory, away from the agent-bridge install. `${CURSOR_PLUGIN_ROOT}` is expanded in plugin **hook**
commands (verified: Cursor's own plugins use it, and the engine substitutes it) and treated as a built-in in plugin MCP config
(the variable scanner skips it); whether the IDE expands it in plugin `mcp.json` is reported as *not* working. Even if it did, the
plugin would have to carry a full copy of agent-bridge with `node_modules`. The honest route is publishing agent-bridge as an npm
package and shipping a plugin whose `mcp.json` runs `npx` with `AGENT_BRIDGE_NAME_FROM=project`. Not done.

## Sources

Verified (read here):

- `@cursor/sdk` 1.4.2 on npm (github.com/cursor/cursor), file `dist/esm/977.js`: the hook engine. Per-event response validators
  (`sessionStart`: `env`, `additional_context`, `continue`, `user_message`; `beforeSubmitPrompt`: `continue`, `user_message`,
  `additional_context`; `stop`: `followup_message`), which events merge `additional_context`, the `hook_additional_contexts`
  field on user messages, exit code 2 = block, JSON parsing (whole stdout, else the last `{...}` suffix), failed/ignored when
  stdout is empty or not JSON unless `failClosed`, `timeout` (seconds, default 60), `loop_limit` (default 5, `null` = none) and
  `loop_count`, shell invocation (POSIX heredoc / PowerShell), env (`CURSOR_PROJECT_DIR`, `CLAUDE_PROJECT_DIR`, `CURSOR_VERSION`,
  `CURSOR_USER_EMAIL`, `CURSOR_TRANSCRIPT_PATH`, `CURSOR_PLUGIN_ROOT`), stdin fields (`conversation_id`, `generation_id`, `model`,
  `session_id`, `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`, `transcript_path`), hook sources and the
  Claude import paths, the Claude event mapping, the enterprise paths, symlink refusal, MCP stdio schema (`command`, `args`, `env`,
  `envFile`, `cwd`, `enabledTools`, `startupTimeoutSec`) and `${env:NAME}` interpolation. This is the SDK/CLI runtime; the IDE
  is believed to share the engine but that was not checked.
- github.com/cursor/plugins (Cursor's own plugins): `ralph-loop/hooks/hooks.json` and `hooks/stop-hook.sh` (stop input
  `status`/`loop_count`, output `followup_message`, empty output ends the loop, `"loop_limit": null`, `CURSOR_PROJECT_DIR`),
  `continual-learning/hooks/hooks.json` (`${CURSOR_PLUGIN_ROOT}` in a hook command), `ralph-loop/.cursor-plugin/plugin.json`
  (manifest shape), `third_party/*/mcp.json` (plugin `mcp.json` shape).
- npm `cursor-hooks` 1.1.6 (third-party typings of the docs as of Oct 2025): `hooks.json` is `{version: 1, hooks: {event: [{command}]}}`;
  that version predates `sessionStart` and `additional_context` and is out of date.
- `test/clients-cursor.js` (this repo): our hooks run through a stand-in for the runner described above.

Reported (not confirmed here; cursor.com was unreachable): `.cursor/mcp.json` project / `~/.cursor/mcp.json` global with the
project entry winning for a same-named server; `${workspaceFolder}` interpolation; Settings menu names; hooks reloaded per
chat; `sessionStart` fire-and-forget and absent in cloud agents; third-party hook import toggle in Settings > Agents; `additional_context`
on `beforeSubmitPrompt` in the IDE (docs and bundles disagree); CLI/ACP 60 s MCP tool timeout; imported Claude hooks under
PowerShell vs bash on Windows; `${CURSOR_PLUGIN_ROOT}` not expanded in plugin `mcp.json`.
