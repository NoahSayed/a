# OpenAI Codex CLI

`init --client codex` wires a repo for the [Codex CLI](https://github.com/openai/codex) the same way `init` wires it for
Claude Code: an MCP server entry, and with `--hook` an "unread mail" hook.

Everything here was checked against the Codex source (`codex-rs/`, paths below are relative to it) and against the real
binary, codex-cli **0.171.0**. Where something could not be checked it says so.

## Setup

```bash
node cli.js init ~/code/frontend frontend "React app, owns the login UI" --hook --client codex
# both tools in one repo:
node cli.js init ~/code/frontend frontend "React app" --hook --client claude,codex
```

It writes two files into the repo:

| File | What |
|---|---|
| `.codex/config.toml` | `[mcp_servers.bridge]`: `command` (this Node), `args` (`server.js`), `env` (agent name, backend settings, token *file* paths), `cwd` (the repo), `tool_timeout_sec = 660` |
| `.codex/hooks.json` (with `--hook`) | one `UserPromptSubmit` command hook running `cli.js peek <name> --format codex` |

Then, in the repo:

1. Start `codex`. **Trust the project** when it asks (or add `[projects."/path/to/repo"] trust_level = "trusted"` to
   `~/.codex/config.toml`). Codex ignores a project's `.codex/` (MCP servers, hooks, exec policy) until then. Checked with the
   real binary: `codex mcp list --json` prints `[]` for an untrusted project.
   Trust is recorded for the git root, or for the folder Codex was started in when there is no git root
   (`config/src/project_trust.rs`, `config/src/loader/mod.rs:1156`).
2. With `--hook`: Codex shows **"Hooks need review"** on start-up. Open `/hooks` and trust the agent-bridge entry (its
   command runs `cli.js peek <name>`). Use "Trust all" only if you have read every hook in `.codex/hooks.json`: a cloned
   repo can ship its own, and `init` keeps them (it prints a WARNING listing each one). Until then the hook is listed but does **not** run. `init` cannot do this for you, by design: trust
   is stored in the user's own `~/.codex/config.toml` (`[hooks.state."<key>"] trusted_hash`), and Codex reads hook trust only
   from the user and session layers, never from a project file (`hooks/src/config_rules.rs`).
3. `send_message` asks for approval before it sends; the other tools run without asking (see "Approvals").

`.codex/config.toml` holds absolute paths for this machine, so you probably want `.codex/` in `.gitignore`. As with
`.mcp.json`, a committed project config that names a command is something every collaborator who trusts the project will run.

Re-running `init` for the same agent replaces the entry and the hook; it does not duplicate them (see "Merging").

## What was verified, and where

| Question | Answer | Source |
|---|---|---|
| Where do project hooks live? | Either `.codex/hooks.json` or a `[hooks]` table in `.codex/config.toml`. Both are read; with both present Codex warns "prefer a single representation" but loads both. `init` uses `hooks.json`. | `hooks/src/engine/discovery.rs` (`discover_handlers`, `load_hooks_json`, `load_toml_hooks_from_layer`) |
| hooks.json shape | `{ "hooks": { "UserPromptSubmit": [ { "hooks": [ { "type": "command", "command": "...", "timeout": 10, "statusMessage": "..." } ] } ] } }`. Top level accepts only `description` and `hooks` (unknown keys are an error). Handler keys: `command`, `commandWindows`, `timeout` (seconds), `async`, `statusMessage`, `additionalContextLimit`. | `config/src/hook_config.rs:14`, `protocol/src/hooks.rs` |
| Same hook as TOML | `[[hooks.UserPromptSubmit]]` + `[[hooks.UserPromptSubmit.hooks]]` with the same keys | `protocol/src/hooks.rs` (same serde types) |
| How is a hook command run? | As **one string** handed to a shell; there is no argv/exec form. The shell is the session's shell: `sh`/`bash`/`zsh` with `-c` on macOS and Linux, PowerShell (`-NoProfile -Command`) or `cmd /c` on Windows. With no shell known it falls back to `$SHELL -lc` (`/bin/sh`), or `%COMSPEC% /C`. | `hooks/src/engine/command_runner.rs:448` (`build_command`), `core/src/session/mod.rs:6371`, `core/src/shell.rs:24` |
| Hook environment, cwd, stdin | The session's environment (minus Codex-internal variables), the session's working directory, and one JSON document on stdin: `cwd`, `hook_event_name`, `model`, `permission_mode`, `prompt`, `session_id`, `transcript_path`, `turn_id`. | `command_runner.rs`, `hooks/schema/generated/user-prompt-submit.command.input.schema.json` |
| What does a `UserPromptSubmit` hook print? | Exit 0 and empty stdout: nothing happens. JSON `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"..."}}`: the text is added to the model's context. Plain text is also accepted as context, **unless it starts with `{` or `[`**, in which case Codex tries to parse it as JSON and reports "hook returned invalid user prompt submit JSON output". Claude Code's plain `[agent-bridge] ...` text starts with `[`, so the Codex format must be JSON. Exit 2 blocks the prompt; any other non-zero exit is a (non-blocking) hook failure. | `hooks/src/events/user_prompt_submit.rs:159-250`, `hooks/src/engine/output_parser.rs:266,360` |
| Default hook timeout | 600 s. `init` sets 10 s. | `discovery.rs` (`normalize_command_hook`) |
| How is a new hook trusted? | A hook from a user-editable layer runs only when its hash is recorded as trusted. The key is `<file>:<event>:<group index>:<handler index>`; the hash covers the event, matcher and handler. Untrusted or changed hooks are listed (`trustStatus` `untrusted` / `modified`) but not run. The user trusts them in the start-up prompt ("Hooks need review" / "Trust all and continue" / "Continue without trusting (hooks won't run)") or in `/hooks`. | `discovery.rs:850-940`, `config_rules.rs`; prompt wording from the 0.171.0 binary (the TUI source is not in the checkout) |
| MCP server environment | **Not** the parent's. Codex starts a stdio server with only `HOME LOGNAME PATH SHELL USER LANG LC_ALL TERM TMPDIR TZ` (a longer list on Windows), the custom-CA variables, any names listed in `env_vars`, and then the entry's `env` table, which is merged on top (entry wins). So `AGENT_NAME`, `CLAUDE_PROJECT_DIR`, proxy settings etc. from your shell do **not** reach the server. | `rmcp-client/src/utils.rs:16`; verified with the real binary |
| MCP server working directory | The entry's `cwd` if set, otherwise the session's working directory (the folder Codex was started in, which may be a sub-folder of the repo). `init` sets `cwd` to the repo so `list_agents` shows the repo whichever folder Codex was started in. | `rmcp-client/src/stdio_server_launcher.rs:454-473`, `core/src/session/mcp_runtime.rs:88`; verified |
| MCP timeouts | `startup_timeout_sec` default 30, `tool_timeout_sec` default **300**. | `codex-mcp/src/rmcp_client.rs:124-125`, `connection_manager.rs:599` |
| Approval for MCP tool calls | In the default mode a tool call needs approval unless the tool declares `readOnlyHint: true` (or both `destructiveHint` and `openWorldHint` false). The bridge's annotations (in `server.js`): `whoami`, `list_agents`, `get_thread` are read-only; `check_inbox` and `wait_for_message` are not destructive and not open-world; `send_message` is open-world. So in Codex only `send_message` asks, until you choose "always allow". That answer is stored as `[mcp_servers.bridge.tools.<tool>] approval_mode = "approve"` in the **project's** `.codex/config.toml`. | `core/src/mcp_tool_call.rs:2878` (`requires_mcp_tool_approval`), `:2758-2830` (persisting) |
| Which project-config keys are ignored | `openai_base_url`, `chatgpt_base_url`, `model_provider(s)`, `notify`, `profile(s)`, `otel` and a few realtime URLs are dropped from a project's config. MCP servers and hooks are not. | `config/src/loader/mod.rs:104` |

### `tool_timeout_sec = 660`

`wait_for_message` blocks for up to `timeout_seconds` (default 50, at most 600). Codex abandons a tool call after
`tool_timeout_sec`, default 300, so a 600 s wait would be cut off. `init` writes 660: the longest wait plus a minute for
the store round trip. The model's default (50 s) never gets near either limit. `startup_timeout_sec` is left at Codex's 30 s;
add `startup_timeout_sec = 60` to the entry if your machine is slow to start Node (`init` keeps keys it does not own).

### Hooks on Windows (not verified)

Codex's Windows default shell is PowerShell, so `init` writes `& 'C:\...\node.exe' 'C:\...\cli.js' 'peek' ...` there. With
`--hook-form shell` (which means "the other shell" on Windows, where the default form is `exec`) it writes the
cmd.exe form, `"node.exe" "cli.js" ...`. Values that cannot be quoted safely (a `"` for PowerShell; `"`, `%` or a trailing
backslash for cmd.exe) make `init` stop instead of writing something that could be re-interpreted. The quoting functions are
unit-tested on every platform, but no Windows machine was available to run Codex itself: treat the Windows hook as untested.

On macOS and Linux the form is POSIX single quotes, which sh, bash and zsh read the same way. There is no `VAR=value`
prefix (that syntax does not exist in PowerShell or cmd); the backend settings travel as `--set KEY=VALUE` arguments, which
`peek` accepts only for bridge settings.

## Merging with a config you already have

`init` edits only `[mcp_servers.bridge]` and leaves every other byte of `.codex/config.toml` alone: comments, order, other
servers, `[projects]`, `[tui]`, line endings and a byte-order mark. It finds the entry with a small TOML scanner, so a line
that only looks like `[mcp_servers.bridge]` inside a multi-line string or array is not mistaken for it. The edited file is
then parsed with [smol-toml](https://github.com/squirrelchat/smol-toml) (pinned to an exact version, no dependencies) and
init checks that the entry reads back exactly as intended **and that nothing outside it changed**; otherwise it writes
nothing. Both files are validated before either is written.

Inside the entry `init` owns `command`, `args`, `env`, `cwd` and `tool_timeout_sec` (and drops the keys of another transport,
`url` and friends, which Codex rejects next to `command`, and an `[mcp_servers.bridge.env]` sub-table). It also **drops
approvals**: `default_tools_approval_mode` and `[mcp_servers.bridge.tools.*] approval_mode`, because a cloned repo could
ship them so that sending never asks (round 4, R4-04); `init` says when it removed them, and Codex asks again. Everything
else is kept: `startup_timeout_sec`, `enabled_tools`, `env_vars`. Files over 1 MiB, symlinks and anything that isn't a
regular file are refused.

`init` refuses (and says why) when the existing file does not parse, when the entry is written with dotted keys or an
inline table (`mcp_servers.bridge.command = ...`, `bridge = { ... }`), or when it is an array of tables. Rewrite it as a
`[mcp_servers.bridge]` table and run `init` again.

`hooks.json`: only the hook for this agent is replaced, **in place** (Codex's trust record is keyed by position, so an
approved hook stays approved when nothing changed); other hooks, other events and other agents' hooks stay.

## Approvals and what to expect

* Only `send_message` asks for approval (see the annotations above); the read tools run without asking. "Always allow" is
  remembered in `.codex/config.toml`. `codex exec` (non-interactive) cannot ask, so to let it send, add
  `default_tools_approval_mode = "approve"` to `[mcp_servers.bridge]` yourself, after `init` (which removes it on every
  run, see "Merging").
* The hook only runs when **you** submit a prompt, like the Claude Code hook. An agent that is mid-task is not interrupted by
  new mail; it sees it at the next prompt, or when it calls `check_inbox` / `wait_for_message`.
* A hook failure never blocks your prompt: `peek` swallows its own errors and exits 0 (set `AGENT_BRIDGE_DEBUG=1` to see them).
* Hooks are a stable Codex feature, on by default.

### Agent names

`init` always writes an explicit `AGENT_NAME`. For a shared entry with `AGENT_BRIDGE_NAME_FROM=project` (no `AGENT_NAME`)
the name comes from the server's working directory, which under Codex is the session's folder (no `CLAUDE_PROJECT_DIR` or
`AGENT_BRIDGE_PROJECT_DIR` reaches the server, and a parent `AGENT_NAME` cannot leak in either; both verified with the real
binary). Start Codex in the project root for such an entry: from a sub-folder the agent would be named after the sub-folder.
No Codex-specific variable was needed in `resolveIdentityEnv`.

## Enterprise notes

* **MCP allowlist.** An admin's `requirements.toml` (`/etc/codex/requirements.toml`, or
  `%ProgramData%\OpenAI\Codex\requirements.toml`; also cloud-managed and MDM sources) can restrict which MCP servers Codex
  starts. A server whose name is not in the list, or whose command does not match, is disabled
  (`codex mcp list --json` shows `disabled_reason`). Format, from `config/src/config_requirements.rs` (tests at `:5463`) and
  `config/src/mcp_requirements.rs`, **not exercised against a live managed install**:

  ```toml
  # name must be "bridge"; match the executable and exactly the arguments init writes
  [mcp_servers.bridge.identity]
  command = { executable = "/usr/local/bin/node", args = [ { match = "exact", value = "/opt/agent-bridge/server.js" } ] }

  # or, looser, only the command (any script run by that node would match):
  # [mcp_servers.bridge.identity]
  # command = "/usr/local/bin/node"
  ```

  An argument matcher is `exact`, `prefix` or `regex` (a regex must match the whole value). The `executable` is compared with
  `command` as written, and the number of matchers must equal the number of `args`; `init` writes the absolute path of the
  Node that ran it (`process.execPath`) and of this checkout's `server.js`.
* **Managed hooks.** With `allow_managed_hooks_only = true` in `requirements.toml`, user and project hooks are ignored
  (`docs/config.md`): the unread-mail hook will not run, and an admin has to ship an equivalent managed hook. The MCP server
  still works; agents then see mail through `check_inbox` / `wait_for_message`.
* **Proxies and private CAs.** The server does not inherit your shell's `HTTPS_PROXY`; `init` copies the proxy and CA
  settings into the entry's `env` (and into the hook as `--set` arguments) exactly as it does for Claude Code. Codex does
  pass the custom-CA variables it knows (`CODEX_CA_CERTIFICATE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, ...; made absolute)
  on to MCP servers (`rmcp-client/src/utils.rs:23`, `network-proxy/src/certs.rs:274`), but not proxy variables.
* **Secrets.** The entry's `env` carries token *file* paths only. `init` refuses to write any variable named like a secret
  value (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, ...) into the repo, in either file. A proxy URL with credentials is still
  written if you have one in your shell (init warns); new files are created readable by the owner only.

## Limits

* Codex-side behaviour was verified on 0.171.0. The hook protocol, the hook trust model and the `[mcp_servers]` keys are
  moving parts of Codex; the tests below catch a change that breaks the files.
* The unread-mail hook has not been run by a live Codex turn: that needs a model, and the hook must be trusted first. What is
  checked instead: Codex parses and lists the hook (`hooks/list`), the generated command is run the way Codex runs it (a shell
  `-c`, hook input on stdin) and its stdout is validated against Codex's own generated JSON schema.
* Windows: see above.
* Not supported: Codex's `exec-server` / remote environments (`environment_id`), plugins that ship their own MCP servers.

## Tests

`node test/clients-codex.js` (no Postgres, no Codex needed). With a Codex binary it also loads the generated files in the
real thing, starts our server through `codex app-server` (`thread/start`, `mcpServerStatus/list`, `mcpServer/tool/call`
and `hooks/list` need no model and no API key), and calls tools:

```bash
CODEX_BIN=/path/to/codex node test/clients-codex.js
```

It always runs Codex with a throw-away `CODEX_HOME` and `HOME`; it never touches `~/.codex`. The JSON schemas in
`test/fixtures/codex-hooks/` are copied from the Codex source (Apache-2.0); refresh them when Codex changes its hook protocol.
