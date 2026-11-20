// OpenAI Codex CLI: .codex/config.toml ([mcp_servers.bridge]) and .codex/hooks.json (UserPromptSubmit hook).
// What Codex does with these files, from its source and the real binary: docs/clients/codex.md.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SERVER_JS, SERVER_NAME, hookText, peekHook, readJson, refuseSymlink, shq } from "./common.js";
import { canon, parse, replaceTable, sameOutside, tomlArray, tomlInlineTable, tomlString } from "./toml-edit.js";

export const label = "Codex";

// wait_for_message blocks for up to 600 s. Codex cuts a tool call off after tool_timeout_sec (default
// 300), so the entry sets 660: the longest wait plus a minute for the store round trip.
export const TOOL_TIMEOUT_SEC = 660;

// Keys of [mcp_servers.bridge] that init owns and rewrites every time. Any other key in the entry
// (Codex itself stores "always allow" answers as [mcp_servers.bridge.tools.<tool>] approval_mode,
// and users add startup_timeout_sec, default_tools_approval_mode, ...) is left alone.
const OWNED_KEYS = new Set([
  "command", "args", "env", "cwd", "tool_timeout_sec",
  // another transport's keys: Codex rejects them next to `command`
  "url", "bearer_token", "bearer_token_env_var", "http_headers", "env_http_headers", "http_headers_helper",
  "oauth", "oauth_resource", "auth",
]);
const OWNED_SUBTABLES = new Set(["env", "http_headers", "env_http_headers", "oauth"]);
const TABLE = ["mcp_servers", SERVER_NAME];

// A secret must never be written into a repo file: the env carries token *file* paths only.
const SECRETISH = /(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)$/i;

const STATUS_MESSAGE = "agent-bridge: checking for unread messages";
const HOOK_TIMEOUT_SEC = 10;
const EVENTS = new Set(["UserPromptSubmit", "SessionStart"]);

// ---------------------------------------------------------------------------------------------
// The hook command line
// ---------------------------------------------------------------------------------------------
// Codex has no exec form: a hook is one command string that Codex hands to the turn's shell
// (bash/zsh/sh with -c on macOS and Linux; PowerShell -Command or cmd /c on Windows). So the
// exec-form argument list is quoted token by token for that shell. No VAR=value prefix is used: that
// syntax does not exist in PowerShell or cmd.

const noControl = (t) => {
  if (/[\u0000-\u001f\u007f]/.test(t)) throw new Error(`hook command: refusing a value with a control character: ${JSON.stringify(t)}`);
  return t;
};

// PowerShell single-quoted string: ' is doubled, and so are the typographic single quotes
// PowerShell also treats as quotes. A double quote would be mangled by Windows PowerShell 5.1 when it
// starts the program, so it is refused.
const psq = (t) => {
  noControl(t);
  if (t.includes('"')) throw new Error(`hook command: a double quote in ${JSON.stringify(t)} cannot be quoted safely for PowerShell`);
  return `'${t.replace(/['\u2018\u2019\u201a\u201b]/g, (c) => c + c)}'`;
};

// cmd.exe: inside "..." only " and %...% are special. Neither can be escaped reliably, so they are refused.
const cmdq = (t) => {
  noControl(t);
  if (/["%]/.test(t) || t.endsWith("\\")) throw new Error(`hook command: ${JSON.stringify(t)} cannot be quoted safely for cmd.exe (a double quote, a % or a trailing backslash)`);
  return `"${t}"`;
};

export function hookCommandLine(tokens, shell) {
  if (shell === "powershell") return "& " + tokens.map(psq).join(" ");
  if (shell === "cmd") return tokens.map(cmdq).join(" ");
  return tokens.map((t) => shq(noControl(t))).join(" ");
}

// Which quoting to use. macOS/Linux: POSIX. Windows: Codex's default shell is PowerShell, and
// `--hook-form shell` (which means "the other one" there) selects cmd.exe.
export const hookShell = (platform, hookForm) => (platform === "win32" ? (hookForm === "shell" ? "cmd" : "powershell") : "posix");

// Matches an earlier agent-bridge hook for this agent in Codex's quoted single-string form, and in the
// forms the other clients write, so re-running init replaces it instead of stacking a second one.
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export const ourCodexHook = (name) => new RegExp(`cli\\.js["']?\\s+["']?peek["']?\\s+["']?${escapeRe(name)}["']?(\\s|$)`);

// ---------------------------------------------------------------------------------------------
// writeConfig
// ---------------------------------------------------------------------------------------------

const stripBom = (t) => (t.charCodeAt(0) === 0xfeff ? [t.slice(1), "\ufeff"] : [t, ""]);

// The edited text of .codex/config.toml, or throws without anything having been written.
// (`_replace` exists so a test can prove the checks below catch a faulty editor.)
export function editConfigToml(existing, { repoDir, env, _replace = replaceTable }) {
  const [text, bom] = stripBom(existing);
  let before;
  try {
    before = parse(text);
  } catch (e) {
    throw new Error(`can't parse the existing .codex/config.toml (${e.message.split("\n")[0]}); fix or move it, then run init again.`);
  }
  const entry = {
    command: process.execPath,
    args: [SERVER_JS],
    env: Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)])),
    cwd: repoDir,
    tool_timeout_sec: TOOL_TIMEOUT_SEC,
  };
  for (const k of Object.keys(entry.env)) {
    if (SECRETISH.test(k)) throw new Error(`refusing to write ${k} into .codex/config.toml: it looks like a secret value. Point the entry at a token file instead.`);
  }
  const lines = [
    `command = ${tomlString(entry.command)}`,
    `args = ${tomlArray(entry.args)}`,
    `env = ${tomlInlineTable(entry.env)}`,
    `cwd = ${tomlString(entry.cwd)}`,
    `tool_timeout_sec = ${entry.tool_timeout_sec}`,
  ];
  const edited = _replace(text, TABLE, { owned: OWNED_KEYS, ownedSubtables: OWNED_SUBTABLES, lines });

  // The parser is the referee: the result must parse, our entry must read back exactly as intended,
  // and nothing outside the entry may have changed (no injected key, nothing lost).
  let after;
  try {
    after = parse(edited);
  } catch (e) {
    throw new Error(`internal error: the edited .codex/config.toml does not parse (${e.message.split("\n")[0]}); nothing was written.`);
  }
  const kept = Object.fromEntries(Object.entries(before.mcp_servers?.[SERVER_NAME] ?? {}).filter(([k]) => !OWNED_KEYS.has(k)));
  const expected = { ...kept, ...entry };
  if (canon(after.mcp_servers?.[SERVER_NAME]) !== canon(expected) || !sameOutside(before, after, TABLE)) {
    throw new Error("internal error: the edited .codex/config.toml does not match what init meant to write (this is a bug); nothing was written.");
  }
  return bom + edited;
}

// The merged hooks.json value: our UserPromptSubmit handler replaced in place (so Codex's trust
// record, which is keyed by position, still applies), everything else kept.
export function mergeHooks(hooks, { name, handler }) {
  if (hooks === null || typeof hooks !== "object" || Array.isArray(hooks)) throw new Error("the existing .codex/hooks.json is not a JSON object; fix or move it, then run init again.");
  if (hooks.hooks !== undefined && (hooks.hooks === null || typeof hooks.hooks !== "object" || Array.isArray(hooks.hooks))) {
    throw new Error('the existing .codex/hooks.json has a "hooks" value that is not an object; fix or move it, then run init again.');
  }
  hooks.hooks ??= {};
  if (hooks.hooks.UserPromptSubmit !== undefined && !Array.isArray(hooks.hooks.UserPromptSubmit)) {
    throw new Error('the existing .codex/hooks.json has a "UserPromptSubmit" value that is not a list; fix or move it, then run init again.');
  }
  const ours = ourCodexHook(name);
  let placed = false;
  const groups = [];
  for (const g of hooks.hooks.UserPromptSubmit ?? []) {
    if (!Array.isArray(g?.hooks)) {
      groups.push(g);
      continue;
    }
    // Only our own handlers go: a group can hold other hooks, which stay where they are.
    const list = [];
    for (const h of g.hooks) {
      if (!ours.test(hookText(h))) list.push(h);
      else if (!placed) {
        list.push(handler);
        placed = true;
      }
    }
    if (list.length) groups.push({ ...g, hooks: list });
  }
  if (!placed) groups.push({ hooks: [handler] });
  hooks.hooks.UserPromptSubmit = groups;
  return hooks;
}

export function writeConfig({ repoDir, name, env, withHook, hookForm, summary = "", notes = [], log = console.log, platform = process.platform }) {
  const dir = join(repoDir, ".codex");
  const cfgPath = join(dir, "config.toml");
  const hooksPath = join(dir, "hooks.json");
  refuseSymlink(dir);
  refuseSymlink(cfgPath);
  if (withHook) refuseSymlink(hooksPath);

  // Everything that can fail (parsing, quoting) happens before the first write, so a refusal
  // leaves both files as they were.
  const cfg = editConfigToml(existsSync(cfgPath) ? readFileSync(cfgPath, "utf8") : "", { repoDir, env });
  let hooksJson = null;
  if (withHook) {
    // Exec-form peek (--set KEY=VALUE arguments: only bridge settings are accepted, nothing is expanded),
    // quoted token by token into the one string Codex runs.
    const peek = peekHook({ form: "exec", name, env, extra: ["--format", "codex"] });
    const command = hookCommandLine([peek.command, ...peek.args], hookShell(platform, hookForm));
    const handler = { type: "command", command, timeout: HOOK_TIMEOUT_SEC, statusMessage: STATUS_MESSAGE };
    let existing;
    try {
      existing = readJson(hooksPath);
    } catch (e) {
      throw new Error(`can't parse the existing .codex/hooks.json (${e.message.split("\n")[0]}); fix or move it, then run init again.`);
    }
    hooksJson = JSON.stringify(mergeHooks(existing, { name, handler }), null, 2) + "\n";
  }

  mkdirSync(dir, { recursive: true });
  // New files are private to the user: the entry can carry a proxy URL with credentials.
  writeFileSync(cfgPath, cfg, { mode: 0o600 });
  const written = [cfgPath];
  log(`wrote ${cfgPath}  (agent "${name}"${summary ? ", " + summary : ""})`);
  for (const n of notes) log(n);

  if (hooksJson !== null) {
    writeFileSync(hooksPath, hooksJson, { mode: 0o600 });
    log(`wrote ${hooksPath}  (unread-mail hook)`);
    written.push(hooksPath);
  }
  log(
    "next (Codex): start Codex in that repo. It loads .codex/ only for a trusted project, so answer 'trust' when it asks about the folder\n" +
      "  (or add it under [projects] with trust_level = \"trusted\" in ~/.codex/config.toml)." +
      (withHook ? "\n  Then choose 'Trust all and continue' at the 'Hooks need review' prompt (or review it with /hooks); until then the unread-mail hook does not run." : "") +
      "\n  The first call of each bridge tool asks for approval; 'always allow' is stored in .codex/config.toml.\n" +
      "tip: .codex/config.toml now holds absolute paths for this machine; add .codex/ to .gitignore if you don't want to commit it."
  );
  return written;
}

// ---------------------------------------------------------------------------------------------
// peek and doctor
// ---------------------------------------------------------------------------------------------

// What Codex's hook runner accepts on stdout. It tries JSON first; any output that merely *starts*
// with `{` or `[` but is not valid hook JSON is an error, so plain "[agent-bridge] ..." text (which is
// fine for Claude Code) must not be printed. No notes: print nothing, which Codex treats as "nothing to add".
export function peekOutput(notes, { event } = {}) {
  if (!notes.length) return "";
  const hookEventName = EVENTS.has(event) ? event : "UserPromptSubmit";
  return JSON.stringify({ hookSpecificOutput: { hookEventName, additionalContext: notes.join("\n") } }) + "\n";
}

// { path, env } of [mcp_servers.bridge].env, or null if there is no file. A file that does not parse
// comes back with an empty env and `error` set, rather than throwing: init reads every client's file
// for an earlier description, and a broken Codex file must not stop `init --client claude`.
export function readServerEnv(repoDir) {
  const path = join(repoDir, ".codex", "config.toml");
  if (!existsSync(path)) return null;
  try {
    const raw = parse(stripBom(readFileSync(path, "utf8"))[0]).mcp_servers?.[SERVER_NAME]?.env;
    const env = {};
    if (raw && typeof raw === "object") for (const [k, v] of Object.entries(raw)) if (typeof v === "string") env[k] = v;
    return { path, env };
  } catch (e) {
    return { path, env: {}, error: e.message.split("\n")[0] };
  }
}

export function previousDescription(repoDir) {
  return readServerEnv(repoDir)?.env?.AGENT_DESCRIPTION;
}
