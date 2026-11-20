// Claude Code: .mcp.json (project MCP servers) and .claude/settings.local.json (UserPromptSubmit hook).

import { join } from "node:path";
import {
  FileTx, SERVER_JS, SERVER_NAME, foreignHooks, foreignServers, hookText, isObject, ourPeekHook, peekHook, readConfigObject,
  readText, refuseSymlink, warnForeign,
} from "./common.js";

export const label = "Claude Code";

// Plans the writes into `tx` (init commits them once every tool's step succeeded); without a tx, writes at once.
export function writeConfig({ repoDir, name, env, withHook, hookForm, summary = "", notes = [], log = console.log, tx }) {
  const own = !tx;
  tx ??= new FileTx();
  const mcpPath = join(repoDir, ".mcp.json");
  const settingsPath = join(repoDir, ".claude", "settings.local.json");
  refuseSymlink(mcpPath);
  if (withHook) {
    refuseSymlink(join(repoDir, ".claude"));
    refuseSymlink(settingsPath);
  }
  const mcp = readConfigObject(mcpPath);
  mcp.mcpServers ??= {};
  if (!isObject(mcp.mcpServers)) throw new Error(`${mcpPath}: "mcpServers" must be an object. Fix the file, then re-run init.`);
  const foreign = foreignServers(mcp.mcpServers, ".mcp.json");
  mcp.mcpServers[SERVER_NAME] = { command: process.execPath, args: [SERVER_JS], env };

  let settings;
  if (withHook) {
    settings = readConfigObject(settingsPath);
    settings.hooks ??= {};
    if (!isObject(settings.hooks)) throw new Error(`${settingsPath}: "hooks" must be an object. Fix the file, then re-run init.`);
    settings.hooks.UserPromptSubmit ??= [];
    if (!Array.isArray(settings.hooks.UserPromptSubmit)) {
      throw new Error(`${settingsPath}: hooks.UserPromptSubmit must be an array. Fix the file, then re-run init.`);
    }
    // Claude Code runs shell-form hooks with sh (macOS/Linux) or Git Bash (Windows); exec form has no shell.
    const hook = { type: "command", ...peekHook({ form: hookForm, name, env }), timeout: 10 };
    const ours = ourPeekHook(name);
    // Only our own entries go: a matcher group can hold other hooks (R2-06), which stay where they are.
    // A group is dropped only if removing ours leaves it empty.
    settings.hooks.UserPromptSubmit = settings.hooks.UserPromptSubmit.flatMap((h) => {
      if (!Array.isArray(h?.hooks)) return [h];
      const kept = h.hooks.filter((x) => !ours.test(hookText(x)));
      if (kept.length === h.hooks.length) return [h];
      return kept.length ? [{ ...h, hooks: kept }] : [];
    });
    foreign.push(...foreignHooks(settings.hooks, ".claude/settings.local.json", (x) => /cli\.js["']?\s+["']?peek/.test(hookText(x))));
    settings.hooks.UserPromptSubmit.push({ hooks: [hook] });
  }

  tx.write(mcpPath, JSON.stringify(mcp, null, 2) + "\n");
  log(`wrote ${mcpPath}  (agent "${name}"${summary ? ", " + summary : ""})`);
  for (const n of notes) log(n);
  if (withHook) {
    tx.write(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    log(`wrote ${settingsPath}  (unread-mail hook)`);
  }
  warnForeign(log, foreign);
  log(
    "next (Claude Code): restart Claude Code in that repo and approve the 'bridge' MCP server.\n" +
      "tip: .mcp.json now holds absolute paths for this machine; add it to .gitignore if you don't want to commit it."
  );
  return own ? tx.commit() : [mcpPath, ...(withHook ? [settingsPath] : [])];
}

// Plain text on stdout is added to the prompt's context.
export const peekOutput = (notes) => (notes.length ? notes.join("\n") + "\n" : "");

// { path, env } of the bridge entry in .mcp.json, or null if there is no file. A file that can't be read or
// parsed comes back with an empty env and `error` set (R4-05): init only looks here for an earlier description.
export function readServerEnv(repoDir) {
  const path = join(repoDir, ".mcp.json");
  try {
    const t = readText(path);
    if (t == null) return null;
    const doc = JSON.parse(t);
    const env = isObject(doc) && isObject(doc.mcpServers) && isObject(doc.mcpServers[SERVER_NAME]?.env) ? doc.mcpServers[SERVER_NAME].env : {};
    return { path, env: Object.fromEntries(Object.entries(env).filter(([, v]) => typeof v === "string")) };
  } catch (e) {
    return { path, env: {}, error: e.message.split("\n")[0] };
  }
}
