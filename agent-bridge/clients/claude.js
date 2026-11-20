// Claude Code: .mcp.json (project MCP servers) and .claude/settings.local.json (UserPromptSubmit hook).

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SERVER_JS, SERVER_NAME, hookText, ourPeekHook, peekHook, readJson, refuseSymlink } from "./common.js";

export const label = "Claude Code";

export function writeConfig({ repoDir, name, env, withHook, hookForm, summary = "", notes = [], log = console.log }) {
  const mcpPath = join(repoDir, ".mcp.json");
  refuseSymlink(mcpPath);
  if (withHook) {
    refuseSymlink(join(repoDir, ".claude"));
    refuseSymlink(join(repoDir, ".claude", "settings.local.json"));
  }
  const mcp = readJson(mcpPath);
  mcp.mcpServers ??= {};
  mcp.mcpServers[SERVER_NAME] = { command: process.execPath, args: [SERVER_JS], env };
  writeFileSync(mcpPath, JSON.stringify(mcp, null, 2) + "\n");
  const written = [mcpPath];
  log(`wrote ${mcpPath}  (agent "${name}"${summary ? ", " + summary : ""})`);
  for (const n of notes) log(n);

  if (withHook) {
    const settingsPath = join(repoDir, ".claude", "settings.local.json");
    mkdirSync(join(repoDir, ".claude"), { recursive: true });
    const settings = readJson(settingsPath);
    settings.hooks ??= {};
    settings.hooks.UserPromptSubmit ??= [];
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
    settings.hooks.UserPromptSubmit.push({ hooks: [hook] });
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    log(`wrote ${settingsPath}  (unread-mail hook)`);
    written.push(settingsPath);
  }
  log(
    "next (Claude Code): restart Claude Code in that repo and approve the 'bridge' MCP server.\n" +
      "tip: .mcp.json now holds absolute paths for this machine; add it to .gitignore if you don't want to commit it."
  );
  return written;
}

// Plain text on stdout is added to the prompt's context.
export const peekOutput = (notes) => (notes.length ? notes.join("\n") + "\n" : "");

export function readServerEnv(repoDir) {
  const path = join(repoDir, ".mcp.json");
  if (!existsSync(path)) return null;
  return { path, env: readJson(path).mcpServers?.[SERVER_NAME]?.env ?? {} };
}

// The description an earlier init stored, so re-running init without one keeps it.
export function previousDescription(repoDir) {
  return readServerEnv(repoDir)?.env?.AGENT_DESCRIPTION;
}
