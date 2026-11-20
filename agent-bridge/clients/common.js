// Shared pieces for the per-client config writers (Claude Code, Cursor, Codex).
// Each client gets the same MCP server (server.js) and the same "unread mail" hook (cli.js peek);
// only the file formats and locations differ.

import { existsSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const HERE = fileURLToPath(new URL("..", import.meta.url));
export const SERVER_JS = join(HERE, "server.js");
export const CLI_JS = join(HERE, "cli.js");

// The MCP server's name in every client's config.
export const SERVER_NAME = "bridge";

export const CLIENTS = ["claude", "cursor", "codex"];

// The only variables an exec-form hook may pass to peek (--set KEY=VALUE).
export const PEEK_ENV_KEYS = new Set([
  "AGENT_NAME", "AGENT_BRIDGE_BACKEND", "AGENT_BRIDGE_DB", "AGENT_BRIDGE_TOKEN_FILE", "AGENT_BRIDGE_LOOKBACK_HOURS",
  "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY", "SLACK_CHANNEL_ID", "SLACK_BOT_TOKEN_FILE",
  "SLACK_API_URL", "RELAY_URL", "RELAY_TLS_CA", "RELAY_TLS_CLIENT_CERT", "RELAY_TLS_CLIENT_KEY",
]);

// Proxy and CA settings an exec-form hook may also pass (R2-12). Node reads these once, at process
// start (NODE_USE_ENV_PROXY and NODE_EXTRA_CA_CERTS cannot be switched on from inside a running
// process, and http.setGlobalProxyFromEnv only exists from Node 24.14), so peek re-runs itself once with
// them in the child's environment. Never NODE_OPTIONS, never the re-exec guard.
export const PEEK_PROCESS_KEYS = new Set([
  "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "NODE_USE_ENV_PROXY",
  "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy",
]);
export const PEEK_REEXEC_GUARD = "AGENT_BRIDGE_PEEK_REEXEC";

// POSIX single-quoting: nothing inside is expanded by the shell that runs the hook (R1-06).
export const shq = (v) => `'${String(v).replace(/'/g, `'\\''`)}'`;

// init writes into the user's repo; never through a symlink that points somewhere else (R1-14).
export function refuseSymlink(p) {
  try {
    if (lstatSync(p).isSymbolicLink()) {
      throw new Error(`${p} is a symlink; refusing to write through it. Replace it with a regular file or directory.`);
    }
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
}

export const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : {});

// The peek hook as { command, args } (exec form: no shell, values as --set arguments) or
// { command } (shell form: one POSIX command line, values single-quoted). `extra` are extra peek
// arguments such as ["--format", "codex"].
export function peekHook({ form, name, env, extra = [], nodePath = process.execPath }) {
  if (form === "exec") {
    const sets = Object.entries(env)
      .filter(([k]) => PEEK_ENV_KEYS.has(k) || PEEK_PROCESS_KEYS.has(k))
      .flatMap(([k, v]) => ["--set", `${k}=${v}`]);
    return { command: nodePath, args: [CLI_JS, "peek", name, ...extra, ...sets] };
  }
  const envPrefix = Object.entries(env)
    .filter(([k]) => k !== "AGENT_DESCRIPTION")
    .map(([k, v]) => `${k}=${shq(v)}`)
    .join(" ");
  return { command: `${envPrefix} ${shq(nodePath)} ${shq(CLI_JS)} peek ${shq(name)}${extra.map((a) => " " + shq(a)).join("")}` };
}

// Matches an earlier agent-bridge peek hook for this agent (either form, quoted or not), so
// re-running init replaces it instead of stacking a second one.
export const ourPeekHook = (name) => new RegExp(`cli\\.js["']?\\s+peek\\s+["']?${name}["']?(\\s|$)`);
export const hookText = (x) => [x?.command, ...(Array.isArray(x?.args) ? x.args : [])].map(String).join(" ");

// Every client module (clients/claude.js, cursor.js, codex.js) exports:
//   writeConfig({ repoDir, name, env, withHook, hookForm, summary, notes, log })
//                                   write that client's MCP (+ hook) files; log "wrote <file>  (agent ..., summary)"
//                                   for the MCP file, then the notes (proxy/TLS lines), then the hook file
//   peekOutput(notes, { event })   what `peek --format <client>` prints; notes are plain-text lines
//   readServerEnv(repoDir)          { path, env } of the bridge server entry in that client's repo config
//                                   (for `doctor <repo>`), or null if the file isn't there
