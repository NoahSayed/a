// Shared pieces for the per-client config writers (Claude Code, Cursor, Codex).
// Each client gets the same MCP server (server.js) and the same "unread mail" hook (cli.js peek);
// only the file formats and locations differ.

import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PROXY_URL_VARS, proxyUrlHasCredentials } from "../proxy.js";

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

// Repo config files are small. A bigger one is refused before it is read or parsed, so a hostile repo
// can't make init, doctor or a hook read /dev/zero, block on a FIFO, or stall a parser (R4-05, R4-06, R4-08).
export const MAX_CONFIG_BYTES = 1024 * 1024;

// The text of a repo config file, or null if it doesn't exist. Refuses symlinks, anything that isn't a
// regular file, and files over MAX_CONFIG_BYTES; checks again on the open descriptor (no swap in between).
export function readText(path, { maxBytes = MAX_CONFIG_BYTES } = {}) {
  let st;
  try {
    st = lstatSync(path);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
  if (st.isSymbolicLink()) throw new Error(`${path} is a symlink; refusing to read through it.`);
  if (!st.isFile()) throw new Error(`${path} is not a regular file.`);
  if (st.size > maxBytes) throw new Error(`${path} is larger than ${maxBytes} bytes; refusing to read it.`);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const fst = fstatSync(fd);
    if (!fst.isFile() || fst.size > maxBytes) throw new Error(`${path} changed while being read; refusing it.`);
    const buf = Buffer.alloc(fst.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

export const readJson = (p) => {
  const t = readText(p);
  return t == null ? {} : JSON.parse(t);
};
export const isObject = (x) => x !== null && typeof x === "object" && !Array.isArray(x);

// PowerShell single-quoted word: ' is doubled, and so are the typographic single quotes PowerShell also
// treats as quotes (U+2018..U+201B). A double quote would be mangled by Windows PowerShell 5.1 when it starts
// the program, and control characters have no safe form, so both are refused (R4-12).
export const psq = (t) => {
  t = String(t);
  if (/[\u0000-\u001f\u007f]/.test(t)) throw new Error(`hook command: refusing a value with a control character: ${JSON.stringify(t)}`);
  if (t.includes('"')) throw new Error(`hook command: a double quote in ${JSON.stringify(t)} cannot be quoted safely for PowerShell`);
  return `'${t.replace(/['\u2018\u2019\u201a\u201b]/g, (c) => c + c)}'`;
};

// init's writes for every tool, collected first and written only when every tool's step succeeded (R4-01).
// Each file is written to a temporary name next to it and renamed into place. A new file gets `mode`; an
// existing file keeps its own mode.
export class FileTx {
  constructor() {
    this.files = [];
  }
  write(path, data, { mode = 0o600 } = {}) {
    this.files = this.files.filter((f) => f.path !== path);
    this.files.push({ path, data, mode });
  }
  commit() {
    for (const f of this.files) refuseSymlink(f.path);
    for (const f of this.files) {
      mkdirSync(dirname(f.path), { recursive: true });
      refuseSymlink(dirname(f.path));
      let mode = f.mode;
      try {
        mode = statSync(f.path).mode & 0o777;
      } catch {}
      const tmp = `${f.path}.agent-bridge-${process.pid}.tmp`;
      try {
        writeFileSync(tmp, f.data, { mode, flag: "wx" });
        renameSync(tmp, f.path);
      } catch (e) {
        rmSync(tmp, { force: true });
        throw e;
      }
    }
    const paths = this.files.map((f) => f.path);
    this.files = [];
    return paths;
  }
}

// The peek hook as { command, args } (exec form: no shell, values as --set arguments) or
// { command } (shell form: one POSIX command line, values single-quoted). `extra` are extra peek
// arguments such as ["--format", "codex"].
//
// A proxy URL that carries credentials (user:password@, or a token as the user name) is left out of the hook
// (R3-05): the command line of a process is visible to every user of the machine (/proc/<pid>/cmdline, Task
// Manager, ps), and the hook runs on every prompt. The hook then uses the HTTPS_PROXY it inherits from the
// environment of the tool that starts it; NODE_USE_ENV_PROXY and the other settings still travel.
export const hookCarriesProxyCredential = ([k, v]) => PROXY_URL_VARS.includes(k) && proxyUrlHasCredentials(v);
export function peekHook({ form, name, env, extra = [], nodePath = process.execPath }) {
  env = Object.fromEntries(Object.entries(env).filter((e) => !hookCarriesProxyCredential(e)));
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

// A repo JSON config that init merges into: {} if missing; refused (nothing written) if it isn't a JSON object.
export function readConfigObject(path) {
  let doc;
  try {
    doc = readJson(path);
  } catch (e) {
    throw new Error(`${path}: can't merge into it (${e.message}). Fix or remove the file, then re-run init.`);
  }
  if (!isObject(doc)) throw new Error(`${path}: can't merge into it (it must be a JSON object). Fix or remove the file, then re-run init.`);
  return doc;
}

// R4-04: init keeps what it doesn't own, but the user must not approve or trust it unread. These describe
// another tool's MCP servers and hooks found in a file init is about to rewrite, for a warning.
const short = (v) => {
  const t = String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ");
  return t.length > 160 ? t.slice(0, 160) + "…" : t;
};
export function foreignServers(servers, label) {
  if (!isObject(servers)) return [];
  return Object.entries(servers)
    .filter(([n]) => n !== SERVER_NAME)
    .map(([n, v]) => `${label}: MCP server "${short(n)}": ${short([v?.command, ...(Array.isArray(v?.args) ? v.args : [])].filter(Boolean).join(" ") || v?.url || "")}`);
}
export function foreignHooks(hooksByEvent, label, isOurs) {
  const out = [];
  if (!isObject(hooksByEvent)) return out;
  for (const [ev, list] of Object.entries(hooksByEvent)) {
    if (!Array.isArray(list)) continue;
    for (const g of list) {
      const handlers = Array.isArray(g?.hooks) ? g.hooks : [g]; // Claude/Codex nest handlers in groups; Cursor doesn't
      for (const h of handlers) if (!isOurs(h)) out.push(`${label}: ${short(ev)} hook: ${short(hookText(h))}`);
    }
  }
  return out;
}
export function warnForeign(log, items) {
  if (!items.length) return;
  log(
    "WARNING: this repo already has hooks or MCP servers that agent-bridge didn't write. They were kept, and they run\n" +
      "  with your permissions once you trust or approve the project. Read them before you do:\n" +
      items.map((i) => "    " + i).join("\n")
  );
}

// A Supabase key an agent must never hold: a new-style secret key, or a legacy JWT for the service_role (R4-03, R3-07).
export function isSecretSupabaseKey(key) {
  const k = String(key ?? "").trim();
  if (/^sb_secret_/.test(k)) return true;
  const parts = k.split(".");
  if (parts.length !== 3) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return payload?.role === "service_role";
  } catch {
    return false;
  }
}
