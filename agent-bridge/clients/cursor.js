// Cursor: .cursor/mcp.json (project MCP servers) and .cursor/hooks.json (unread-mail hooks).
// See clients/common.js for the module interface, and docs/clients/cursor.md for what is verified and what is reported.
//
// What the hooks do (all three print JSON; Cursor's hook runner fails on plain text):
//   sessionStart        -> {"continue":true,"additional_context":"..."}   a new chat starts with the unread-mail note
//   beforeSubmitPrompt  -> {"continue":true,"additional_context":"..."}   every prompt carries it (accepted by Cursor's
//                          own hook engine; the public docs only list `continue` and `user_message` for this event)
//   stop                -> {"followup_message":"..."}   opt-in (--cursor-events ...,stop): after a finished turn with
//                          unread mail, Cursor sends the agent one more message. Capped, see stopMayFollowUp().

import { join } from "node:path";
import {
  FileTx, SERVER_JS, SERVER_NAME, foreignHooks, foreignServers, hookText, isObject, ourPeekHook, peekHook, psq, readConfigObject,
  readText, refuseSymlink, shq, warnForeign,
} from "./common.js";

export const label = "Cursor";

export const EVENTS = ["sessionStart", "beforeSubmitPrompt", "stop"];
export const DEFAULT_EVENTS = ["sessionStart", "beforeSubmitPrompt"];

const HOOK_TIMEOUT_SEC = 10;
// `stop` can make Cursor send the agent another message. Cursor's own cap is `loop_limit` (default 5, null = none);
// ours is smaller and written explicitly, and peek checks `loop_count` itself too.
export const STOP_LOOP_LIMIT = 2;
// Text sent to the agent is capped: JSON escaping keeps it valid, the cap keeps one huge note from flooding a prompt.
const MAX_TEXT = 8000;
const UNREAD_NOTE = /^\[agent-bridge\] You have unread bridge messages/;


// --cursor-events "sessionStart,stop" (string or array) -> a validated list. Throws before anything is written.
export function parseEvents(value) {
  const list = (Array.isArray(value) ? value : String(value ?? "").split(",")).map((s) => String(s).trim()).filter(Boolean);
  if (!list.length) return [...DEFAULT_EVENTS];
  for (const ev of list) {
    if (!EVENTS.includes(ev)) throw new Error(`--cursor-events: unknown event "${ev}" (use ${EVENTS.join(", ")})`);
  }
  return EVENTS.filter((ev) => list.includes(ev));
}

// ------------------------------------------------------------------ the hook command
// Cursor's hooks.json `command` is ONE string. On macOS/Linux Cursor runs it in a POSIX shell (the JSON input is
// appended as a heredoc); on Windows its runner wraps it for PowerShell (`& <command>`). So "exec form" here means:
// no environment prefix, settings passed as `--set K=V` arguments, every word quoted for the shell in use.
const BARE_POSIX = /^[A-Za-z0-9_.\/:=+-]+$/;
const BARE_PS = /^[A-Za-z0-9_.\/:=+\\-]+$/;
const posixQuote = (v) => (BARE_POSIX.test(v) ? v : shq(v));
// PowerShell: the shared psq (doubles ' and the typographic quotes, refuses " and control characters; R4-12).
const psQuote = (v) => (BARE_PS.test(v) ? v : psq(v));

export function hookCommand({ form, name, env, event, platform = process.platform, nodePath = process.execPath }) {
  const h = peekHook({ form, name, env, extra: ["--format", "cursor", "--event", event], nodePath });
  if (!Array.isArray(h.args)) return h.command; // shell form: POSIX env prefix + single-quoted words
  const q = platform === "win32" ? psQuote : posixQuote;
  // the program itself is always quoted: a bare Windows path is not one word
  const [program, ...rest] = [h.command, ...h.args];
  return [platform === "win32" ? psq(program) : shq(program), ...rest.map(q)].join(" ");
}

// ------------------------------------------------------------------ files
const paths = (repoDir) => ({
  dir: join(repoDir, ".cursor"),
  mcp: join(repoDir, ".cursor", "mcp.json"),
  hooks: join(repoDir, ".cursor", "hooks.json"),
});

const readConfig = readConfigObject;

// Replaces our entries in a parsed hooks.json (mutates `doc`); everything else stays, `version` included.
function mergeHooks(doc, path, { name, env, hookForm, events }) {
  doc.version ??= 1;
  doc.hooks ??= {};
  if (!isObject(doc.hooks)) throw new Error(`${path}: "hooks" must be an object. Fix the file, then re-run init.`);
  for (const ev of EVENTS) {
    if (doc.hooks[ev] !== undefined && !Array.isArray(doc.hooks[ev])) {
      throw new Error(`${path}: hooks.${ev} must be an array. Fix the file, then re-run init.`);
    }
  }
  const ours = ourPeekHook(name);
  for (const ev of EVENTS) {
    let list = doc.hooks[ev];
    if (list) {
      const kept = list.filter((x) => !ours.test(hookText(x)));
      if (kept.length !== list.length) list = kept.length ? kept : undefined; // an array only we filled goes away
    }
    if (events.includes(ev)) {
      const entry = { command: hookCommand({ form: hookForm, name, env, event: ev }), timeout: HOOK_TIMEOUT_SEC };
      if (ev === "stop") entry.loop_limit = STOP_LOOP_LIMIT;
      list = [...(list ?? []), entry];
    }
    if (list) doc.hooks[ev] = list;
    else delete doc.hooks[ev];
  }
}

export function writeConfig({ repoDir, name, env, withHook, hookForm, summary = "", notes = [], log = console.log, cursorEvents, tx }) {
  const own = !tx;
  tx ??= new FileTx();
  const events = parseEvents(cursorEvents);
  const p = paths(repoDir);
  // Everything is checked and merged in memory first, so a refusal leaves the repo untouched.
  refuseSymlink(p.dir);
  refuseSymlink(p.mcp);
  if (withHook) refuseSymlink(p.hooks);

  const mcp = readConfig(p.mcp);
  mcp.mcpServers ??= {};
  if (!isObject(mcp.mcpServers)) throw new Error(`${p.mcp}: "mcpServers" must be an object. Fix the file, then re-run init.`);
  const foreign = foreignServers(mcp.mcpServers, ".cursor/mcp.json");
  mcp.mcpServers[SERVER_NAME] = { command: process.execPath, args: [SERVER_JS], env };

  let hooks;
  if (withHook) {
    hooks = readConfig(p.hooks);
    mergeHooks(hooks, p.hooks, { name, env, hookForm, events });
    foreign.push(...foreignHooks(hooks.hooks, ".cursor/hooks.json", (x) => ourPeekHook(name).test(hookText(x))));
  }

  tx.write(p.mcp, JSON.stringify(mcp, null, 2) + "\n");
  const written = [p.mcp];
  log(`wrote ${p.mcp}  (agent "${name}"${summary ? ", " + summary : ""})`);
  for (const n of notes) log(n);
  if (withHook) {
    tx.write(p.hooks, JSON.stringify(hooks, null, 2) + "\n");
    log(`wrote ${p.hooks}  (unread-mail hook: ${events.join(", ")})`);
    written.push(p.hooks);
  }
  warnForeign(log, foreign);
  log(
    "next (Cursor): open the repo in Cursor, go to Cursor Settings > Tools & MCP (older versions: MCP) and switch the 'bridge' server on;\n" +
      "  Cursor does not start a project server until you do. Start a new chat afterwards." +
      (withHook
        ? "\n  The hooks apply to new chats (Cursor Settings > Hooks lists them). Cursor also runs hooks it imports from .claude/settings*.json;\n" +
          "  `peek` notices that and does not print the same note twice."
        : "") +
      "\ntip: .cursor/mcp.json and .cursor/hooks.json now hold absolute paths for this machine; add them to .gitignore if you don't want to commit them."
  );
  return own ? tx.commit() : written;
}

// { path, env }, null without a file; a file that can't be read or parsed gives an empty env and `error` (R4-05).
export function readServerEnv(repoDir) {
  const path = paths(repoDir).mcp;
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

// The description an earlier init stored, so re-running init without one keeps it.
export function previousDescription(repoDir) {
  return readServerEnv(repoDir)?.env?.AGENT_DESCRIPTION;
}

// ------------------------------------------------------------------ what the hook prints
const clip = (text) => text.slice(0, MAX_TEXT).toWellFormed();
const json = (o) => JSON.stringify(o) + "\n";

// After a finished turn only: not after the user pressed stop (aborted) or an error, and not beyond the loop limit.
// With no readable input there is nothing to go on, so no follow-up.
export function stopMayFollowUp(input) {
  return (
    isObject(input) &&
    input.status === "completed" &&
    Number.isInteger(input.loop_count) &&
    input.loop_count >= 0 &&
    input.loop_count < STOP_LOOP_LIMIT
  );
}

// `notes` are plain-text lines from peek. The result is always one line of valid JSON: the no-op answer when there
// is nothing to say, so a broken or silent bridge never blocks a prompt.
export function peekOutput(notes, { event, input } = {}) {
  switch (event) {
    case "sessionStart":
    case "beforeSubmitPrompt":
      return json(notes.length ? { continue: true, additional_context: clip(notes.join("\n")) } : { continue: true });
    case "stop": {
      // a scan warning alone is no reason to wake the agent
      const mail = notes.filter((n) => UNREAD_NOTE.test(n));
      if (!mail.length || !stopMayFollowUp(input)) return json({});
      return json({ followup_message: clip(mail.join("\n") + "\nCall check_inbox now.") });
    }
    default:
      return json({});
  }
}

// ------------------------------------------------------------------ hooks run by Cursor without --format
// Cursor imports Claude Code hooks from .claude/settings.json and settings.local.json, including ours, which prints
// plain text. Cursor's hook runner sets CURSOR_PROJECT_DIR / CURSOR_VERSION and sends JSON on stdin; peek uses that
// to answer in Cursor's format instead.

export const looksLikeCursorEnv = (env = process.env) => Boolean(env.CURSOR_PROJECT_DIR || env.CURSOR_VERSION);

// The hook's JSON input from stdin, or null. Never reads a terminal, never waits longer than timeoutMs, never
// buffers more than maxBytes, never throws.
export function readHookInput({ stream, timeoutMs = 300, maxBytes = 4 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    let s;
    try {
      s = stream ?? process.stdin;
      if (!s || s.isTTY || s.destroyed) return resolve(null);
    } catch {
      return resolve(null);
    }
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (complete) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      s.off("data", onData);
      s.off("end", onEnd);
      s.off("error", onError);
      try {
        s.destroy();
      } catch {}
      if (!complete) return resolve(null);
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        resolve(isObject(v) ? v : null);
      } catch {
        resolve(null);
      }
    };
    const onData = (d) => {
      size += d.length;
      if (size > maxBytes) return finish(false);
      chunks.push(d);
    };
    const onEnd = () => finish(true);
    const onError = () => finish(false);
    const timer = setTimeout(() => finish(false), timeoutMs);
    try {
      s.on("data", onData);
      s.on("end", onEnd);
      s.on("error", onError);
    } catch {
      finish(false);
    }
  });
}

// Is this the input of a Cursor hook? Returns its event name ("" if it is one we don't handle), or null if the input
// isn't Cursor's (Claude Code sends hook_event_name "UserPromptSubmit" and no cursor_version).
export function detectCursorInput(input) {
  if (!isObject(input)) return null;
  const ev = typeof input.hook_event_name === "string" ? input.hook_event_name : "";
  if (EVENTS.includes(ev)) return ev;
  return typeof input.cursor_version === "string" ? "" : null;
}

export const workspaceOf = (input, env = process.env) => {
  const root = Array.isArray(input?.workspace_roots) ? input.workspace_roots[0] : undefined;
  return typeof root === "string" && root ? root : env.CURSOR_PROJECT_DIR || undefined;
};

// Does <workspace>/.cursor/hooks.json already run our Cursor-format hook for this agent and event? Then an imported
// Claude hook for the same event would only repeat its note.
export function hasNativeHook(workspaceDir, name, event) {
  try {
    if (!workspaceDir || !name || !event) return false;
    const file = join(workspaceDir, ".cursor", "hooks.json");
    // readText: no symlink, no FIFO or device, at most 1 MiB, checked on the open file (R4-06)
    const t = readText(file);
    if (t == null) return false;
    const list = JSON.parse(t)?.hooks?.[event];
    const ours = ourPeekHook(name);
    return Array.isArray(list) && list.some((x) => ours.test(hookText(x)) && /--format["']?\s+["']?cursor/.test(hookText(x)));
  } catch {
    return false;
  }
}
