// Mutations for the Cursor client (clients/cursor.js, the Cursor parts of cli.js peek/init, store.js project folder).
// Same shape as the entries in test/mutations.js: { name, file, find, replace, suite }; `find` occurs exactly once.
// Every guard added for Cursor has an entry here, and test/clients-cursor.js must fail with it applied.
const CC = ["test/clients-cursor.js"];
const F = "clients/cursor.js";

export default [
  // --- files: symlinks, merging, shape
  // Symlinks and a bad --cursor-events: the writer's own checks are second layers. FileTx.commit() refuses
  // a symlinked file or directory, and nothing is written until every tool's files are planned, so a
  // late failure writes nothing (mutated as R4-01). These mutate the shared symlink layer instead, tested on its own in test/clients.js.
  { name: "CU FileTx writes through a symlinked file", file: "clients/common.js", find: `    for (const f of this.files) refuseSymlink(f.path);\n`, replace: ``, suite: ["test/clients.js"] },
  { name: "CU FileTx writes through a symlinked directory", file: "clients/common.js", find: `      refuseSymlink(dirname(f.path));\n`, replace: ``, suite: ["test/clients.js"] },
  { name: "CU the user's other MCP servers are dropped", file: F, find: `  mcp.mcpServers ??= {};`, replace: `  mcp.mcpServers = {};`, suite: CC },
  { name: "CU hooks.json `version` not preserved", file: F, find: `  doc.version ??= 1;`, replace: `  doc.version = 1;`, suite: CC },
  { name: "CU the user's other hooks are dropped", file: F, find: `      list = [...(list ?? []), entry];`, replace: `      list = [entry];`, suite: CC },
  { name: "CU an earlier hook of ours isn't replaced (re-running stacks hooks)", file: F, find: `      const kept = list.filter((x) => !ours.test(hookText(x)));`, replace: `      const kept = list;`, suite: CC },
  { name: "CU every peek hook is treated as ours (other agents' hooks removed)", file: F, find: `  const ours = ourPeekHook(name);\n  for (const ev of EVENTS) {\n    let list`, replace: `  const ours = /cli\\.js/;\n  for (const ev of EVENTS) {\n    let list`, suite: CC },
  { name: "CU empty arrays left behind for events no longer wanted", file: F, find: `list = kept.length ? kept : undefined;`, replace: `list = kept;`, suite: CC },
  { name: "CU a non-object mcp.json is merged into", file: "clients/common.js", find: `  if (!isObject(doc)) throw new Error(\`\${path}: can't merge into it (it must be a JSON object).`, replace: `  if (false) throw new Error(\`\${path}: can't merge into it (it must be a JSON object).`, suite: CC },
  { name: "CU a non-object mcpServers is overwritten", file: F, find: `  if (!isObject(mcp.mcpServers)) throw new Error(`, replace: `  if (false) throw new Error(`, suite: CC },
  { name: "CU a non-array hooks.<event> is merged into", file: F, find: `    if (doc.hooks[ev] !== undefined && !Array.isArray(doc.hooks[ev])) {`, replace: `    if (false) {`, suite: CC },
  { name: "CU unknown --cursor-events accepted", file: F, find: `    if (!EVENTS.includes(ev)) throw new Error(`, replace: `    if (false) throw new Error(`, suite: CC },
  { name: "CU stop is on by default", file: F, find: `export const DEFAULT_EVENTS = ["sessionStart", "beforeSubmitPrompt"];`, replace: `export const DEFAULT_EVENTS = ["sessionStart", "beforeSubmitPrompt", "stop"];`, suite: CC },
  { name: "CU stop hook has no loop limit", file: F, find: `      if (ev === "stop") entry.loop_limit = STOP_LOOP_LIMIT;`, replace: ``, suite: CC },
  { name: "CU hook timeout lost", file: F, find: `const HOOK_TIMEOUT_SEC = 10;`, replace: `const HOOK_TIMEOUT_SEC = 3600;`, suite: CC },
  { name: "CU hook doesn't ask for Cursor's output format", file: F, find: `extra: ["--format", "cursor", "--event", event]`, replace: `extra: ["--event", event]`, suite: CC },

  // --- the hook command line
  { name: "CU POSIX words not quoted (settings run as shell code)", file: F, find: `const posixQuote = (v) => (BARE_POSIX.test(v) ? v : shq(v));`, replace: `const posixQuote = (v) => v;`, suite: CC },
  { name: "CU PowerShell quote not doubled (a path with ' breaks out)", file: F, find: `const psQuote = (v) => (BARE_PS.test(v) ? v : psq(v));`, replace: `const psQuote = (v) => (BARE_PS.test(v) ? v : \`'\${v}'\`);`, suite: CC },

  // --- what the hook prints
  { name: "CU no-op answer lacks continue:true", file: F, find: `{ continue: true, additional_context: clip(notes.join("\\n")) } : { continue: true }`, replace: `{ continue: true, additional_context: clip(notes.join("\\n")) } : {}`, suite: CC },
  { name: "CU an unknown event answers with something other than {}", file: F, find: `    default:\n      return json({});`, replace: `    default:\n      return json({ continue: true });`, suite: CC },
  { name: "CU output built by hand (a quote in a note breaks the JSON)", file: F, find: `const json = (o) => JSON.stringify(o) + "\\n";`, replace: `const json = (o) => "{" + Object.entries(o).map(([k, v]) => \`"\${k}":\${typeof v === "string" ? '"' + v + '"' : v}\`).join(",") + "}\\n";`, suite: CC },
  { name: "CU note text not capped", file: F, find: `const clip = (text) => text.slice(0, MAX_TEXT).toWellFormed();`, replace: `const clip = (text) => text.toWellFormed();`, suite: CC },
  { name: "CU a cut surrogate pair is left in the text", file: F, find: `const clip = (text) => text.slice(0, MAX_TEXT).toWellFormed();`, replace: `const clip = (text) => text.slice(0, MAX_TEXT);`, suite: CC },
  { name: "CU stop follows up after an aborted or failed turn", file: F, find: `    input.status === "completed" &&\n`, replace: ``, suite: CC },
  { name: "CU stop ignores the loop count limit", file: F, find: `    input.loop_count < STOP_LOOP_LIMIT`, replace: `    input.loop_count < 1e9`, suite: CC },
  { name: "CU stop accepts a garbage loop_count", file: F, find: `    Number.isInteger(input.loop_count) &&\n`, replace: ``, suite: CC },
  { name: "CU stop follows up on a scan warning alone", file: F, find: `      const mail = notes.filter((n) => UNREAD_NOTE.test(n));`, replace: `      const mail = notes;`, suite: CC },

  // --- stdin and auto-detection
  { name: "CU a terminal on stdin is read", file: F, find: `      if (!s || s.isTTY || s.destroyed) return resolve(null);`, replace: `      if (!s || s.destroyed) return resolve(null);`, suite: CC },
  { name: "CU stdin read has no timeout (hangs on an open pipe)", file: F, find: `    const timer = setTimeout(() => finish(false), timeoutMs);`, replace: `    const timer = setTimeout(() => {}, timeoutMs);`, suite: CC },
  { name: "CU stdin buffer not capped", file: F, find: `      if (size > maxBytes) return finish(false);`, replace: ``, suite: CC },
  { name: "CU Claude Code's own stdin is taken for Cursor's", file: F, find: `  return typeof input.cursor_version === "string" ? "" : null;`, replace: `  return "";`, suite: CC },
  { name: "CU dedupe: any peek hook counts as a native Cursor hook", file: F, find: `ours.test(hookText(x)) && /--format["']?\\s+["']?cursor/.test(hookText(x))`, replace: `ours.test(hookText(x))`, suite: CC },
  { name: "CU dedupe: a native hook for another event counts", file: F, find: `?.hooks?.[event];`, replace: `?.hooks?.beforeSubmitPrompt;`, suite: CC },
  { name: "CU workspace not taken from CURSOR_PROJECT_DIR", file: F, find: `env.CURSOR_PROJECT_DIR || undefined;`, replace: `undefined;`, suite: CC },
  { name: "CU stdin read for any hook even when Cursor's environment is absent", file: "cli.js", find: `(!flagValue("--format") && cursorClient.looksLikeCursorEnv(process.env))`, replace: `(!flagValue("--format"))`, suite: CC },
  { name: "CU stdin not read for --format cursor (stop never sees its status)", file: "cli.js", find: `if (format === "cursor" || (!flagValue("--format")`, replace: `if ((!flagValue("--format")`, suite: CC },
  { name: "CU an imported hook isn't marked imported (no dedupe, no explicit flags for the re-run)", file: "cli.js", find: `          imported = true;`, replace: `          imported = false;`, suite: CC },
  { name: "CU imported hook repeats the native hook's note", file: "cli.js", find: `        if (imported && cursorClient.hasNativeHook(`, replace: `        if (false && cursorClient.hasNativeHook(`, suite: CC },
  { name: "CU the proxy re-run gets no hook input", file: "cli.js", find: `            input: asCursor ? JSON.stringify(hookInput ?? {}) : undefined,`, replace: `            input: undefined,`, suite: CC },
  { name: "CU the proxy re-run's junk output reaches Cursor", file: "cli.js", find: `              ok = typeof child.stdout === "string" && child.stdout.trim() !== "" && JSON.parse(child.stdout) !== null;`, replace: `              ok = true;`, suite: CC },
  { name: "CU a dead proxy re-run leaves Cursor without an answer", file: "cli.js", find: `            else emit();\n          }\n          await flush();`, replace: `            else {}\n          }\n          await flush();`, suite: CC },

  // --- project folder as the agent's name
  { name: "CU an inherited CURSOR_PROJECT_DIR names the agent (R4-11)", file: "store.js", find: `    out.AGENT_NAME = agentNameFromDir(env.AGENT_BRIDGE_PROJECT_DIR || env.CLAUDE_PROJECT_DIR || cwd);`, replace: `    out.AGENT_NAME = agentNameFromDir(env.AGENT_BRIDGE_PROJECT_DIR || env.CLAUDE_PROJECT_DIR || env.CURSOR_PROJECT_DIR || cwd);`, suite: CC },
];
