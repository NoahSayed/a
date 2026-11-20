// OpenAI Codex CLI support: init --client codex (.codex/config.toml + .codex/hooks.json) and peek --format codex.
//   node test/clients-codex.js                       (no Postgres, no Codex needed)
//   CODEX_BIN=/path/to/codex node test/clients-codex.js
//       also runs the parts that need the real Codex binary: it loads the generated files, starts our
//       server through `codex app-server` (no model, no API key) and lists/calls its tools. Skipped when
//       CODEX_BIN is not set. Codex is always run with a throw-away CODEX_HOME and HOME.
import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { slackLocalBackend, sqliteBackend } from "./backends.js";
import { IS_WIN, baseEnv, rmrf, runCli, skip, summary, test } from "./harness.js";
import * as codex from "../clients/codex.js";
import * as claude from "../clients/claude.js";
import * as toml from "../clients/toml-edit.js";
import { SERVER_JS } from "../clients/common.js";

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-codex-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);
const repo = (name) => {
  const d = join(tmp, name);
  mkdirSync(d, { recursive: true });
  return d;
};
const read = (p) => readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(read(p));
const cfgPath = (r) => join(r, ".codex", "config.toml");
const hooksPath = (r) => join(r, ".codex", "hooks.json");
const cfgOf = (r) => toml.parse(read(cfgPath(r)));
const bridgeOf = (r) => cfgOf(r).mcp_servers.bridge;
const posixTest = (name, fn) => (IS_WIN ? skip(name, "POSIX shell / file modes do not exist on Windows") : test(name, fn));
const FIX = fileURLToPath(new URL("./fixtures/codex-hooks/", import.meta.url));
const fixture = (n) => readJson(join(FIX, n));

// ---------------------------------------------------------------------------------------------
// A small JSON Schema (draft 7) checker: just what Codex's generated hook schemas use.
// ---------------------------------------------------------------------------------------------
function schemaErrors(schema, value, root = schema, path = "$") {
  if (schema.$ref) return schemaErrors(root.definitions[schema.$ref.replace("#/definitions/", "")], value, root, path);
  const errs = [];
  for (const s of schema.allOf ?? []) errs.push(...schemaErrors(s, value, root, path));
  if (schema.const !== undefined && value !== schema.const) errs.push(`${path}: must be ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errs.push(`${path}: not one of ${schema.enum}`);
  const types = schema.type === undefined ? [] : [].concat(schema.type);
  const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);
  if (types.length && !types.includes(typeOf(value))) return [...errs, `${path}: expected ${types}, got ${typeOf(value)}`];
  if (typeOf(value) === "object") {
    for (const k of schema.required ?? []) if (!(k in value)) errs.push(`${path}: missing ${k}`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) errs.push(...schemaErrors(schema.properties[k], v, root, `${path}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${path}: unknown property ${k}`);
    }
  }
  return errs;
}
const OUT_SCHEMA = fixture("user-prompt-submit.command.output.schema.json");
const IN_SCHEMA = fixture("user-prompt-submit.command.input.schema.json");
const SESSION_OUT_SCHEMA = fixture("session-start.command.output.schema.json");
const assertValid = (schema, value, what) => assert.deepEqual(schemaErrors(schema, value), [], `${what} does not match Codex's schema: ${JSON.stringify(value)}`);

// What Codex sends a UserPromptSubmit hook on stdin (see the input schema).
const hookInput = (cwd) => ({
  cwd,
  hook_event_name: "UserPromptSubmit",
  model: "gpt-test",
  permission_mode: "default",
  prompt: "hello",
  session_id: "s-1",
  transcript_path: null,
  turn_id: "t-1",
});

// Runs a hook command the way Codex does on macOS/Linux: the string goes to the user's shell as `sh -c`
// (bash/zsh behave the same for these commands), in the session cwd, with the hook input on stdin.
// Codex's own environment is not passed on; this one has a PATH and a HOME only.
function runHookCommand(command, cwd, stdin = JSON.stringify(hookInput(cwd))) {
  return new Promise((resolve) => {
    const p = spawn("sh", ["-c", command], { cwd, env: { ...baseEnv(HOME), AGENT_BRIDGE_DEBUG: "1" } });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.stdin.end(stdin);
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

const init = (r, name, args = [], env = localEnv) => runCli(["init", r, name, ...args, "--client", "codex"], env);

let localEnv;
const sqlite = await sqliteBackend();
localEnv = { HOME, AGENT_BRIDGE_DB: sqlite.envFor("x").AGENT_BRIDGE_DB };

try {
  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: init writes .codex/config.toml ===");

  await test("init --client codex writes [mcp_servers.bridge] and nothing for the other clients", async () => {
    const r = repo("basic");
    const res = await init(r, "alpha", ["React app, owns the login UI"]);
    assert.equal(res.code, 0, res.err);
    const b = bridgeOf(r);
    assert.equal(b.command, process.execPath);
    assert.deepEqual(b.args, [SERVER_JS]);
    assert.equal(b.env.AGENT_NAME, "alpha");
    assert.equal(b.env.AGENT_DESCRIPTION, "React app, owns the login UI");
    assert.equal(b.env.AGENT_BRIDGE_DB, localEnv.AGENT_BRIDGE_DB);
    assert.deepEqual(Object.keys(cfgOf(r)), ["mcp_servers"]);
    assert.ok(!existsSync(join(r, ".mcp.json")) && !existsSync(join(r, ".claude")), "wrote files for another client");
    assert.ok(!existsSync(hooksPath(r)), "wrote a hook without --hook");
    assert.match(res.out, /wrote .*config\.toml  \(agent "alpha", local /);
    assert.match(res.out, /next \(Codex\):.*trust/s);
    assert.ok(!/Hooks need review/.test(res.out), "talks about hook approval without --hook");
  });

  await test("tool_timeout_sec outlasts the longest wait_for_message (600 s) and cwd pins the project dir", async () => {
    const b = bridgeOf(repo("basic"));
    assert.ok(b.tool_timeout_sec > 600, `tool_timeout_sec = ${b.tool_timeout_sec}: a 600 s wait would be cut off`);
    assert.equal(b.tool_timeout_sec, 660);
    assert.equal(b.cwd, repo("basic"));
  });

  await test("init --hook says what Codex asks the user to approve", async () => {
    const r = repo("hookmsg");
    const res = await init(r, "alpha", ["--hook"]);
    assert.equal(res.code, 0, res.err);
    assert.match(res.out, /wrote .*hooks\.json  \(unread-mail hook\)/);
    assert.match(res.out, /Hooks need review/);
    // R4-04: never "Trust all": the user is told to trust the agent-bridge hook and to read anything else
    assert.doesNotMatch(res.out, /Trust all/);
    assert.match(res.out, /trust the agent-bridge hook \(its command runs cli\.js peek alpha\)/);
    // R4-10: what Codex really asks for, given the tool annotations
    assert.match(res.out, /send_message asks before each send/);
  });

  posixTest("new files are readable by the owner only (the entry can hold a proxy URL with credentials)", async () => {
    const r = repo("mode");
    assert.equal((await init(r, "alpha", ["--hook"])).code, 0);
    assert.equal(statSync(cfgPath(r)).mode & 0o777, 0o600);
    assert.equal(statSync(hooksPath(r)).mode & 0o777, 0o600);
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: merging with the user's own settings ===");

  const USER_CONFIG = `# my codex settings
model = "gpt-5"   # keep this comment
notify = ["echo", "done"]

[mcp_servers.docs]
command = "docs-server"
args = ["--stdio",
  "--verbose"]
env = { DOCS_KEY = "k" }

[mcp_servers.bridge]
# an old entry, written by hand
command = "node"
args = [
  "/old/server.js",
]
startup_timeout_sec = 45
default_tools_approval_mode = "prompt"
url = "https://stale.example/mcp"

[mcp_servers.bridge.env]
AGENT_NAME = "stale"
OLD_SETTING = "1"

[mcp_servers.bridge.tools.whoami]
approval_mode = "approve"

[mcp_servers.after]
command = "after-server"

[projects."/work/app"]
trust_level = "trusted"

[tui]
notifications = true
`;

  await test("merge: other settings stay byte-for-byte, our keys are replaced, the user's keys inside the entry stay", async () => {
    const r = repo("merge");
    mkdirSync(join(r, ".codex"));
    writeFileSync(cfgPath(r), USER_CONFIG);
    const res = await init(r, "alpha", ["owns /api"]);
    assert.equal(res.code, 0, res.err);
    const after = read(cfgPath(r));
    // every line the user wrote outside the bridge entry is still there, in order, unchanged
    const kept = USER_CONFIG.split("\n").filter((l) => !/^(# an old entry|command = "node"|  "\/old|\]$|args = \[$|url = |AGENT_NAME = "stale"|OLD_SETTING|\[mcp_servers\.bridge\.env\]$|default_tools_approval_mode|\[mcp_servers\.bridge\.tools\.whoami\]$|approval_mode = "approve"$)/.test(l));
    let pos = 0;
    for (const line of kept) {
      const at = after.indexOf(line, pos);
      assert.ok(at >= 0, `lost or reordered: ${JSON.stringify(line)}\n${after}`);
      pos = at;
    }
    assert.ok(after.includes("# keep this comment") && after.includes('args = ["--stdio",\n  "--verbose"]'));
    const c = toml.parse(after);
    assert.equal(c.model, "gpt-5");
    assert.deepEqual(c.notify, ["echo", "done"]);
    assert.deepEqual(c.mcp_servers.docs, { command: "docs-server", args: ["--stdio", "--verbose"], env: { DOCS_KEY: "k" } });
    assert.deepEqual(c.mcp_servers.after, { command: "after-server" });
    assert.deepEqual(c.projects, { "/work/app": { trust_level: "trusted" } });
    assert.equal(c.tui.notifications, true);
    const b = c.mcp_servers.bridge;
    assert.equal(b.command, process.execPath);
    assert.deepEqual(b.args, [SERVER_JS]);
    assert.equal(b.env.AGENT_NAME, "alpha");
    assert.ok(!("OLD_SETTING" in b.env), "the old env table survived");
    assert.ok(!("url" in b), "another transport's key survived next to command");
    assert.equal(b.startup_timeout_sec, 45, "the user's own key in the entry was dropped");
    // R4-04: approvals in the bridge entry are dropped (a cloned repo could pre-approve sending), and init says so
    assert.ok(!("default_tools_approval_mode" in b), "a pre-set approval mode survived");
    assert.ok(!("tools" in b), "a pre-set per-tool approval survived");
    assert.match(res.out, /removed default_tools_approval_mode, tools from \[mcp_servers\.bridge\]/);
    assert.equal(after.split("[mcp_servers.bridge]").length, 2, "the entry is duplicated");
  });

  await test("re-running init is idempotent for both files and keeps the description", async () => {
    const r = repo("idem");
    mkdirSync(join(r, ".codex"));
    writeFileSync(cfgPath(r), USER_CONFIG);
    writeFileSync(hooksPath(r), JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "echo bye" }] }] } }));
    assert.equal((await init(r, "alpha", ["--hook", "first description"])).code, 0);
    const cfg1 = read(cfgPath(r));
    const hooks1 = read(hooksPath(r));
    const second = await init(r, "alpha", ["--hook"]);
    assert.equal(second.code, 0, second.err);
    assert.equal(read(cfgPath(r)), cfg1, "second run changed config.toml");
    assert.equal(read(hooksPath(r)), hooks1, "second run changed hooks.json");
    assert.equal(bridgeOf(r).env.AGENT_DESCRIPTION, "first description");
    assert.equal((await init(r, "alpha", ["--hook"])).code, 0);
    assert.equal(read(cfgPath(r)), cfg1);
  });

  await test("a file with CRLF line endings, no final newline and a BOM stays that way", async () => {
    const r = repo("crlf");
    mkdirSync(join(r, ".codex"));
    writeFileSync(cfgPath(r), "\ufeffmodel = \"x\"\r\n\r\n[mcp_servers.bridge]\r\ncommand = \"old\"\r\n\r\n[tui]\r\nfoo = 1");
    assert.equal((await init(r, "alpha")).code, 0);
    const after = read(cfgPath(r));
    assert.ok(after.startsWith("\ufeffmodel = \"x\"\r\n"), "BOM or first line lost");
    assert.ok(!/[^\r]\n/.test(after), "a bare LF was introduced: " + JSON.stringify(after));
    assert.ok(after.endsWith("[tui]\r\nfoo = 1"), "the tail changed: " + JSON.stringify(after.slice(-30)));
    const c = toml.parse(after.slice(1));
    assert.equal(c.tui.foo, 1);
    assert.equal(c.mcp_servers.bridge.env.AGENT_NAME, "alpha");
  });

  await test("an entry that exists only as sub-tables, or the file ending in our header, is handled", async () => {
    const a = repo("only-sub");
    mkdirSync(join(a, ".codex"));
    writeFileSync(cfgPath(a), '[mcp_servers.bridge.env]\nA = "1"\n\n[mcp_servers.bridge.tools.send_message]\napproval_mode = "approve"\n');
    assert.equal((await init(a, "alpha")).code, 0);
    assert.equal(bridgeOf(a).env.AGENT_NAME, "alpha");
    assert.ok(!("A" in bridgeOf(a).env));
    assert.ok(!("tools" in bridgeOf(a)), "a pre-set approval for send_message survived (R4-04)");
    const e = repo("header-at-eof");
    mkdirSync(join(e, ".codex"));
    writeFileSync(cfgPath(e), "x = 1\n[mcp_servers.bridge]");
    assert.equal((await init(e, "alpha")).code, 0);
    assert.equal(cfgOf(e).x, 1);
    assert.equal(bridgeOf(e).env.AGENT_NAME, "alpha");
    const z = repo("empty-file");
    mkdirSync(join(z, ".codex"));
    writeFileSync(cfgPath(z), "");
    assert.equal((await init(z, "alpha")).code, 0);
    assert.equal(bridgeOf(z).env.AGENT_NAME, "alpha");
  });

  await test("header-looking text inside strings and arrays is not mistaken for a table", async () => {
    const r = repo("tricky");
    mkdirSync(join(r, ".codex"));
    const tricky = [
      'multi = """',
      "[mcp_servers.bridge]",
      'command = "decoy"',
      '"""',
      "lit = '''",
      "[mcp_servers.bridge.env]",
      "'''",
      "nested = [",
      "  [1, 2],",
      '  ["[mcp_servers.bridge]"],',
      "]",
      'inline = { a = "[x]", b = [ "y" ] }',
      "",
    ].join("\n");
    writeFileSync(cfgPath(r), tricky);
    assert.equal((await init(r, "alpha")).code, 0);
    const after = read(cfgPath(r));
    assert.ok(after.startsWith(tricky), "the user's lines before our entry changed");
    const c = toml.parse(after);
    assert.equal(c.multi, "[mcp_servers.bridge]\ncommand = \"decoy\"\n");
    assert.equal(c.lit, "[mcp_servers.bridge.env]\n");
    assert.deepEqual(c.nested, [[1, 2], ["[mcp_servers.bridge]"]]);
    assert.equal(c.mcp_servers.bridge.command, process.execPath);
  });

  await test("a config that init cannot edit safely is refused and left as it was (and so is hooks.json)", async () => {
    const cases = {
      "does not parse": ["[mcp_servers.bridge\ncommand = 1", /can't parse/],
      "dotted keys": ['mcp_servers.bridge.command = "x"\n', /dotted keys or an inline table/],
      "inline table": ['[mcp_servers]\nbridge = { command = "x" }\n', /dotted keys or an inline table/],
      "root inline table": ['mcp_servers = { bridge = { command = "x" } }\n', /dotted keys or an inline table/],
      "array of tables": ['[[mcp_servers.bridge]]\ncommand = "x"\n', /array of tables/],
    };
    for (const [what, [text, re]] of Object.entries(cases)) {
      const r = repo("refuse-" + what.replace(/\W/g, ""));
      mkdirSync(join(r, ".codex"));
      writeFileSync(cfgPath(r), text);
      const res = await init(r, "alpha", ["--hook"]);
      assert.notEqual(res.code, 0, `${what}: init succeeded`);
      assert.match(res.err, re, what);
      assert.equal(read(cfgPath(r)), text, `${what}: the file was changed`);
      assert.ok(!existsSync(hooksPath(r)), `${what}: hooks.json was written although config.toml was refused`);
    }
  });

  await test("a hooks.json that init cannot merge is refused before config.toml is touched", async () => {
    for (const [i, bad] of ["[]", "not json", '{"hooks": []}', '{"hooks": {"UserPromptSubmit": {}}}'].entries()) {
      const r = repo("badhooks-" + i);
      mkdirSync(join(r, ".codex"));
      writeFileSync(hooksPath(r), bad);
      const res = await init(r, "alpha", ["--hook"]);
      assert.notEqual(res.code, 0, bad);
      assert.match(res.err, /hooks\.json/, bad);
      assert.ok(!existsSync(cfgPath(r)), `config.toml was written although hooks.json was refused (${bad})`);
      assert.equal(read(hooksPath(r)), bad);
    }
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: hostile text cannot inject TOML ===");

  const HOSTILE = [
    'plain "quotes" and \\ backslash \\" \\\\',
    'evil"\n\n[mcp_servers.evil]\ncommand = "/bin/sh"\n',
    'x"]\n[mcp_servers.bridge.env]\nPWN = "1"\n#',
    'triple """ and \'\'\' quotes',
    'line1\nline2\r\nline3\ttab',
    "]]] [[[ ] [ = # not a comment",
    "unicode: caf\u00e9 \u65e5\u672c\u8a9e \ud83d\ude00 \u2028 \u2029 \u0085 \ufeff",
    "ends with backslash \\",
    'key = "value"\nargs = ["--evil"]\ncwd = "/"\n',
    "\u007f del and \u0001 control (via writeConfig only)",
  ];

  await test("descriptions with quotes, newlines, brackets, triple quotes, backslashes and unicode round-trip as plain strings", async () => {
    for (const [i, desc] of HOSTILE.entries()) {
      const r = repo(`hostile-${i}`);
      mkdirSync(join(r, ".codex"));
      writeFileSync(cfgPath(r), '[tui]\nx = 1\n\n[mcp_servers.bridge.tools.whoami]\napproval_mode = "approve"\n');
      // through the CLI where argv can carry the text; NUL is impossible in argv, the rest can be passed
      const res = await init(r, "alpha", [desc, "--hook"]);
      assert.equal(res.code, 0, `#${i}: ${res.err}`);
      const c = cfgOf(r);
      assert.deepEqual(Object.keys(c).sort(), ["mcp_servers", "tui"], `#${i}: top-level keys: ${Object.keys(c)}`);
      assert.deepEqual(Object.keys(c.mcp_servers), ["bridge"], `#${i}: servers: ${Object.keys(c.mcp_servers)}`);
      assert.deepEqual(Object.keys(c.mcp_servers.bridge).sort(), ["args", "command", "cwd", "env", "tool_timeout_sec"], `#${i}`);
      assert.deepEqual(Object.keys(c.mcp_servers.bridge.env).sort(), ["AGENT_BRIDGE_DB", "AGENT_DESCRIPTION", "AGENT_NAME"], `#${i}`);
      assert.equal(c.mcp_servers.bridge.env.AGENT_DESCRIPTION, desc, `#${i}: description changed`);
      assert.equal(c.mcp_servers.bridge.cwd, r, `#${i}: cwd was overridden`);
      assert.equal(c.tui.x, 1);
      // and the description is not in the hook command at all
      assert.ok(!read(hooksPath(r)).includes("AGENT_DESCRIPTION"));
      assert.equal(readJson(hooksPath(r)).hooks.UserPromptSubmit.length, 1);
    }
  });

  await test("hostile values written directly (agent name, paths, env keys and values) also stay inside their strings", async () => {
    const r = repo("hostile-direct");
    const log = [];
    const nasty = 'a"\n[evil]\nx = """ \\u0000 \u007f \u0001';
    codex.writeConfig({ repoDir: r, name: "alpha", env: { AGENT_NAME: "alpha", [nasty]: nasty, AGENT_DESCRIPTION: nasty }, withHook: false, log: (l) => log.push(l) });
    const c = cfgOf(r);
    assert.deepEqual(Object.keys(c), ["mcp_servers"]);
    assert.deepEqual(c.mcp_servers.bridge.env, { AGENT_NAME: "alpha", [nasty]: nasty, AGENT_DESCRIPTION: nasty });
    const weird = repo('weird "dir" [x]\\y\nz');
    codex.writeConfig({ repoDir: weird, name: "alpha", env: { AGENT_NAME: "alpha" }, withHook: true, log: () => {} });
    assert.equal(bridgeOf(weird).cwd, weird);
  });

  await test("a lone surrogate (cannot be encoded) is refused and nothing is written", async () => {
    const r = repo("surrogate");
    mkdirSync(join(r, ".codex"));
    writeFileSync(cfgPath(r), "# mine\n");
    assert.throws(() => codex.writeConfig({ repoDir: r, name: "alpha", env: { AGENT_NAME: "alpha", AGENT_DESCRIPTION: "bad \ud800 end" }, withHook: true, log: () => {} }), /surrogate/);
    assert.equal(read(cfgPath(r)), "# mine\n");
    assert.ok(!existsSync(hooksPath(r)));
    assert.throws(() => toml.tomlString("bad \udc00 end"), /surrogate/);
    assert.throws(() => toml.tomlString("bad \ud800"), /surrogate/);
    assert.equal(toml.parse(`k = ${toml.tomlString("ok \ud83d\ude00")}`).k, "ok \ud83d\ude00");
  });

  await test("tomlString escapes everything that could end the string or start a line", async () => {
    for (const s of ['"', "\\", "\n", "\r", "\t", "\u0000", "\u001f", "\u007f", "\u0085", "\u2028", "\ufeff", '"""', "'''", "\\u0041", "\ud83d\ude00"]) {
      const lit = toml.tomlString(s);
      assert.ok(!/[\u0000-\u0008\u000a-\u001f\u007f\u0080-\u009f\u2028\u2029\ufeff]/.test(lit), `${JSON.stringify(s)} -> raw control character in ${JSON.stringify(lit)}`);
      assert.equal(toml.parse(`k = ${lit}`).k, s);
    }
    assert.equal(toml.tomlKey("AGENT_NAME"), "AGENT_NAME");
    assert.equal(toml.parse(`${toml.tomlKey("a b.c\"")} = 1`)["a b.c\""], 1);
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: secrets and symlinks ===");

  await test("an env that carries a secret value is refused; token file paths are fine", async () => {
    const r = repo("secret");
    for (const k of ["SLACK_BOT_TOKEN", "AGENT_BRIDGE_TOKEN", "SUPABASE_SECRET_KEY_TOKEN", "RELAY_PASSWORD", "MY_SECRET"]) {
      assert.throws(() => codex.writeConfig({ repoDir: r, name: "alpha", env: { AGENT_NAME: "alpha", [k]: "xoxb-value" }, withHook: false, log: () => {} }), /looks like a secret/, k);
    }
    assert.ok(!existsSync(cfgPath(r)));
    codex.writeConfig({ repoDir: r, name: "alpha", env: { AGENT_NAME: "alpha", AGENT_BRIDGE_TOKEN_FILE: "/t/a.token", SLACK_BOT_TOKEN_FILE: "/t/s", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_x" }, withHook: false, log: () => {} });
    assert.equal(bridgeOf(r).env.AGENT_BRIDGE_TOKEN_FILE, "/t/a.token");
  });

  await test("init --slack writes the bot token's path, never the token, into both files", async () => {
    const r = repo("slack-secret");
    const tf = join(HOME, "slack.token");
    const secret = "xoxb-1234567890-very-secret-value";
    writeFileSync(tf, secret + "\n", { mode: 0o600 });
    const res = await runCli(["init", r, "alpha", "--slack", "--hook", "--token-file", tf, "--client", "codex"], { HOME, SLACK_CHANNEL_ID: "C0123456789" });
    assert.equal(res.code, 0, res.err);
    for (const f of [cfgPath(r), hooksPath(r)]) assert.ok(!read(f).includes(secret), `bot token leaked into ${f}`);
    assert.equal(bridgeOf(r).env.SLACK_BOT_TOKEN_FILE, tf);
    assert.match(readJson(hooksPath(r)).hooks.UserPromptSubmit[0].hooks[0].command, /SLACK_BOT_TOKEN_FILE=/);
  });

  const symlinkTest = (name, fn) => (IS_WIN ? skip(name, "creating symlinks needs privileges on Windows") : test(name, fn));

  await symlinkTest("init refuses to write through a symlinked .codex, config.toml or hooks.json", async () => {
    const victim = repo("victim");
    // .codex is a symlink
    const a = repo("sym-dir");
    symlinkSync(victim, join(a, ".codex"));
    let res = await init(a, "alpha", ["--hook"]);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /symlink/);
    assert.ok(!existsSync(join(victim, "config.toml")) && !existsSync(join(victim, "hooks.json")), "wrote through the .codex symlink");
    // config.toml is a symlink
    const b = repo("sym-cfg");
    mkdirSync(join(b, ".codex"));
    writeFileSync(join(victim, "target.toml"), "# victim\n");
    symlinkSync(join(victim, "target.toml"), cfgPath(b));
    res = await init(b, "alpha");
    assert.notEqual(res.code, 0);
    assert.match(res.err, /symlink/);
    assert.equal(read(join(victim, "target.toml")), "# victim\n", "wrote through the config.toml symlink");
    // hooks.json is a symlink: refused before config.toml is written
    const c = repo("sym-hooks");
    mkdirSync(join(c, ".codex"));
    writeFileSync(join(victim, "target.json"), "{}");
    symlinkSync(join(victim, "target.json"), hooksPath(c));
    res = await init(c, "alpha", ["--hook"]);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /symlink/);
    assert.equal(read(join(victim, "target.json")), "{}", "wrote through the hooks.json symlink");
    assert.ok(!existsSync(cfgPath(c)), "config.toml was written although hooks.json was refused");
    // without --hook a symlinked hooks.json is not touched, so it is not an error
    res = await init(c, "alpha");
    assert.equal(res.code, 0, res.err);
    assert.ok(lstatSync(hooksPath(c)).isSymbolicLink());
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: the hook entry ===");

  await test("hooks.json has one UserPromptSubmit command hook that runs peek --format codex", async () => {
    const r = repo("hookshape");
    assert.equal((await init(r, "alpha", ["--hook", "a description that must not be in the hook"])).code, 0);
    const h = readJson(hooksPath(r));
    assert.deepEqual(Object.keys(h), ["hooks"], "Codex rejects unknown top-level keys in hooks.json");
    assert.deepEqual(Object.keys(h.hooks), ["UserPromptSubmit"]);
    const [group] = h.hooks.UserPromptSubmit;
    assert.deepEqual(Object.keys(group), ["hooks"]);
    const [hook] = group.hooks;
    assert.equal(hook.type, "command");
    assert.equal(hook.args, undefined, "Codex has no exec form: a hook is a single command string");
    assert.equal(typeof hook.command, "string");
    assert.ok(hook.timeout > 0 && hook.timeout <= 30, `timeout ${hook.timeout}`);
    assert.deepEqual(Object.keys(hook).sort(), ["command", "statusMessage", "timeout", "type"]);
    if (!IS_WIN) {
      assert.match(hook.command, new RegExp(`^'${process.execPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}' '[^']*cli\\.js' 'peek' 'alpha' '--format' 'codex' '--set' 'AGENT_NAME=alpha' '--set' 'AGENT_BRIDGE_DB=[^']*'$`));
    }
    assert.ok(!hook.command.includes("AGENT_DESCRIPTION") && !hook.command.includes("must not be"));
    assert.ok(!/^\s*\w+=/.test(hook.command), "a VAR=value prefix does not exist in PowerShell or cmd");
  });

  await test("only bridge settings reach the hook command; proxy settings travel as --set arguments", async () => {
    const r = repo("hookenv");
    codex.writeConfig({
      repoDir: r, name: "alpha", withHook: true, hookForm: "shell", log: () => {},
      env: { AGENT_NAME: "alpha", AGENT_BRIDGE_DB: "/d.db", AGENT_DESCRIPTION: "d", NODE_OPTIONS: "--require /evil.js", HTTPS_PROXY: "http://p:3128", EVIL: "x" },
    });
    const cmd = readJson(hooksPath(r)).hooks.UserPromptSubmit[0].hooks[0].command;
    if (!IS_WIN) {
      assert.ok(cmd.includes("'--set' 'HTTPS_PROXY=http://p:3128'"), cmd);
      assert.ok(!cmd.includes("NODE_OPTIONS") && !cmd.includes("EVIL"), cmd);
    }
  });

  await test("re-running init replaces our hook in place (Codex's trust record is keyed by position) and leaves the user's hooks alone", async () => {
    const r = repo("hookmerge");
    mkdirSync(join(r, ".codex"));
    const lint = { type: "command", command: "node scripts/lint.js", timeout: 5 };
    const before = { type: "command", command: "echo first" };
    const old1 = { type: "command", command: `'/old/node' '/old/agent-bridge/cli.js' 'peek' 'alpha' '--format' 'codex'` };
    const old2 = { type: "command", command: `AGENT_BRIDGE_DB='/x' '/old/node' '/older/agent-bridge/cli.js' peek alpha --format codex` };
    const other = { type: "command", command: `'/n/node' '/elsewhere/agent-bridge/cli.js' 'peek' 'alphabet' '--format' 'codex'` }; // another agent's hook
    writeFileSync(
      hooksPath(r),
      JSON.stringify({
        description: "mine",
        hooks: {
          Stop: [{ hooks: [{ type: "command", command: "echo stopped" }] }],
          UserPromptSubmit: [{ hooks: [before] }, { matcher: "*", hooks: [lint, old1, other] }, { hooks: [old2] }, { hooks: [{ type: "command", command: "echo last" }] }],
        },
      })
    );
    for (let i = 0; i < 2; i++) assert.equal((await init(r, "alpha", ["--hook"])).code, 0);
    const h = readJson(hooksPath(r));
    assert.equal(h.description, "mine");
    assert.deepEqual(h.hooks.Stop, [{ hooks: [{ type: "command", command: "echo stopped" }] }]);
    const groups = h.hooks.UserPromptSubmit;
    assert.equal(groups.length, 3, JSON.stringify(groups));
    assert.deepEqual(groups[0], { hooks: [before] });
    assert.equal(groups[1].matcher, "*");
    assert.deepEqual(groups[1].hooks[0], lint);
    assert.match(groups[1].hooks[1].command, /cli\.js' 'peek' 'alpha' '--format' 'codex' '--set'/, "ours moved: " + JSON.stringify(groups[1]));
    assert.deepEqual(groups[1].hooks[2], other, "another agent's hook was removed");
    assert.deepEqual(groups[2], { hooks: [{ type: "command", command: "echo last" }] });
    assert.ok(!JSON.stringify(h).includes("/old"), "an old agent-bridge hook of this agent is still there");
  });

  await test("the agent name is matched literally: a name with regex characters does not remove another agent's hook", async () => {
    const r = repo("regex-name");
    const mine = (n) => ({ type: "command", command: `'/n/node' '/x/agent-bridge/cli.js' 'peek' '${n}' '--format' 'codex'` });
    mkdirSync(join(r, ".codex"));
    writeFileSync(hooksPath(r), JSON.stringify({ hooks: { UserPromptSubmit: [{ hooks: [mine("abc")] }] } }));
    codex.writeConfig({ repoDir: r, name: "a.c", env: { AGENT_NAME: "a.c" }, withHook: true, log: () => {} });
    const cmds = readJson(hooksPath(r)).hooks.UserPromptSubmit.flatMap((g) => g.hooks.map((x) => x.command));
    assert.equal(cmds.length, 2, cmds.join("\n"));
    assert.ok(cmds[0].includes("'abc'"), "the hook of agent abc was replaced by the one for a.c");
  });

  await test("two agents in one repo's hooks.json do not replace each other's hook", async () => {
    const r = repo("two-agents");
    assert.equal((await init(r, "alpha", ["--hook"])).code, 0);
    assert.equal((await init(r, "beta", ["--hook"])).code, 0);
    const cmds = readJson(hooksPath(r)).hooks.UserPromptSubmit.flatMap((g) => g.hooks.map((x) => x.command));
    assert.equal(cmds.length, 2);
    assert.ok(cmds.some((c) => c.includes("'peek' 'alpha'")) && cmds.some((c) => c.includes("'peek' 'beta'")));
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: quoting for each shell Codex can use ===");

  await test("POSIX quoting survives quotes, spaces, $ and backticks; control characters are refused", async () => {
    const line = codex.hookCommandLine(["/p a/node", "it's", "$HOME `id` $(id) ; & | > <", "--set", "A=b c"], "posix");
    assert.equal(line, `'/p a/node' 'it'\\''s' '$HOME \`id\` $(id) ; & | > <' '--set' 'A=b c'`);
    if (!IS_WIN) {
      const out = execFileSync("sh", ["-c", `printf '%s|' ${line.replace("'/p a/node'", "")}`], { encoding: "utf8", env: { PATH: process.env.PATH } });
      assert.equal(out, "it's|$HOME `id` $(id) ; & | > <|--set|A=b c|");
    }
    assert.throws(() => codex.hookCommandLine(["a\nb"], "posix"), /control character/);
    assert.throws(() => codex.hookCommandLine(["a\u0000b"], "posix"), /control character/);
  });

  await test("PowerShell form: & call operator, single quotes doubled (typographic ones too), double quotes refused", async () => {
    assert.equal(codex.hookCommandLine(["C:\\Program Files\\nodejs\\node.exe", "it's", "a\u2019b"], "powershell"), "& 'C:\\Program Files\\nodejs\\node.exe' 'it''s' 'a\u2019\u2019b'");
    assert.throws(() => codex.hookCommandLine(['a"b'], "powershell"), /double quote/);
    assert.throws(() => codex.hookCommandLine(["a\nb"], "powershell"), /control character/);
  });

  await test("cmd.exe form: double quotes, and %, \" or a trailing backslash refused", async () => {
    assert.equal(codex.hookCommandLine(["C:\\Program Files\\nodejs\\node.exe", "a b", "x&y"], "cmd"), '"C:\\Program Files\\nodejs\\node.exe" "a b" "x&y"');
    for (const bad of ['a"b', "%PATH%", "dir\\"]) assert.throws(() => codex.hookCommandLine([bad], "cmd"), /cmd\.exe/, bad);
    assert.throws(() => codex.hookCommandLine(["a\nb"], "cmd"), /control character/);
  });

  await test("on Windows the default is PowerShell, --hook-form shell selects cmd.exe, other platforms are POSIX", async () => {
    assert.equal(codex.hookShell("win32", "exec"), "powershell");
    assert.equal(codex.hookShell("win32", undefined), "powershell");
    assert.equal(codex.hookShell("win32", "shell"), "cmd");
    for (const p of ["linux", "darwin"]) for (const f of ["shell", "exec"]) assert.equal(codex.hookShell(p, f), "posix");
    const r = repo("win-hook");
    const w = (hookForm) => {
      codex.writeConfig({ repoDir: r, name: "alpha", env: { AGENT_NAME: "alpha" }, withHook: true, hookForm, platform: "win32", log: () => {} });
      return readJson(hooksPath(r)).hooks.UserPromptSubmit[0].hooks[0].command;
    };
    assert.match(w("exec"), /^& '.*' '.*cli\.js' 'peek' 'alpha' '--format' 'codex' '--set' 'AGENT_NAME=alpha'$/);
    assert.match(w("shell"), /^".*" ".*cli\.js" "peek" "alpha" "--format" "codex" "--set" "AGENT_NAME=alpha"$/);
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: peek --format codex ===");

  await test("peekOutput: nothing without notes; Codex hook JSON with them; never bare text", async () => {
    assert.equal(codex.peekOutput([]), "");
    assert.equal(codex.peekOutput([], { event: "SessionStart" }), "");
    const out = codex.peekOutput(["[agent-bridge] You have unread bridge messages (1 from bob).", '[agent-bridge] WARNING: "quoted" \n second line'], {});
    assert.ok(out.endsWith("\n") && out.split("\n").length === 2, "one JSON document on one line");
    const j = JSON.parse(out);
    assertValid(OUT_SCHEMA, j, "UserPromptSubmit output");
    assert.equal(j.hookSpecificOutput.hookEventName, "UserPromptSubmit");
    assert.equal(j.hookSpecificOutput.additionalContext, '[agent-bridge] You have unread bridge messages (1 from bob).\n[agent-bridge] WARNING: "quoted" \n second line');
    // plain text starting with [ or { makes Codex report "invalid JSON output" instead of reading it as context
    assert.ok(out.startsWith("{"));
    const session = JSON.parse(codex.peekOutput(["note"], { event: "SessionStart" }));
    assertValid(SESSION_OUT_SCHEMA, session, "SessionStart output");
    assert.equal(session.hookSpecificOutput.hookEventName, "SessionStart");
    // an event name that is not one of ours cannot be echoed into the output
    assert.equal(JSON.parse(codex.peekOutput(["note"], { event: "PreToolUse" })).hookSpecificOutput.hookEventName, "UserPromptSubmit");
    assert.equal(JSON.parse(codex.peekOutput(["note"], { event: 'x","evil":"1' })).hookSpecificOutput.hookEventName, "UserPromptSubmit");
  });

  await test("peek --format codex: mail gives valid hook JSON, no mail gives empty output (SQLite)", async () => {
    const quiet = await runCli(["peek", "gamma", "--format", "codex"], localEnv);
    assert.equal(quiet.code, 0);
    assert.equal(quiet.out, "", "no mail must print nothing");
    await runCli(["send", "gamma", "ping", "from", "cli"], { ...localEnv, AGENT_NAME: "human" });
    const mail = await runCli(["peek", "gamma", "--format", "codex"], localEnv);
    assert.equal(mail.code, 0);
    const j = JSON.parse(mail.out);
    assertValid(OUT_SCHEMA, j, "peek output");
    assert.match(j.hookSpecificOutput.additionalContext, /^\[agent-bridge\] You have unread bridge messages \(1 from human\)\. Call check_inbox when relevant\.$/);
    // the Claude format is unchanged: plain text
    const plain = await runCli(["peek", "gamma"], localEnv);
    assert.match(plain.out, /^\[agent-bridge\] You have unread/);
  });

  await test("peek --format codex with an incomplete Slack scan: the warning is in the hook JSON", async () => {
    const b = await slackLocalBackend();
    try {
      for (const a of ["alice", "bob", "eve"]) await b.addAgent(a);
      const { createStore } = await import("../store.js");
      const alice = await createStore({ env: b.envFor("alice") });
      await alice.identify();
      await alice.send({ to: "bob", body: "older request the capped scan cannot reach" });
      for (let i = 0; i < 700; i++) b.slack.postAs(b.users.eve, { text: "noise " + i });
      const res = await runCli(["peek", "bob", "--format", "codex"], { ...b.envFor("bob"), AGENT_BRIDGE_SLACK_MAX_PAGES: "3", HOME });
      assert.equal(res.code, 0, res.err);
      const j = JSON.parse(res.out);
      assertValid(OUT_SCHEMA, j, "peek output");
      assert.match(j.hookSpecificOutput.additionalContext, /\[agent-bridge\] WARNING: The channel scan is INCOMPLETE/);
    } finally {
      await b.cleanup?.();
    }
  });

  await test("peek --format codex stays silent (exit 0, empty) when the backend is unreachable", async () => {
    const res = await runCli(["peek", "gamma", "--format", "codex"], { HOME, AGENT_BRIDGE_BACKEND: "supabase", SUPABASE_URL: "http://127.0.0.1:1", SUPABASE_PUBLISHABLE_KEY: "x", AGENT_BRIDGE_TOKEN: "t" });
    assert.equal(res.code, 0);
    assert.equal(res.out, "");
  });

  posixTest("the generated hook command, run the way Codex runs it, prints nothing without mail and schema-valid JSON with mail", async () => {
    const r = repo("hookrun");
    assert.equal((await init(r, "delta", ["--hook"])).code, 0);
    const command = readJson(hooksPath(r)).hooks.UserPromptSubmit[0].hooks[0].command;
    assertValid(IN_SCHEMA, hookInput(r), "the hook input this test feeds the hook");
    const quiet = await runHookCommand(command, r);
    assert.equal(quiet.code, 0, quiet.err);
    assert.equal(quiet.out, "");
    assert.equal(quiet.err, "");
    await runCli(["send", "delta", "please", "review"], { ...localEnv, AGENT_NAME: "human" });
    const mail = await runHookCommand(command, r);
    assert.equal(mail.code, 0, mail.err);
    const j = JSON.parse(mail.out);
    assertValid(OUT_SCHEMA, j, "hook stdout");
    assert.match(j.hookSpecificOutput.additionalContext, /1 from human/);
    // the same, from a directory with spaces and a quote in its name and a node path with spaces
    const odd = repo("odd dir 'q'");
    assert.equal((await init(odd, "delta", ["--hook"])).code, 0);
    const again = await runHookCommand(readJson(hooksPath(odd)).hooks.UserPromptSubmit[0].hooks[0].command, odd);
    assert.match(JSON.parse(again.out).hookSpecificOutput.additionalContext, /1 from human/);
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: --client combinations and readServerEnv ===");

  await test("--client claude,codex writes both clients' files in one run", async () => {
    const r = repo("both");
    const res = await runCli(["init", r, "alpha", "both clients", "--hook", "--client", "claude,codex"], localEnv);
    assert.equal(res.code, 0, res.err);
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_NAME, "alpha");
    assert.ok(readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit.length);
    assert.equal(bridgeOf(r).env.AGENT_NAME, "alpha");
    assert.equal(bridgeOf(r).env.AGENT_DESCRIPTION, "both clients");
    assert.ok(readJson(hooksPath(r)).hooks.UserPromptSubmit.length);
    assert.match(res.out, /next \(Claude Code\)/);
    assert.match(res.out, /next \(Codex\)/);
    // the Claude hook still prints plain text, the Codex hook JSON
    assert.match(readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit[0].hooks[0].command, /peek/);
  });

  await test("readServerEnv round-trips the env (including a hostile description) and is null without a file", async () => {
    const r = repo("rse");
    assert.equal(codex.readServerEnv(r), null);
    const env = { AGENT_NAME: "alpha", AGENT_BRIDGE_DB: "/tmp/x y/b.db", AGENT_DESCRIPTION: HOSTILE[1] + HOSTILE[6] };
    codex.writeConfig({ repoDir: r, name: "alpha", env, withHook: false, log: () => {} });
    const got = codex.readServerEnv(r);
    assert.equal(got.path, cfgPath(r));
    assert.deepEqual(got.env, env);
    assert.equal(codex.previousDescription(r), env.AGENT_DESCRIPTION);
    // a file without our entry: an empty env
    const e = repo("rse-empty");
    mkdirSync(join(e, ".codex"));
    writeFileSync(cfgPath(e), 'model = "x"\n');
    assert.deepEqual(codex.readServerEnv(e), { path: cfgPath(e), env: {} });
    // only strings are env values
    writeFileSync(cfgPath(e), '[mcp_servers.bridge]\nenv = { A = "x", B = 1, C = true, D = ["y"] }\n');
    assert.deepEqual(codex.readServerEnv(e), { path: cfgPath(e), env: { A: "x" } });
    // a description from an earlier Codex init is kept when init runs for another client without one
    const res = await runCli(["init", r, "alpha", "--client", "claude"], { ...localEnv });
    assert.equal(res.code, 0, res.err);
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_DESCRIPTION, env.AGENT_DESCRIPTION);
  });

  await test("a broken .codex/config.toml does not stop init for another client, and readServerEnv reports it instead of throwing", async () => {
    const r = repo("broken-codex");
    mkdirSync(join(r, ".codex"));
    writeFileSync(cfgPath(r), "[mcp_servers.bridge\n");
    const got = codex.readServerEnv(r);
    assert.deepEqual(got.env, {});
    assert.match(got.error, /./);
    const res = await runCli(["init", r, "alpha", "--client", "claude"], localEnv);
    assert.equal(res.code, 0, res.err);
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_NAME, "alpha");
  });

  await test("the claude module is unaffected (still writes plain-text peek output)", async () => {
    assert.equal(claude.peekOutput(["a", "b"]), "a\nb\n");
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: the editor's own checks ===");

  const edit = (text, opts = {}) => codex.editConfigToml(text, { repoDir: "/r", env: { AGENT_NAME: "alpha" }, ...opts });

  await test("the result is verified: an editor that adds a key outside the entry, or writes a wrong entry, is caught", async () => {
    const rogue = (text, table, o) => toml.replaceTable(text, table, o) + '\nevil = "1"\n';
    assert.throws(() => edit("a = 1\n", { _replace: rogue }), /does not match what init meant/);
    const wrongEntry = (text, table, o) => toml.replaceTable(text, table, { ...o, lines: o.lines.map((l) => l.replace('command = "', 'command = "/bin/evil" #')) });
    assert.throws(() => edit("a = 1\n", { _replace: wrongEntry }), /does not match what init meant|does not parse/);
    const dropsUser = (text, table, o) => toml.replaceTable(text, table, o).replace("a = 1", "");
    assert.throws(() => edit("a = 1\n", { _replace: dropsUser }), /does not match what init meant/);
    const broken = (text, table, o) => toml.replaceTable(text, table, o) + "[[[\n";
    assert.throws(() => edit("a = 1\n", { _replace: broken }), /does not parse/);
    assert.ok(edit("a = 1\n").includes("a = 1\n"));
  });

  await test("scan finds headers and statements with exact ranges", async () => {
    const text = 'a = 1\n[t.u] # c\nk = """x\n[no]\n"""\nl = [\n [1],\n]\n[[arr]]\nz = 2';
    const items = toml.scan(text);
    assert.deepEqual(
      items.map((i) => (i.kind === "header" ? `[${i.array ? "[" : ""}${i.path.join(".")}` : i.key.join("."))),
      ["a", "[t.u", "k", "l", "[[arr", "z"]
    );
    assert.equal(text.slice(items[1].start, items[1].end), "[t.u] # c\n");
    assert.equal(text.slice(items[2].start, items[2].end), 'k = """x\n[no]\n"""\n');
    assert.equal(text.slice(items.at(-1).start, items.at(-1).end), "z = 2");
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: Codex starts servers without the parent environment ===");

  // Codex starts a stdio server in the session's working directory with a short list of inherited
  // variables (HOME, PATH, ...) plus the entry's env; it passes no CLAUDE_PROJECT_DIR or AGENT_NAME.
  async function connectLikeCodex(r) {
    const e = bridgeOf(r);
    const client = new Client({ name: "codex-like", version: "0" });
    await client.connect(new StdioClientTransport({ command: e.command, args: e.args, env: { ...baseEnv(HOME), ...e.env }, cwd: e.cwd ?? r }));
    const call = async (tool, args = {}) => (await client.callTool({ name: tool, arguments: args })).content.map((c) => c.text).join("\n");
    return { call, close: () => client.close() };
  }

  await test("AGENT_BRIDGE_NAME_FROM=project names the agent after the project folder when the server is started as Codex starts it", async () => {
    const r = repo("my-service");
    codex.writeConfig({ repoDir: r, name: "ignored", env: { AGENT_BRIDGE_NAME_FROM: "project", AGENT_BRIDGE_DB: localEnv.AGENT_BRIDGE_DB }, withHook: false, log: () => {} });
    const s = await connectLikeCodex(r);
    assert.match(await s.call("whoami"), /"agent": "my-service"/);
    await s.close();
  });

  await test("the entry's cwd is the repo, so list_agents shows the project dir whichever folder Codex was started in", async () => {
    const r = repo("proj-dir");
    assert.equal((await init(r, "projdir")).code, 0);
    const s = await connectLikeCodex(r);
    await s.call("whoami");
    const agents = JSON.parse(await s.call("list_agents"));
    assert.equal(realpathSync(agents.find((a) => a.name === "projdir").project_dir), realpathSync(r));
    await s.close();
  });

  // ------------------------------------------------------------------------------------------
  console.log("\n=== codex: the real Codex binary ===");

  const CODEX_BIN = process.env.CODEX_BIN;
  if (!CODEX_BIN) {
    skip("real Codex binary: config accepted, server started, tools listed and called, hook listed", "CODEX_BIN is not set (point it at a Codex CLI to run these)");
  } else {
    const run = promisify(execFile);
    const codexHome = (trustRepo) => {
      const h = mkdtempSync(join(tmp, "codex-home-"));
      if (trustRepo) {
        const keys = new Set([trustRepo, realpathSync(trustRepo)]);
        writeFileSync(join(h, "config.toml"), [...keys].map((k) => `[projects.${toml.tomlString(k)}]\ntrust_level = "trusted"\n`).join("\n"));
      }
      return h;
    };
    const cenv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, CODEX_HOME: home, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) });
    const codexJson = async (home, cwd, ...args) => JSON.parse((await run(CODEX_BIN, args, { cwd, env: cenv(home), timeout: 60000 })).stdout);

    // A JSON-RPC client for `codex app-server` over stdio: enough to start a thread (no model is called) and ask
    // for the MCP servers' status and tools, call a tool on a server, and list the hooks.
    async function appServer(home, cwd, fn, extraEnv = {}) {
      const p = spawn(CODEX_BIN, ["app-server"], { cwd, env: { ...cenv(home), ...extraEnv }, stdio: ["pipe", "pipe", "pipe"] });
      let buf = "";
      let stderr = "";
      const pending = new Map();
      let id = 0;
      p.stderr.on("data", (d) => (stderr += d));
      p.stdout.on("data", (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          if (!line.trim()) continue;
          const m = JSON.parse(line);
          if (m.id !== undefined && pending.has(m.id)) {
            pending.get(m.id)(m);
            pending.delete(m.id);
          }
        }
      });
      const rpc = (method, params) =>
        new Promise((resolve, reject) => {
          const i = ++id;
          const t = setTimeout(() => reject(new Error(`codex app-server: no answer to ${method}; stderr: ${stderr.slice(-500)}`)), 45000);
          pending.set(i, (m) => {
            clearTimeout(t);
            if (m.error) reject(new Error(`${method}: ${JSON.stringify(m.error)}`));
            else resolve(m.result);
          });
          p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: i, method, params }) + "\n");
        });
      try {
        await rpc("initialize", { clientInfo: { name: "agent-bridge-test", version: "0" } });
        p.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "initialized" }) + "\n");
        return await fn(rpc);
      } finally {
        p.kill();
      }
    }
    const toolText = (r) => r.content.map((c) => c.text).join("\n");
    // Codex starts MCP servers in the background after the thread starts: wait until the server is up.
    async function serverStatus(rpc, threadId, name = "bridge") {
      for (let i = 0; i < 100; i++) {
        const { data } = await rpc("mcpServerStatus/list", { threadId });
        const s = data.find((d) => d.name === name);
        if (s && s.runtimeStatus !== "starting") return s;
        await new Promise((r) => setTimeout(r, 200));
      }
      throw new Error(`MCP server ${name} did not finish starting`);
    }

    const real = repo("real-alpha");
    const desc = 'Real "Codex" test\n[mcp_servers.evil]\ncommand = "x"\n\\ done';
    const res = await init(real, "alpha", [desc, "--hook"]);
    assert.equal(res.code, 0, res.err);
    const trusted = codexHome(real);

    await test("Codex lists the entry (trusted project): command, args, env, cwd and the 660 s tool timeout", async () => {
      const list = await codexJson(trusted, real, "mcp", "list", "--json");
      assert.deepEqual(list.map((s) => s.name), ["bridge"], "an injected server appeared, or ours is missing");
      const s = list[0];
      assert.equal(s.enabled, true);
      assert.equal(s.transport.type, "stdio");
      assert.equal(s.transport.command, process.execPath);
      assert.deepEqual(s.transport.args, [SERVER_JS]);
      assert.equal(s.transport.env.AGENT_NAME, "alpha");
      assert.equal(s.transport.env.AGENT_DESCRIPTION, desc);
      assert.equal(s.transport.cwd, real);
      assert.equal(s.tool_timeout_sec, 660);
      const one = await codexJson(trusted, real, "mcp", "get", "bridge", "--json");
      assert.equal(one.transport.env.AGENT_DESCRIPTION, desc);
    });

    await test("Codex ignores the project's .codex/ until the project is trusted", async () => {
      assert.deepEqual(await codexJson(codexHome(null), real, "mcp", "list", "--json"), []);
    });

    await test("Codex accepts the merged file: the user's settings and Codex's own approval answers survive", async () => {
      const r = repo("real-merge");
      mkdirSync(join(r, ".codex"));
      writeFileSync(cfgPath(r), USER_CONFIG.replace('"/work/app"', toml.tomlString(r)).replace('"stale"', '"stale"'));
      assert.equal((await init(r, "alpha")).code, 0);
      const list = await codexJson(codexHome(r), r, "mcp", "list", "--json");
      assert.deepEqual(list.map((s) => s.name).sort(), ["after", "bridge", "docs"]);
      const b = await codexJson(codexHome(r), r, "mcp", "get", "bridge", "--json");
      assert.equal(b.startup_timeout_sec, 45);
      assert.equal(b.transport.env.AGENT_NAME, "alpha");
      assert.equal(b.tool_timeout_sec, 660);
    });

    await test("Codex starts our server and lists its tools (codex app-server, no model involved)", async () => {
      await appServer(trusted, real, async (rpc) => {
        const { thread } = await rpc("thread/start", { cwd: real, ephemeral: true });
        const bridge = await serverStatus(rpc, thread.id);
        assert.equal(bridge.runtimeStatus, "connected");
        for (const t of ["whoami", "list_agents", "send_message", "check_inbox", "wait_for_message", "get_thread"]) {
          assert.ok(bridge.tools[t], `tool ${t} missing: ${Object.keys(bridge.tools)}`);
        }
      });
    });

    await test("a tool call through Codex reaches the server as agent alpha, in the repo, and mail arrives", async () => {
      await appServer(trusted, real, async (rpc) => {
        const { thread } = await rpc("thread/start", { cwd: real, ephemeral: true });
        const call = async (tool, args = {}) => toolText(await rpc("mcpServer/tool/call", { server: "bridge", threadId: thread.id, tool, arguments: args }));
        assert.match(await call("whoami"), /"agent": "alpha"/);
        const agents = JSON.parse(await call("list_agents"));
        assert.equal(realpathSync(agents.find((a) => a.name === "alpha").project_dir), realpathSync(real));
        assert.equal(agents.find((a) => a.name === "alpha").description, desc);
        await runCli(["send", "alpha", "hello", "through", "codex"], { ...localEnv, AGENT_NAME: "human" });
        assert.match(await call("check_inbox"), /hello through codex/);
      });
    });

    await test("started from a sub-folder of the repo, Codex still finds the entry, and project_dir is the repo (the entry pins cwd)", async () => {
      const top = repo("real-sub");
      try {
        execFileSync("git", ["init", "-q", top], { stdio: "ignore" }); // Codex records trust for the repository root
      } catch {
        return skip("started from a sub-folder", "git is not available");
      }
      assert.equal((await init(top, "subby")).code, 0);
      const sub = join(top, "packages", "ui");
      mkdirSync(sub, { recursive: true });
      await appServer(codexHome(top), sub, async (rpc) => {
        const { thread } = await rpc("thread/start", { cwd: sub, ephemeral: true });
        await serverStatus(rpc, thread.id);
        const call = async (tool) => toolText(await rpc("mcpServer/tool/call", { server: "bridge", threadId: thread.id, tool, arguments: {} }));
        assert.match(await call("whoami"), /"agent": "subby"/);
        assert.equal(realpathSync(JSON.parse(await call("list_agents")).find((a) => a.name === "subby").project_dir), realpathSync(top));
      });
    });

    await test("with AGENT_BRIDGE_NAME_FROM=project Codex's server is named after the repo folder, and the parent's AGENT_NAME / CLAUDE_PROJECT_DIR do not reach it", async () => {
      const r = repo("real-from-project");
      // a shared entry like a managed one: no AGENT_NAME and no cwd, so the server runs in the session's folder
      mkdirSync(join(r, ".codex"));
      writeFileSync(
        cfgPath(r),
        `[mcp_servers.bridge]\ncommand = ${toml.tomlString(process.execPath)}\nargs = [${toml.tomlString(SERVER_JS)}]\n` +
          `env = { AGENT_BRIDGE_NAME_FROM = "project", AGENT_BRIDGE_DB = ${toml.tomlString(localEnv.AGENT_BRIDGE_DB)} }\n`
      );
      await appServer(
        codexHome(r),
        r,
        async (rpc) => {
          const { thread } = await rpc("thread/start", { cwd: r, ephemeral: true });
          const out = toolText(await rpc("mcpServer/tool/call", { server: "bridge", threadId: thread.id, tool: "whoami", arguments: {} }));
          assert.match(out, /"agent": "real-from-project"/, out);
        },
        { AGENT_NAME: "mallory", CLAUDE_PROJECT_DIR: "/tmp/elsewhere", AGENT_BRIDGE_PROJECT_DIR: "/tmp/elsewhere2" }
      );
    });

    await test("Codex lists our hook: UserPromptSubmit, project source, our command, no warnings or errors, untrusted until the user trusts it", async () => {
      await appServer(trusted, real, async (rpc) => {
        const { data } = await rpc("hooks/list", { cwds: [real] });
        assert.deepEqual(data[0].warnings, []);
        assert.deepEqual(data[0].errors, []);
        const ours = data[0].hooks.filter((h) => h.command.includes("cli.js"));
        assert.equal(ours.length, 1, JSON.stringify(data[0].hooks));
        const h = ours[0];
        assert.equal(h.eventName, "userPromptSubmit");
        assert.equal(h.handlerType, "command");
        assert.equal(h.source, "project");
        assert.equal(h.timeoutSec, 10);
        assert.equal(h.command, readJson(hooksPath(real)).hooks.UserPromptSubmit[0].hooks[0].command);
        assert.equal(h.trustStatus, "untrusted", "init must not mark the hook trusted: only the user can");
        assert.equal(h.enabled, true);
        assert.match(h.key, /\.codex\/hooks\.json:user_prompt_submit:0:0$/);
      });
    });

    await test("a second init (same arguments) gives Codex the same hook hash, so an approved hook stays approved", async () => {
      const hash = async (r) =>
        appServer(codexHome(r), r, async (rpc) => (await rpc("hooks/list", { cwds: [r] })).data[0].hooks.find((h) => h.command.includes("cli.js")).currentHash);
      const r = repo("real-hash");
      assert.equal((await init(r, "alpha", ["--hook"])).code, 0);
      const h1 = await hash(r);
      assert.equal((await init(r, "alpha", ["--hook"])).code, 0);
      assert.equal(await hash(r), h1);
      assert.match(h1, /^sha256:[0-9a-f]{64}$/);
    });
  }
} finally {
  await sqlite.cleanup?.();
  rmrf(tmp);
}

process.exit(summary() ? 1 : 0);
