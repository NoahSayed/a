// Cursor client suite: `init --client cursor`, the hook output Cursor's runner accepts, stdin auto-detection.
//   node test/clients-cursor.js            (no Postgres needed; the Slack warning test uses the local Slack stand-in)
//
// The hook runner below mimics what Cursor's own hook engine does (read from the cursor-sdk 1.4.2 bundle, see
// docs/clients/cursor.md): the hooks.json `command` is a shell string, the JSON input is appended as a heredoc,
// CURSOR_PROJECT_DIR / CLAUDE_PROJECT_DIR / CURSOR_VERSION are set, exit 0 + JSON on stdout is the answer.
// `assertValidResponse` mirrors that engine's per-event response validators.
import assert from "node:assert/strict";
import { spawn, execFile, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { promisify } from "node:util";
import { slackLocalBackend } from "./backends.js";
import { CLI, IS_WIN, baseEnv, cleanEnv, rmrf, runCli, skip, summary, test } from "./harness.js";
import * as cursor from "../clients/cursor.js";
import { agentNameFromDir, resolveIdentityEnv } from "../store.js";

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-cursor-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);
const DB = join(tmp, "bridge.db");
const localEnv = { HOME, AGENT_BRIDGE_DB: DB };
const repo = (name) => {
  const d = join(tmp, name);
  mkdirSync(d, { recursive: true });
  return d;
};
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const mcpPath = (r) => join(r, ".cursor", "mcp.json");
const hooksPath = (r) => join(r, ".cursor", "hooks.json");
const posixTest = (name, fn) => (IS_WIN ? skip(name, "the hook runner here is POSIX sh; see the Windows notes in docs/clients/cursor.md") : test(name, fn));
const send = (to, text, from = "human") => runCli(["send", to, ...text.split(" ")], { ...localEnv, AGENT_NAME: from });

// What Cursor's engine accepts per event (mirrors its response validators; unknown keys are tolerated by Cursor,
// but we only ever print the documented ones).
function assertValidResponse(event, o) {
  assert.ok(o && typeof o === "object" && !Array.isArray(o), "response must be a JSON object");
  const allowed = { sessionStart: ["continue", "user_message", "additional_context", "env"], beforeSubmitPrompt: ["continue", "user_message", "additional_context"], stop: ["followup_message"] }[event];
  assert.ok(allowed, `unknown event ${event}`);
  for (const k of Object.keys(o)) assert.ok(allowed.includes(k), `${k} is not an output field of ${event}`);
  if (o.continue !== undefined) assert.equal(typeof o.continue, "boolean");
  for (const k of ["user_message", "additional_context", "followup_message"]) if (o[k] !== undefined) assert.equal(typeof o[k], "string");
}

const input = (event, extra = {}, workspace) => ({
  conversation_id: "c-1",
  generation_id: "g-1",
  hook_event_name: event,
  cursor_version: "3.0.0",
  workspace_roots: [workspace],
  ...extra,
});

// Runs one hooks.json entry the way Cursor does on macOS/Linux.
async function runEntry(repoDir, entry, payload, extraEnv = {}) {
  const script = `${entry.command} <<'CURSOR_HOOK_EOF'\n${JSON.stringify(payload)}\nCURSOR_HOOK_EOF`;
  const env = { ...baseEnv(HOME), CURSOR_PROJECT_DIR: repoDir, CLAUDE_PROJECT_DIR: repoDir, CURSOR_VERSION: "3.0.0", ...extraEnv };
  try {
    const { stdout, stderr } = await promisify(execFile)("bash", ["-c", script], { cwd: repoDir, env, timeout: 20000 });
    return { stdout, stderr, code: 0 };
  } catch (e) {
    return { stdout: e.stdout ?? "", stderr: e.stderr ?? "", code: e.code };
  }
}
const entryFor = (repoDir, event) => readJson(hooksPath(repoDir)).hooks[event][0];
async function runEvent(repoDir, event, extra = {}, extraEnv = {}) {
  const r = await runEntry(repoDir, entryFor(repoDir, event), input(event, extra, repoDir), extraEnv);
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout); // must be valid JSON, always
  assertValidResponse(event, out);
  return out;
}

// stdout of `peek` with stdin left open (never closed) so that a read without a timeout would hang.
function runPeekOpenStdin(args, env, { feed, killAfterMs = 8000 } = {}) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const p = spawn(process.execPath, [CLI, ...args], { env: { ...cleanEnv(), ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stdin.on("error", () => {}); // the child may exit (EPIPE) before it has taken everything
    if (feed != null) p.stdin.write(feed);
    const killer = setTimeout(() => p.kill("SIGKILL"), killAfterMs);
    p.on("close", (code) => {
      clearTimeout(killer);
      resolve({ out, code, ms: Date.now() - t0 });
    });
  });
}

try {
  console.log("\n=== cursor: init ===");

  await test("init --client cursor writes .cursor/mcp.json (same entry as Claude's .mcp.json) and no Claude files", async () => {
    const r = repo("a-basic");
    const res = await runCli(["init", r, "alpha", "React app", "--client", "cursor"], localEnv);
    assert.equal(res.code, 0, res.err);
    const cfg = readJson(mcpPath(r));
    assert.deepEqual(Object.keys(cfg), ["mcpServers"]);
    assert.equal(cfg.mcpServers.bridge.command, process.execPath);
    assert.equal(cfg.mcpServers.bridge.args.length, 1);
    assert.match(cfg.mcpServers.bridge.args[0], /server\.js$/);
    assert.deepEqual(cfg.mcpServers.bridge.env, { AGENT_NAME: "alpha", AGENT_BRIDGE_DB: DB, AGENT_DESCRIPTION: "React app" });
    assert.ok(!existsSync(hooksPath(r)), "no hook without --hook");
    assert.ok(!existsSync(join(r, ".mcp.json")) && !existsSync(join(r, ".claude")), "Claude files written for --client cursor");
    // the same entry Claude gets
    const c = repo("a-basic-claude");
    await runCli(["init", c, "alpha", "React app"], localEnv);
    assert.deepEqual(readJson(join(c, ".mcp.json")).mcpServers.bridge, cfg.mcpServers.bridge);
    assert.match(res.out, /wrote .*\.cursor.*mcp\.json  \(agent "alpha", local /);
    assert.match(res.out, /next \(Cursor\):/);
    assert.match(res.out, /Settings.*MCP/s, "the next-steps line must say where to enable the server");
  });

  await test("init --hook writes hooks.json: version 1, sessionStart + beforeSubmitPrompt, peek --format cursor --event <event>", async () => {
    const r = repo("a-hook");
    const res = await runCli(["init", r, "alpha", "--client", "cursor", "--hook"], localEnv);
    assert.equal(res.code, 0, res.err);
    const h = readJson(hooksPath(r));
    assert.equal(h.version, 1);
    assert.deepEqual(Object.keys(h.hooks).sort(), ["beforeSubmitPrompt", "sessionStart"]);
    for (const ev of ["sessionStart", "beforeSubmitPrompt"]) {
      assert.equal(h.hooks[ev].length, 1);
      const e = h.hooks[ev][0];
      assert.equal(typeof e.command, "string", "Cursor's command is a single string");
      assert.match(e.command, /cli\.js'? +'?peek'? +'?alpha'? +'?--format'? +'?cursor'? +'?--event'? +'?(sessionStart|beforeSubmitPrompt)/);
      assert.ok(e.command.includes(ev));
      assert.equal(e.timeout, 10);
      assert.ok(!JSON.stringify(e).includes("AGENT_DESCRIPTION"));
    }
    assert.match(res.out, /unread-mail hook/);
  });

  await test("--hook-form exec: one command string with --set arguments, no env prefix, runnable", async () => {
    const r = repo("a-exec");
    assert.equal((await runCli(["init", r, "alpha", "--client", "cursor", "--hook", "--hook-form", "exec"], localEnv)).code, 0);
    const e = entryFor(r, "sessionStart");
    assert.doesNotMatch(e.command, /^AGENT_/, "exec form must not start with an env assignment");
    assert.ok(e.command.includes(`AGENT_BRIDGE_DB=${DB}`), e.command);
    assert.ok(!e.command.includes("AGENT_DESCRIPTION"));
    if (!IS_WIN) {
      await send("alpha", "hello exec form");
      const out = await runEvent(r, "sessionStart");
      assert.match(out.additional_context, /unread bridge messages \(1 from human\)/);
    }
  });

  await test("--cursor-events picks the events; stop gets a loop limit; unknown events are refused before anything is written", async () => {
    const r = repo("a-events");
    assert.equal((await runCli(["init", r, "alpha", "--client", "cursor", "--hook", "--cursor-events", "sessionStart,stop"], localEnv)).code, 0);
    const h = readJson(hooksPath(r));
    assert.deepEqual(Object.keys(h.hooks).sort(), ["sessionStart", "stop"]);
    assert.equal(h.hooks.stop[0].loop_limit, 2, "stop must have a small explicit loop limit");
    assert.equal(h.hooks.sessionStart[0].loop_limit, undefined);
    const bad = repo("a-events-bad");
    const res = await runCli(["init", bad, "alpha", "--client", "cursor", "--hook", "--cursor-events", "sessionStart,preToolUse"], localEnv);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /--cursor-events/);
    assert.ok(!existsSync(join(bad, ".cursor")), "something was written before the events were validated");
  });

  console.log("\n=== cursor: merging and re-running ===");

  await test("merge keeps the user's other servers, other hooks, `version` and unknown keys; ours replaces only ours", async () => {
    const r = repo("m-merge");
    mkdirSync(join(r, ".cursor"));
    writeFileSync(mcpPath(r), JSON.stringify({ mcpServers: { other: { command: "x", args: ["1"] }, bridge: { command: "old" } }, note: "keep" }));
    const mine = { command: "echo before", timeout: 3 };
    const otherAgent = { command: `AGENT_NAME='beta' '/x/node' '/old/cli.js' peek 'beta' '--format' 'cursor' '--event' 'sessionStart'` };
    const stale = { command: `'/old/node' "/old/agent-bridge/cli.js" peek alpha --format cursor --event sessionStart` };
    writeFileSync(
      hooksPath(r),
      JSON.stringify({ version: 1, extra: { a: 1 }, hooks: { sessionStart: [mine, stale, otherAgent], afterFileEdit: [{ command: "fmt" }], beforeSubmitPrompt: [] } })
    );
    assert.equal((await runCli(["init", r, "alpha", "--client", "cursor", "--hook"], localEnv)).code, 0);
    const cfg = readJson(mcpPath(r));
    assert.deepEqual(cfg.mcpServers.other, { command: "x", args: ["1"] });
    assert.equal(cfg.note, "keep");
    assert.notEqual(cfg.mcpServers.bridge.command, "old");
    const h = readJson(hooksPath(r));
    assert.equal(h.version, 1);
    assert.deepEqual(h.extra, { a: 1 });
    assert.deepEqual(h.hooks.afterFileEdit, [{ command: "fmt" }]);
    assert.deepEqual(h.hooks.sessionStart.slice(0, 2), [mine, otherAgent], "the user's hook and another agent's hook must stay, in order");
    assert.equal(h.hooks.sessionStart.length, 3);
    assert.ok(!JSON.stringify(h).includes("/old/agent-bridge"), "the stale hook of ours was not replaced");
    assert.equal(h.hooks.beforeSubmitPrompt.length, 1);
  });

  await test("an existing hooks.json `version` other than 1 is preserved; a missing one becomes 1", async () => {
    const r = repo("m-version");
    mkdirSync(join(r, ".cursor"));
    writeFileSync(hooksPath(r), JSON.stringify({ version: 2, hooks: {} }));
    await runCli(["init", r, "alpha", "--client", "cursor", "--hook"], localEnv);
    assert.equal(readJson(hooksPath(r)).version, 2);
    const r2 = repo("m-version2");
    mkdirSync(join(r2, ".cursor"));
    writeFileSync(hooksPath(r2), JSON.stringify({ hooks: {} }));
    await runCli(["init", r2, "alpha", "--client", "cursor", "--hook"], localEnv);
    assert.equal(readJson(hooksPath(r2)).version, 1);
  });

  await test("re-running init is idempotent (byte-identical files, no stacked hooks), also across --hook-form switches", async () => {
    const r = repo("m-idem");
    const run = () => runCli(["init", r, "alpha", "desc", "--client", "cursor", "--hook"], localEnv);
    await run();
    const a = [readFileSync(mcpPath(r), "utf8"), readFileSync(hooksPath(r), "utf8")];
    await run();
    await run();
    assert.deepEqual([readFileSync(mcpPath(r), "utf8"), readFileSync(hooksPath(r), "utf8")], a);
    for (const form of ["exec", "shell", "exec"]) {
      assert.equal((await runCli(["init", r, "alpha", "--client", "cursor", "--hook", "--hook-form", form], localEnv)).code, 0);
      const h = readJson(hooksPath(r)).hooks;
      assert.equal(h.sessionStart.length, 1);
      assert.equal(h.beforeSubmitPrompt.length, 1);
    }
    // no description given: the stored one is kept
    assert.equal(readJson(mcpPath(r)).mcpServers.bridge.env.AGENT_DESCRIPTION, "desc");
  });

  await test("re-running with different --cursor-events removes our hooks from the events no longer wanted (and the empty arrays we leave)", async () => {
    const r = repo("m-switch");
    writeFileSync(join(r, "x"), "");
    await runCli(["init", r, "alpha", "--client", "cursor", "--hook"], localEnv);
    await runCli(["init", r, "alpha", "--client", "cursor", "--hook", "--cursor-events", "stop"], localEnv);
    const h = readJson(hooksPath(r)).hooks;
    assert.deepEqual(Object.keys(h), ["stop"], JSON.stringify(h));
  });

  await test("a hooks.json / mcp.json of the wrong shape is refused without being touched", async () => {
    const r = repo("m-shape");
    mkdirSync(join(r, ".cursor"));
    writeFileSync(mcpPath(r), JSON.stringify({ mcpServers: [] }));
    const res = await runCli(["init", r, "alpha", "--client", "cursor"], localEnv);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /mcpServers/);
    assert.equal(readFileSync(mcpPath(r), "utf8"), JSON.stringify({ mcpServers: [] }));
    writeFileSync(mcpPath(r), "[]");
    const res0 = await runCli(["init", r, "alpha", "--client", "cursor"], localEnv);
    assert.notEqual(res0.code, 0);
    assert.match(res0.err, /JSON object/);
    assert.equal(readFileSync(mcpPath(r), "utf8"), "[]");
    writeFileSync(mcpPath(r), "{}");
    writeFileSync(hooksPath(r), JSON.stringify({ version: 1, hooks: { sessionStart: "nope" } }));
    const res2 = await runCli(["init", r, "alpha", "--client", "cursor", "--hook"], localEnv);
    assert.notEqual(res2.code, 0);
    assert.match(res2.err, /sessionStart/);
    assert.equal(readFileSync(mcpPath(r), "utf8"), "{}", "mcp.json was rewritten although hooks.json could not be merged");
  });

  await test("--client claude,cursor with bad --cursor-events writes nothing, not even Claude's files", async () => {
    const r = repo("m-both-bad");
    const res = await runCli(["init", r, "alpha", "--client", "claude,cursor", "--hook", "--cursor-events", "nope"], localEnv);
    assert.notEqual(res.code, 0);
    assert.deepEqual(existsSync(join(r, ".mcp.json")) || existsSync(join(r, ".claude")) || existsSync(join(r, ".cursor")), false);
  });

  await test("--client claude,cursor writes both clients' files with the same server entry", async () => {
    const r = repo("m-both");
    const res = await runCli(["init", r, "alpha", "both", "--client", "claude,cursor", "--hook"], localEnv);
    assert.equal(res.code, 0, res.err);
    for (const f of [join(r, ".mcp.json"), join(r, ".claude", "settings.local.json"), mcpPath(r), hooksPath(r)]) assert.ok(existsSync(f), f);
    assert.deepEqual(readJson(join(r, ".mcp.json")).mcpServers.bridge, readJson(mcpPath(r)).mcpServers.bridge);
    assert.equal(readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit.length, 1);
    assert.match(res.out, /next \(Claude Code\)/);
    assert.match(res.out, /next \(Cursor\)/);
  });

  await test("a description stored by an earlier Cursor init is kept when a later init gives none", async () => {
    const r = repo("m-desc");
    await runCli(["init", r, "alpha", "the", "api", "--client", "cursor"], localEnv);
    await runCli(["init", r, "alpha", "--client", "cursor"], localEnv);
    assert.equal(readJson(mcpPath(r)).mcpServers.bridge.env.AGENT_DESCRIPTION, "the api");
  });

  await test("readServerEnv returns { path, env } of the bridge entry, null when there is no file", async () => {
    const r = repo("m-read");
    assert.equal(cursor.readServerEnv(r), null);
    await runCli(["init", r, "alpha", "d", "--client", "cursor"], localEnv);
    const got = cursor.readServerEnv(r);
    assert.equal(got.path, mcpPath(r));
    assert.deepEqual(got.env, readJson(mcpPath(r)).mcpServers.bridge.env);
    writeFileSync(mcpPath(r), JSON.stringify({ mcpServers: { other: {} } }));
    assert.deepEqual(cursor.readServerEnv(r), { path: mcpPath(r), env: {} });
  });

  console.log("\n=== cursor: hostile input and symlinks ===");

  await test("a hostile description lands only in mcp.json (as data); the hook text never contains it", async () => {
    const r = repo("h-desc");
    const evil = `"; touch ${join(tmp, "PWNED-desc")}; echo ' $(touch ${join(tmp, "PWNED-desc2")}) \`id\` \n ]} \u2028 ../../x`;
    const res = await runCli(["init", r, "alpha", evil, "--client", "cursor", "--hook"], localEnv);
    assert.equal(res.code, 0, res.err);
    assert.equal(readJson(mcpPath(r)).mcpServers.bridge.env.AGENT_DESCRIPTION, evil);
    const raw = readFileSync(hooksPath(r), "utf8");
    assert.ok(!raw.includes("PWNED") && !raw.includes("touch"));
    for (const ev of ["sessionStart", "beforeSubmitPrompt"]) assert.ok(!JSON.stringify(readJson(hooksPath(r)).hooks[ev]).includes("AGENT_DESCRIPTION"));
    if (!IS_WIN) {
      await runEvent(r, "sessionStart");
      assert.ok(!existsSync(join(tmp, "PWNED-desc")) && !existsSync(join(tmp, "PWNED-desc2")));
    }
  });

  await test("hostile settings values (mailbox path with quotes and $()) are quoted in the hook command: nothing is executed", async () => {
    const r = repo("h-path");
    // on Windows a backslash inside a folder name is a separator, so the touch targets are bare names there
    const target = (n) => (IS_WIN ? n : join(tmp, n));
    const dir = join(tmp, `it's $(touch ${target("PWNED-path")}) \`touch ${target("PWNED-path2")}\``);
    mkdirSync(dir, { recursive: true });
    const env = { HOME, AGENT_BRIDGE_DB: join(dir, "bridge.db") };
    for (const form of IS_WIN ? ["exec"] : ["shell", "exec"]) {
      assert.equal((await runCli(["init", r, "alpha", "--client", "cursor", "--hook", "--hook-form", form], env)).code, 0);
      if (IS_WIN) continue;
      await runCli(["send", "alpha", "x"], { ...env, AGENT_NAME: "human" });
      const out = await runEvent(r, "sessionStart", {}, {});
      assert.match(out.additional_context ?? "", /\d from human/, `${form}: the hook did not reach the mailbox`);
      assert.ok(!existsSync(join(tmp, "PWNED-path")) && !existsSync(join(tmp, "PWNED-path2")), `${form}: a command ran`);
    }
  });

  await test("hookCommand quotes for the shell Cursor uses: POSIX single quotes, PowerShell on Windows (exec form: no env prefix)", async () => {
    const env = { AGENT_NAME: "alpha", AGENT_BRIDGE_DB: "C:\\Users\\O'Brien\\bridge.db", AGENT_DESCRIPTION: "x" };
    const ps = cursor.hookCommand({ form: "exec", name: "alpha", env, event: "stop", platform: "win32", nodePath: "C:\\Program Files\\nodejs\\node.exe" });
    assert.match(ps, /^'C:\\Program Files\\nodejs\\node\.exe' (?:'[^']*cli\.js'|\S*cli\.js) peek alpha --format cursor --event stop /);
    assert.ok(ps.includes(`'AGENT_BRIDGE_DB=C:\\Users\\O''Brien\\bridge.db'`), ps);
    assert.ok(!ps.includes("AGENT_DESCRIPTION"));
    const px = cursor.hookCommand({ form: "exec", name: "alpha", env, event: "stop", platform: "linux", nodePath: "/usr/bin/node" });
    assert.ok(px.includes(`'AGENT_BRIDGE_DB=C:\\Users\\O'\\''Brien\\bridge.db'`), px);
  });

  posixTest("symlinks are refused: .cursor, mcp.json and hooks.json, nothing is written through them", async () => {
    const outside = repo("sym-outside");
    // .cursor -> outside
    const r1 = repo("sym-dir");
    symlinkSync(outside, join(r1, ".cursor"));
    let res = await runCli(["init", r1, "alpha", "--client", "cursor", "--hook"], localEnv);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /symlink/);
    assert.deepEqual(existsSync(join(outside, "mcp.json")) || existsSync(join(outside, "hooks.json")), false);
    // mcp.json -> outside file
    const r2 = repo("sym-mcp");
    mkdirSync(join(r2, ".cursor"));
    writeFileSync(join(outside, "target.json"), "{}");
    symlinkSync(join(outside, "target.json"), mcpPath(r2));
    res = await runCli(["init", r2, "alpha", "--client", "cursor"], localEnv);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /symlink/);
    assert.equal(readFileSync(join(outside, "target.json"), "utf8"), "{}");
    // hooks.json -> outside file: refused before mcp.json is written
    const r3 = repo("sym-hooks");
    mkdirSync(join(r3, ".cursor"));
    symlinkSync(join(outside, "target.json"), hooksPath(r3));
    res = await runCli(["init", r3, "alpha", "--client", "cursor", "--hook"], localEnv);
    assert.notEqual(res.code, 0);
    assert.match(res.err, /symlink/);
    assert.equal(readFileSync(join(outside, "target.json"), "utf8"), "{}");
    assert.ok(!existsSync(mcpPath(r3)), "mcp.json was written although hooks.json is a symlink");
    // without --hook a symlinked hooks.json is not our business
    assert.equal((await runCli(["init", r3, "alpha", "--client", "cursor"], localEnv)).code, 0);
  });

  console.log("\n=== cursor: what the hook prints ===");

  const MAIL = "[agent-bridge] You have unread bridge messages (2 from human, 1 from beta). Call check_inbox when relevant.";
  const WARN = "[agent-bridge] WARNING: The channel scan is INCOMPLETE (covers back to 2026-01-01T00:00:00.000Z).";

  await test("peekOutput: no-op JSON when there is nothing to say, for every event", async () => {
    assert.deepEqual(JSON.parse(cursor.peekOutput([], { event: "sessionStart" })), { continue: true });
    assert.deepEqual(JSON.parse(cursor.peekOutput([], { event: "beforeSubmitPrompt" })), { continue: true });
    assert.deepEqual(JSON.parse(cursor.peekOutput([], { event: "stop", input: { status: "completed", loop_count: 0 } })), {});
    assert.deepEqual(JSON.parse(cursor.peekOutput([], {})), {}, "unknown event");
    assert.deepEqual(JSON.parse(cursor.peekOutput([], { event: "preToolUse" })), {}, "an event we don't handle");
    assert.ok(cursor.peekOutput([], { event: "sessionStart" }).endsWith("\n"));
  });

  await test("peekOutput: mail goes into additional_context (sessionStart, beforeSubmitPrompt) and into followup_message (stop)", async () => {
    for (const ev of ["sessionStart", "beforeSubmitPrompt"]) {
      const o = JSON.parse(cursor.peekOutput([MAIL], { event: ev }));
      assertValidResponse(ev, o);
      assert.equal(o.continue, true, "continue:true must be present: the prompt must go through");
      assert.equal(o.additional_context, MAIL);
    }
    const s = JSON.parse(cursor.peekOutput([MAIL, WARN], { event: "stop", input: { status: "completed", loop_count: 0 } }));
    assertValidResponse("stop", s);
    assert.ok(s.followup_message.includes("2 from human, 1 from beta"));
    assert.match(s.followup_message, /check_inbox/);
    const w = JSON.parse(cursor.peekOutput([MAIL, WARN], { event: "beforeSubmitPrompt" }));
    assert.equal(w.additional_context, MAIL + "\n" + WARN);
  });

  await test("peekOutput: stop follows up only after a completed turn, below the loop limit, and only for mail (not for a warning alone)", async () => {
    const ok = { status: "completed", loop_count: 0 };
    const fu = (inp, notes = [MAIL]) => JSON.parse(cursor.peekOutput(notes, { event: "stop", input: inp })).followup_message;
    assert.ok(fu(ok));
    assert.ok(fu({ status: "completed", loop_count: 1 }), "one follow-up already happened: a second is still allowed");
    assert.equal(fu({ status: "completed", loop_count: 2 }), undefined, "loop limit");
    assert.equal(fu({ status: "completed", loop_count: 99 }), undefined);
    assert.equal(fu({ status: "aborted", loop_count: 0 }), undefined, "the user stopped the agent: don't restart it");
    assert.equal(fu({ status: "error", loop_count: 0 }), undefined);
    assert.equal(fu({ loop_count: 0 }), undefined, "no status: don't");
    assert.equal(fu(undefined), undefined, "no stdin at all: don't");
    assert.equal(fu(null), undefined);
    assert.equal(fu({ status: "completed", loop_count: "0" }), undefined, "garbage loop_count: don't");
    assert.equal(fu(ok, [WARN]), undefined, "a scan warning alone must not wake the agent");
    assert.equal(fu(ok, []), undefined);
  });

  await test("peekOutput: always valid JSON, whatever the notes contain (quotes, newlines, U+2028, lone surrogates, huge text)", async () => {
    const nasty = [
      `x"}, "continue": false, "additional_context": "y`,
      'back\\slash \n newline \r\n \t tab \u2028 \u2029 \u0000 nul \ud800 lone <\/script> ]}',
      "é日本語😀",
      "A".repeat(500000),
      "x" + "😀".repeat(9000), // the cap falls inside a surrogate pair
    ];
    for (const ev of ["sessionStart", "beforeSubmitPrompt", "stop"]) {
      for (const n of nasty) {
        const raw = cursor.peekOutput([`[agent-bridge] You have unread bridge messages (${n})`], { event: ev, input: { status: "completed", loop_count: 0 } });
        const o = JSON.parse(raw);
        assertValidResponse(ev, o);
        if (ev !== "stop") assert.equal(o.continue, true, "an injected continue:false must not survive");
        const text = o.additional_context ?? o.followup_message;
        assert.equal(text, text.toWellFormed(), "the text has a lone surrogate");
        assert.ok(raw.length < 200000, "output must be capped");
        assert.equal(raw.trim().split("\n").length, 1, "one line");
      }
    }
    const o = JSON.parse(cursor.peekOutput([nasty[0]], { event: "beforeSubmitPrompt" }));
    assert.equal(o.continue, true);
    assert.equal(o.additional_context, nasty[0]);
  });

  posixTest("end to end through Cursor's runner: sessionStart / beforeSubmitPrompt / stop, with mail and without", async () => {
    const r = repo("e-run");
    const mailbox = { AGENT_BRIDGE_DB: join(tmp, "e-run.db") };
    const env = { HOME, ...mailbox };
    assert.equal((await runCli(["init", r, "gamma", "--client", "cursor", "--hook", "--cursor-events", "sessionStart,beforeSubmitPrompt,stop"], env)).code, 0);
    const done = { status: "completed", loop_count: 0 };
    // no mail
    assert.deepEqual(await runEvent(r, "sessionStart"), { continue: true });
    assert.deepEqual(await runEvent(r, "beforeSubmitPrompt", { prompt: "hi", attachments: [] }), { continue: true });
    assert.deepEqual(await runEvent(r, "stop", done), {});
    // mail
    await runCli(["send", "gamma", "please", "review"], { ...env, AGENT_NAME: "human" });
    assert.match((await runEvent(r, "sessionStart")).additional_context, /1 from human/);
    const p = await runEvent(r, "beforeSubmitPrompt", { prompt: "hi", attachments: [] });
    assert.equal(p.continue, true);
    assert.match(p.additional_context, /1 from human/);
    assert.match((await runEvent(r, "stop", done)).followup_message, /check_inbox/);
    assert.deepEqual(await runEvent(r, "stop", { status: "aborted", loop_count: 0 }), {});
    assert.deepEqual(await runEvent(r, "stop", { status: "completed", loop_count: 2 }), {});
    // peek did not consume the mail
    assert.match((await runEvent(r, "sessionStart")).additional_context, /1 from human/);
  });

  await test("a broken bridge never blocks the prompt: valid no-op JSON, exit 0, whatever fails", async () => {
    const cases = [
      ["unreachable Supabase", ["peek", "alpha"], { AGENT_BRIDGE_BACKEND: "supabase", SUPABASE_URL: "http://127.0.0.1:1", SUPABASE_PUBLISHABLE_KEY: "k", AGENT_BRIDGE_TOKEN: "abt_" + "ab".repeat(32) }],
      ["mailbox path is a file's child", ["peek", "alpha"], { AGENT_BRIDGE_DB: join(tmp, "a-basic", ".cursor", "mcp.json", "x", "bridge.db") }],
      ["no agent name", ["peek"], {}],
      ["bad --set", ["peek", "alpha", "--set", "NODE_OPTIONS=--require /x.js"], {}],
      ["bad token file", ["peek", "alpha"], { AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: "http://127.0.0.1:1", AGENT_BRIDGE_TOKEN_FILE: join(tmp, "nope.token") }],
      ["bad backend name", ["peek", "alpha"], { AGENT_BRIDGE_BACKEND: "carrier-pigeon" }],
      [
        "proxy settings that need the re-run (a child process), pointing nowhere",
        ["peek", "alpha", "--set", "HTTPS_PROXY=http://127.0.0.1:1", "--set", "NODE_USE_ENV_PROXY=1", "--set", "AGENT_BRIDGE_BACKEND=supabase", "--set", "SUPABASE_URL=https://bridge.invalid", "--set", "SUPABASE_PUBLISHABLE_KEY=k"],
        { AGENT_BRIDGE_TOKEN: "abt_" + "ab".repeat(32) },
      ],
    ];
    for (const [what, args, env] of cases) {
      for (const [ev, want] of [["sessionStart", { continue: true }], ["beforeSubmitPrompt", { continue: true }], ["stop", {}]]) {
        const res = await runCli([...args, "--format", "cursor", "--event", ev], { HOME, ...env }, { input: JSON.stringify(input(ev, { status: "completed", loop_count: 0 }, tmp)) });
        assert.equal(res.code, 0, `${what}: ${res.err}`);
        assert.deepEqual(JSON.parse(res.out), want, `${what} / ${ev}: ${res.out}`);
      }
    }
  });

  await test("the proxy re-run (child process) gets Cursor's input and answers in Cursor's format, also for an imported Claude hook", async () => {
    const mb = join(tmp, "e-rerun.db");
    await runCli(["send", "rerun", "hi"], { HOME, AGENT_BRIDGE_DB: mb, AGENT_NAME: "human" });
    const sets = ["--set", "NODE_EXTRA_CA_CERTS=" + join(tmp, "no-such-ca.pem"), "--set", "AGENT_BRIDGE_DB=" + mb];
    const stop = await runCli(["peek", "rerun", "--format", "cursor", "--event", "stop", ...sets], { HOME }, { input: JSON.stringify({ status: "completed", loop_count: 0 }) });
    assert.match(JSON.parse(stop.out).followup_message, /1 from human/, stop.out + stop.err);
    const imported = await runCli(["peek", "rerun", ...sets], { HOME, CURSOR_VERSION: "3.0.0", CURSOR_PROJECT_DIR: tmp }, { input: JSON.stringify(input("beforeSubmitPrompt", {}, tmp)) });
    assert.match(JSON.parse(imported.out).additional_context, /1 from human/, imported.out + imported.err);
  });

  await test("peek --format cursor with no --event (or a foreign one) prints {} and never fails", async () => {
    for (const args of [["peek", "alpha", "--format", "cursor"], ["peek", "alpha", "--format", "cursor", "--event", "afterFileEdit"]]) {
      const res = await runCli(args, localEnv);
      assert.equal(res.code, 0);
      assert.deepEqual(JSON.parse(res.out), {});
    }
  });

  console.log("\n=== cursor: Slack scan warning ===");
  {
    const b = await slackLocalBackend();
    try {
      await b.addAgent("alice");
      await b.addAgent("bob");
      await test("an incomplete Slack scan is passed on as a warning inside valid JSON (and does not wake the agent at stop)", async () => {
        const { createStore } = await import("../store.js");
        const alice = await createStore({ env: b.envFor("alice"), agentName: "alice" });
        await alice.send({ to: "bob", body: "older request the capped scan can't reach" });
        const eve = b.addHuman("eve");
        for (let i = 0; i < 700; i++) b.slack.postAs(eve, { text: "noise " + i });
        const env = { ...b.envFor("bob"), AGENT_BRIDGE_SLACK_MAX_PAGES: "3", HOME };
        const sess = await runCli(["peek", "bob", "--format", "cursor", "--event", "sessionStart"], env);
        const o = JSON.parse(sess.out);
        assert.equal(o.continue, true);
        assert.match(o.additional_context, /\[agent-bridge\] WARNING: The channel scan is INCOMPLETE/);
        const stop = await runCli(["peek", "bob", "--format", "cursor", "--event", "stop"], env, { input: JSON.stringify({ status: "completed", loop_count: 0 }) });
        assert.deepEqual(JSON.parse(stop.out), {}, "a warning alone woke the agent");
      });
    } finally {
      await b.cleanup();
    }
  }

  console.log("\n=== cursor: Claude hook imported by Cursor (auto-detection) ===");

  const claudePlain = /^\[agent-bridge\] You have unread bridge messages \(1 from human\)/;

  await test("without Cursor's environment `peek` stays plain text and never reads stdin (a Cursor-looking stdin is ignored)", async () => {
    const env = { ...localEnv, AGENT_BRIDGE_DB: join(tmp, "d1.db") };
    const cursorish = JSON.stringify(input("beforeSubmitPrompt", {}, tmp));
    const r = await runCli(["peek", "delta"], env, { input: cursorish });
    assert.equal(r.code, 0);
    assert.equal(r.out, "", "Cursor-looking stdin was acted on without Cursor's environment");
    await runCli(["send", "delta", "mail"], { HOME, AGENT_BRIDGE_DB: join(tmp, "d1.db"), AGENT_NAME: "human" });
    const r2 = await runCli(["peek", "delta"], env, { input: cursorish });
    assert.match(r2.out, claudePlain, r2.out);
    // and with stdin that never closes it doesn't wait for it at all
    const r3 = await runPeekOpenStdin(["peek", "delta"], env, { feed: cursorish });
    assert.match(r3.out, claudePlain, r3.out);
    assert.ok(r3.ms < 4000);
  });

  await test("a hook run by Cursor without --format answers in Cursor's format, picking the event from stdin", async () => {
    const r = repo("i-detect");
    const db = join(tmp, "i-detect.db");
    const env = { HOME, AGENT_BRIDGE_DB: db, CURSOR_PROJECT_DIR: r, CURSOR_VERSION: "3.0.0" };
    // Claude-only repo: Cursor imports .claude/settings.local.json and runs the plain `peek` hook
    assert.equal((await runCli(["init", r, "delta", "--hook"], { HOME, AGENT_BRIDGE_DB: db })).code, 0);
    const none = await runCli(["peek", "delta"], env, { input: JSON.stringify(input("beforeSubmitPrompt", { prompt: "x" }, r)) });
    assert.deepEqual(JSON.parse(none.out), { continue: true });
    await runCli(["send", "delta", "hello"], { HOME, AGENT_BRIDGE_DB: db, AGENT_NAME: "human" });
    const mail = await runCli(["peek", "delta"], env, { input: JSON.stringify(input("beforeSubmitPrompt", { prompt: "x" }, r)) });
    const o = JSON.parse(mail.out);
    assertValidResponse("beforeSubmitPrompt", o);
    assert.equal(o.continue, true);
    assert.match(o.additional_context, /1 from human/);
    // another event name from stdin
    const ss = JSON.parse((await runCli(["peek", "delta"], env, { input: JSON.stringify(input("sessionStart", {}, r)) })).out);
    assert.match(ss.additional_context, /1 from human/);
    // Claude Code itself (same repo, but Cursor-looking env was inherited from a terminal): Claude's own stdin -> plain text
    const claude = await runCli(["peek", "delta"], env, { input: JSON.stringify({ session_id: "s", hook_event_name: "UserPromptSubmit", prompt: "x", cwd: r }) });
    assert.match(claude.out, claudePlain);
    // Cursor's env but nothing readable on stdin: plain text, as before
    const empty = await runCli(["peek", "delta"], env);
    assert.match(empty.out, claudePlain);
    const junk = await runCli(["peek", "delta"], env, { input: "not json {" });
    assert.match(junk.out, claudePlain);
  });

  await test("repo set up for both clients: the imported Claude hook stays quiet (no duplicate note) because the native Cursor hook reports", async () => {
    const r = repo("i-dedupe");
    const db = join(tmp, "i-dedupe.db");
    const env = { HOME, AGENT_BRIDGE_DB: db, CURSOR_PROJECT_DIR: r, CURSOR_VERSION: "3.0.0" };
    assert.equal((await runCli(["init", r, "delta", "--client", "claude,cursor", "--hook"], { HOME, AGENT_BRIDGE_DB: db })).code, 0);
    await runCli(["send", "delta", "hello"], { HOME, AGENT_BRIDGE_DB: db, AGENT_NAME: "human" });
    const imported = await runCli(["peek", "delta"], env, { input: JSON.stringify(input("beforeSubmitPrompt", { prompt: "x" }, r)) });
    assert.deepEqual(JSON.parse(imported.out), { continue: true }, "both hooks would have delivered the same note");
    if (!IS_WIN) assert.match((await runEvent(r, "beforeSubmitPrompt", { prompt: "x" })).additional_context, /1 from human/, "the native hook must still deliver");
    // a hook for another agent name in .cursor/hooks.json doesn't count
    const only = repo("i-dedupe2");
    mkdirSync(join(only, ".cursor"));
    writeFileSync(hooksPath(only), JSON.stringify({ version: 1, hooks: { beforeSubmitPrompt: [{ command: "'/x/node' '/x/cli.js' peek 'other' '--format' 'cursor'" }] } }));
    const env2 = { ...env, CURSOR_PROJECT_DIR: only };
    const o = JSON.parse((await runCli(["peek", "delta"], env2, { input: JSON.stringify(input("beforeSubmitPrompt", {}, only)) })).out);
    assert.match(o.additional_context, /1 from human/);
  });

  await test("stdin detection never hangs: stdin that stays open is given up on after a moment, output unchanged", async () => {
    const env = { ...localEnv, AGENT_BRIDGE_DB: join(tmp, "d1.db"), CURSOR_PROJECT_DIR: tmp };
    const r = await runPeekOpenStdin(["peek", "delta"], env); // nothing written, never closed
    assert.equal(r.code, 0);
    assert.match(r.out, claudePlain);
    assert.ok(r.ms < 5000, `took ${r.ms}ms`);
    // a huge stdin is capped, not buffered forever
    const big = await runPeekOpenStdin(["peek", "delta"], env, { feed: "x".repeat(20 * 1024 * 1024) });
    assert.equal(big.code, 0);
    assert.match(big.out, claudePlain);
    // the stop event (which needs stdin) with stdin left open: gives up, prints {}
    const stop = await runPeekOpenStdin(["peek", "delta", "--format", "cursor", "--event", "stop"], env);
    assert.equal(stop.code, 0);
    assert.deepEqual(JSON.parse(stop.out), {});
    assert.ok(stop.ms < 5000);
  });

  await test("readHookInput: parses JSON, refuses terminals, caps its buffer, gives up on silence, never throws", async () => {
    const feed = (chunks, extra = {}) => Object.assign(Readable.from(chunks.map((c) => Buffer.from(c))), extra);
    assert.deepEqual(await cursor.readHookInput({ stream: feed(['{"a":', "1}"]) }), { a: 1 });
    assert.equal(await cursor.readHookInput({ stream: feed(["[1]"]) }), null, "arrays are not hook input");
    assert.equal(await cursor.readHookInput({ stream: feed(["nope"]) }), null);
    assert.equal(await cursor.readHookInput({ stream: feed(["{}"], { isTTY: true }) }), null, "a terminal is never read");
    assert.equal(await cursor.readHookInput({ stream: feed(['{"a":"' + "x".repeat(100) + '"}']), maxBytes: 50 }), null, "over the cap");
    const silent = new Readable({ read() {} }); // never ends
    const t0 = Date.now();
    assert.equal(await cursor.readHookInput({ stream: silent, timeoutMs: 50 }), null);
    assert.ok(Date.now() - t0 < 2000);
    const exploding = {
      get isTTY() {
        throw new Error("boom");
      },
    };
    assert.equal(await cursor.readHookInput({ stream: exploding }), null);
  });

  await test("an imported hook is not silenced by a plain `peek` entry, by a native hook for another event, or by another repo", async () => {
    const r = repo("i-native");
    const db = join(tmp, "i-native.db");
    await runCli(["send", "delta", "hello"], { HOME, AGENT_BRIDGE_DB: db, AGENT_NAME: "human" });
    const env = { HOME, AGENT_BRIDGE_DB: db, CURSOR_VERSION: "3.0.0" };
    const ask = async (hooksDoc, withRoots = true, event = "beforeSubmitPrompt") => {
      mkdirSync(join(r, ".cursor"), { recursive: true });
      writeFileSync(hooksPath(r), JSON.stringify(hooksDoc));
      const inp = input(event, {}, r);
      if (!withRoots) delete inp.workspace_roots;
      return JSON.parse((await runCli(["peek", "delta"], { ...env, CURSOR_PROJECT_DIR: r }, { input: JSON.stringify(inp) })).out);
    };
    const quiet = { continue: true };
    const native = (ev) => ({ command: `'/x/node' '/x/cli.js' peek 'delta' '--format' 'cursor' '--event' '${ev}'` });
    // a plain-text peek entry in .cursor/hooks.json would not report in Cursor's format: don't rely on it
    assert.match((await ask({ version: 1, hooks: { beforeSubmitPrompt: [{ command: "'/x/node' '/x/cli.js' peek 'delta'" }] } })).additional_context, /1 from human/);
    // a native hook for another event doesn't cover this one
    assert.match((await ask({ version: 1, hooks: { stop: [native("stop")] } })).additional_context, /1 from human/);
    assert.match((await ask({ version: 1, hooks: { beforeSubmitPrompt: [native("beforeSubmitPrompt")] } }, true, "sessionStart")).additional_context, /1 from human/);
    // the native hook for this event does
    assert.deepEqual(await ask({ version: 1, hooks: { beforeSubmitPrompt: [native("beforeSubmitPrompt")] } }), quiet);
    // the workspace comes from CURSOR_PROJECT_DIR when stdin names none
    assert.deepEqual(await ask({ version: 1, hooks: { beforeSubmitPrompt: [native("beforeSubmitPrompt")] } }, false), quiet);
    // a broken hooks.json is no reason to fail
    writeFileSync(hooksPath(r), "{ not json");
    const inp = input("beforeSubmitPrompt", {}, r);
    const broken = await runCli(["peek", "delta"], { ...env, CURSOR_PROJECT_DIR: r }, { input: JSON.stringify(inp) });
    assert.match(JSON.parse(broken.out).additional_context, /1 from human/);
  });

  await test("if the proxy re-run's child dies or prints junk, Cursor still gets valid JSON", async () => {
    const hook = join(tmp, "break-child.cjs");
    writeFileSync(
      hook,
      `if (process.env.AGENT_BRIDGE_PEEK_REEXEC === "1") { if (process.env.BREAK === "junk") process.stdout.write("garbage, not json\\n"); process.exit(process.env.BREAK === "junk" ? 0 : 3); }`
    );
    const base = { HOME, AGENT_BRIDGE_DB: join(tmp, "e-rerun.db"), NODE_OPTIONS: `--require ${JSON.stringify(hook)}` };
    const args = ["peek", "rerun", "--format", "cursor", "--event", "sessionStart", "--set", "NODE_EXTRA_CA_CERTS=" + join(tmp, "no-such-ca.pem")];
    for (const how of ["die", "junk"]) {
      const res = await runCli(args, { ...base, BREAK: how });
      assert.equal(res.code, 0, res.err);
      assert.deepEqual(JSON.parse(res.out), { continue: true }, `${how}: ${res.out}`);
    }
  });

  const py = spawnSync("python3", ["-c", "import pty"], { encoding: "utf8" });
  if (IS_WIN || py.status !== 0) skip("a terminal stdin is never read", "needs python3 with pty on a POSIX system");
  else {
    await test("a terminal stdin is never read (typed-in Cursor JSON is not mistaken for a hook input)", async () => {
      const script = `
import os, pty, sys, time, select
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1], sys.argv[2], "peek", "delta"])
os.write(fd, (sys.argv[3] + "\\n").encode())
out = b""
end = time.time() + 10
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            d = os.read(fd, 4096)
        except OSError:
            break
        if not d: break
        out += d
sys.stdout.write(out.decode(errors="replace"))
`;
      const payload = JSON.stringify(input("beforeSubmitPrompt", {}, tmp));
      const res = spawnSync("python3", ["-I", "-c", script, process.execPath, CLI, payload], {
        encoding: "utf8",
        env: { ...cleanEnv(), ...localEnv, AGENT_BRIDGE_DB: join(tmp, "d1.db"), CURSOR_PROJECT_DIR: tmp },
        timeout: 20000,
      });
      assert.match(res.stdout, /\[agent-bridge\] You have unread bridge messages/, res.stdout + res.stderr);
      assert.doesNotMatch(res.stdout, /additional_context/);
    });
  }

  console.log("\n=== cursor: project folder as the agent's name (managed installs) ===");

  await test("an inherited CURSOR_PROJECT_DIR never names the agent (R4-11); AGENT_BRIDGE_PROJECT_DIR and CLAUDE_PROJECT_DIR still do", async () => {
    const base = { AGENT_BRIDGE_NAME_FROM: "project" };
    assert.equal(resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: "/work/payments" }, "/work/billing").AGENT_NAME, "billing");
    assert.equal(resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: "/work/cur", CLAUDE_PROJECT_DIR: "/work/cla" }, "/x/cwd").AGENT_NAME, "cla");
    assert.equal(resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: "/work/cur", AGENT_BRIDGE_PROJECT_DIR: "/work/own" }, "/x/cwd").AGENT_NAME, "own");
    assert.equal(resolveIdentityEnv(base, "/x/the-cwd").AGENT_NAME, "the-cwd");
    assert.equal(resolveIdentityEnv({ ...base, AGENT_NAME: "x", CURSOR_PROJECT_DIR: "/work/cur" }, "/x").AGENT_NAME, "x");
    assert.equal(agentNameFromDir("/a/b/Proj_1"), "proj_1");
    assert.throws(() => agentNameFromDir("/a/b/Proj 1"), /agent name/); // not cleaned up (R3-06)
  });

  await test("as a Cursor hook, peek names a project-named agent after the workspace folder Cursor sends (not an inherited variable)", async () => {
    const folder = repo("Hook-Proj");
    const db = join(tmp, "hookproj.db");
    const env = { HOME, AGENT_BRIDGE_DB: db };
    const sent = await runCli(["send", "hook-proj", "hello there"], { ...env, AGENT_NAME: "sender" });
    assert.equal(sent.code, 0, sent.err);
    const inp = JSON.stringify({ hook_event_name: "beforeSubmitPrompt", cursor_version: "3.0.0", workspace_roots: [folder] });
    const named = await runCli(["peek", "--format", "cursor", "--event", "beforeSubmitPrompt"], { ...env, AGENT_BRIDGE_NAME_FROM: "project" }, { input: inp });
    assert.match(JSON.parse(named.out).additional_context ?? "", /1 from sender/);
    // a relative "workspace" is not used
    const rel = JSON.stringify({ hook_event_name: "beforeSubmitPrompt", cursor_version: "3.0.0", workspace_roots: ["Hook-Proj"] });
    const relOut = await runCli(["peek", "--format", "cursor", "--event", "beforeSubmitPrompt"], { ...env, AGENT_BRIDGE_NAME_FROM: "project" }, { input: rel });
    assert.ok(!/1 from sender/.test(relOut.out), relOut.out);
  });

  await test("a server started the way Cursor would from a managed entry (AGENT_BRIDGE_PROJECT_DIR = the substituted ${workspaceFolder}) is named after the folder", async () => {
    const { connectAgent } = await import("./harness.js");
    const { sqliteBackend } = await import("./backends.js");
    const b = await sqliteBackend();
    try {
      const folder = repo("Cursor-Proj");
      const a = await connectAgent(b, "x", { AGENT_NAME: "", AGENT_BRIDGE_NAME_FROM: "project", AGENT_BRIDGE_PROJECT_DIR: folder });
      try {
        assert.equal(JSON.parse((await a.call("whoami")).text).agent, "cursor-proj");
      } finally {
        await a.close();
      }
      // an inherited CURSOR_PROJECT_DIR alone does not rename the server (R4-11)
      const c = await connectAgent(b, "x", { AGENT_NAME: "", AGENT_BRIDGE_NAME_FROM: "project", CURSOR_PROJECT_DIR: folder });
      try {
        assert.notEqual(JSON.parse((await c.call("whoami")).text).agent, "cursor-proj");
      } finally {
        await c.close();
      }
    } finally {
      await b.cleanup();
    }
  });
} finally {
  const failed = summary();
  rmrf(tmp);
  process.exit(failed ? 1 : 0);
}
