// CLI suite: init (local + Supabase), hook, peek, admin commands, token files.
//   node test/cli.js            (sqlite + supabase-local + slack-local; AGENT_BRIDGE_TEST_NO_PG=1 skips the Postgres part)
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { NO_PG, slackLocalBackend, sqliteBackend, supabaseLocalBackend } from "./backends.js";
import { expandHome } from "../store.js";
import { IS_WIN, baseEnv, rmrf, runCli, skip, summary, test } from "./harness.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-cli-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);
const repo = (name) => {
  const d = join(tmp, name);
  mkdirSync(d, { recursive: true });
  return d;
};
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const tokenFile = (n) => join(HOME, ".agent-bridge", "tokens", `${n}.token`);

// Launch the MCP server exactly as Claude Code would from a generated .mcp.json.
async function connectFromMcpJson(repoDir) {
  const cfg = readJson(join(repoDir, ".mcp.json")).mcpServers.bridge;
  const client = new Client({ name: "cli-test", version: "0" });
  await client.connect(
    new StdioClientTransport({ command: cfg.command, args: cfg.args, env: { ...baseEnv(HOME), ...cfg.env }, cwd: repoDir })
  );
  const call = async (tool, args = {}) =>
    (await client.callTool({ name: tool, arguments: args })).content.map((c) => c.text).join("\n");
  return { call, close: () => client.close() };
}

// Runs the hook from settings.local.json the way Claude Code does: a hook with `args` is spawned
// directly (exec form, no shell); one without goes through a POSIX shell (`sh -c` / Git Bash).
// Async on purpose: the fake Supabase server lives in this process and must keep serving.
async function runHook(repoDir) {
  const s = readJson(join(repoDir, ".claude", "settings.local.json"));
  const hook = s.hooks.UserPromptSubmit.at(-1).hooks[0];
  const opts = { cwd: repoDir, env: { ...baseEnv(HOME), AGENT_BRIDGE_DEBUG: "1" } };
  const { stdout, stderr } = Array.isArray(hook.args)
    ? await promisify(execFile)(hook.command, hook.args, opts)
    : await promisify(execFile)("bash", ["-c", hook.command], opts);
  if (stderr) console.log(`       hook stderr: ${stderr.trim()}`);
  return stdout;
}

// POSIX-only assertions (modes, shell-form hooks): skipped, with the reason, where they can't apply.
const posixTest = (name, fn) => (IS_WIN ? skip(name, "POSIX file modes / POSIX shell form do not exist on Windows") : test(name, fn));
const assertMode = (p, want) =>
  IS_WIN ? skip(`mode check of ${p}`, "NTFS has no POSIX permission bits; Windows relies on the user-profile ACL") : assert.equal(statSync(p).mode & 0o777, want, `mode of ${p}`);

try {
  console.log("\n=== cli: local (sqlite) ===");
  const lb = await sqliteBackend();
  const localEnv = { HOME, AGENT_BRIDGE_DB: lb.envFor("x").AGENT_BRIDGE_DB };

  await test("init writes .mcp.json and keeps existing servers", async () => {
    const r = repo("local-a");
    writeFileSync(join(r, ".mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } } }));
    const res = await runCli(["init", r, "alpha", "React app", "--hook"], localEnv);
    assert.equal(res.code, 0, res.err);
    const cfg = readJson(join(r, ".mcp.json")).mcpServers;
    assert.ok(cfg.other, "existing server was dropped");
    assert.equal(cfg.bridge.env.AGENT_NAME, "alpha");
    assert.equal(cfg.bridge.env.AGENT_DESCRIPTION, "React app");
  });

  await test("re-running init keeps the description and doesn't duplicate the hook", async () => {
    const r = repo("local-a");
    await runCli(["init", r, "alpha", "--hook"], localEnv);
    await runCli(["init", r, "alpha", "--hook"], localEnv);
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_DESCRIPTION, "React app");
    const hooks = readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit;
    assert.equal(hooks.length, 1);
  });

  await test("upgrading replaces a stage-1 hook (old double-quoted format) instead of adding a second", async () => {
    const r = repo("local-upgrade");
    mkdirSync(join(r, ".claude"), { recursive: true });
    const old = `AGENT_BRIDGE_DB="/x/bridge.db" "${process.execPath}" "/old/agent-bridge/cli.js" peek alpha`;
    const other = { hooks: [{ type: "command", command: "echo unrelated" }] };
    writeFileSync(
      join(r, ".claude", "settings.local.json"),
      JSON.stringify({ hooks: { UserPromptSubmit: [other, { hooks: [{ type: "command", command: old }] }] } })
    );
    await runCli(["init", r, "alpha", "--hook"], localEnv);
    const hooks = readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit;
    assert.equal(hooks.length, 2, JSON.stringify(hooks));
    assert.deepEqual(hooks[0], other, "an unrelated hook was touched");
    assert.ok(!JSON.stringify(hooks).includes("/old/agent-bridge"));
  });

  await test("init rejects bad names and missing repos", async () => {
    assert.notEqual((await runCli(["init", repo("local-x"), "Bad Name"], localEnv)).code, 0);
    assert.notEqual((await runCli(["init", join(tmp, "nope"), "ok"], localEnv)).code, 0);
  });

  await test("generated config starts a working server; two repos can talk", async () => {
    const rb = repo("local-b");
    await runCli(["init", rb, "beta", "--hook"], localEnv);
    const a = await connectFromMcpJson(repo("local-a"));
    const b = await connectFromMcpJson(rb);
    assert.match(await a.call("send_message", { to: "beta", body: "hi beta" }), /Sent message/);
    assert.match(await b.call("check_inbox"), /hi beta/);
    await a.close();
    await b.close();
  });

  await test("hook prints a notice only when there is unread mail", async () => {
    const rb = repo("local-b");
    assert.equal((await runHook(rb)).trim(), "");
    await runCli(["send", "beta", "ping", "from", "cli"], { ...localEnv, AGENT_NAME: "human" });
    assert.match(await runHook(rb), /1 from human/);
  });

  await test("log / agents / whoami work", async () => {
    const log = await runCli(["log", "5"], localEnv);
    assert.match(log.out, /human -> beta/);
    const agents = await runCli(["agents"], localEnv);
    assert.match(agents.out, /alpha/);
    const who = await runCli(["whoami"], { ...localEnv, AGENT_NAME: "beta" });
    assert.equal(JSON.parse(who.out).unread, 1);
  });

  console.log("\n=== cli: portability (no Postgres needed) ===");
  await test("expandHome: only ~ and ~/x mean the home directory; ~name is a plain relative name", async () => {
    assert.equal(expandHome("~"), resolve(homedir()));
    assert.equal(expandHome("~/a/b"), join(homedir(), "a", "b"));
    assert.equal(expandHome("~foo"), resolve("~foo"));
    assert.notEqual(expandHome("~foo"), resolve(homedir() + "foo"));
  });

  await test("--hook-form exec writes command + args with no shell; settings travel as --set args", async () => {
    const r = repo("hook-exec");
    const res = await runCli(["init", r, "alpha", "--hook", "--hook-form", "exec"], localEnv);
    assert.equal(res.code, 0, res.err);
    const hook = readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit.at(-1).hooks[0];
    assert.equal(hook.command, process.execPath);
    assert.ok(Array.isArray(hook.args));
    assert.deepEqual(hook.args.slice(1, 3), ["peek", "alpha"]);
    assert.ok(hook.args.includes(`AGENT_BRIDGE_DB=${localEnv.AGENT_BRIDGE_DB}`), "the mailbox path isn't in the hook's own args");
    assert.ok(!hook.args.some((a) => /AGENT_DESCRIPTION/.test(a)));
    assert.equal((await runHook(r)).trim(), "");
    await runCli(["send", "alpha", "exec", "form"], { ...localEnv, AGENT_NAME: "human" });
    assert.match(await runHook(r), /1 from human/, "the exec-form hook did not read its mailbox");
  });

  await test("the exec-form hook ignores a changed .mcp.json (a committed file must not redirect it)", async () => {
    const r = repo("hook-exec");
    // someone edits the repo's .mcp.json to point the bridge elsewhere (here: another mailbox with mail in it)
    const evilDb = join(tmp, "evil", "bridge.db");
    await runCli(["send", "alpha", "from", "the", "evil", "mailbox"], { HOME, AGENT_BRIDGE_DB: evilDb, AGENT_NAME: "mallory" });
    const cfg = readJson(join(r, ".mcp.json"));
    cfg.mcpServers.bridge.env.AGENT_BRIDGE_DB = evilDb;
    writeFileSync(join(r, ".mcp.json"), JSON.stringify(cfg));
    const out = await runHook(r);
    assert.doesNotMatch(out, /mallory/, "the hook followed the edited .mcp.json");
    assert.match(out, /1 from human/);
  });

  await test("switching hook form replaces the old hook instead of stacking; bad forms are refused", async () => {
    const r = repo("hook-switch");
    for (const form of ["shell", "exec", "shell", "exec"]) {
      assert.equal((await runCli(["init", r, "alpha", "--hook", "--hook-form", form], localEnv)).code, 0);
    }
    assert.equal(readJson(join(r, ".claude", "settings.local.json")).hooks.UserPromptSubmit.length, 1);
    const bad = await runCli(["init", r, "alpha", "--hook", "--hook-form", "cmd"], localEnv);
    assert.notEqual(bad.code, 0);
    assert.match(bad.err, /hook-form/);
  });

  await test("peek --set accepts only bridge settings, and stays silent on a bad one", async () => {
    const ok = await runCli(["peek", "alpha", "--set", `AGENT_BRIDGE_DB=${localEnv.AGENT_BRIDGE_DB}`], { HOME });
    assert.match(ok.out, /1 from human/);
    const bad = await runCli(
      ["peek", "alpha", "--set", `AGENT_BRIDGE_DB=${localEnv.AGENT_BRIDGE_DB}`, "--set", "NODE_OPTIONS=--require /tmp/x.js"],
      { HOME, AGENT_BRIDGE_DEBUG: "1" }
    );
    assert.equal(bad.code, 0);
    assert.equal(bad.out, "");
    assert.match(bad.err, /not a bridge setting/);
  });

  await test("save-token stores a token file (no Postgres involved)", async () => {
    const tok = "abt_" + "ab".repeat(32);
    const r = await runCli(["save-token", "portable"], { HOME }, { input: tok + "\r\n" }); // CRLF, as typed on Windows
    assert.equal(r.code, 0, r.err);
    assert.equal(readFileSync(tokenFile("portable"), "utf8"), tok + "\n");
    assertMode(tokenFile("portable"), 0o600);
  });

  await test("init --supabase points at the token file and keeps the token out of the repo (no Postgres)", async () => {
    const env = { HOME, SUPABASE_URL: "http://127.0.0.1:1", SUPABASE_PUBLISHABLE_KEY: "x" };
    const r = repo("s-portable");
    const res = await runCli(["init", r, "portable", "--supabase", "--hook"], env);
    assert.equal(res.code, 0, res.err);
    const tok = readFileSync(tokenFile("portable"), "utf8").trim();
    for (const f of [".mcp.json", ".claude/settings.local.json"]) {
      assert.ok(!readFileSync(join(r, f), "utf8").includes(tok), `token leaked into ${f}`);
    }
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_BRIDGE_TOKEN_FILE, tokenFile("portable"));
    assert.equal((await runHook(r)).trim(), "", "an unreachable bridge must not print anything or fail the hook");
  });
  await lb.cleanup();

  if (NO_PG) {
    console.log("\n=== cli: supabase section skipped (AGENT_BRIDGE_TEST_NO_PG=1: no Postgres on this runner) ===");
  } else {
  console.log("\n=== cli: supabase (local stand-in) ===");
  const sb = await supabaseLocalBackend();
  const sEnv = { HOME, SUPABASE_URL: sb.url, SUPABASE_PUBLISHABLE_KEY: sb.publishable };
  const adminEnv = { ...sEnv, SUPABASE_SECRET_KEY: sb.secret };

  await test("admin commands need the secret key", async () => {
    const r = await runCli(["add-agent", "gamma"], sEnv);
    assert.notEqual(r.code, 0);
    assert.match(r.err, /SUPABASE_SECRET_KEY/);
  });

  await test("add-agent --save writes a private token file", async () => {
    const r = await runCli(["add-agent", "gamma", "API server", "--save"], adminEnv);
    assert.equal(r.code, 0, r.err);
    const st = statSync(tokenFile("gamma"));
    assertMode(tokenFile("gamma"), 0o600);
    assert.match(readFileSync(tokenFile("gamma"), "utf8"), /^abt_[0-9a-f]{64}\n$/);
  });

  await test("add-agent without --save prints the token once; duplicates refused", async () => {
    const r = await runCli(["add-agent", "delta"], adminEnv);
    const tok = r.out.match(/abt_[0-9a-f]{64}/)?.[0];
    assert.ok(tok);
    const dup = await runCli(["add-agent", "delta"], adminEnv);
    assert.notEqual(dup.code, 0);
    assert.match(dup.err, /already exists/);
    const save = await runCli(["save-token", "delta"], { HOME }, { input: tok + "\n" });
    assert.equal(save.code, 0, save.err);
    assert.equal(readFileSync(tokenFile("delta"), "utf8").trim(), tok);
  });

  await test("save-token rejects garbage", async () => {
    const r = await runCli(["save-token", "eps"], { HOME }, { input: "not-a-token\n" });
    assert.notEqual(r.code, 0);
    assert.ok(!existsSync(tokenFile("eps")));
  });

  await test("init --supabase refuses without config or token file", async () => {
    const noEnv = await runCli(["init", repo("s-x"), "gamma", "--supabase"], { HOME });
    assert.match(noEnv.err, /SUPABASE_URL/);
    const noTok = await runCli(["init", repo("s-x"), "zeta", "--supabase"], sEnv);
    assert.match(noTok.err, /no token file/);
  });

  await test("init --supabase keeps the token out of the repo", async () => {
    const r = repo("s-gamma");
    const res = await runCli(["init", r, "gamma", "--supabase", "--hook"], sEnv);
    assert.equal(res.code, 0, res.err);
    const tok = readFileSync(tokenFile("gamma"), "utf8").trim();
    for (const f of [".mcp.json", ".claude/settings.local.json"]) {
      assert.ok(!readFileSync(join(r, f), "utf8").includes(tok), `token leaked into ${f}`);
    }
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_BRIDGE_TOKEN_FILE, tokenFile("gamma"));
  });

  await test("--token-file points at a custom location", async () => {
    const custom = join(tmp, "custom.token");
    writeFileSync(custom, readFileSync(tokenFile("delta")));
    const r = repo("s-delta");
    const res = await runCli(["init", r, "delta", "--supabase", "--hook", "--token-file", custom], sEnv);
    assert.equal(res.code, 0, res.err);
    assert.equal(readJson(join(r, ".mcp.json")).mcpServers.bridge.env.AGENT_BRIDGE_TOKEN_FILE, custom);
  });

  await test("two 'machines' talk through Supabase from generated configs", async () => {
    const g = await connectFromMcpJson(repo("s-gamma"));
    const d = await connectFromMcpJson(repo("s-delta"));
    assert.match(await g.call("whoami"), /"agent": "gamma"/);
    assert.match(await g.call("send_message", { to: "delta", body: "schema v2 is live" }), /Sent message/);
    assert.match(await runHook(repo("s-delta")), /1 from gamma/);
    assert.match(await d.call("check_inbox"), /schema v2 is live/);
    assert.equal((await runHook(repo("s-delta"))).trim(), "");
    await g.close();
    await d.close();
  });

  await test("hook stays silent (exit 0) when Supabase is unreachable", async () => {
    const r = await runCli(["peek", "gamma"], {
      HOME,
      AGENT_BRIDGE_BACKEND: "supabase",
      SUPABASE_URL: "http://127.0.0.1:1",
      SUPABASE_PUBLISHABLE_KEY: "x",
      AGENT_BRIDGE_TOKEN_FILE: tokenFile("gamma"),
    });
    assert.equal(r.code, 0);
    assert.equal(r.out, "");
  });

  await test("rotate-token --save: old token dies, new one works", async () => {
    const old = readFileSync(tokenFile("gamma"), "utf8").trim();
    const r = await runCli(["rotate-token", "gamma", "--save"], adminEnv);
    assert.equal(r.code, 0, r.err);
    const oldWho = await runCli(["whoami"], { ...sEnv, AGENT_BRIDGE_TOKEN: old });
    assert.notEqual(oldWho.code, 0);
    assert.match(oldWho.err, /invalid agent token/);
    const newWho = await runCli(["whoami"], { ...sEnv, AGENT_BRIDGE_TOKEN_FILE: tokenFile("gamma") });
    assert.equal(JSON.parse(newWho.out).agent, "gamma");
  });

  await test("revoke-agent blocks the agent", async () => {
    assert.equal((await runCli(["revoke-agent", "delta"], adminEnv)).code, 0);
    const who = await runCli(["whoami"], { ...sEnv, AGENT_BRIDGE_TOKEN_FILE: tokenFile("delta") });
    assert.notEqual(who.code, 0);
  });

  await test("purge deletes old messages", async () => {
    const r = await runCli(["purge", "0"], adminEnv);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /deleted \d+ message/);
  });

  await test("a token file that doesn't exist gives a clear error", async () => {
    const r = await runCli(["whoami"], { ...sEnv, AGENT_BRIDGE_TOKEN_FILE: join(tmp, "missing.token") });
    assert.match(r.err, /Can't read AGENT_BRIDGE_TOKEN_FILE/);
  });

  await sb.cleanup();
  }

  console.log("\n=== cli: slack (fake Slack API) ===");
  const sl = await slackLocalBackend();
  for (const a of ["web", "api"]) await sl.addAgent(a);
  const slackEnv = { HOME, SLACK_CHANNEL_ID: sl.slack.channel.id, SLACK_API_URL: sl.slack.url };
  const slackTok = (n) => join(HOME, ".agent-bridge", "tokens", `${n}.slack-token`);

  await test("slack-manifest prints a valid manifest with exactly the scopes the code uses", async () => {
    const r = await runCli(["slack-manifest", "web", "React app"], { HOME });
    assert.equal(r.code, 0, r.err);
    const m = JSON.parse(r.out);
    assert.equal(m.features.bot_user.display_name, "web");
    assert.deepEqual(m.oauth_config.scopes.bot.sort(), [
      "channels:history", "channels:read", "chat:write", "groups:history", "groups:read",
      "metadata.message:read", "reactions:read", "reactions:write", "users:read",
    ]);
    assert.notEqual((await runCli(["slack-manifest", "Bad Name"], { HOME })).code, 0);
  });

  await test("save-slack-token stores the bot token 0600 and rejects anything else", async () => {
    for (const a of ["web", "api"]) {
      const r = await runCli(["save-slack-token", a], { HOME }, { input: sl.tokens[a] + "\n" });
      assert.equal(r.code, 0, r.err);
      assertMode(slackTok(a), 0o600);
    }
    const bad = await runCli(["save-slack-token", "web2"], { HOME }, { input: "xoxp-user-token-not-a-bot\n" });
    assert.notEqual(bad.code, 0);
    assert.ok(!existsSync(slackTok("web2")));
  });

  await test("init --slack refuses without a channel or token file, and keeps the token out of the repo", async () => {
    assert.match((await runCli(["init", repo("sl-x"), "web", "--slack"], { HOME })).err, /SLACK_CHANNEL_ID/);
    assert.match((await runCli(["init", repo("sl-x"), "nobody", "--slack"], slackEnv)).err, /no Slack token file/);
    assert.match((await runCli(["init", repo("sl-x"), "web", "--slack", "--supabase"], slackEnv)).err, /choose one/);
    for (const a of ["web", "api"]) {
      const r = repo(`sl-${a}`);
      const res = await runCli(["init", r, a, "--slack", "--hook"], slackEnv);
      assert.equal(res.code, 0, res.err);
      for (const f of [".mcp.json", ".claude/settings.local.json"]) {
        assert.ok(!readFileSync(join(r, f), "utf8").includes(sl.tokens[a]), `bot token leaked into ${f}`);
      }
    }
  });

  await test("two repos talk through the Slack channel from generated configs; the hook sees Slack mail", async () => {
    const w = await connectFromMcpJson(repo("sl-web"));
    const a = await connectFromMcpJson(repo("sl-api"));
    assert.match(await w.call("whoami"), /"agent": "web"/);
    assert.match(await w.call("send_message", { to: "api", body: "is /v2 live?" }), /Sent message/);
    assert.match(await runHook(repo("sl-api")), /1 from web/);
    assert.match(await a.call("check_inbox"), /is \/v2 live\?/);
    assert.equal((await runHook(repo("sl-api"))).trim(), "");
    await w.close();
    await a.close();
  });

  await sl.cleanup();
} finally {
  rmrf(tmp);
}

process.exit(summary() ? 1 : 0);
