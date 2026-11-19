// CLI suite: init (local + Supabase), hook, peek, admin commands, token files.
//   node test/cli.js            (uses sqlite + supabase-local)
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { slackLocalBackend, sqliteBackend, supabaseLocalBackend } from "./backends.js";
import { runCli, summary, test } from "./harness.js";
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

// Launch the MCP server exactly as Claude Code would from a generated .mcp.json.
async function connectFromMcpJson(repoDir) {
  const cfg = readJson(join(repoDir, ".mcp.json")).mcpServers.bridge;
  const client = new Client({ name: "cli-test", version: "0" });
  await client.connect(
    new StdioClientTransport({ command: cfg.command, args: cfg.args, env: { PATH: process.env.PATH, HOME, ...cfg.env }, cwd: repoDir })
  );
  const call = async (tool, args = {}) =>
    (await client.callTool({ name: tool, arguments: args })).content.map((c) => c.text).join("\n");
  return { call, close: () => client.close() };
}

// Runs the hook command from settings.local.json through a real shell, like Claude Code does.
// Async on purpose: the fake Supabase server lives in this process and must keep serving.
async function runHook(repoDir) {
  const s = readJson(join(repoDir, ".claude", "settings.local.json"));
  const cmd = s.hooks.UserPromptSubmit.at(-1).hooks[0].command;
  const { stdout, stderr } = await promisify(execFile)("bash", ["-c", cmd], {
    cwd: repoDir,
    env: { PATH: process.env.PATH, HOME, AGENT_BRIDGE_DEBUG: "1" },
  });
  if (stderr) console.log(`       hook stderr: ${stderr.trim()}`);
  return stdout;
}

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
  await lb.cleanup();

  console.log("\n=== cli: supabase (local stand-in) ===");
  const sb = await supabaseLocalBackend();
  const sEnv = { HOME, SUPABASE_URL: sb.url, SUPABASE_PUBLISHABLE_KEY: sb.publishable };
  const adminEnv = { ...sEnv, SUPABASE_SECRET_KEY: sb.secret };
  const tokenFile = (n) => join(HOME, ".agent-bridge", "tokens", `${n}.token`);

  await test("admin commands need the secret key", async () => {
    const r = await runCli(["add-agent", "gamma"], sEnv);
    assert.notEqual(r.code, 0);
    assert.match(r.err, /SUPABASE_SECRET_KEY/);
  });

  await test("add-agent --save writes a private token file", async () => {
    const r = await runCli(["add-agent", "gamma", "API server", "--save"], adminEnv);
    assert.equal(r.code, 0, r.err);
    const st = statSync(tokenFile("gamma"));
    assert.equal(st.mode & 0o777, 0o600);
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
      assert.equal(statSync(slackTok(a)).mode & 0o777, 0o600);
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
  rmSync(tmp, { recursive: true, force: true });
}

process.exit(summary() ? 1 : 0);
