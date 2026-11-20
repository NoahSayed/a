// Admin-managed installs: `cli.js managed-config` prints a managed-mcp.json entry with one fixed
// launch command (what Claude Code's allowlist compares) and all settings in env; with
// AGENT_BRIDGE_NAME_FROM=project every project gets its own agent name from its folder.
//   node test/managed.js
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { NO_PG, supabaseLocalBackend } from "./backends.js";
import { SERVER, baseEnv, homeEnv, rmrf, runCli, skip, summary, test } from "./harness.js";

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-managed-"));
const HOME = join(tmp, "home");
mkdirSync(HOME, { recursive: true });

async function managedConfig(extraEnv = {}, args = []) {
  const r = await runCli(["managed-config", ...args], { ...homeEnv(HOME), ...extraEnv });
  let json = null;
  try {
    json = JSON.parse(r.out);
  } catch {}
  return { ...r, json, entry: json?.mcpServers?.["agent-bridge"] };
}

// Start the server exactly as a managed entry says, from a project folder, and ask whoami.
async function whoamiFrom(entry, projectDir, extraEnv = {}) {
  const client = new Client({ name: "managed-test", version: "0" });
  await client.connect(
    new StdioClientTransport({
      command: entry.command,
      args: entry.args,
      env: { ...baseEnv(HOME), ...entry.env, ...extraEnv },
      cwd: projectDir,
    })
  );
  const r = await client.callTool({ name: "whoami", arguments: {} });
  await client.close();
  return JSON.parse(r.content[0].text);
}

const project = (name) => {
  const d = join(tmp, "projects", name);
  mkdirSync(d, { recursive: true });
  return d;
};

console.log("\n=== managed installs ===");
try {
  const localDb = join(tmp, "bridge.db");

  await test("managed-config prints valid JSON: one fixed command, settings only in env", async () => {
    const r = await managedConfig({ AGENT_BRIDGE_DB: localDb });
    assert.equal(r.code, 0, r.err);
    assert.ok(r.entry, `no agent-bridge entry in: ${r.out}`);
    assert.equal(r.entry.command, process.execPath);
    assert.deepEqual(r.entry.args, [SERVER], "the launch command must not carry per-agent arguments");
    assert.equal(r.entry.env.AGENT_BRIDGE_NAME_FROM, "project");
    assert.equal(r.entry.env.AGENT_BRIDGE_DB, localDb);
    assert.ok(!("AGENT_NAME" in r.entry.env), "a machine-wide entry must not pin one agent name");
    assert.match(r.err, /allowedMcpServers/, "the allowlist snippet for admins is printed on stderr");
  });

  await test("--node and --server set the paths admins deploy to", async () => {
    const r = await managedConfig({}, ["--node", "/usr/bin/node", "--server", "/opt/agent-bridge/server.js"]);
    assert.equal(r.entry.command, "/usr/bin/node");
    assert.deepEqual(r.entry.args, ["/opt/agent-bridge/server.js"]);
  });

  await test("a server started from the entry takes its name from the project folder", async () => {
    const { entry } = await managedConfig({ AGENT_BRIDGE_DB: localDb });
    assert.equal((await whoamiFrom(entry, project("Payments API!"))).agent, "payments-api");
    assert.equal((await whoamiFrom(entry, project("ledger"))).agent, "ledger");
  });

  await test("CLAUDE_PROJECT_DIR wins over the working directory; AGENT_NAME wins over both", async () => {
    const { entry } = await managedConfig({ AGENT_BRIDGE_DB: localDb });
    const elsewhere = project("not-this-one");
    assert.equal((await whoamiFrom(entry, elsewhere, { CLAUDE_PROJECT_DIR: project("risk-engine") })).agent, "risk-engine");
    assert.equal((await whoamiFrom(entry, elsewhere, { AGENT_NAME: "pinned" })).agent, "pinned");
  });

  await test("a folder name that can't become an agent name is a clear startup error", async () => {
    const { entry } = await managedConfig({ AGENT_BRIDGE_DB: localDb });
    await assert.rejects(() => whoamiFrom(entry, project("___")));
  });

  await test("no secret ever lands in the managed file, even if the shell has them", async () => {
    const r = await managedConfig({
      AGENT_BRIDGE_BACKEND: "supabase",
      SUPABASE_URL: "https://proj.supabase.co",
      SUPABASE_PUBLISHABLE_KEY: "sb_publishable_ok",
      SUPABASE_SECRET_KEY: "sb_secret_SHOULD_NOT_APPEAR",
      AGENT_BRIDGE_TOKEN: "abt_" + "1".repeat(64),
      RELAY_ADMIN_KEY: "x".repeat(40),
    });
    assert.equal(r.code, 0, r.err);
    const text = JSON.stringify(r.json);
    for (const secret of ["sb_secret_SHOULD_NOT_APPEAR", "abt_" + "1".repeat(64), "x".repeat(40)]) {
      assert.ok(!text.includes(secret), "a secret was written into the managed config");
    }
    assert.equal(r.entry.env.AGENT_BRIDGE_TOKEN_FILE, "~/.agent-bridge/tokens/{agent}.token");
    assert.equal(r.entry.env.SUPABASE_PUBLISHABLE_KEY, "sb_publishable_ok");
  });

  await test("a proxy URL with a password is refused (the managed file is readable by every user)", async () => {
    // a network backend (the local one never touches a proxy, so it ignores proxy settings)
    const relay = { AGENT_BRIDGE_BACKEND: "relay", RELAY_URL: "https://bridge.corp.internal:8787" };
    const r = await managedConfig({ ...relay, HTTPS_PROXY: "http://alice:s3cret@proxy.corp:8080" });
    assert.notEqual(r.code, 0);
    assert.match(r.err, /credentials/);
    assert.ok(!r.out.includes("s3cret"));
    const ok = await managedConfig({ ...relay, HTTPS_PROXY: "http://proxy.corp:8080", NO_PROXY: "localhost" });
    assert.equal(ok.code, 0, ok.err);
    assert.equal(ok.entry.env.HTTPS_PROXY, "http://proxy.corp:8080");
    assert.equal(ok.entry.env.NODE_USE_ENV_PROXY, "1");
    const ca = await managedConfig({ ...relay, NODE_EXTRA_CA_CERTS: "certs/corp-root.pem" });
    assert.ok(isAbsolute(ca.entry.env.NODE_EXTRA_CA_CERTS), "a relative CA path breaks when Claude Code starts the server elsewhere");
    const local = await managedConfig({ AGENT_BRIDGE_DB: localDb, HTTPS_PROXY: "http://proxy.corp:8080" });
    assert.ok(!("HTTPS_PROXY" in local.entry.env), "the local backend needs no proxy settings");
  });

  await test("Slack: the bot token file is per project ({agent}), never the token", async () => {
    const r = await managedConfig({ AGENT_BRIDGE_BACKEND: "slack", SLACK_CHANNEL_ID: "C0BRIDGE01", SLACK_BOT_TOKEN: "xoxb-should-not-appear" });
    assert.equal(r.entry.env.SLACK_BOT_TOKEN_FILE, "~/.agent-bridge/tokens/{agent}.slack-token");
    assert.ok(!JSON.stringify(r.json).includes("xoxb-should-not-appear"));
  });

  if (NO_PG) {
    skip("Supabase: each project uses its own token file through {agent}", "AGENT_BRIDGE_TEST_NO_PG=1");
  } else {
    await test("Supabase: each project uses its own token file through {agent}", async () => {
      const b = await supabaseLocalBackend();
      try {
        await b.addAgent("payments-api");
        const tokDir = join(HOME, ".agent-bridge", "tokens");
        mkdirSync(tokDir, { recursive: true });
        writeFileSync(join(tokDir, "payments-api.token"), b.tokens["payments-api"] + "\n", { mode: 0o600 });
        const r = await managedConfig({
          AGENT_BRIDGE_BACKEND: "supabase",
          SUPABASE_URL: b.url,
          SUPABASE_PUBLISHABLE_KEY: b.publishable,
        });
        const me = await whoamiFrom(r.entry, project("payments-api"));
        assert.equal(me.agent, "payments-api");
      } finally {
        await b.cleanup();
      }
    });
  }
} finally {
  rmrf(tmp);
}

process.exit(summary() ? 1 : 0);
