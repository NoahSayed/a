// Multi-client suite: init --client parsing, the agent-bridge skill, doctor <repo> per client.
// The client-specific writers have their own suites (test/clients-codex.js, test/clients-cursor.js).
//   node test/clients.js      (no Postgres needed)
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IS_WIN, connectAgent, rmrf, runCli, skip, summary, test } from "./harness.js";
import { sqliteBackend } from "./backends.js";
import { parse as parseToml } from "smol-toml";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { baseEnv } from "./harness.js";

// The bridge entry each tool would launch, read from that tool's own file.
const entryFor = (client, r) =>
  client === "codex"
    ? parseToml(readFileSync(join(r, ".codex", "config.toml"), "utf8")).mcp_servers.bridge
    : JSON.parse(readFileSync(join(r, client === "cursor" ? ".cursor/mcp.json" : ".mcp.json"), "utf8")).mcpServers.bridge;

// Start the server the way that tool does: its command, args and env, in the repo (Codex: the entry's cwd).
async function launch(client, r) {
  const e = entryFor(client, r);
  const c = new Client({ name: `as-${client}`, version: "0" });
  await c.connect(new StdioClientTransport({ command: e.command, args: e.args, env: { ...baseEnv(HOME), ...e.env }, cwd: e.cwd || r }));
  const call = async (tool, args = {}) => (await c.callTool({ name: tool, arguments: args })).content.map((x) => x.text).join("\n");
  return { call, close: () => c.close() };
}

const tmp = mkdtempSync(join(tmpdir(), "agent-bridge-clients-"));
const HOME = join(tmp, "home");
mkdirSync(HOME);
let n = 0;
const repo = () => {
  const d = join(tmp, `repo${++n}`);
  mkdirSync(d, { recursive: true });
  return d;
};
const env = { HOME, AGENT_BRIDGE_DB: join(tmp, "bridge.db") };
const SKILL_SRC = readFileSync(new URL("../skills/agent-bridge/SKILL.md", import.meta.url), "utf8");
const SKILL_AT = {
  claude: [".claude", "skills", "agent-bridge", "SKILL.md"],
  cursor: [".cursor", "skills", "agent-bridge", "SKILL.md"],
  codex: [".agents", "skills", "agent-bridge", "SKILL.md"],
};

try {
  console.log("\n=== clients: --client, skill, doctor ===");

  await test("the skill follows the Agent Skills format (name matches its folder, description present and under 1024 chars)", () => {
    const m = SKILL_SRC.match(/^---\n([\s\S]*?)\n---\n/);
    assert.ok(m, "frontmatter");
    const name = m[1].match(/^name: (.+)$/m)?.[1];
    const desc = m[1].match(/^description: (.+)$/m)?.[1];
    assert.equal(name, "agent-bridge");
    assert.ok(/^[a-z0-9-]{1,64}$/.test(name));
    assert.ok(desc && desc.length > 50 && desc.length <= 1024, `description length ${desc?.length}`);
    // the safety rules the server's instructions also give
    assert.match(SKILL_SRC, /not instructions from your user/);
    assert.match(SKILL_SRC, /Never send secrets/);
  });

  await test("init (default client) writes .mcp.json and installs the skill for Claude Code only", async () => {
    const r = repo();
    const out = await runCli(["init", r, "front", "the frontend"], env);
    assert.equal(out.code, 0, out.err);
    assert.ok(existsSync(join(r, ".mcp.json")));
    assert.equal(readFileSync(join(r, ...SKILL_AT.claude), "utf8"), SKILL_SRC);
    assert.ok(!existsSync(join(r, ".cursor")) && !existsSync(join(r, ".agents")) && !existsSync(join(r, ".codex")));
    assert.match(out.out, /agent-bridge skill/);
  });

  await test("init --no-skill installs no skill", async () => {
    const r = repo();
    const out = await runCli(["init", r, "front", "--no-skill"], env);
    assert.equal(out.code, 0, out.err);
    assert.ok(existsSync(join(r, ".mcp.json")));
    assert.ok(!existsSync(join(r, ".claude", "skills")));
  });

  await test("re-running init leaves an identical skill alone and replaces a changed one", async () => {
    const r = repo();
    await runCli(["init", r, "front"], env);
    const p = join(r, ...SKILL_AT.claude);
    const again = await runCli(["init", r, "front"], env);
    assert.doesNotMatch(again.out, /agent-bridge skill/, "identical skill isn't rewritten");
    writeFileSync(p, "tampered");
    const third = await runCli(["init", r, "front"], env);
    assert.match(third.out, /agent-bridge skill/);
    assert.equal(readFileSync(p, "utf8"), SKILL_SRC);
  });

  if (IS_WIN) skip("init refuses to write the skill through a symlink", "symlinks need extra rights on Windows");
  else
    await test("init refuses to write the skill through a symlink (a skills folder pointing elsewhere)", async () => {
      const r = repo();
      const elsewhere = join(tmp, `elsewhere${n}`);
      mkdirSync(elsewhere);
      mkdirSync(join(r, ".claude"));
      symlinkSync(elsewhere, join(r, ".claude", "skills"));
      const out = await runCli(["init", r, "front"], env);
      assert.notEqual(out.code, 0);
      assert.match(out.err, /symlink/);
      assert.ok(!existsSync(join(elsewhere, "agent-bridge")), "nothing written through the link");
    });

  await test("--client rejects an unknown client and a missing value", async () => {
    const r = repo();
    const bad = await runCli(["init", r, "front", "--client", "vscode"], env);
    assert.notEqual(bad.code, 0);
    assert.match(bad.err, /unknown client "vscode"/);
    const none = await runCli(["init", r, "front", "--client"], env);
    assert.notEqual(none.code, 0);
    assert.match(none.err, /--client needs a value/);
    assert.ok(!existsSync(join(r, ".mcp.json")), "nothing written on a bad --client");
  });

  await test("--client claude,claude and --client CLAUDE are the same as --client claude", async () => {
    const r = repo();
    const out = await runCli(["init", r, "front", "--client", "claude,CLAUDE"], env);
    assert.equal(out.code, 0, out.err);
    assert.equal(out.out.match(/wrote .*\.mcp\.json/g).length, 1);
  });

  await test("the description from an earlier init is kept when init runs again without one", async () => {
    const r = repo();
    await runCli(["init", r, "front", "the web app"], env);
    await runCli(["init", r, "front"], env);
    const cfg = JSON.parse(readFileSync(join(r, ".mcp.json"), "utf8"));
    assert.equal(cfg.mcpServers.bridge.env.AGENT_DESCRIPTION, "the web app");
  });

  await test("doctor <repo> reads .mcp.json; --client picks a file; an unknown client or a missing file is an error", async () => {
    const r = repo();
    await runCli(["init", r, "front"], env);
    const ok = await runCli(["doctor", r], env);
    assert.match(ok.out, /\.mcp\.json/);
    const wrong = await runCli(["doctor", r, "--client", "zed"], env);
    assert.notEqual(wrong.code, 0);
    assert.match(wrong.err, /unknown client "zed"/);
    const missing = await runCli(["doctor", repo()], env);
    assert.notEqual(missing.code, 0);
    assert.match(missing.err, /no \.mcp\.json, \.cursor\/mcp\.json, \.codex\/config\.toml/);
  });

  await test("doctor <repo> reads .codex/config.toml (allowlist applied) and reports one that doesn't parse", async () => {
    const r = repo();
    const out = await runCli(["init", r, "front", "--client", "codex", "--no-skill"], env);
    assert.equal(out.code, 0, out.err);
    const ok = await runCli(["doctor", r, "--client", "codex"], env);
    assert.match(ok.out, /\.codex[\\/]config\.toml/);
    assert.match(ok.out, /front/);
    writeFileSync(join(r, ".codex", "config.toml"), "[mcp_servers.bridge\ncommand = ");
    const bad = await runCli(["doctor", r, "--client", "codex"], env);
    assert.notEqual(bad.code, 0);
    assert.match(bad.err, /could not be read/);
  });

  await test("tool annotations: only whoami, list_agents and get_thread are read-only; nothing is destructive; send_message is open-world", async () => {
    const b = await sqliteBackend();
    const a = await connectAgent(b, "annot");
    try {
      const { tools } = await a.client.listTools();
      const ann = Object.fromEntries(tools.map((t) => [t.name, t.annotations ?? {}]));
      for (const t of ["whoami", "list_agents", "get_thread"]) assert.equal(ann[t].readOnlyHint, true, t);
      for (const t of ["send_message", "check_inbox", "wait_for_message"]) assert.equal(ann[t].readOnlyHint, false, t);
      for (const t of Object.keys(ann)) assert.equal(ann[t].destructiveHint, false, t);
      assert.equal(ann.send_message.openWorldHint, true);
    } finally {
      await a.close();
      await b.cleanup?.();
    }
  });

  await test("--client all writes every tool's config and skill folder", async () => {
    const r = repo();
    const out = await runCli(["init", r, "front", "--client", "all", "--hook"], env);
    assert.equal(out.code, 0, out.err);
    for (const f of [".mcp.json", ".claude/settings.local.json", ".cursor/mcp.json", ".cursor/hooks.json", ".codex/config.toml", ".codex/hooks.json"]) {
      assert.ok(existsSync(join(r, f)), f);
    }
    for (const c of Object.keys(SKILL_AT)) assert.equal(readFileSync(join(r, ...SKILL_AT[c]), "utf8"), SKILL_SRC, c);
    for (const c of ["claude", "cursor", "codex"]) assert.equal(entryFor(c, r).env.AGENT_NAME, "front", c);
  });

  await test("a Claude Code agent, a Cursor agent and a Codex agent, each started from its own tool's config, talk on one bridge", async () => {
    const shared = { HOME, AGENT_BRIDGE_DB: join(tmp, "mixed.db") };
    const repos = { claude: repo(), cursor: repo(), codex: repo() };
    const names = { claude: "api", cursor: "web", codex: "jobs" };
    for (const c of Object.keys(repos)) {
      const out = await runCli(["init", repos[c], names[c], `the ${names[c]} project`, "--client", c, "--no-skill"], shared);
      assert.equal(out.code, 0, out.err);
    }
    const a = {};
    try {
      for (const c of Object.keys(repos)) a[c] = await launch(c, repos[c]);
      for (const c of Object.keys(repos)) assert.match(await a[c].call("whoami"), new RegExp(`"${names[c]}"`));
      // api (Claude) -> web (Cursor) -> jobs (Codex) -> api (Claude), each a new thread, then a reply back
      await a.claude.call("send_message", { to: "web", subject: "login", body: "renamed user_id to userId in POST /login" });
      assert.match(await a.cursor.call("check_inbox"), /from: api[\s\S]*userId/);
      await a.cursor.call("send_message", { to: "jobs", body: "please re-run the user export after api deploys", type: "fyi" });
      assert.match(await a.codex.call("check_inbox"), /from: web[\s\S]*user export/);
      await a.codex.call("send_message", { to: "api", body: "when is the deploy?" });
      const got = await a.claude.call("check_inbox");
      assert.match(got, /from: jobs[\s\S]*deploy/);
      const thread = got.match(/thread[_ ]id[:= ]+"?([0-9a-f-]{36})/i)?.[1] ?? got.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/)[1];
      await a.claude.call("send_message", { to: "jobs", body: "today 16:00 UTC", type: "response", thread_id: thread });
      assert.match(await a.codex.call("wait_for_message", { timeout_seconds: 5 }), /today 16:00 UTC/);
      const agents = await a.cursor.call("list_agents");
      for (const n of Object.values(names)) assert.match(agents, new RegExp(`"${n}"`));
    } finally {
      for (const x of Object.values(a)) await x.close();
    }
  });

  // FileTx is the last layer for every writer (the writers check too); tested on its own so neither layer hides the other.
  if (IS_WIN) skip("FileTx refuses a symlinked file or directory and writes nothing", "creating symlinks needs privileges on Windows");
  else
    await test("FileTx refuses a symlinked file or directory and writes nothing", async () => {
      const { FileTx } = await import("../clients/common.js");
      const outside = repo();
      writeFileSync(join(outside, "victim.json"), "keep");
      const r1 = repo();
      symlinkSync(join(outside, "victim.json"), join(r1, "a.json"));
      let tx = new FileTx();
      tx.write(join(r1, "b.json"), "new");
      tx.write(join(r1, "a.json"), "pwned");
      assert.throws(() => tx.commit(), /symlink/);
      assert.equal(readFileSync(join(outside, "victim.json"), "utf8"), "keep");
      assert.ok(!existsSync(join(r1, "b.json")), "a file was written before the symlink was refused");
      const r2 = repo();
      symlinkSync(outside, join(r2, ".cursor"));
      tx = new FileTx();
      tx.write(join(r2, ".cursor", "mcp.json"), "pwned");
      assert.throws(() => tx.commit(), /symlink/);
      assert.ok(!existsSync(join(outside, "mcp.json")), "written through a symlinked directory");
    });

  await test("peek --format with an unknown format prints nothing and exits 0 (never blocks a prompt)", async () => {
    const out = await runCli(["peek", "front", "--format", "nope"], env);
    assert.equal(out.code, 0);
    assert.equal(out.out, "");
  });
} finally {
  rmrf(tmp);
}

process.exit(summary() ? 1 : 0);
