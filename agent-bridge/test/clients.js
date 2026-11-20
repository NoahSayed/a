// Multi-client suite: init --client parsing, the agent-bridge skill, doctor <repo> per client.
// The client-specific writers have their own suites (test/clients-codex.js, test/clients-cursor.js).
//   node test/clients.js      (no Postgres needed)
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IS_WIN, connectAgent, rmrf, runCli, skip, summary, test } from "./harness.js";
import { sqliteBackend } from "./backends.js";

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

  await test("peek --format with an unknown format prints nothing and exits 0 (never blocks a prompt)", async () => {
    const out = await runCli(["peek", "front", "--format", "nope"], env);
    assert.equal(out.code, 0);
    assert.equal(out.out, "");
  });
} finally {
  rmrf(tmp);
}

process.exit(summary() ? 1 : 0);
