const AB = "/home/user/a/.claude/worktrees/agent-afdfad158458690dc/agent-bridge";
const { editConfigToml } = await import(AB + "/clients/codex.js");
const env = { AGENT_NAME: "web" };
const t = (name, text) => {
  const s = performance.now();
  let r;
  try { editConfigToml(text, { repoDir: "/r", env }); r = "ok"; } catch (e) { r = e.constructor.name + ": " + e.message.split("\n")[0].slice(0, 80); }
  console.log(name, (text.length / 1e6).toFixed(1) + "MB", Math.round(performance.now() - s) + "ms", r);
};
t("many keys", "[mcp_servers.bridge]\ncommand='x'\n" + Array.from({ length: 200000 }, (_, i) => `k${i} = ${i}\n`).join(""));
t("many tables", Array.from({ length: 100000 }, (_, i) => `[t${i}]\nx=1\n`).join(""));
t("many sub tools", "[mcp_servers.bridge]\n" + Array.from({ length: 50000 }, (_, i) => `[mcp_servers.bridge.tools.t${i}]\napproval_mode="approve"\n`).join(""));
t("deep arrays", "x = " + "[".repeat(20000) + "]".repeat(20000) + "\n");
t("deep inline", "x = " + "{a=".repeat(5000) + "1" + "}".repeat(5000) + "\n");
t("long dotted key", "a" + ".a".repeat(100000) + " = 1\n");
t("huge string", 'x = "' + "a".repeat(5e6) + '"\n');
t("ml string many quotes", 'x = """' + '""\\'.repeat(100000) + '"""\n');
t("bare keys scan slice", Array.from({ length: 20000 }, (_, i) => "k".repeat(200) + i + " = 1\n").join(""));
