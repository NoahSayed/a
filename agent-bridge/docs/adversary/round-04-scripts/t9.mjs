const AB = "/home/user/a/.claude/worktrees/agent-afdfad158458690dc/agent-bridge";
const cur = await import(AB + "/clients/cursor.js");
const cdx = await import(AB + "/clients/codex.js");
const env = { AGENT_NAME: "web", AGENT_BRIDGE_DB: "C:\\Users\\a\u2018; calc.exe; \u2018b\\bridge.db" };
console.log("cursor win32:", cur.hookCommand({ form: "exec", name: "web", env, event: "beforeSubmitPrompt", platform: "win32", nodePath: "C:\\Program Files\\nodejs\\node.exe" }));
console.log("cursor win32 dq:", cur.hookCommand({ form: "exec", name: "web", env: { AGENT_NAME: "web", AGENT_BRIDGE_DB: 'C:\\a"b' }, event: "stop", platform: "win32", nodePath: "C:\\n.exe" }));
console.log("cursor win32 nodePath quote:", cur.hookCommand({ form: "exec", name: "web", env: { AGENT_NAME: "web" }, event: "stop", platform: "win32", nodePath: "C:\\O\u2019Brien\\n.exe" }));
console.log("codex ps:", cdx.hookCommandLine(["C:\\n.exe", "x", "--set", env.AGENT_BRIDGE_DB], "powershell"));
for (const v of ["a b!^&|<>()", "100%", "C:\\dir\\", "a\u00a0b", "$(calc)", "a\u201cb\u201d"]) {
  try { console.log("codex cmd:", JSON.stringify(v), "=>", cdx.hookCommandLine(["n", v], "cmd")); } catch (e) { console.log("codex cmd:", JSON.stringify(v), "refused"); }
  try { console.log("codex ps :", JSON.stringify(v), "=>", cdx.hookCommandLine(["n", v], "powershell")); } catch (e) { console.log("codex ps :", JSON.stringify(v), "refused"); }
}
