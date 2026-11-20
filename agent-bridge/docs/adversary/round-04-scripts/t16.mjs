const AB = "/home/user/a/.claude/worktrees/agent-afdfad158458690dc/agent-bridge";
const { parse, scan, replaceTable, canon } = await import(AB + "/clients/toml-edit.js");
for (const n of [25000, 50000, 100000, 200000]) {
  const text = "[mcp_servers.bridge]\ncommand='x'\n" + Array.from({ length: n }, (_, i) => `k${i} = ${i}\n`).join("");
  let s = performance.now(); const p = parse(text); const tp = performance.now() - s;
  s = performance.now(); scan(text); const ts = performance.now() - s;
  s = performance.now(); replaceTable(text, ["mcp_servers", "bridge"], { owned: new Set(["command"]), ownedSubtables: new Set(), lines: ["command='y'"] }); const tr = performance.now() - s;
  s = performance.now(); canon(p); const tc = performance.now() - s;
  console.log(n, "keys", (text.length / 1e6).toFixed(2) + "MB", "parse", Math.round(tp), "scan", Math.round(ts), "replace(total)", Math.round(tr), "canon", Math.round(tc));
}
