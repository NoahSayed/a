const AB="/home/user/a/.claude/worktrees/agent-afdfad158458690dc/agent-bridge";
const { editConfigToml } = await import(AB+"/clients/codex.js");
const { parse } = await import(AB+"/clients/toml-edit.js");
const env = { AGENT_NAME:"web", AGENT_DESCRIPTION:"a\"\nb[mcp_servers.x]\n''' \u0000 $(id) `id` %PATH% \\" };
const cases = {
 empty: "",
 crlf: "[a]\r\nx=1\r\n[mcp_servers.bridge]\r\ncommand='old'\r\n",
 quotedHeader: '[ mcp_servers . "bridge" ]\ncommand = "old"\n# keep\n',
 mlstr: 'x = """\n[mcp_servers.bridge]\ncommand = "evil"\n"""\n[mcp_servers.bridge]\ncommand="o"\n',
 mlstr4: 'x = """a""""\n[mcp_servers.bridge]\ncommand="o"\n',
 mlstrEsc: 'x = """a\\"""b\n[mcp_servers.bridge]\n"""\n[mcp_servers.bridge]\ncommand="o"\n',
 lit3: "x = '''\n[mcp_servers.bridge]\n'''\n[mcp_servers.bridge]\ncommand='o'\n",
 envBefore: '[mcp_servers.bridge.env]\nMY_KEY="secret"\n[mcp_servers.bridge.tools.check_inbox]\napproval_mode="approve"\n',
 noMainTools: '[mcp_servers.bridge.tools.check_inbox]\napproval_mode="approve"\n',
 inlineArr: '[mcp_servers.bridge]\nargs = [\n "a", # c ]\n "b]"\n]\nenabled_tools=["x"]\n',
 dottedEnv: '[mcp_servers.bridge]\nenv.FOO = "bar"\ncommand="o"\nstartup_timeout_sec=60\n',
 inlineMain: '[mcp_servers]\nbridge = { command = "x" }\n',
 date: '[mcp_servers.bridge]\ncommand="o"\nd = 1979-05-27 07:32:00\nx = { a = 1,\n b = 2 }\n',
 tail: '[mcp_servers.bridge]\ncommand="o"',
 hdrComment: '[mcp_servers.bridge] # hi\ncommand="o"\n',
 other: '[mcp_servers.bridge2]\ncommand="o"\n[mcp_servers.bridge]\ncommand="p"\n[mcp_servers.bridge.tools."a.b"]\nx=1\n',
 bom: "﻿[a]\nx=1\n",
 arrTbl: '[[mcp_servers.bridge]]\ncommand="x"\n',
 inlineHeaderEnv: '[mcp_servers.bridge]\ncommand="x"\n[mcp_servers.bridge.env]\nA="1"\n[other]\nz=1\n',
 emptyKey: '[mcp_servers.bridge]\n"" = 1\n"command " = 2\n',
 sepcomment: '[mcp_servers.bridge]\ncommand = "x" # c\n# trailing\n\n\n[z]\n',
};
for (const [k,t] of Object.entries(cases)) {
  try {
    const out = editConfigToml(t, { repoDir:"/r p/'\"x", env });
    const p = parse(out.replace(/^﻿/,""));
    const d = p.mcp_servers.bridge.env.AGENT_DESCRIPTION;
    console.log("OK  ", k, d===env.AGENT_DESCRIPTION ? "desc-roundtrip" : "DESC MISMATCH");
  } catch(e){ console.log("ERR ", k, e.message.split("\n")[0].slice(0,150)); }
}
