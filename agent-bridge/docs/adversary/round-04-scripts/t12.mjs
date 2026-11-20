const AB = "/home/user/a/.claude/worktrees/agent-afdfad158458690dc/agent-bridge";
const { resolveIdentityEnv } = await import(AB + "/store.js");
const base = { AGENT_BRIDGE_NAME_FROM: "project", AGENT_BRIDGE_TOKEN_FILE: "~/.agent-bridge/tokens/{agent}.token" };
console.log("cwd=/work/billing, no ambient:", resolveIdentityEnv(base, "/work/billing").AGENT_NAME);
console.log("cwd=/work/billing, stale CURSOR_PROJECT_DIR=/work/payments:", resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: "/work/payments" }, "/work/billing").AGENT_NAME,
  resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: "/work/payments" }, "/work/billing").AGENT_BRIDGE_TOKEN_FILE);
console.log("CURSOR_PROJECT_DIR='' :", resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: "" }, "/work/billing").AGENT_NAME);
console.log("CURSOR_PROJECT_DIR relative '..':", (() => { try { return resolveIdentityEnv({ ...base, CURSOR_PROJECT_DIR: ".." }, "/work/billing").AGENT_NAME; } catch (e) { return e.message; } })());
