import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, existsSync, rmSync, mkdirSync } from "node:fs";
const S = "/tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4";
const AB = "/home/user/a/.claude/worktrees/agent-afdfad158458690dc/agent-bridge";
const nasty = [
  `${S}/d b/it's`,
  `${S}/d$(touch ${S}/PWN1)b`,
  `${S}/d\`touch ${S}/PWN2\`b`,
  `${S}/d\nb`,
  `${S}/d\\'b`,
  `${S}/d"b%PATH%`,
  `${S}/d‘b’`,
  `${S}/d;touch ${S}/PWN3;`,
];
for (const form of ["shell", "exec"]) {
  for (const [i, db] of nasty.entries()) {
    rmSync(`${S}/rr`, { recursive: true, force: true });
    mkdirSync(`${S}/rr`);
    const r = spawnSync("node", [`${AB}/cli.js`, "init", `${S}/rr`, "web", "--client", "cursor,codex,claude", "--hook", "--hook-form", form], {
      env: { ...process.env, HOME: `${S}/home`, AGENT_BRIDGE_DB: db }, encoding: "utf8",
    });
    if (r.status !== 0) { console.log(form, i, "init refused:", (r.stderr || "").trim().slice(0, 110)); continue; }
    const hooks = JSON.parse(readFileSync(`${S}/rr/.cursor/hooks.json`, "utf8"));
    const cmd = hooks.hooks.beforeSubmitPrompt[0].command;
    const out = spawnSync("sh", ["-c", `${cmd} <<'CURSOR_HOOK_EOF'\n{"hook_event_name":"beforeSubmitPrompt"}\nCURSOR_HOOK_EOF`], { encoding: "utf8", env: { ...process.env, HOME: `${S}/home` } });
    const pwn = ["PWN1", "PWN2", "PWN3"].filter((n) => existsSync(`${S}/${n}`));
    // claude and codex hooks too
    const ccmd = JSON.parse(readFileSync(`${S}/rr/.claude/settings.local.json`, "utf8")).hooks.UserPromptSubmit.at(-1).hooks[0];
    const cx = JSON.parse(readFileSync(`${S}/rr/.codex/hooks.json`, "utf8")).hooks.UserPromptSubmit[0].hooks[0].command;
    const o2 = spawnSync("sh", ["-c", cx], { encoding: "utf8", env: { ...process.env, HOME: `${S}/home` } });
    const pwn2 = ["PWN1", "PWN2", "PWN3"].filter((n) => existsSync(`${S}/${n}`));
    console.log(form, i, JSON.stringify(db.slice(S.length)), "cursor:", JSON.stringify(out.stdout.trim()).slice(0, 40), "err:", out.stderr.slice(0, 80).replace(/\n/g, " "), "pwn:", pwn, "codexpwn:", pwn2);
  }
}
