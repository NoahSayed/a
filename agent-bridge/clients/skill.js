// The agent-bridge skill (skills/agent-bridge/SKILL.md, Agent Skills format): one file that teaches the
// agent when and how to use the bridge. Claude Code, Cursor and Codex all read SKILL.md skills, each from
// its own folder in the repo. init copies it there (unless --no-skill).

import { copyFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { HERE, refuseSymlink } from "./common.js";

export const SKILL_SRC = join(HERE, "skills", "agent-bridge", "SKILL.md");

// Where each client looks for project skills.
export const SKILL_DIRS = {
  claude: [".claude", "skills"],
  cursor: [".cursor", "skills"],
  codex: [".agents", "skills"],
};

// Copy SKILL.md into <repo>/<client skills dir>/agent-bridge/. Returns the path written, or null if the
// file there is already identical. Never writes through a symlink at any level we create.
export function installSkill(repoDir, client) {
  const parts = SKILL_DIRS[client];
  if (!parts) throw new Error(`no skill folder known for client "${client}"`);
  const dirs = [];
  let d = repoDir;
  for (const p of [...parts, "agent-bridge"]) {
    d = join(d, p);
    dirs.push(d);
  }
  const dest = join(d, "SKILL.md");
  for (const p of [...dirs, dest]) refuseSymlink(p);
  if (existsSync(dest) && readFileSync(dest, "utf8") === readFileSync(SKILL_SRC, "utf8")) return null;
  mkdirSync(d, { recursive: true });
  copyFileSync(SKILL_SRC, dest);
  return dest;
}
