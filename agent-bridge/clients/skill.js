// The agent-bridge skill (skills/agent-bridge/SKILL.md, Agent Skills format): one file that teaches the
// agent when and how to use the bridge. Claude Code, Cursor and Codex all read SKILL.md skills, each from
// its own folder in the repo. init copies it there (unless --no-skill).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { HERE, readText, refuseSymlink } from "./common.js";

export const SKILL_SRC = join(HERE, "skills", "agent-bridge", "SKILL.md");

// Where each client looks for project skills.
export const SKILL_DIRS = {
  claude: [".claude", "skills"],
  cursor: [".cursor", "skills"],
  codex: [".agents", "skills"],
};

// Plan SKILL.md into <repo>/<client skills dir>/agent-bridge/ (written when `tx` commits). Returns
// { path, backup } or null if the file there is already identical. A SKILL.md there that differs from ours (a
// team's own edits, or an older version of ours) is kept as SKILL.md.bak, never silently lost (R4-07).
// Never writes through a symlink at any level.
export function installSkill(repoDir, client, tx) {
  const parts = SKILL_DIRS[client];
  if (!parts) throw new Error(`no skill folder known for client "${client}"`);
  const dirs = [];
  let d = repoDir;
  for (const p of [...parts, "agent-bridge"]) {
    d = join(d, p);
    dirs.push(d);
  }
  const dest = join(d, "SKILL.md");
  const bak = join(d, "SKILL.md.bak");
  for (const p of [...dirs, dest, bak]) refuseSymlink(p);
  const ours = readFileSync(SKILL_SRC, "utf8");
  const current = readText(dest);
  if (current === ours) return null;
  if (current != null) tx.write(bak, current, { mode: 0o644 });
  tx.write(dest, ours, { mode: 0o644 });
  return { path: dest, backup: current != null ? bak : null };
}
