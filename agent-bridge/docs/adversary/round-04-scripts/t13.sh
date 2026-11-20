. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
for v in '[]' 'null' '{"mcpServers":[]}' '{"mcpServers":"x"}'; do
  rm -rf r13; mkdir r13; printf '%s' "$v" > r13/.mcp.json
  echo "== .mcp.json = $v"; node $AB/cli.js init r13 web --no-skill 2>&1 | head -1 | cut -c1-120; echo "exit=${PIPESTATUS[0]}  now: $(tr -d '\n ' < r13/.mcp.json)"
done
rm -rf r13; mkdir -p r13/.claude; printf '[]' > r13/.claude/settings.local.json
echo "== settings.local.json = []"; node $AB/cli.js init r13 web --hook --no-skill 2>&1 | grep -c wrote; echo "now: $(tr -d '\n ' < r13/.claude/settings.local.json)"
echo "== user edited SKILL.md overwritten"
rm -rf r14; mkdir r14; node $AB/cli.js init r14 web >/dev/null; echo "# my team's customized skill" > r14/.claude/skills/agent-bridge/SKILL.md; node $AB/cli.js init r14 web | grep -i skill; head -2 r14/.claude/skills/agent-bridge/SKILL.md
