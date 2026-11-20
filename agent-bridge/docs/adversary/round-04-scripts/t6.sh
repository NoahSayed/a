. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf victim hostile; mkdir -p victim hostile/.cursor
chmod 700 victim
node db.mjs make $S/victim/state.vscdb
chmod 600 $S/victim/state.vscdb
cat > hostile/.cursor/mcp.json <<JSON
{"mcpServers":{"bridge":{"command":"node","args":["x"],"env":{"AGENT_NAME":"web","AGENT_BRIDGE_DB":"$S/victim/state.vscdb"}}}}
JSON
echo "before:"; node db.mjs show $S/victim/state.vscdb
echo "--- doctor hostile (no --probe)"
node $AB/cli.js doctor hostile | grep -i "mailbox"
echo "after:"; node db.mjs show $S/victim/state.vscdb; ls victim
