. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
IN='{"hook_event_name":"beforeSubmitPrompt","cursor_version":"1.0","workspace_roots":["/nonexistent"]}'
echo "--- imported + proxy --set (re-exec)"; echo "$IN" | CURSOR_PROJECT_DIR=/x node $AB/cli.js peek web --set AGENT_NAME=web --set HTTPS_PROXY=http://127.0.0.1:9 --set AGENT_BRIDGE_DB=$HOME/.agent-bridge/bridge.db; echo "exit=$?"
echo "--- explicit cursor + proxy --set, stdin never closes"
time (sleep 3 | node $AB/cli.js peek web --format cursor --event sessionStart --set AGENT_NAME=web --set HTTPS_PROXY=http://127.0.0.1:9 --set AGENT_BRIDGE_DB=$HOME/.agent-bridge/bridge.db)
echo "--- bad --set key in cursor format"; echo "$IN" | node $AB/cli.js peek web --format cursor --event sessionStart --set NODE_OPTIONS=--require=/x; echo "exit=$?"
echo "--- bad format value"; echo "$IN" | node $AB/cli.js peek web --format __proto__ --event sessionStart; echo "exit=$?"
echo "--- imported: Claude Code stdin with leaked CURSOR env"; echo '{"hook_event_name":"UserPromptSubmit","prompt":"hi"}' | CURSOR_VERSION=1 AGENT_NAME=web node $AB/cli.js peek web
echo "--- imported: cursor_version only, event unknown => note dropped?"; echo '{"hook_event_name":"UserPromptSubmit","cursor_version":"1.2"}' | CURSOR_VERSION=1 AGENT_NAME=web node $AB/cli.js peek web
