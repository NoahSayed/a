. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf hz; mkdir -p hz/.cursor; ln -s /dev/zero hz/.cursor/hooks.json
IN="{\"hook_event_name\":\"beforeSubmitPrompt\",\"workspace_roots\":[\"$S/hz\"]}"
echo "$IN" > in.json
echo '--- /dev/zero symlink'; time (CURSOR_PROJECT_DIR=$S/hz AGENT_NAME=web timeout 30 node --max-old-space-size=4096 $AB/cli.js peek web < in.json; echo exit=$?)
rm -rf hf; mkdir -p hf/.cursor; mkfifo hf/.cursor/hooks.json
IN="{\"hook_event_name\":\"beforeSubmitPrompt\",\"workspace_roots\":[\"$S/hf\"]}"
echo "$IN" > in2.json
echo '--- fifo'; time (CURSOR_PROJECT_DIR=$S/hf AGENT_NAME=web timeout 8 node $AB/cli.js peek web < in2.json; echo exit=$?)
