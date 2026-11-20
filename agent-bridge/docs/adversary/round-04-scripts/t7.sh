. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf r7; mkdir -p r7/.cursor; echo '{ // comment
"mcpServers": {} }' > r7/.cursor/mcp.json
echo "--- init --client claude with commented .cursor/mcp.json (no description given)"
node $AB/cli.js init r7 web --client claude; echo "exit=$?"; ls -A r7
echo "--- same with description given"
node $AB/cli.js init r7 web "d" --client claude >/dev/null; echo "exit=$?"
echo "--- symlink .mcp.json -> /dev/zero, init --client cursor, no description"
rm -rf r8; mkdir r8; ln -s /dev/zero r8/.mcp.json
( ulimit -v 3000000; timeout 20 node $AB/cli.js init r8 web --client cursor; echo "exit=$?" ) 2>&1 | tail -3
