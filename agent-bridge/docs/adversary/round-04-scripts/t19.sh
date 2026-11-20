. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf r19; mkdir r19
node $AB/cli.js init r19 web --client=cursor --hook --cursor-events=stop | grep -c "^wrote"; echo "exit=${PIPESTATUS[0]}"; find r19 -type f | sed "s|$S/||" | sort
echo "--- unknown flag accepted silently"
node $AB/cli.js init r19 web --hok --clinet cursor | grep -c "^wrote"
echo "--- peek --format=cursor"
echo '{}' | AGENT_NAME=web node $AB/cli.js peek web --format=cursor --event=sessionStart | cut -c1-100
