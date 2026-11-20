. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
AGENT_NAME=other node $AB/cli.js send web "hello"
echo '--- cursor format normal'; echo '{"hook_event_name":"beforeSubmitPrompt","workspace_roots":["/x"]}' | AGENT_NAME=web node $AB/cli.js peek web --format cursor --event beforeSubmitPrompt
echo '--- claude'; AGENT_NAME=web node $AB/cli.js peek web </dev/null
echo '--- stdin hang'; time (sleep 5 | AGENT_NAME=web node $AB/cli.js peek web --format cursor --event sessionStart)
echo '--- giant stdin'; time (head -c 200000000 /dev/zero | tr '\0' 'a' | AGENT_NAME=web node $AB/cli.js peek web --format cursor --event sessionStart)
