. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf r11; mkdir r11; git -C r11 init -q
mkdir -p $HOME/.agent-bridge/tokens
printf 'abt_%064d\n' 1 | sed 's/0/a/g' > $HOME/.agent-bridge/tokens/web.token; chmod 600 $HOME/.agent-bridge/tokens/web.token
export SUPABASE_URL=https://abc.supabase.co SUPABASE_PUBLISHABLE_KEY=sb_publishable_xxxxxxxxxxxxxxxx
export HTTPS_PROXY='http://svc:S3cretPw@proxy.corp:3128'
unset NODE_USE_ENV_PROXY
echo "=== no NODE_USE_ENV_PROXY"
node $AB/cli.js init r11 web --supabase --client all --hook 2>&1 | grep -i "warn\|proxy" | cut -c1-200
grep -rl 'S3cretPw' r11 | sort
ls -l r11/.cursor r11/.codex r11/.mcp.json | grep -v '^total'
git -C r11 add -A -n . | head -20
echo "=== claude gitignore state"; git -C r11 status --short --ignored | head
