. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf r20; mkdir r20
export SUPABASE_URL=https://abc.supabase.co
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NODE_USE_ENV_PROXY
for key in sb_secret_ABCDEFGHIJKLMNOP1234 "eyJhbGciOiJIUzI1NiJ9.$(printf '{"role":"service_role"}' | base64 -w0 | tr -d =).sig"; do
  rm -rf r20; mkdir r20
  SUPABASE_PUBLISHABLE_KEY="$key" node $AB/cli.js init r20 web --supabase --client all --hook >/dev/null 2>&1; echo "exit=$?"
  grep -rl -- "${key:0:20}" r20 | sed "s|$S/||" | sort | tr '\n' ' '; echo
done
