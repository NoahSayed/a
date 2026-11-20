. /tmp/claude-0/-home-user-a/f9407917-d4b1-5c0a-a481-0ad006f6aa8a/scratchpad/adv4/env.sh
rm -rf r17; mkdir -p r17/.codex
node -e 'let s="";for(let i=0;i<200000;i++)s+=`k${i} = ${i}\n`;require("fs").writeFileSync(process.argv[1],s)' $S/r17/.codex/config.toml
ls -l r17/.codex/config.toml | awk '{print $5" bytes"}'
echo "--- init --client claude (no description), repo ships a 3 MB .codex/config.toml"
time node $AB/cli.js init r17 web --client claude | head -1 | cut -c1-60
echo "--- doctor"
time node $AB/cli.js doctor r17 --client codex | head -2 | cut -c1-100
