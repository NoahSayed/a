// Mutations for the Codex client (clients/codex.js, clients/toml-edit.js): each breaks one guard and
// test/clients-codex.js must notice. Same shape as the entries in test/mutations.js (`find` occurs exactly
// once in `file`); test/mutations.js spreads this list into its own.
const CODEX = "clients/codex.js";
const TOML = "clients/toml-edit.js";
const SUITE = ["test/clients-codex.js"];

export default [
  // ---- injection: nothing the user or an agent writes can leave its TOML string
  { name: "CX TOML string: double quote not escaped", file: TOML,
    find: `if (c === 0x22) out += '\\\\"';`, replace: `if (c === 0x22) out += '"';`, suite: SUITE },
  { name: "CX TOML string: backslash not escaped", file: TOML,
    find: `else if (c === 0x5c) out += "\\\\\\\\";`, replace: `else if (c === 0x5c) out += "\\\\";`, suite: SUITE },
  { name: "CX TOML string: newline not escaped", file: TOML,
    find: `else if (c === 0x0a) out += "\\\\n";`, replace: `else if (c === 0x0a) out += "\\n";`, suite: SUITE },
  { name: "CX TOML string: carriage return not escaped", file: TOML,
    find: `else if (c === 0x0d) out += "\\\\r";`, replace: `else if (c === 0x0d) out += "\\r";`, suite: SUITE },
  { name: "CX TOML string: DEL not escaped", file: TOML,
    find: `c < 0x20 || c === 0x7f || (c >= 0x80`, replace: `c < 0x20 || (c >= 0x80`, suite: SUITE },
  { name: "CX TOML string: C1 controls not escaped", file: TOML,
    find: `|| (c >= 0x80 && c <= 0x9f) ||`, replace: `||`, suite: SUITE },
  { name: "CX TOML string: line separators not escaped", file: TOML,
    find: `|| c === 0x2028 || c === 0x2029`, replace: ``, suite: SUITE },
  { name: "CX TOML string: unpaired high surrogate accepted", file: TOML,
    find: `if (!(d >= 0xdc00 && d <= 0xdfff)) throw new Error(`, replace: `if (false) throw new Error(`, suite: SUITE },
  { name: "CX TOML string: unpaired low surrogate accepted", file: TOML,
    find: `if (c >= 0xdc00 && c <= 0xdfff) throw new Error(`, replace: `if (false) throw new Error(`, suite: SUITE },
  { name: "CX TOML key: any key written bare", file: TOML,
    find: `(/^[A-Za-z0-9_-]+$/.test(k) ? k : tomlString(k))`, replace: `k`, suite: SUITE },
  { name: "CX the edited config is not re-parsed", file: CODEX,
    find: `    after = parse(edited);`, replace: `    after = parse(text);`, suite: SUITE },
  { name: "CX the entry is not compared with what init meant to write", file: CODEX,
    find: `if (canon(after.mcp_servers?.[SERVER_NAME]) !== canon(expected) || !sameOutside(before, after, TABLE)) {`,
    replace: `if (!sameOutside(before, after, TABLE)) {`, suite: SUITE },
  { name: "CX nothing outside the entry is compared with the original", file: CODEX,
    find: `if (canon(after.mcp_servers?.[SERVER_NAME]) !== canon(expected) || !sameOutside(before, after, TABLE)) {`,
    replace: `if (canon(after.mcp_servers?.[SERVER_NAME]) !== canon(expected)) {`, suite: SUITE },
  { name: "CX a bridge entry defined by dotted keys or an inline table is edited anyway", file: TOML,
    find: `    if (definesFromOutside) {`, replace: `    if (false) {`, suite: SUITE },
  { name: "CX an array of tables named bridge is edited anyway", file: TOML,
    find: `if (it.array && it.path.length === tablePath.length) throw`, replace: `if (false) throw`, suite: SUITE },

  // ---- never lose the user's file
  { name: "CX init overwrites a config.toml that does not parse", file: CODEX,
    find: `    before = parse(text);
  } catch (e) {`, replace: `    before = {};
  } catch (e) {`, suite: SUITE },
  { name: "CX config.toml is written before hooks.json is validated", file: CODEX,
    find: `  const cfg = editConfigToml(cfgText, { repoDir, env });`,
    replace: `  const cfg = editConfigToml(cfgText, { repoDir, env });
  tx.write(cfgPath, cfg, { mode: 0o600 });
  tx.commit();`, suite: SUITE },
  { name: "CX a hooks.json that is not an object is replaced", file: CODEX,
    find: `if (hooks === null || typeof hooks !== "object" || Array.isArray(hooks)) throw`, replace: `if (false) throw`, suite: SUITE },
  { name: "CX a UserPromptSubmit that is not a list is replaced", file: CODEX,
    find: `if (hooks.hooks.UserPromptSubmit !== undefined && !Array.isArray(hooks.hooks.UserPromptSubmit)) {`, replace: `if (false) {`, suite: SUITE },
  { name: "CX a hooks.json that does not parse gives a raw JSON error", file: CODEX,
    find: `throw new Error(\`can't parse the existing .codex/hooks.json (`, replace: `throw new Error(\`(`, suite: SUITE },
  { name: "CX the user's own keys inside the bridge entry are dropped", file: TOML,
    find: `if (samePath(current, tablePath) && owned.has(it.key[0]))`, replace: `if (samePath(current, tablePath))`, suite: SUITE },
  { name: "CX the user's sub-tables of the bridge entry (Codex's saved approvals) are dropped", file: TOML,
    find: `else if (ownedSubtables.has(it.path[tablePath.length]))`, replace: `else if (true)`, suite: SUITE },
  { name: "CX the old env sub-table is kept next to the new env", file: CODEX,
    find: `const OWNED_SUBTABLES = new Set(["env", "http_headers", "env_http_headers", "oauth", "tools"]);`, replace: `const OWNED_SUBTABLES = new Set(["tools"]);`, suite: SUITE },
  { name: "CX tool_timeout_sec is not replaced on re-run", file: CODEX,
    find: `"command", "args", "env", "cwd", "tool_timeout_sec",`, replace: `"command", "args", "env", "cwd",`, suite: SUITE },
  { name: "CX another transport's url survives next to command", file: CODEX,
    find: `"url", "bearer_token", "bearer_token_env_var", "http_headers", "env_http_headers", "http_headers_helper",`, replace: ``, suite: SUITE },
  { name: "CX CRLF files get LF line endings", file: TOML,
    find: `const eol = text.includes("\\r\\n") ? "\\r\\n" : "\\n";`, replace: `const eol = "\\n";`, suite: SUITE },
  { name: "CX a header at the end of the file without a newline gets the entry glued on", file: TOML,
    find: `text: (atEof ? eol : "") + lines`, replace: `text: lines`, suite: SUITE },
  { name: "CX a byte-order mark is not handled", file: CODEX,
    find: `const stripBom = (t) => (t.charCodeAt(0) === 0xfeff ? [t.slice(1), "\\ufeff"] : [t, ""]);`, replace: `const stripBom = (t) => [t, ""];`, suite: SUITE },
  { name: "CX the scanner does not skip multi-line literal strings", file: TOML,
    find: `    if (text.startsWith("'''", i)) {`, replace: `    if (false) {`, suite: SUITE },
  { name: "CX the scanner does not skip multi-line basic strings", file: TOML,
    find: `    if (text.startsWith('"""', i)) {`, replace: `    if (false) {`, suite: SUITE },
  { name: "CX the scanner does not skip arrays", file: TOML,
    find: `    if (c === "[") {
      i++;
      for (;;) {
        skipBlank();
        if (text[i] === "]") return void i++;`, replace: `    if (false) {
      i++;
      for (;;) {
        skipBlank();
        if (text[i] === "]") return void i++;`, suite: SUITE },
  { name: "CX the scanner does not skip inline tables", file: TOML,
    find: `    if (c === "{") {
      i++;
      for (;;) {
        skipBlank();
        if (text[i] === "}") return void i++;`, replace: `    if (false) {
      i++;
      for (;;) {
        skipBlank();
        if (text[i] === "}") return void i++;`, suite: SUITE },

  // ---- secrets and symlinks
  { name: "CX a secret value in the env is written into the repo", file: CODEX,
    find: `if (SECRETISH.test(k)) throw`, replace: `if (false) throw`, suite: SUITE },
  { name: "CX the secret-name check also refuses token file paths", file: CODEX,
    find: `const SECRETISH = /(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)$/i;`,
    replace: `const SECRETISH = /(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)(_FILE)?$/i;`, suite: SUITE },
  { name: "CX .codex symlink not refused", file: CODEX,
    find: `  refuseSymlink(dir);\n`, replace: ``, suite: SUITE },
  { name: "CX config.toml symlink not refused", file: CODEX,
    find: `  refuseSymlink(cfgPath);\n`, replace: ``, suite: SUITE },
  { name: "CX hooks.json symlink not refused", file: CODEX,
    find: `  if (withHook) refuseSymlink(hooksPath);\n`, replace: ``, suite: SUITE },
  { name: "CX new config.toml is world-readable", file: CODEX,
    find: `  tx.write(cfgPath, cfg, { mode: 0o600 });`, replace: `  tx.write(cfgPath, cfg, { mode: 0o644 });`, suite: SUITE },
  { name: "CX new hooks.json is world-readable", file: CODEX,
    find: `    tx.write(hooksPath, hooksJson, { mode: 0o600 });`, replace: `    tx.write(hooksPath, hooksJson, { mode: 0o644 });`, suite: SUITE },

  // ---- what Codex needs from the entry
  { name: "CX tool_timeout_sec is Codex's 300 s default (a 600 s wait_for_message is cut off)", file: CODEX,
    find: `export const TOOL_TIMEOUT_SEC = 660;`, replace: `export const TOOL_TIMEOUT_SEC = 300;`, suite: SUITE },
  { name: "CX the entry does not pin cwd to the repo", file: CODEX,
    find: `    \`cwd = \${tomlString(entry.cwd)}\`,\n`, replace: ``, suite: SUITE },
  { name: "CX the hook is written even without --hook", file: CODEX,
    find: `  if (withHook) {
    // Exec-form peek`, replace: `  if (true) {
    // Exec-form peek`, suite: SUITE },
  { name: "CX the hook runs without --format codex (Claude's plain text reaches Codex)", file: CODEX,
    find: `extra: ["--format", "codex"]`, replace: `extra: []`, suite: SUITE },
  { name: "CX the hook timeout is Codex's ten-minute default", file: CODEX,
    find: `const HOOK_TIMEOUT_SEC = 10;`, replace: `const HOOK_TIMEOUT_SEC = 600;`, suite: SUITE },

  // ---- hooks.json merge
  { name: "CX our hook is moved to the end on re-run (Codex's trust record is positional)", file: CODEX,
    find: `      else if (!placed) {
        list.push(handler);
        placed = true;
      }`, replace: ``, suite: SUITE },
  { name: "CX the earlier hook is not recognised in Codex's quoted form (hooks stack up)", file: CODEX,
    find: "cli\\\\.js[\"']?\\\\s+[\"']?peek[\"']?\\\\s+[\"']?${escapeRe(name)}",
    replace: "cli\\\\.js[\"']?\\\\s+peek\\\\s+[\"']?${escapeRe(name)}", suite: SUITE },
  { name: "CX another agent whose name starts the same loses its hook", file: CODEX,
    find: "${escapeRe(name)}[\"']?(\\\\s|$)`)", replace: "${escapeRe(name)}`)", suite: SUITE },
  { name: "CX the agent name is used as a regular expression", file: CODEX,
    find: `const escapeRe = (s) => s.replace(/[.*+?^\${}()|[\\]\\\\]/g, "\\\\$&");`, replace: `const escapeRe = (s) => s;`, suite: SUITE },
  { name: "CX the user's other hooks in our group are dropped with ours", file: CODEX,
    find: `if (!ours.test(hookText(h))) list.push(h);`, replace: `if (false) list.push(h);`, suite: SUITE },

  // ---- quoting for the shell Codex uses
  { name: "CX POSIX hook tokens are not quoted", file: CODEX,
    find: `return tokens.map((t) => shq(noControl(t))).join(" ");`, replace: `return tokens.map((t) => noControl(t)).join(" ");`, suite: SUITE },
  { name: "CX control characters are allowed in the hook command", file: CODEX,
    find: `if (/[\\u0000-\\u001f\\u007f]/.test(t)) throw`, replace: `if (false) throw`, suite: SUITE },
  { name: "CX PowerShell: single quotes not doubled", file: "clients/common.js",
    find: `(c) => c + c)}'\`;`, replace: `(c) => c)}'\`;`, suite: SUITE },
  { name: "CX PowerShell: double quotes accepted", file: "clients/common.js",
    find: `  if (t.includes('"')) throw new Error(`, replace: `if (false) throw new Error(`, suite: SUITE },
  { name: "CX PowerShell: no call operator", file: CODEX,
    find: `return "& " + tokens.map(psq).join(" ");`, replace: `return tokens.map(psq).join(" ");`, suite: SUITE },
  { name: "CX cmd.exe: double quote, % and trailing backslash accepted", file: CODEX,
    find: `if (/["%]/.test(t) || t.endsWith("\\\\")) throw`, replace: `if (false) throw`, suite: SUITE },
  { name: "CX Windows default shell is cmd.exe", file: CODEX,
    find: `(hookForm === "shell" ? "cmd" : "powershell")`, replace: `(hookForm === "shell" ? "powershell" : "cmd")`, suite: SUITE },

  // ---- what peek prints for Codex
  { name: "CX peek prints plain text (Codex reports invalid JSON for text starting with [)", file: CODEX,
    find: `return JSON.stringify({ hookSpecificOutput: { hookEventName, additionalContext: notes.join("\\n") } }) + "\\n";`,
    replace: `return notes.join("\\n") + "\\n";`, suite: SUITE },
  { name: "CX peek prints an empty JSON object when there is no mail", file: CODEX,
    find: `if (!notes.length) return "";`, replace: `if (!notes.length) return "{}\\n";`, suite: SUITE },
  { name: "CX peek echoes any event name into the output", file: CODEX,
    find: `const hookEventName = EVENTS.has(event) ? event : "UserPromptSubmit";`, replace: `const hookEventName = event || "UserPromptSubmit";`, suite: SUITE },
  { name: "CX peek puts the notes under the wrong output key", file: CODEX,
    find: `additionalContext: notes.join("\\n") } }) + "\\n";`, replace: `additional_context: notes.join("\\n") } }) + "\\n";`, suite: SUITE },
  { name: "CX a broken .codex/config.toml makes readServerEnv throw (init for another client dies)", file: CODEX,
    find: `return { path, env: {}, error: e.message.split("\\n")[0] };`, replace: `throw e;`, suite: SUITE },
  { name: "CX readServerEnv returns non-string env values", file: CODEX,
    find: `if (typeof v === "string") env[k] = v;`, replace: `env[k] = v;`, suite: SUITE },
];
