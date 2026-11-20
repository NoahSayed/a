// Changes the AI makes are checked for things a human must approve, whatever the tests say.
// Lab lesson: on the Next.js site every AI fix "repaired" a key-size error by generating a new RSA key at
// server start. Tests passed; logins died on every restart. Key management is a human decision.
const HUMAN_REQUIRED = [
  ['key generation / key material', /generateKeyPair|generateKey\s*\(|createPrivateKey|createSecretKey|BEGIN (RSA |EC )?PRIVATE KEY|openssl_pkey_new/],
  ['secrets or credentials in code', /(secret|password|passwd|api[_-]?key|token)\s*[:=]\s*['"][^'"]{6,}['"]/i],
  ['reads environment / config secrets', /process\.env\b|getenv\s*\(|\$_ENV|\$_SERVER\[['"](PHP_AUTH|HTTP_AUTHORIZATION)/],
  ['user or role creation', /wp_(insert|create)_user\s*\(|add_role\s*\(|set_role\s*\(|createUser\s*\(/],
  ['code execution', /\beval\s*\(|new\s+Function\s*\(|child_process|shell_exec|passthru|proc_open/],
  ['remote calls', /wp_remote_(get|post|request)|fetch\s*\(\s*['"`]https?:|https?\.request\s*\(|curl_exec/],
  ['signing / verification algorithms', /algorithms?\s*:\s*\[?\s*['"](none|HS256|RS256)|allowInsecureKeySizes|allowInvalidAsymmetricKeyTypes/],
];
const REVIEW = [
  ['authentication or session logic', /session|cookie|jwt|jsonwebtoken|login|logout|auth/i],
  ['authorization checks', /current_user_can|isAdmin|role|permission|capabilit/i],
  ['CORS / CSP / security headers', /Access-Control-Allow|Content-Security-Policy|X-Frame-Options|cors\(/i],
];

/** diffText: unified diff of the AI's changes. Only added lines count. */
export function assessChanges(diffText, extraPatterns = []) {
  const added = diffText.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).map((l) => l.slice(1)).join('\n');
  const human = HUMAN_REQUIRED.filter(([, re]) => re.test(added)).map(([k]) => k);
  for (const p of extraPatterns) if (new RegExp(p).test(added)) human.push(`custom pattern ${p}`);
  const review = REVIEW.filter(([, re]) => re.test(added)).map(([k]) => k);
  return { humanApprovalRequired: human.length > 0, reasons: human, reviewNotes: review };
}
