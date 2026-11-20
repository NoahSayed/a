// Probe for FICTIONAL-BAKERY-2024-0001. node order-notes.mjs <baseUrl>
// exit 0 = STILL VULNERABLE (an anonymous request changed another customer's note), exit 1 = blocked, 2 = probe error.
const base = process.argv[2];
const j = (r) => r.json().catch(() => ({}));
const login = await fetch(new URL('/api/auth/login', base), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'bob', password: 'bob-pass-1' }) });
const cookie = (login.headers.getSetCookie?.() || []).map((c) => c.split(';')[0]).join('; ');
if (!login.ok || !cookie) { console.error('probe could not log in as bob'); process.exit(2); }
const read = async () => (await j(await fetch(new URL('/api/orders/2/note', base), { headers: { cookie } }))).text;
const before = await read();
let changed = false;
for (const method of ['PUT', 'POST']) {
  const marker = `PROBE-${method}-${Date.now()}`;
  await fetch(new URL('/api/orders/2/note', base), { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: marker }) }).catch(() => {});
  const now = await read();
  if (now !== before) { changed = true; await fetch(new URL('/api/orders/2/note', base), { method: 'PUT', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ text: before }) }); break; }
}
if (before === undefined) { console.error('probe could not read the note'); process.exit(2); }
process.exit(changed ? 0 : 1);
