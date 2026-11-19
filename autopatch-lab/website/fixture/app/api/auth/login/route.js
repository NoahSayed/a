import { NextResponse } from 'next/server';
import { authenticate, issueSession, COOKIE } from '../../../../lib/auth.js';

export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const user = authenticate(body.username, body.password);
  if (!user) return NextResponse.json({ error: 'invalid credentials' }, { status: 401 });
  try {
    const token = issueSession(user);
    const res = NextResponse.json({ ok: true, user: { id: user.id, role: user.role } });
    res.cookies.set(COOKIE, token, { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 3600 });
    return res;
  } catch (e) {
    console.error('login: could not issue session token:', e.message);
    return NextResponse.json({ error: 'login unavailable' }, { status: 500 });
  }
}
