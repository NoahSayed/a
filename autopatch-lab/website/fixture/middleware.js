import { NextResponse } from 'next/server';

// Everything under /admin needs a valid admin session. Middleware runs on the edge runtime, where the
// session library is not available, so it asks our own verify endpoint.
export async function middleware(request) {
  const verify = new URL('/api/auth/verify', request.url);
  let ok = false;
  try {
    const r = await fetch(verify, { headers: { cookie: request.headers.get('cookie') || '' }, cache: 'no-store' });
    if (r.ok) ok = (await r.json()).role === 'admin';
  } catch {
    ok = false;
  }
  if (ok) return NextResponse.next();
  const login = new URL('/login', request.url);
  login.searchParams.set('next', request.nextUrl.pathname);
  return NextResponse.redirect(login);
}

export const config = { matcher: ['/admin/:path*'] };
