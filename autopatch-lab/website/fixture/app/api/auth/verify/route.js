import { NextResponse } from 'next/server';
import { sessionFromRequest } from '../../../../lib/auth.js';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  const s = sessionFromRequest(request);
  return s ? NextResponse.json(s) : NextResponse.json({ error: 'no session' }, { status: 401 });
}
