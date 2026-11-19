import { NextResponse } from 'next/server';
import { sessionFromRequest } from '../../../../../lib/auth.js';
import { notes } from '../../../../../lib/notes.js';

export const dynamic = 'force-dynamic';

export async function GET(request, { params }) {
  const session = sessionFromRequest(request);
  if (!session) return NextResponse.json({ error: 'login required' }, { status: 401 });
  const note = notes.get(params.id);
  if (!note) return NextResponse.json({ error: 'no such order' }, { status: 404 });
  if (note.owner !== session.sub && session.role !== 'admin') return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  return NextResponse.json({ orderId: params.id, text: note.text });
}

async function save(request, { params }) {
  const session = sessionFromRequest(request);
  const body = await request.json().catch(() => ({}));
  try {
    // order-notes enforces ownership for the user we pass in.
    notes.set(params.id, body.text, { userId: session?.sub });
  } catch (e) {
    return NextResponse.json({ error: e.message }, { status: e.status || 400 });
  }
  return NextResponse.json({ ok: true });
}

export const PUT = save;
export const POST = save;
