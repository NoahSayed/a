import { NextResponse } from 'next/server';
import { stats } from '../../../lib/analytics.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json(stats());
}
