import { NextResponse } from 'next/server';
import { products } from '../../../lib/data.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json(products());
}
