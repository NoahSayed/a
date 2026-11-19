import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { readSession, COOKIE } from '../../lib/auth.js';
import { orders } from '../../lib/data.js';
import { notes } from '../../lib/notes.js';
import NoteEditor from '../../components/NoteEditor.js';

export const dynamic = 'force-dynamic';

export default function Orders() {
  const session = readSession(cookies().get(COOKIE)?.value);
  if (!session) redirect('/login?next=/orders');
  const mine = orders().filter((o) => o.userId === session.sub);
  return (
    <section>
      <h2>Your orders</h2>
      {mine.map((o) => (
        <div key={o.id} className="order">
          <h3>Order #{o.id}</h3>
          <p>{o.items.join(', ')} - ${o.total.toFixed(2)}</p>
          <NoteEditor orderId={o.id} initial={notes.get(o.id)?.text || ''} />
        </div>
      ))}
    </section>
  );
}
