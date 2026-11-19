import { orders } from '../../lib/data.js';
import { notes } from '../../lib/notes.js';
import { stats } from '../../lib/analytics.js';

export const dynamic = 'force-dynamic';

// Access control for /admin is enforced by middleware.js.
export default function Admin() {
  const all = orders();
  return (
    <section>
      <h2>Admin dashboard</h2>
      <p className="views">Product views: {stats().events}</p>
      <table>
        <tbody>
          {all.map((o) => (
            <tr key={o.id}>
              <td>#{o.id}</td>
              <td>{o.userId}</td>
              <td>${o.total.toFixed(2)}</td>
              <td className="admin-note">{notes.get(o.id)?.text}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
