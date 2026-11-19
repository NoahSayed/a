import Link from 'next/link';
import { products } from '../lib/data.js';

export default function Home() {
  const featured = products().filter((p) => p.featured);
  return (
    <section>
      <h2>Fresh bread daily</h2>
      <p>Baked every morning, sold until it is gone.</p>
      <ul className="featured">
        {featured.map((p) => (
          <li key={p.id} className="featured-item">
            <Link href={`/products/${p.id}`}>{p.name}</Link> - ${p.price.toFixed(2)}
          </li>
        ))}
      </ul>
    </section>
  );
}
