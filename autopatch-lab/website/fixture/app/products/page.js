import Link from 'next/link';
import { products } from '../../lib/data.js';

export default function Products() {
  return (
    <section>
      <h2>Our products</h2>
      <ul className="product-list">
        {products().map((p) => (
          <li key={p.id} className="product">
            <Link href={`/products/${p.id}`}>{p.name}</Link> - ${p.price.toFixed(2)}
            <div>{p.blurb}</div>
          </li>
        ))}
      </ul>
    </section>
  );
}
