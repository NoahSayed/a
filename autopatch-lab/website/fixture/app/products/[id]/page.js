import { notFound } from 'next/navigation';
import { products } from '../../../lib/data.js';
import { track } from '../../../lib/analytics.js';

export const dynamic = 'force-dynamic';

export default function Product({ params }) {
  const p = products().find((x) => String(x.id) === params.id);
  if (!p) notFound();
  track('product_view', { id: p.id });
  return (
    <article>
      <h2 className="product-name">{p.name}</h2>
      <p>{p.blurb}</p>
      <p className="price">Price: ${p.price.toFixed(2)}</p>
    </article>
  );
}
