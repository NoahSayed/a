import Link from 'next/link';

export const metadata = { title: 'Bakery Shop', description: 'Fresh bread daily.' };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: 'Georgia, serif', maxWidth: 760, margin: '0 auto', padding: 16 }}>
        <header>
          <h1>Bakery Shop</h1>
          <nav style={{ display: 'flex', gap: 16 }}>
            <Link href="/">Home</Link>
            <Link href="/products">Products</Link>
            <Link href="/orders">My orders</Link>
            <Link href="/login">Login</Link>
            <Link href="/admin">Admin</Link>
          </nav>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
