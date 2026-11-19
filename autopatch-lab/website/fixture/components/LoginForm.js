'use client';
import { useState } from 'react';

export default function LoginForm() {
  const [msg, setMsg] = useState('');
  async function submit(e) {
    e.preventDefault();
    const f = new FormData(e.target);
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: f.get('username'), password: f.get('password') }),
    });
    if (r.ok) window.location.href = new URLSearchParams(window.location.search).get('next') || '/orders';
    else setMsg('Login failed');
  }
  return (
    <form onSubmit={submit}>
      <label>User <input name="username" /></label>{' '}
      <label>Password <input name="password" type="password" /></label>{' '}
      <button type="submit">Log in</button>
      <p role="alert">{msg}</p>
    </form>
  );
}
