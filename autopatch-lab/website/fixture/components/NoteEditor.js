'use client';
import { useState } from 'react';

export default function NoteEditor({ orderId, initial }) {
  const [text, setText] = useState(initial);
  const [msg, setMsg] = useState('');
  async function save() {
    const r = await fetch(`/api/orders/${orderId}/note`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    setMsg(r.ok ? 'Saved' : 'Could not save');
  }
  return (
    <div>
      <input value={text} onChange={(e) => setText(e.target.value)} />
      <button onClick={save}>Save note</button> <span>{msg}</span>
    </div>
  );
}
