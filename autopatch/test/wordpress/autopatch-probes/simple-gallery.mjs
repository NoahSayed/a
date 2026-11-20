// exit 0 = still vulnerable (path traversal reads a file outside the gallery folder)
import { base, vulnerable, blocked } from './lib.mjs';
const r = await fetch(new URL('/?sg_download=../private-note.txt', base), { redirect: 'manual' });
(await r.text()).includes('SECRET-UPLOADS-NOTE') ? vulnerable() : blocked();
