import path from 'node:path';
import { createNoteStore } from '@bakery/order-notes';

// Order notes live in data/notes.json. The library keeps each note's owner and, when we tell it who is
// writing, refuses writes from anyone else.
export const notes = createNoteStore({ file: path.join(process.cwd(), 'data', 'notes.json') });
