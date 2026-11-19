import fs from 'node:fs';
import path from 'node:path';

export const DATA_DIR = path.join(process.cwd(), 'data');
export const readJson = (name) => JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8'));
export const products = () => readJson('products.json');
export const orders = () => readJson('orders.json');
export const orderById = (id) => orders().find((o) => String(o.id) === String(id)) || null;
