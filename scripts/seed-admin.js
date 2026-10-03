// One-off: creates YOUR super_admin account. Run after `npm run db:init`.
import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { pool } from '../src/db.js';

const email = (process.env.ADMIN_EMAIL || '').toLowerCase();
const password = process.env.ADMIN_PASSWORD || '';
if (!email || password.length < 12) {
  console.error('Set ADMIN_EMAIL and an ADMIN_PASSWORD of 12+ characters in .env');
  process.exit(1);
}

const hash = await bcrypt.hash(password, 12);
const { rowCount } = await pool.query(
  `INSERT INTO users (email, password_hash, full_name, role_id)
   VALUES ($1, $2, 'Super Admin', (SELECT id FROM roles WHERE name = 'super_admin'))
   ON CONFLICT (email) DO NOTHING`,
  [email, hash]
);
console.log(rowCount ? `Super admin created: ${email}` : 'Admin already exists, nothing changed');
await pool.end();
