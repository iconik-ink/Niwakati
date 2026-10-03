// ============================================================
// STEP 3: AUTOMATIC EXPIRATION
// Two layers:
//   (a) authenticate() rejects expired clients on every request (authoritative, instant).
//   (b) this cron sweeps the DB, marks accounts 'expired', bumps token_version so any
//       outstanding JWTs die, and writes an audit entry. It keeps the data tidy and
//       visible to you; even if it never ran, (a) would still lock the client out.
// ============================================================
import cron from 'node-cron';
import { withTx } from '../db.js';
import { audit } from '../utils/audit.js';

export async function expireClientAccess() {
  return withTx(async (db) => {
    const { rows } = await db.query(
      `WITH expired AS (
         UPDATE users
            SET status = 'expired', token_version = token_version + 1, updated_at = now()
          WHERE status = 'active'
            AND access_expires_at IS NOT NULL
            AND access_expires_at <= now()
            AND role_id = (SELECT id FROM roles WHERE name = 'client')
        RETURNING id, email
       ), g AS (
         UPDATE access_grants SET status = 'expired'
          WHERE status = 'active' AND user_id IN (SELECT id FROM expired)
       )
       SELECT id, email FROM expired`
    );
    for (const u of rows) {
      await audit(db, { action: 'access.expired', targetId: u.id, meta: { email: u.email } });
    }
    if (rows.length) console.log(`[expiry] locked ${rows.length} client account(s)`);
    return rows.length;
  });
}

export function startExpiryJob() {
  const run = () => expireClientAccess().catch((e) => console.error('[expiry] failed', e));
  cron.schedule('*/5 * * * *', run); // idempotent, so safe if several instances run it
  run();                             // catch anything that expired while the server was down
}
