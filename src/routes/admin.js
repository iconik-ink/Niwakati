// Everything here is super_admin only. A client token can never reach these handlers.
import { Router } from 'express';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { config } from '../config.js';
import { query, withTx } from '../db.js';
import { h, HttpError, pageParams } from '../utils/http.js';
import { audit } from '../utils/audit.js';
import {
  authenticate, requireRole, requirePermission, requirePasswordChanged,
} from '../middleware/auth.js';

const router = Router();
router.use(authenticate, requirePasswordChanged, requireRole('super_admin'));

// ---------- Grant review access (call this once the client has paid in full) ----------
const grantSchema = z.object({
  email: z.string().email().max(254).transform((e) => e.toLowerCase()),
  fullName: z.string().max(120).optional(),
  paymentReference: z.string().min(3).max(100),
  days: z.number().int().min(1).max(30).default(config.clientAccessDays),
  note: z.string().max(500).optional(),
});

router.post('/clients', requirePermission('access:manage'), h(async (req, res) => {
  const b = grantSchema.parse(req.body);
  const tempPassword = crypto.randomBytes(12).toString('base64url');
  const hash = await bcrypt.hash(tempPassword, config.bcryptRounds);

  const client = await withTx(async (db) => {
    const { rows: [u] } = await db.query(
      `INSERT INTO users (email, password_hash, full_name, role_id, status, access_expires_at, must_change_password)
       VALUES ($1, $2, $3, (SELECT id FROM roles WHERE name = 'client'), 'active',
               now() + make_interval(days => $4), true)
       RETURNING id, email, access_expires_at`,
      [b.email, hash, b.fullName ?? null, b.days]
    );
    await db.query(
      `INSERT INTO access_grants (user_id, granted_by, expires_at, payment_reference, note)
       VALUES ($1, $2, $3, $4, $5)`,
      [u.id, req.user.id, u.access_expires_at, b.paymentReference, b.note ?? null]
    );
    await audit(db, { actorId: req.user.id, action: 'access.granted', targetId: u.id, meta: { days: b.days, paymentReference: b.paymentReference }, ip: req.ip });
    return u;
  });

  // Shown ONCE. Send it to the client over a separate channel; they must change it at first login.
  res.status(201).json({ client, temporaryPassword: tempPassword });
}));

// ---------- Renew (extends from the later of now / current expiry; reactivates expired) ----------
router.post('/clients/:id/renew', requirePermission('access:manage'), h(async (req, res) => {
  const { days, paymentReference, note } = z.object({
    days: z.number().int().min(1).max(30).default(config.clientAccessDays),
    paymentReference: z.string().max(100).optional(),
    note: z.string().max(500).optional(),
  }).parse(req.body ?? {});

  const result = await withTx(async (db) => {
    const { rows: [target] } = await db.query(
      `SELECT u.id FROM users u JOIN roles r ON r.id = u.role_id
        WHERE u.id = $1 AND r.name = 'client' FOR UPDATE OF u`, [req.params.id]);
    if (!target) throw new HttpError(404, 'Client not found');

    const { rows: [u] } = await db.query(
      `UPDATE users SET status = 'active',
              access_expires_at = GREATEST(now(), COALESCE(access_expires_at, now())) + make_interval(days => $2),
              updated_at = now()
        WHERE id = $1 RETURNING id, email, access_expires_at`, [target.id, days]);

    await db.query(`UPDATE access_grants SET status = 'superseded' WHERE user_id = $1 AND status = 'active'`, [target.id]);
    await db.query(
      `INSERT INTO access_grants (user_id, granted_by, expires_at, payment_reference, note) VALUES ($1,$2,$3,$4,$5)`,
      [target.id, req.user.id, u.access_expires_at, paymentReference ?? null, note ?? null]);
    await audit(db, { actorId: req.user.id, action: 'access.renewed', targetId: target.id, meta: { days }, ip: req.ip });
    return u;
  });
  res.json({ client: result });
}));

// ---------- Revoke immediately ----------
router.post('/clients/:id/revoke', requirePermission('access:manage'), h(async (req, res) => {
  const out = await withTx(async (db) => {
    const { rows: [u] } = await db.query(
      `UPDATE users SET status = 'suspended', token_version = token_version + 1, updated_at = now()
        WHERE id = $1 AND id <> $2
          AND role_id = (SELECT id FROM roles WHERE name = 'client')
        RETURNING id, email`, [req.params.id, req.user.id]);
    if (!u) throw new HttpError(404, 'Client not found');
    await db.query(`UPDATE access_grants SET status = 'revoked' WHERE user_id = $1 AND status = 'active'`, [u.id]);
    await audit(db, { actorId: req.user.id, action: 'access.revoked', targetId: u.id, ip: req.ip });
    return u;
  });
  res.json({ revoked: out });
}));

// ---------- Change a user's role (super_admin <-> user). Clients are made via /clients. ----------
router.post('/users/:id/role', requirePermission('roles:manage'), h(async (req, res) => {
  const { role } = z.object({ role: z.enum(['super_admin', 'user']) }).parse(req.body);
  // Lock-out guard: you cannot change your own role. Because the caller is a super_admin
  // and is never the target, at least one super_admin (you) always remains.
  if (req.params.id === req.user.id) throw new HttpError(400, 'You cannot change your own role');

  const { rows: [u] } = await query(
    `UPDATE users SET role_id = (SELECT id FROM roles WHERE name = $2),
            access_expires_at = NULL, status = 'active',
            token_version = token_version + 1, updated_at = now()
      WHERE id = $1 RETURNING id, email`, [req.params.id, role]);
  if (!u) throw new HttpError(404, 'User not found');
  await audit({ query }, { actorId: req.user.id, action: 'role.changed', targetId: u.id, meta: { role }, ip: req.ip });
  res.json({ user: u, role });
}));

router.get('/users', requirePermission('users:manage'), h(async (req, res) => {
  const { limit, offset, page } = pageParams(req, 100);
  const { rows } = await query(
    `SELECT u.id, u.email, u.full_name, r.name AS role, u.status, u.access_expires_at, u.created_at
       FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.created_at DESC LIMIT $1 OFFSET $2`,
    [limit, offset]);
  res.json({ page, limit, data: rows });
}));

router.get('/audit', requirePermission('audit:read'), h(async (req, res) => {
  const { limit, offset, page } = pageParams(req, 200);
  const { rows } = await query(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT $1 OFFSET $2`, [limit, offset]);
  res.json({ page, limit, data: rows });
}));

// ---------- Example export: exists ONLY here, so clients can't reach it ----------
const csvCell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@]/.test(s)) s = "'" + s; // neutralise spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
};
router.get('/subscribers/export.csv', requirePermission('subscribers:export'), h(async (req, res) => {
  const { rows } = await query(`SELECT email, source, created_at FROM subscribers ORDER BY id`);
  await audit({ query }, { actorId: req.user.id, action: 'export.subscribers', meta: { rows: rows.length }, ip: req.ip });
  res.type('text/csv').attachment('subscribers.csv');
  res.send(['email,source,created_at', ...rows.map((r) => [r.email, r.source, r.created_at.toISOString()].map(csvCell).join(','))].join('\n'));
}));

export default router;
