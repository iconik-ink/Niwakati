// Routes a Client (reviewer) may use. All read-only; sensitive fields are masked.
import { Router } from 'express';
import { query } from '../db.js';
import { h, maskEmail, pageParams } from '../utils/http.js';
import {
  authenticate, requirePermission, clientReadOnly, blockExports, requirePasswordChanged,
} from '../middleware/auth.js';

const router = Router();

// Order matters: identify -> force password change -> read-only -> no exports.
router.use(authenticate, requirePasswordChanged, clientReadOnly, blockExports);

// Lets the review UI show a countdown banner.
router.get('/access', (req, res) => {
  const exp = req.user.access_expires_at;
  res.json({
    role: req.user.role,
    expiresAt: exp,
    secondsRemaining: exp ? Math.max(0, Math.floor((new Date(exp) - Date.now()) / 1000)) : null,
  });
});

router.get('/overview', requirePermission('dashboard:view'), h(async (_req, res) => {
  const { rows } = await query(
    `SELECT (SELECT count(*) FROM subscribers)::int AS subscribers,
            (SELECT count(*) FROM inquiries)::int AS inquiries,
            (SELECT count(*) FROM inquiries WHERE created_at > now() - interval '7 days')::int AS inquiries_last_7d`
  );
  res.json(rows[0]);
}));

router.get('/subscribers', requirePermission('subscribers:read'), h(async (req, res) => {
  const { limit, offset, page } = pageParams(req);
  const { rows } = await query(
    `SELECT id, email, source, created_at FROM subscribers ORDER BY id DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  const mask = req.user.role === 'client'; // privacy: reviewers never see full subscriber emails
  res.json({ page, limit, data: rows.map((r) => ({ ...r, email: mask ? maskEmail(r.email) : r.email })) });
}));

router.get('/inquiries', requirePermission('inquiries:read'), h(async (req, res) => {
  const { limit, offset, page } = pageParams(req);
  const { rows } = await query(
    `SELECT id, kind, name, email, message, status, created_at
       FROM inquiries ORDER BY id DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  const mask = req.user.role === 'client';
  res.json({
    page, limit,
    data: rows.map((r) => (mask ? { ...r, name: r.name.slice(0, 1) + '***', email: maskEmail(r.email), message: (r.message || '').slice(0, 80) } : r)),
  });
}));

export default router;
