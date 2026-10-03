import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { config } from '../config.js';
import { query } from '../db.js';
import { h, HttpError } from '../utils/http.js';
import { audit } from '../utils/audit.js';
import { authenticate, isAccessExpired } from '../middleware/auth.js';

const router = Router();

// SECURITY: brute-force protection per IP (plus per-account lockout below).
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

// Compared against when the email doesn't exist, so response time doesn't reveal valid emails.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', config.bcryptRounds);

const loginSchema = z.object({
  email: z.string().email().max(254).transform((e) => e.toLowerCase()),
  password: z.string().min(1).max(128),
});

router.post('/login', loginLimiter, h(async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);

  const { rows } = await query(
    `SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id WHERE u.email = $1`,
    [email]
  );
  const user = rows[0];

  if (user?.locked_until && new Date(user.locked_until) > new Date()) {
    throw new HttpError(429, 'Too many attempts. Try again later.');
  }

  const ok = await bcrypt.compare(password, user?.password_hash ?? DUMMY_HASH);
  if (!user || !ok) {
    if (user) {
      // 5 failures => 15 minute lock, counter resets
      await query(
        `UPDATE users SET
           failed_logins = CASE WHEN failed_logins + 1 >= 5 THEN 0 ELSE failed_logins + 1 END,
           locked_until  = CASE WHEN failed_logins + 1 >= 5 THEN now() + interval '15 minutes' ELSE locked_until END
         WHERE id = $1`,
        [user.id]
      );
    }
    throw new HttpError(401, 'Invalid email or password'); // same message either way
  }

  // Checked only AFTER the password is verified, so it can't be used to probe accounts.
  if (user.status === 'suspended') throw new HttpError(403, 'Account suspended', 'ACCOUNT_SUSPENDED');
  if (isAccessExpired(user)) throw new HttpError(403, 'Review access has expired', 'ACCESS_EXPIRED');

  await query(`UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, [user.id]);

  // A client's token can never outlive their access window.
  let ttl = config.tokenTtlSeconds;
  if (user.role === 'client') {
    ttl = Math.min(ttl, Math.floor((new Date(user.access_expires_at) - Date.now()) / 1000));
  }

  const token = jwt.sign({ sub: user.id, tv: user.token_version }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: ttl,
    issuer: config.jwtIssuer,
  });

  await audit({ query }, { actorId: user.id, action: 'auth.login', ip: req.ip });

  res.json({
    token,
    expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      accessExpiresAt: user.access_expires_at,
      mustChangePassword: user.must_change_password,
    },
  });
}));

router.get('/me', authenticate, (req, res) => {
  const { id, email, role, permissions, access_expires_at, must_change_password } = req.user;
  res.json({ id, email, role, permissions, accessExpiresAt: access_expires_at, mustChangePassword: must_change_password });
});

// Bumping token_version kills every token this user holds (all devices).
router.post('/logout', authenticate, h(async (req, res) => {
  await query(`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, [req.user.id]);
  res.json({ message: 'Logged out' });
}));

router.post('/change-password', authenticate, h(async (req, res) => {
  const { currentPassword, newPassword } = z.object({
    currentPassword: z.string().max(128),
    newPassword: z.string().min(12).max(128),
  }).parse(req.body);

  const { rows } = await query(`SELECT password_hash FROM users WHERE id = $1`, [req.user.id]);
  if (!(await bcrypt.compare(currentPassword, rows[0].password_hash))) {
    throw new HttpError(401, 'Current password is incorrect');
  }
  const hash = await bcrypt.hash(newPassword, config.bcryptRounds);
  await query(
    `UPDATE users SET password_hash = $2, must_change_password = false,
            token_version = token_version + 1, updated_at = now() WHERE id = $1`,
    [req.user.id, hash]
  );
  await audit({ query }, { actorId: req.user.id, action: 'auth.password_changed', ip: req.ip });
  res.json({ message: 'Password changed. Please log in again.' });
}));

export default router;
