// Open endpoints for End Users (website visitors). No auth, strict validation + rate limits.
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { query } from '../db.js';
import { h } from '../utils/http.js';

const router = Router();
const limiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
router.use(limiter);

router.post('/subscribe', h(async (req, res) => {
  const { email, source } = z.object({
    email: z.string().email().max(254).transform((e) => e.toLowerCase()),
    source: z.string().max(50).optional(),
  }).parse(req.body);

  await query(`INSERT INTO subscribers (email, source) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`, [email, source ?? null]);
  // Same response whether new or existing: doesn't leak who is already subscribed.
  res.status(201).json({ message: 'Thanks for subscribing!' });
}));

router.post('/inquiries', h(async (req, res) => {
  const b = z.object({
    kind: z.enum(['contact', 'host_event', 'partner', 'volunteer']).default('contact'),
    name: z.string().trim().min(1).max(120),
    email: z.string().email().max(254),
    message: z.string().max(3000).optional(),
  }).parse(req.body);

  await query(`INSERT INTO inquiries (kind, name, email, message) VALUES ($1,$2,$3,$4)`, [b.kind, b.name, b.email, b.message ?? null]);
  res.status(201).json({ message: 'Message received. We will be in touch.' });
}));

export default router;
