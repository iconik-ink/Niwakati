import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ZodError } from 'zod';
import { config } from './config.js';
import authRoutes from './routes/auth.js';
import publicRoutes from './routes/public.js';
import dashboardRoutes from './routes/dashboard.js';
import adminRoutes from './routes/admin.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set('trust proxy', 1); // correct client IPs for rate limiting behind a proxy/host
// CSP is off because the current pages use inline scripts and Google Fonts.
// Tighten it once scripts are moved to external files.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: config.corsOrigins.length ? config.corsOrigins : false }));
app.use(express.json({ limit: '10kb' })); // small body cap blocks oversized payloads
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));

app.use('/api/auth', authRoutes);
app.use('/api/public', publicRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found' }));

// The public marketing site: HTML pages + assets/ (images, videos). Range requests work for video.
app.use(express.static(path.join(__dirname, '../public'), { extensions: ['html'], maxAge: '7d' }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err instanceof ZodError) return res.status(400).json({ error: 'Invalid input', details: err.flatten().fieldErrors });
  if (err.code === '23505') return res.status(409).json({ error: 'Already exists' });
  if (err.status) return res.status(err.status).json({ error: err.message, code: err.code });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' }); // never leak internals
});

export default app;
