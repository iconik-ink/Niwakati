import 'dotenv/config';

const need = (key) => {
  const v = process.env[key];
  if (!v) throw new Error(`Missing required env var: ${key}`);
  return v;
};

export const config = {
  port: Number(process.env.PORT || 3000),
  databaseUrl: need('DATABASE_URL'),
  jwtSecret: need('JWT_SECRET'),
  jwtIssuer: 'niwakati-api',
  tokenTtlSeconds: Number(process.env.TOKEN_TTL_SECONDS || 3600),
  clientAccessDays: Number(process.env.CLIENT_ACCESS_DAYS || 7),
  corsOrigins: (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
  bcryptRounds: 12,
};

// SECURITY: refuse to boot with a weak signing key.
if (config.jwtSecret.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}
