// ============================================================
// STEP 2: AUTHENTICATION + PARTIAL-ACCESS (RBAC) MIDDLEWARE
// ============================================================
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { query } from '../db.js';
import { HttpError } from '../utils/http.js';

// SECURITY: Client access is time-boxed. Fails CLOSED: missing expiry = expired.
export function isAccessExpired(u) {
  if (u.role !== 'client') return false; // super_admin / user never expire
  return (
    u.status === 'expired' ||
    !u.access_expires_at ||
    new Date(u.access_expires_at) <= new Date()
  );
}

/**
 * 1) Verifies the JWT signature (HS256 only, pinned issuer).
 * 2) Re-loads the user + permissions from the DB on EVERY request, so revocation,
 *    role changes and expiry take effect immediately, not when the token expires.
 */
export async function authenticate(req, _res, next) {
  try {
    const [scheme, token] = (req.headers.authorization || '').split(' ');
    if (scheme !== 'Bearer' || !token) throw new HttpError(401, 'Authentication required');

    let payload;
    try {
      payload = jwt.verify(token, config.jwtSecret, {
        algorithms: ['HS256'], // blocks alg=none / algorithm-confusion attacks
        issuer: config.jwtIssuer,
      });
    } catch {
      throw new HttpError(401, 'Invalid or expired token');
    }

    const { rows } = await query(
      `SELECT u.id, u.email, u.status, u.access_expires_at, u.token_version,
              u.must_change_password, r.name AS role,
              COALESCE(array_agg(p.code) FILTER (WHERE p.code IS NOT NULL), '{}') AS permissions
         FROM users u
         JOIN roles r ON r.id = u.role_id
         LEFT JOIN role_permissions rp ON rp.role_id = r.id
         LEFT JOIN permissions p ON p.id = rp.permission_id
        WHERE u.id = $1
        GROUP BY u.id, r.name`,
      [payload.sub]
    );
    const user = rows[0];

    // token_version mismatch = revoked / logged out / role changed
    if (!user || user.token_version !== payload.tv) throw new HttpError(401, 'Session revoked');
    if (user.status === 'suspended') throw new HttpError(403, 'Account suspended', 'ACCOUNT_SUSPENDED');
    if (isAccessExpired(user)) throw new HttpError(403, 'Review access has expired', 'ACCESS_EXPIRED');

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

// Hard role gate (e.g. the whole /api/admin tree is super_admin only).
export const requireRole = (...roles) => (req, _res, next) =>
  roles.includes(req.user.role)
    ? next()
    : next(new HttpError(403, 'Insufficient role', 'FORBIDDEN'));

// Fine-grained gate: every listed permission must be held.
export const requirePermission = (...codes) => (req, _res, next) =>
  codes.every((c) => req.user.permissions.includes(c))
    ? next()
    : next(new HttpError(403, 'Missing permission', 'FORBIDDEN'));

// Defense-in-depth: even if a write route is added by mistake, a client can't use it.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
export function clientReadOnly(req, _res, next) {
  if (req.user.role === 'client' && !SAFE_METHODS.has(req.method)) {
    return next(new HttpError(403, 'Read-only access', 'CLIENT_READ_ONLY'));
  }
  next();
}

// Defense-in-depth: stops clients from pulling bulk data even through "format" tricks.
const EXPORT_PATH = /(export|download|backup|dump)/i;
const EXPORT_FORMATS = new Set(['csv', 'xlsx', 'xls', 'pdf', 'sql']);
export function blockExports(req, _res, next) {
  if (req.user.role !== 'client') return next();
  const fmt = String(req.query.format || '').toLowerCase();
  const accept = req.headers.accept || '';
  if (EXPORT_PATH.test(req.path) || EXPORT_FORMATS.has(fmt) || /text\/csv|spreadsheet/i.test(accept)) {
    return next(new HttpError(403, 'Exports are disabled for reviewers', 'EXPORT_BLOCKED'));
  }
  next();
}

// Temp-password accounts must set their own password before touching anything else.
export function requirePasswordChanged(req, _res, next) {
  if (req.user.must_change_password) {
    return next(new HttpError(403, 'Password change required', 'PASSWORD_CHANGE_REQUIRED'));
  }
  next();
}
