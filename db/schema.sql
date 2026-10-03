-- ============================================================
-- STEP 1: DATABASE SCHEMA (PostgreSQL 13+)
-- ============================================================

-- ---------- RBAC core ----------
CREATE TABLE IF NOT EXISTS roles (
  id          SERIAL PRIMARY KEY,
  name        TEXT UNIQUE NOT NULL,          -- super_admin | client | user
  description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
  id   SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL                  -- e.g. 'subscribers:read'
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       INT NOT NULL REFERENCES roles(id)       ON DELETE CASCADE,
  permission_id INT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

-- ---------- Users ----------
CREATE TABLE IF NOT EXISTS users (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email                TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
  password_hash        TEXT NOT NULL,                       -- bcrypt, never plaintext
  full_name            TEXT,
  role_id              INT  NOT NULL REFERENCES roles(id),
  status               TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','suspended','expired')),
  -- Authoritative expiry for the Client role. NULL for super_admin/user.
  -- Middleware FAILS CLOSED: a client with NULL here is treated as expired.
  access_expires_at    TIMESTAMPTZ,
  -- Bump to instantly invalidate every JWT issued to this user (revoke, role change, logout).
  token_version        INT NOT NULL DEFAULT 0,
  must_change_password BOOLEAN NOT NULL DEFAULT false,
  failed_logins        INT NOT NULL DEFAULT 0,
  locked_until         TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Lets the expiry cron find due clients without scanning the table.
CREATE INDEX IF NOT EXISTS idx_users_expiry
  ON users (access_expires_at) WHERE status = 'active' AND access_expires_at IS NOT NULL;

-- ---------- Access grant ledger (history of payments/renewals) ----------
-- users.access_expires_at is the source of truth for enforcement;
-- this table is the human-readable history / audit trail.
CREATE TABLE IF NOT EXISTS access_grants (
  id                SERIAL PRIMARY KEY,
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_by        UUID REFERENCES users(id),
  starts_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ NOT NULL,
  status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','expired','revoked','superseded')),
  payment_reference TEXT,                                   -- e.g. M-Pesa / bank / invoice ref
  note              TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON access_grants (user_id);

-- ---------- Audit log (append-only by convention) ----------
CREATE TABLE IF NOT EXISTS audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  actor_id   UUID,
  action     TEXT NOT NULL,
  target_id  UUID,
  meta       JSONB NOT NULL DEFAULT '{}',
  ip         TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Website data (End Users submit these via public forms) ----------
CREATE TABLE IF NOT EXISTS subscribers (
  id         BIGSERIAL PRIMARY KEY,
  email      TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
  source     TEXT,                                          -- which page they signed up on
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inquiries (
  id         BIGSERIAL PRIMARY KEY,
  kind       TEXT NOT NULL DEFAULT 'contact',               -- contact | host_event | partner | volunteer
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  message    TEXT,
  status     TEXT NOT NULL DEFAULT 'new',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Seed roles & permissions ----------
INSERT INTO roles (name, description) VALUES
  ('super_admin', 'Developer/owner: full control'),
  ('client',      'Temporary reviewer: read-only, time-boxed'),
  ('user',        'Standard website visitor/customer')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (code) VALUES
  ('dashboard:view'),
  ('subscribers:read'), ('subscribers:export'), ('subscribers:delete'),
  ('inquiries:read'),   ('inquiries:update'),   ('inquiries:export'),
  ('users:manage'), ('roles:manage'), ('access:manage'),
  ('settings:manage'), ('audit:read')
ON CONFLICT (code) DO NOTHING;

-- super_admin gets everything
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.name = 'super_admin'
ON CONFLICT DO NOTHING;

-- client gets ONLY these three read permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON p.code IN ('dashboard:view','subscribers:read','inquiries:read')
WHERE r.name = 'client'
ON CONFLICT DO NOTHING;
