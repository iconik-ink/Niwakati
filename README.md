# Backend: role-based access with paid, time-boxed client review

Stack: Node 20+, Express, PostgreSQL, JWT.

## Setup
1. `cp .env.example .env` and fill it in (generate a real JWT_SECRET)
2. Copy your site into `public/` (index.html, events.html, insights.html, involved.html, assets/)
3. `npm install && npm run db:init && npm run seed:admin && npm start`

## Flow
1. Log in as you:      POST /api/auth/login
2. Client pays in full, then you grant access (7 days by default):
   POST /api/admin/clients      { "email": "...", "paymentReference": "INV-001", "days": 7 }
   (returns a one-time temporary password)
3. Client logs in, must POST /api/auth/change-password, then can use GET /api/dashboard/*
4. Extend:  POST /api/admin/clients/:id/renew   { "days": 7 }
5. Cut off: POST /api/admin/clients/:id/revoke  (instant)
6. After the window, access locks automatically (per-request check + 5-minute cron).

## Route map
| Route                    | super_admin | client | public |
|--------------------------|:-----------:|:------:|:------:|
| /api/public/*            | yes         | yes    | yes    |
| /api/dashboard/* (GET)   | yes         | yes (masked, no export) | no |
| /api/admin/*             | yes         | never  | no     |
