# Multi-tenant SaaS Database (PostgreSQL)

A production-grade PostgreSQL foundation for B2B SaaS: **one database, shared schema, hard tenant isolation enforced by the database itself**. It uses row-level security, tenant-scoped composite keys, and an indexing strategy that was checked against realistic, skewed data.

The domain is a small project tracker (tenants → projects → tasks → comments). The patterns are the point, and they carry over to any B2B product: CRM, helpdesk, invoicing, LMS, and so on.

```
tenants ─┬─< tenant_memberships >── users (global identities; one person, many tenants)
         ├─< tenant_invitations  (the only way in: hashed, email-bound, single-use tokens)
         ├─< projects ─< tasks ─< task_comments
         ├─< tenant_counters     (per-tenant #1, #2, … numbering)
         └─< audit_log           (append-only, written by trigger)
```

## What you get

| Concern | How it's handled |
|---|---|
| **Tenant isolation** | RLS on every tenant table, `FORCE`d so it applies to the table owner too. The app connects as a role that is neither owner nor `BYPASSRLS`. |
| **Fails closed** | If a request never sets tenant context, it sees **0 rows**, and inserts fail with `tenant context not set`. |
| **Forged tenant IDs (IDOR)** | A restrictive policy requires the user to be a *member* of the tenant. Sending someone else's `X-Tenant-Id` returns nothing. |
| **Cross-tenant references** | Composite foreign keys `(tenant_id, x_id)`. The *schema* makes it impossible for a task to point at another tenant's project, even for admin roles. |
| **Connection pooling** | Context is set per transaction (`set_config(..., true)`), so it's safe with PgBouncer transaction mode and can't leak across requests. |
| **In-tenant roles** | owner / admin / member / viewer via per-command restrictive policies (viewers are read-only, only admins delete, authors edit their own comments). |
| **Least privilege** | Column-level grants: users can rename their workspace but can't change `plan` or `status`. System columns (`tenant_id`, `id`, `number`, `created_by`, `created_at`, `completed_at`…) can't be written by the app at all, so they can't be forged. |
| **Joining a tenant** | Only by invitation: a 244-bit token, stored as a SHA-256 hash, tied to the invitee's email, usable once, and expiring after 7 days. Admins can't attach arbitrary users to their tenant. |
| **Suspension** | A suspended tenant is locked out everywhere (reads, writes, search, tenant switcher) until it's reactivated. |
| **Abuse limits** | Size caps on text/jsonb columns; `statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout` on the app role. |
| **Audit trail** | Generic trigger stores actor + changed columns only, and covers tenant setting changes. Token hashes are never copied into it. The app role can't insert, update or delete audit rows. |
| **Onboarding / offboarding** | `app.create_tenant()` for signup, `app.create_invitation()` / `app.accept_invitation()` for invites, `app.my_tenants()` for the tenant switcher, `app.purge_tenant()` for GDPR erasure. |
| **Guards for future migrations** | Tests fail the build if a new table lacks forced RLS, a `SECURITY DEFINER` function lacks a pinned `search_path` or is executable by `PUBLIC`, or a foreign key has no index. New functions default to not executable by `PUBLIC`. |
| **Safe tooling** | The migration runner checksums applied migrations, takes an advisory lock, refuses to `--reset` non-local or production databases, and refuses to manage a superuser as the app login. |
| **Indexing** | `tenant_id`-leading composite indexes, FK-covering indexes, partial indexes for hot subsets, UUIDv7 keys, and BRIN for audit retention. [Benchmarked under RLS.](docs/INDEXING.md) |
| **Search under RLS** | Works around the "non-leakproof operators can't use indexes under RLS" problem with a narrow `SECURITY DEFINER` search function. On the largest tenant it's **8x faster**. |

## Quick start

**No Docker? No Postgres install?** This runs real PostgreSQL binaries from npm:

```bash
npm install
npm run test:embedded     # migrate + seed + 42 isolation/security tests
npm run demo:embedded     # request-lifecycle walkthrough
npm run bench:embedded    # 300k tasks / 500 tenants, EXPLAIN under RLS
```

**With Docker:**

```bash
docker compose up -d
npm install
npm test                  # migrates, seeds, runs tests against localhost:5432
npm run demo
npm run bench -- --verbose
```

To use your own server, set `MIGRATION_DATABASE_URL`, `APP_DATABASE_URL` and `ADMIN_DATABASE_URL` (see [.env.example](.env.example); a `.env` file is loaded automatically). The runner creates the login roles from those URLs. `--reset` (used by `npm test`) only runs against local databases unless you set `ALLOW_DESTRUCTIVE_DB=1`. The embedded runner always ignores `.env`, so `npm run test:embedded` can never touch a real database. Requires **PostgreSQL 15+** and Node 22+.

## Using it from an app

Every request runs inside `withTenant()` ([src/db.mjs](src/db.mjs)). Queries never mention `tenant_id`:

```js
import { createAppPool, withTenant } from './src/db.mjs';
const pool = createAppPool();

app.get('/tasks', async (req, res) => {
  // tenantId/userId come from your verified session, not a raw header
  const tasks = await withTenant(pool, { tenantId: req.session.tenantId, userId: req.session.userId },
    (db) => db.query("SELECT * FROM app.tasks WHERE status = 'todo' ORDER BY id DESC LIMIT 50"));
  res.json(tasks.rows);
});
```

Under the hood that's:

```sql
BEGIN;
SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true);
-- ... your queries; RLS scopes all of them ...
COMMIT;   -- context disappears here
```

## Project layout

```
db/
  bootstrap.sql            roles + extensions (idempotent, superuser)
  migrations/
    001_foundation.sql     schema, UUIDv7, tenant context functions
    002_tables.sql         tables, composite PKs/FKs, invitations
    003_security.sql       grants, SECURITY DEFINER helpers, RLS policies
    004_triggers.sql       per-tenant numbering, audit trail
    005_indexes.sql        indexing strategy
    006_search.sql         index-friendly full-text search under RLS
  seed.sql                 two demo tenants, five users
src/db.mjs                 withTenant() / withUser() — the only way the app touches data
test/                      42 tests: isolation, roles, invitations, audit, search,
                           offboarding, schema invariants (regressions.test.mjs)
scripts/                   migration runner, embedded Postgres, benchmark
docs/
  ARCHITECTURE.md          tenancy models, role model, threat model, operations
  INDEXING.md              index-by-index rationale + benchmark results
```

## Read next

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): why a shared schema, what each role can do, the threats this design covers (and the ones it doesn't), and how to scale it.
- [docs/INDEXING.md](docs/INDEXING.md): the indexing rules, the RLS/leakproof gotcha, and measured query plans.
