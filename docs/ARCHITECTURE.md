# Architecture

## 1. Choosing a tenancy model

| Model | Isolation | Cost per tenant | Migrations | Cross-tenant analytics | Fits |
|---|---|---|---|---|---|
| **Database per tenant** | Strongest (separate DBs) | High: connections, backups, monitoring × N | Run N times, and they drift | Hard | A few large, regulated customers |
| **Schema per tenant** | Strong (`search_path`) | Medium. The catalog bloats past a few thousand schemas | Run N times | Painful (`UNION ALL` over N schemas) | Hundreds of mid-size tenants |
| **Shared schema + `tenant_id` + RLS** *(this repo)* | Strong, **if enforced by the DB** | Near zero | Once | Trivial | Thousands to millions of tenants, the typical B2B SaaS |

The shared-schema model has one well-known risk: a single missing `WHERE tenant_id = ?` leaks data. This design takes that risk away from application code. The database adds the predicate to every query, and a query that "forgets" gets zero rows instead of every tenant's rows.

**Hybrid path.** If an enterprise customer later demands physical isolation, the same schema can run in a dedicated database for them (a "silo"), because nothing in it assumes a single deployment. Because `tenant_id` leads every PK and FK, the schema is also ready for Citus distribution by `tenant_id` with no key changes.

## 2. Roles

```
            ┌──────────────┐  owns all objects; subject to RLS (FORCE)
            │  saas_owner  │  used only by migrations
            └──────┬───────┘
                   │ can hand ownership to
            ┌──────▼───────┐  BYPASSRLS, NOLOGIN; owns the few SECURITY DEFINER
            │ saas_definer │  functions: my_tenants, create_tenant, current_member_role,
            └──────────────┘  create/accept_invitation, search_tasks, audit + numbering triggers

 app_user ──► saas_app      NOBYPASSRLS, not owner → RLS always applies. The web tier.
 admin_user ► saas_admin    BYPASSRLS → support tools, billing jobs, reporting. Not the web tier.
```

Why `FORCE ROW LEVEL SECURITY`? By default a table's owner skips RLS. Without `FORCE`, someone who "temporarily" points the app at the owner credentials turns isolation off without anyone noticing. With it, even the owner sees nothing without context.

## 3. Request lifecycle

1. **Authenticate** the user (session/JWT) → `user_id`.
2. **Tenant switcher**: `SELECT * FROM app.my_tenants()` (user context only). This SECURITY DEFINER function returns only the caller's own memberships.
3. **Select a tenant** (subdomain, path, or picker) → `tenant_id`, stored in the server-side session.
4. **Joining another tenant**: an admin calls `app.create_invitation(email, role)` and emails the returned token. The invitee signs in and calls `app.accept_invitation(token)`, which succeeds only for that email, only once, and only before it expires. Admins cannot insert memberships directly.
5. **Each request**: `BEGIN` → `set_config('app.tenant_id', …, true)` + `set_config('app.user_id', …, true)` → queries → `COMMIT`.

Even if step 3 is compromised (e.g. the tenant id is read from a client header), the `member_only` restrictive policy checks the user's membership in that tenant *inside the database*.

## 4. Policy design

Each tenant table has:

- a **permissive** `tenant_isolation` policy: `tenant_id = app.current_tenant_id()`, used for both `USING` and `WITH CHECK`. It is a plain equality on the leading index column, so it becomes an index condition.
- a **restrictive** `member_only` policy: `(SELECT app.current_member_role()) IS NOT NULL`. Wrapping it in `(SELECT …)` makes it an InitPlan, run **once per statement** instead of once per row.
- **restrictive per-command** role rules (e.g. `FOR DELETE … IN ('owner','admin')`).

Restrictive policies are AND-ed with the permissive ones. Adding a rule therefore can only narrow access, never widen it by accident.

`current_member_role()` must be `SECURITY DEFINER` (owned by a `BYPASSRLS` role). Otherwise the policy on `tenant_memberships` would call a function that queries `tenant_memberships`, which would apply the same policy again and recurse forever.

## 5. Threat model

| Threat | Mitigation | Test |
|---|---|---|
| Handler forgets tenant filter | RLS adds it; no context → 0 rows | `fails closed` |
| Client sends another tenant's id | Membership re-checked in DB | `forged tenant header` |
| ID guessing / IDOR on UPDATE/DELETE | RLS `USING` → 0 rows affected | `guessing another tenant's id` |
| Writing into / moving rows to another tenant | `tenant_id` not writable (column grants), plus RLS `WITH CHECK` | `cannot insert a row into another tenant`, `cannot move…` |
| Linking to another tenant's rows | Composite FKs | `composite FK …` |
| Context leaks across pooled connections | Transaction-local `set_config` | `context is transaction-scoped` |
| App tries to disable RLS / escalate | Not owner; can't `SET ROLE`; `row_security=off` errors | `the app role cannot switch RLS off` |
| Privilege escalation inside a tenant | Restrictive role policies + column grants | `viewer…`, `column privileges…` |
| Tampering with history | Audit written only by a definer trigger; app has SELECT only (admins) | `audit log …` |
| Forging system columns (`number`, `created_by`, `created_at`, `completed_at`) | Column-level INSERT/UPDATE grants exclude them | `members cannot forge system columns` |
| Admin pulls a stranger into their tenant to read their email | No INSERT on memberships; email-bound, single-use, hashed invitation tokens | `admins cannot pull arbitrary users…`, `invitations …` |
| Suspended customer keeps using the product | `current_member_role()` requires `status = 'active'` | `suspended tenants are locked out` |
| Oversized payloads (tsvector 1 MB limit, jsonb bloat) | CHECK constraints on text/jsonb sizes | `oversized payloads are rejected` |
| Runaway / abandoned transactions holding locks | `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` on the app login | `app role has … timeouts` |
| A future migration forgets RLS / `REVOKE` / `search_path` | Secure default privileges + invariant tests | `invariant: …` |

**Not covered here, and still your job:**

- verifying the session → `tenant_id` mapping in the app
- rate limiting and noisy-neighbour quotas
- encryption at rest and backups
- per-tenant secrets

Treat every `SECURITY DEFINER` function as security-critical code: inside it, its `WHERE` clause *is* the isolation boundary.

## 6. Operations

- **Migrations** run as `saas_owner`, one transaction per file, under an advisory lock (two deploys can't race). Applied files are checksummed, so editing one is an error: add a new migration instead. `--reset` refuses non-local hosts and `NODE_ENV=production`. For big tables in production, put `CREATE INDEX CONCURRENTLY` in its own non-transactional migration.
- **Backfills** need to see all tenants: run them as `saas_admin` (the owner is subject to RLS).
- **Per-tenant export**: as `saas_admin`, `COPY (SELECT … WHERE tenant_id = $1) TO …` for each table.
- **Tenant deletion**: `SELECT app.purge_tenant($1)` cascades through every table, then removes the tenant's audit rows.
- **Audit retention**: `DELETE FROM app.audit_log WHERE occurred_at < now() - interval '13 months'` uses the BRIN index. At very high volume, switch to monthly range partitions and `DROP PARTITION`.
- **Noisy neighbours**: watch `pg_stat_statements` for queries against the largest tenants. The whale tenant is where a missing index shows up first (see INDEXING.md).
- **Scaling path**: read replicas → partition the largest tables by `hash(tenant_id)` → Citus with `tenant_id` as the distribution column. The keys are already shaped for it.
