# Indexing strategy

## The rules

1. **`tenant_id` leads every index on a tenant table.** RLS adds `tenant_id = <const>` to every query. With `tenant_id` first, that becomes a range scan over only this tenant's slice, and the rest of the index key (status, project, date…) narrows it further. An index on `(status)` alone would span every tenant.

2. **Primary keys are `(tenant_id, id)`, not `(id)`.** One index serves both point lookups and tenant-wide scans. It also doubles as the FK target for composite foreign keys.

3. **Ids are UUIDv7 (time-ordered).** Inserts go to the right edge of the B-tree rather than random pages, which gives less page splitting, a smaller working set, and better cache hit rates. `ORDER BY id DESC` also means "newest first", so keyset pagination runs off the PK with no extra `created_at` index:
   ```sql
   SELECT … FROM app.tasks WHERE id < $cursor ORDER BY id DESC LIMIT 50;
   ```

4. **Every foreign key gets an index** (a test enforces this for future migrations). Postgres indexes the *referenced* side, not the *referencing* side. Without an index on `tasks (tenant_id, project_id)`, deleting a project seq-scans `tasks` while holding locks. The same goes for `assignee_id`, `created_by`, `author_id` and the rest. Partial `WHERE x IS NOT NULL` versions are enough, because FK lookups always use a concrete value.

5. **Partial indexes for the hot subset.** In a mature tenant, about 75% of tasks are done or cancelled. `tasks_assignee_open_idx` and `tasks_due_open_idx` index only open tasks, so they're roughly 4x smaller and stay in memory.

6. **Equality columns first, then the sort column.** `(tenant_id, project_id, status, priority)` lets `WHERE project_id=? AND status=? ORDER BY priority LIMIT 100` stop after 100 index entries instead of sorting the whole column.

7. **BRIN for append-only time data.** `audit_log (occurred_at)` BRIN is a few KB and serves cross-tenant retention purges. Per-tenant feeds use the B-tree `(tenant_id, occurred_at DESC)`.

8. **`btree_gin` to put `tenant_id` inside GIN.** `GIN (tenant_id, search)` answers "this tenant AND this text" in a single index scan (see the gotcha below).

## Index inventory

| Index | Serves |
|---|---|
| `tasks_pkey (tenant_id, id)` | point lookup, newest-first pagination |
| `tasks_tenant_id_number_key (tenant_id, number)` | `#1234` lookups, uniqueness |
| `tasks_project_status_idx (tenant_id, project_id, status, priority)` | kanban board, FK from projects |
| `tasks_assignee_open_idx (tenant_id, assignee_id, priority, due_date) WHERE open` | "my tasks" |
| `tasks_due_open_idx (tenant_id, due_date) WHERE open AND due_date IS NOT NULL` | overdue dashboards (index-only) |
| `tasks_assignee_fk_idx`, `tasks_created_by_fk_idx` | membership removal (FK) |
| `tasks_search_idx GIN (tenant_id, search)` | full-text search |
| `task_comments_task_idx (tenant_id, task_id, created_at)` | comment thread, FK from tasks |
| `projects_active_name_key UNIQUE (tenant_id, lower(name)) WHERE archived_at IS NULL` | case-insensitive unique names among active projects |
| `tenant_memberships_user_idx (user_id)` | tenant switcher (before a tenant is chosen) |
| `tenant_invitations_pending_key UNIQUE (tenant_id, lower(email)) WHERE accepted_at IS NULL` | one pending invite per address |
| `tenant_invitations_token_hash_key UNIQUE (token_hash)` | redeeming an invitation |
| `users_email_key UNIQUE (lower(email))` | login |
| `audit_log_tenant_time_idx`, `audit_log_record_idx` | activity feed, record history |
| `audit_log_occurred_brin BRIN (occurred_at)` | retention purge |

## The RLS gotcha: leakproof operators

Under RLS, Postgres uses a condition from **your** `WHERE` clause as an index condition only if its operator function is marked `LEAKPROOF`. Otherwise that function could leak another tenant's values (through an error message, say) before the policy has filtered the row out.

| Operator | Function | Leakproof | Under RLS |
|---|---|---|---|
| `=` on uuid/text/int, `<` on date | `uuid_eq`, `texteq`, `date_lt`… | ✅ | index condition |
| `@@` full-text | `ts_match_vq` | ❌ | **filter after fetching every tenant row** |
| `LIKE` / `ILIKE`, pg_trgm `%` | `textlike`… | ❌ | same |
| most `jsonb` operators (`@>`, `?`) | | ❌ | same |

Check any operator's function yourself: `SELECT proname, proleakproof FROM pg_proc WHERE proname = '…'`.

Small tenants never notice. Your largest customer, the one paying the most, gets a query that grows linearly with their data.

**Fix used here:** [`app.search_tasks()`](../db/migrations/006_search.sql). It is a small `SECURITY DEFINER` function whose owner bypasses RLS, and it applies `tenant_id = current_tenant_id()` and the membership check itself, so both predicates become GIN index conditions. Alternatives:

- `ALTER FUNCTION … LEAKPROOF` (needs a superuser, and you are vouching for that C function);
- denormalized search tables;
- an external search engine with per-tenant filters.

## Benchmark

`npm run bench:embedded`: 300,000 tasks across 500 tenants. One "whale" tenant holds about 20% of rows, and 75% of tasks are closed. Every query runs **as `app_user` with RLS active**. Numbers are from a laptop, PostgreSQL 18, warm cache.

**Whale tenant (~60,000 tasks)**

| Query | Time | Buffers | Plan |
|---|---:|---:|---|
| Board: project column (`ORDER BY priority LIMIT 100`) | 2.5 ms | 176 | Index Scan `tasks_project_status_idx` |
| My open tasks | 0.65 ms | 56 | Index Scan `tasks_assignee_open_idx` (partial) |
| Overdue dashboard (count) | 0.58 ms | 10 | **Index Only Scan** `tasks_due_open_idx` (partial) |
| Newest first, keyset page | 0.19 ms | 34 | Index Scan `tasks_pkey` (UUIDv7) |
| Lookup by `#number` | 0.13 ms | 10 | Index Scan `tasks_tenant_id_number_key` |
| Full-text, raw `@@` under RLS | **39 ms** | 2,615 | GIN on tenant_id only → rechecks all 60k rows |
| Full-text via `app.search_tasks()` | **4.9 ms** | 1,182 | GIN on (tenant_id **and** search) |
| Audit feed | 0.21 ms | 56 | Index Scan `audit_log_tenant_time_idx` |

**Typical tenant (~500 tasks):** every query is under 0.5 ms.

The benchmark also caught a design problem. The first version of the board index was `(tenant_id, project_id, status)`, without `priority`. On the whale tenant that query read **1,428 buffers** to sort the whole column. Adding the sort column cut it to **176**. Run the benchmark against a skewed data set before you ship an index.

Run `npm run bench -- --verbose` for the full `EXPLAIN (ANALYZE, BUFFERS)` of every query.
