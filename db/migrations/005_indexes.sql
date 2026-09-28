-- =============================================================================
-- 005 — indexing strategy. See docs/INDEXING.md for the reasoning.
--
-- Rules:
--   * tenant_id leads every tenant-table index. RLS injects
--     "tenant_id = <const>" into every query; a leading tenant_id turns that
--     into an index range scan over just that tenant's slice.
--   * Every composite FK gets a matching index (Postgres does not create them).
--     Without one, deleting a project or removing a member seq-scans the child
--     table while holding locks.
--   * Partial indexes for the hot subset (open tasks, active projects).
--   * UUIDv7 primary keys: (tenant_id, id) is already "newest-first" order, so
--     keyset pagination needs no extra created_at index.
--
-- Already created by constraints in 002:
--   tenants(id), tenants(slug), users(id), tenant_memberships(tenant_id, user_id),
--   projects(tenant_id, id), projects(tenant_id, key), tasks(tenant_id, id),
--   tasks(tenant_id, number), task_comments(tenant_id, id),
--   tenant_counters(tenant_id, scope), audit_log(tenant_id, id)
--
-- On a live database, create each of these with CREATE INDEX CONCURRENTLY in
-- its own non-transactional migration.
-- =============================================================================

-- users: case-insensitive unique email (login lookup)
CREATE UNIQUE INDEX users_email_key ON app.users (lower(email));

-- memberships: "which tenants is this user in?" (my_tenants, login)
-- and FK support for users -> memberships cascade.
CREATE INDEX tenant_memberships_user_idx ON app.tenant_memberships (user_id);

-- projects: active projects by name (unique among non-archived only),
-- and FK support for created_by.
CREATE UNIQUE INDEX projects_active_name_key
  ON app.projects (tenant_id, lower(name)) WHERE archived_at IS NULL;
CREATE INDEX projects_created_by_idx
  ON app.projects (tenant_id, created_by) WHERE created_by IS NOT NULL;

-- tasks: board view  (WHERE project_id = ? AND status = ? ORDER BY priority LIMIT n)
--        Equality columns first, then the sort column, so the LIMIT stops
--        after n index entries instead of sorting the whole column.
--        Also the FK support index for projects -> tasks cascade.
CREATE INDEX tasks_project_status_idx
  ON app.tasks (tenant_id, project_id, status, priority);

-- tasks: "my open work" — partial: done/cancelled tasks (the bulk of a mature
-- tenant's history) are not in the index at all.
CREATE INDEX tasks_assignee_open_idx
  ON app.tasks (tenant_id, assignee_id, priority, due_date)
  WHERE status IN ('todo', 'in_progress');

-- tasks: overdue / due-soon dashboards.
CREATE INDEX tasks_due_open_idx
  ON app.tasks (tenant_id, due_date)
  WHERE status IN ('todo', 'in_progress') AND due_date IS NOT NULL;

-- tasks: FK support for assignee/creator removal (partial: most are NULL-free
-- lookups by an exact user id, which implies IS NOT NULL).
CREATE INDEX tasks_assignee_fk_idx
  ON app.tasks (tenant_id, assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX tasks_created_by_fk_idx
  ON app.tasks (tenant_id, created_by) WHERE created_by IS NOT NULL;

-- tasks: full-text search. btree_gin lets tenant_id live INSIDE the GIN index,
-- so one index scan can satisfy both the tenant predicate and the text match.
-- Under RLS that only happens via app.search_tasks() — see 006_search.sql.
CREATE INDEX tasks_search_idx
  ON app.tasks USING gin (tenant_id, search);

-- invitations: one pending invite per address (re-invite replaces it), and
-- FK support for invited_by.
CREATE UNIQUE INDEX tenant_invitations_pending_key
  ON app.tenant_invitations (tenant_id, lower(email)) WHERE accepted_at IS NULL;
CREATE INDEX tenant_invitations_invited_by_fk_idx
  ON app.tenant_invitations (tenant_id, invited_by) WHERE invited_by IS NOT NULL;

-- comments: thread for a task in order + FK support for tasks -> comments.
CREATE INDEX task_comments_task_idx
  ON app.task_comments (tenant_id, task_id, created_at);
CREATE INDEX task_comments_author_fk_idx
  ON app.task_comments (tenant_id, author_id) WHERE author_id IS NOT NULL;

-- audit_log: per-tenant activity feed, and history of one record.
CREATE INDEX audit_log_tenant_time_idx
  ON app.audit_log (tenant_id, occurred_at DESC);
CREATE INDEX audit_log_record_idx
  ON app.audit_log (tenant_id, table_name, record_id, occurred_at DESC);
-- retention purges across ALL tenants ("older than 13 months"): BRIN is ~1000x
-- smaller than a B-tree and ideal for append-only, time-correlated data.
CREATE INDEX audit_log_occurred_brin
  ON app.audit_log USING brin (occurred_at);
