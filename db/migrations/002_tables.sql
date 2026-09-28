-- =============================================================================
-- 002 — tables.
--
-- Tenancy model: shared database, shared schema, tenant_id on every
-- tenant-owned row ("pool" model). Rules applied everywhere:
--
--   1. tenant_id is the FIRST column of every primary key: PK (tenant_id, id).
--      RLS adds "tenant_id = ?" to every query, so the PK index serves both
--      point lookups and tenant-wide scans, and the layout is ready for
--      Citus-style sharding by tenant_id later.
--
--   2. Foreign keys between tenant tables are COMPOSITE and include tenant_id:
--      FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
--      A task can therefore never point at another tenant's project — enforced
--      by the database, independent of RLS and of application code.
--
--   3. tenant_id defaults to app.require_tenant_id(): the app never sends it.
-- =============================================================================

-- ---------------------------------------------------------------- tenants ---
CREATE TABLE app.tenants (
  id          uuid        PRIMARY KEY DEFAULT app.uuid_v7(),
  slug        text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  plan        text        NOT NULL DEFAULT 'free'   CHECK (plan IN ('free', 'pro', 'enterprise')),
  status      text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  settings    jsonb       NOT NULL DEFAULT '{}'::jsonb
                          CHECK (octet_length(settings::text) <= 65536),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------------ users ---
-- Global identities: one person can belong to many tenants.
CREATE TABLE app.users (
  id            uuid        PRIMARY KEY DEFAULT app.uuid_v7(),
  email         text        NOT NULL CHECK (email ~ '^[^@\s]+@[^@\s]+$'),
  display_name  text        NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------- tenant_memberships ---
CREATE TABLE app.tenant_memberships (
  tenant_id   uuid        NOT NULL DEFAULT app.require_tenant_id()
                          REFERENCES app.tenants (id) ON DELETE CASCADE,
  user_id     uuid        NOT NULL REFERENCES app.users (id) ON DELETE CASCADE,
  role        text        NOT NULL DEFAULT 'member'
                          CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

-- --------------------------------------------------------------- projects ---
CREATE TABLE app.projects (
  tenant_id    uuid        NOT NULL DEFAULT app.require_tenant_id()
                           REFERENCES app.tenants (id) ON DELETE CASCADE,
  id           uuid        NOT NULL DEFAULT app.uuid_v7(),
  key          text        NOT NULL CHECK (key ~ '^[A-Z][A-Z0-9]{1,9}$'),
  name         text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description  text        CHECK (length(description) <= 20000),
  created_by   uuid        DEFAULT app.current_user_id(),
  archived_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, key),
  -- creator must be a member of the SAME tenant; if they leave, keep the row.
  FOREIGN KEY (tenant_id, created_by)
    REFERENCES app.tenant_memberships (tenant_id, user_id) ON DELETE SET NULL (created_by)
);

-- ------------------------------------------------------------------ tasks ---
CREATE TABLE app.tasks (
  tenant_id     uuid        NOT NULL DEFAULT app.require_tenant_id(),
  id            uuid        NOT NULL DEFAULT app.uuid_v7(),
  project_id    uuid        NOT NULL,
  number        bigint      NOT NULL,          -- per-tenant, human friendly (#42); set by trigger
  title         text        NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  description   text        CHECK (length(description) <= 100000),  -- bounds the generated tsvector (1 MB hard limit)
  status        text        NOT NULL DEFAULT 'todo'
                            CHECK (status IN ('todo', 'in_progress', 'done', 'cancelled')),
  priority      smallint    NOT NULL DEFAULT 2 CHECK (priority BETWEEN 0 AND 4),
  assignee_id   uuid,
  due_date      date,
  completed_at  timestamptz,
  created_by    uuid        DEFAULT app.current_user_id(),
  search        tsvector    GENERATED ALWAYS AS (
                  setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
                  setweight(to_tsvector('simple', coalesce(description, '')), 'B')
                ) STORED,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, project_id)
    REFERENCES app.projects (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, assignee_id)
    REFERENCES app.tenant_memberships (tenant_id, user_id) ON DELETE SET NULL (assignee_id),
  FOREIGN KEY (tenant_id, created_by)
    REFERENCES app.tenant_memberships (tenant_id, user_id) ON DELETE SET NULL (created_by)
) WITH (fillfactor = 90);  -- headroom for HOT updates: tasks change status often

-- ----------------------------------------------------- tenant_invitations ---
-- The ONLY way a user joins an existing tenant. Admins cannot insert
-- memberships directly: that would let them attach any user to their tenant
-- without consent (and then read that user's email). Only the SHA-256 of the
-- token is stored; the plaintext goes out by email once.
CREATE TABLE app.tenant_invitations (
  tenant_id    uuid        NOT NULL DEFAULT app.require_tenant_id()
                           REFERENCES app.tenants (id) ON DELETE CASCADE,
  id           uuid        NOT NULL DEFAULT app.uuid_v7(),
  email        text        NOT NULL CHECK (email ~ '^[^@\s]+@[^@\s]+$'),
  role         text        NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member', 'viewer')),
  token_hash   bytea       NOT NULL UNIQUE,
  invited_by   uuid        DEFAULT app.current_user_id(),
  expires_at   timestamptz NOT NULL DEFAULT now() + interval '7 days',
  accepted_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, invited_by)
    REFERENCES app.tenant_memberships (tenant_id, user_id) ON DELETE SET NULL (invited_by)
);

-- ---------------------------------------------------------- task_comments ---
CREATE TABLE app.task_comments (
  tenant_id   uuid        NOT NULL DEFAULT app.require_tenant_id(),
  id          uuid        NOT NULL DEFAULT app.uuid_v7(),
  task_id     uuid        NOT NULL,
  author_id   uuid        DEFAULT app.current_user_id(),
  body        text        NOT NULL CHECK (length(body) BETWEEN 1 AND 10000),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, task_id)
    REFERENCES app.tasks (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, author_id)
    REFERENCES app.tenant_memberships (tenant_id, user_id) ON DELETE SET NULL (author_id)
);

-- -------------------------------------------------------- tenant_counters ---
-- Per-tenant gapless-ish sequences (task #1, #2, ... per tenant). Only touched
-- by a SECURITY DEFINER trigger; the app role has no privileges on it.
CREATE TABLE app.tenant_counters (
  tenant_id  uuid   NOT NULL REFERENCES app.tenants (id) ON DELETE CASCADE,
  scope      text   NOT NULL,
  value      bigint NOT NULL,
  PRIMARY KEY (tenant_id, scope)
);

-- -------------------------------------------------------------- audit_log ---
-- Append-only. Written only by a SECURITY DEFINER trigger. Deliberately no FK
-- to tenants: rows are written while a tenant is being cascade-deleted, and
-- app.purge_tenant() removes them explicitly afterwards.
CREATE TABLE app.audit_log (
  tenant_id    uuid        NOT NULL,
  id           bigint      GENERATED ALWAYS AS IDENTITY,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  actor_id     uuid,
  table_name   text        NOT NULL,
  record_id    uuid,
  action       text        NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
  old_data     jsonb,
  new_data     jsonb,
  PRIMARY KEY (tenant_id, id)
) WITH (autovacuum_vacuum_insert_scale_factor = 0.05);  -- append-only: keep visibility map fresh

-- ------------------------------------------------------ updated_at triggers ---
CREATE TRIGGER tenants_updated_at       BEFORE UPDATE ON app.tenants       FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER users_updated_at         BEFORE UPDATE ON app.users         FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER projects_updated_at      BEFORE UPDATE ON app.projects      FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER tasks_updated_at         BEFORE UPDATE ON app.tasks         FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER task_comments_updated_at BEFORE UPDATE ON app.task_comments FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
