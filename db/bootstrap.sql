-- =============================================================================
-- bootstrap.sql — cluster/database-level setup. Run ONCE per database as a
-- superuser (the migration runner does this automatically and it is idempotent).
--
-- Role model (group roles are NOLOGIN; login roles are created by the runner
-- from the credentials in your connection URLs):
--
--   saas_owner    owns every schema object. Migrations run as this role.
--                 Subject to RLS because every table uses FORCE ROW LEVEL SECURITY.
--   saas_definer  owns the handful of SECURITY DEFINER functions that must see
--                 across tenants (tenant switcher, audit writer, counters).
--                 BYPASSRLS. Never used for a connection.
--   saas_app      what the application connects as. NOBYPASSRLS, not an owner,
--                 so RLS always applies — even if the app has a bug.
--   saas_admin    support tooling / billing jobs / cross-tenant reporting.
--                 BYPASSRLS. Keep these credentials away from the web tier.
-- =============================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saas_owner') THEN
    CREATE ROLE saas_owner NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saas_definer') THEN
    CREATE ROLE saas_definer NOLOGIN BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saas_app') THEN
    CREATE ROLE saas_app NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saas_admin') THEN
    CREATE ROLE saas_admin NOLOGIN BYPASSRLS;
  END IF;
END $$;

-- The owner must be able to hand function ownership to saas_definer.
GRANT saas_definer TO saas_owner;

-- The owner creates the `app` schema.
DO $$ BEGIN
  EXECUTE format('GRANT CREATE, CONNECT ON DATABASE %I TO saas_owner', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO saas_app, saas_admin', current_database());
  EXECUTE format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END $$;

-- Nobody gets to drop objects into `public` by accident.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- btree_gin lets a GIN index lead with tenant_id (see 005_indexes.sql).
CREATE EXTENSION IF NOT EXISTS btree_gin;
