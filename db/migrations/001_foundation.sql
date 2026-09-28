-- =============================================================================
-- 001 — schema, ID generation, and the tenant/user request context.
-- Runs as saas_owner (the runner does SET LOCAL ROLE saas_owner).
-- =============================================================================

CREATE SCHEMA app;
REVOKE ALL ON SCHEMA app FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO saas_app, saas_admin;
-- CREATE is required so functions can be re-owned by saas_definer.
GRANT USAGE, CREATE ON SCHEMA app TO saas_definer;

-- Secure defaults for everything created from here on (including future
-- migrations): functions are NOT executable by PUBLIC unless granted — so a
-- forgotten REVOKE on a new SECURITY DEFINER function fails closed — and the
-- admin role automatically gets access to new tables.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT ALL ON TABLES    TO saas_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT ALL ON SEQUENCES TO saas_admin;

-- -----------------------------------------------------------------------------
-- UUIDv7: time-ordered UUIDs. New rows land at the right-hand edge of every
-- (tenant_id, id) B-tree instead of random pages, which keeps indexes compact,
-- hot pages in cache, and lets "ORDER BY id DESC" double as "newest first".
-- (PostgreSQL 18 ships a native uuidv7(); this works on 15+.)
-- -----------------------------------------------------------------------------
CREATE FUNCTION app.uuid_v7() RETURNS uuid
LANGUAGE sql VOLATILE PARALLEL SAFE AS $$
  SELECT encode(
    set_bit(set_bit(
      overlay(uuid_send(gen_random_uuid())
              PLACING substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
              FROM 1 FOR 6),
    52, 1), 53, 1),
  'hex')::uuid
$$;

-- -----------------------------------------------------------------------------
-- Request context.
--
-- The application sets these per TRANSACTION (set_config(..., true) / SET LOCAL)
-- right after BEGIN. Transaction scope is what makes this safe behind PgBouncer
-- in transaction-pooling mode: the value can never leak to the next borrower of
-- the connection.
--
-- Unset => NULL => every tenant policy evaluates to NULL => zero rows.
-- The system fails CLOSED.
-- -----------------------------------------------------------------------------
CREATE FUNCTION app.current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

CREATE FUNCTION app.current_user_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;

-- Used as the DEFAULT for every tenant_id column: callers never pass tenant_id,
-- and an INSERT without context fails loudly instead of writing an orphan row.
CREATE FUNCTION app.require_tenant_id() RETURNS uuid
LANGUAGE plpgsql STABLE AS $$
DECLARE
  v uuid := app.current_tenant_id();
BEGIN
  IF v IS NULL THEN
    RAISE EXCEPTION 'tenant context not set (app.tenant_id)'
      USING ERRCODE = 'insufficient_privilege',
            HINT = 'Call set_config(''app.tenant_id'', <uuid>, true) inside the transaction.';
  END IF;
  RETURN v;
END $$;

CREATE FUNCTION app.set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- Used in column DEFAULTs and policies, so every role that writes or reads
-- tenant data needs them.
GRANT EXECUTE ON FUNCTION app.uuid_v7(), app.current_tenant_id(), app.current_user_id(), app.require_tenant_id()
  TO saas_app, saas_admin, saas_definer;
