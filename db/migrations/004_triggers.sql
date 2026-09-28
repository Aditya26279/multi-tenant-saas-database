-- =============================================================================
-- 004 — per-tenant numbering, status timestamps, and the audit trail.
-- =============================================================================

-- Per-tenant task numbers (#1, #2, ...). The upsert takes a row lock on the
-- tenant's counter, so concurrent inserts in ONE tenant serialize briefly while
-- other tenants are unaffected. Numbers are gap-free unless a transaction rolls
-- back after taking one — fine for display ids, not for invoices.
--
-- Safe as SECURITY DEFINER: the app cannot supply tenant_id at all (column
-- grants), and even if it could, the INSERT's RLS WITH CHECK (evaluated after
-- BEFORE triggers) would fail and roll the counter bump back with it.
CREATE FUNCTION app.assign_task_number() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
BEGIN
  INSERT INTO app.tenant_counters AS c (tenant_id, scope, value)
  VALUES (NEW.tenant_id, 'task', 1)
  ON CONFLICT (tenant_id, scope) DO UPDATE SET value = c.value + 1
  RETURNING c.value INTO NEW.number;
  RETURN NEW;
END $$;
ALTER FUNCTION app.assign_task_number() OWNER TO saas_definer;
REVOKE EXECUTE ON FUNCTION app.assign_task_number() FROM PUBLIC;

CREATE TRIGGER tasks_assign_number
  BEFORE INSERT ON app.tasks
  FOR EACH ROW EXECUTE FUNCTION app.assign_task_number();

-- Keep completed_at consistent with status.
CREATE FUNCTION app.task_status_timestamps() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = 'done' AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'done') THEN
    NEW.completed_at := now();
  ELSIF NEW.status <> 'done' THEN
    NEW.completed_at := NULL;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER tasks_status_timestamps
  BEFORE INSERT OR UPDATE OF status ON app.tasks
  FOR EACH ROW EXECUTE FUNCTION app.task_status_timestamps();

-- -----------------------------------------------------------------------------
-- Audit trail. Generic row trigger; stores only changed columns on UPDATE.
-- SECURITY DEFINER because the app role cannot INSERT into audit_log — so the
-- app can neither forge nor erase history.
-- -----------------------------------------------------------------------------
CREATE FUNCTION app.audit_row_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
DECLARE
  v_old jsonb;
  v_new jsonb;
  v_row jsonb;
BEGIN
  -- never copy derived data or secrets into the audit trail
  IF TG_OP IN ('UPDATE', 'DELETE') THEN v_old := to_jsonb(OLD) - 'search' - 'token_hash'; END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN v_new := to_jsonb(NEW) - 'search' - 'token_hash'; END IF;
  v_row := coalesce(v_new, v_old);

  IF TG_OP = 'UPDATE' THEN
    SELECT jsonb_object_agg(n.key, n.value) INTO v_new
    FROM jsonb_each(v_new) n
    WHERE n.key <> 'updated_at' AND n.value IS DISTINCT FROM v_old -> n.key;

    IF v_new IS NULL THEN RETURN NULL; END IF;       -- no-op update: nothing to record

    SELECT jsonb_object_agg(o.key, o.value) INTO v_old
    FROM jsonb_each(v_old) o
    WHERE v_new ? o.key;
  END IF;

  INSERT INTO app.audit_log (tenant_id, actor_id, table_name, record_id, action, old_data, new_data)
  VALUES (
    CASE WHEN TG_TABLE_NAME = 'tenants' THEN v_row ->> 'id' ELSE v_row ->> 'tenant_id' END::uuid,
    app.current_user_id(),
    TG_TABLE_NAME,
    coalesce(v_row ->> 'id', v_row ->> 'user_id')::uuid,
    TG_OP,
    v_old,
    v_new
  );
  RETURN NULL;
END $$;
ALTER FUNCTION app.audit_row_change() OWNER TO saas_definer;
REVOKE EXECUTE ON FUNCTION app.audit_row_change() FROM PUBLIC;

-- tenants: UPDATE only (plan/status/settings changes — e.g. SSO enforcement — are security events)
CREATE TRIGGER audit AFTER UPDATE                     ON app.tenants            FOR EACH ROW EXECUTE FUNCTION app.audit_row_change();
CREATE TRIGGER audit AFTER INSERT OR UPDATE OR DELETE ON app.tenant_invitations FOR EACH ROW EXECUTE FUNCTION app.audit_row_change();
CREATE TRIGGER audit AFTER INSERT OR UPDATE OR DELETE ON app.tenant_memberships FOR EACH ROW EXECUTE FUNCTION app.audit_row_change();
CREATE TRIGGER audit AFTER INSERT OR UPDATE OR DELETE ON app.projects           FOR EACH ROW EXECUTE FUNCTION app.audit_row_change();
CREATE TRIGGER audit AFTER INSERT OR UPDATE OR DELETE ON app.tasks              FOR EACH ROW EXECUTE FUNCTION app.audit_row_change();
CREATE TRIGGER audit AFTER INSERT OR UPDATE OR DELETE ON app.task_comments      FOR EACH ROW EXECUTE FUNCTION app.audit_row_change();
