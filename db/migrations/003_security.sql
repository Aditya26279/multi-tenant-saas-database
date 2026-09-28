-- =============================================================================
-- 003 — privileges, SECURITY DEFINER helpers, and row-level security.
--
-- Two layers of policy on every tenant table:
--
--   PERMISSIVE  tenant_isolation   tenant_id = app.current_tenant_id()
--               The index-friendly filter. Also the WITH CHECK that stops rows
--               being written to (or moved into) another tenant.
--
--   RESTRICTIVE member_only        the current user must be a member of the
--               current (active) tenant. A forged/stale tenant id (the classic
--               IDOR: "X-Tenant-Id: <someone else>") returns nothing.
--
--   RESTRICTIVE per-command role rules (viewers read-only, only admins delete…)
--
-- Row-independent calls are wrapped in (SELECT ...) so the planner runs them
-- once per statement as an InitPlan, not once per row.
-- =============================================================================

-- ------------------------------------------------------------- privileges ---
-- Least privilege. Column lists matter: system-managed columns (tenant_id, id,
-- number, created_by, author_id, created_at, completed_at, ...) are NOT
-- writable by the app, so they are always filled from defaults/triggers and
-- cannot be forged or rewritten.
GRANT SELECT                          ON app.tenants            TO saas_app;
GRANT UPDATE (name, settings)         ON app.tenants            TO saas_app;
GRANT SELECT                          ON app.users              TO saas_app;
GRANT UPDATE (display_name)           ON app.users              TO saas_app;
GRANT SELECT, DELETE                  ON app.tenant_memberships TO saas_app;  -- joining is via invitations only
GRANT UPDATE (role)                   ON app.tenant_memberships TO saas_app;
GRANT SELECT (tenant_id, id, email, role, invited_by, expires_at, accepted_at, created_at), DELETE
                                      ON app.tenant_invitations TO saas_app;  -- never token_hash
GRANT SELECT, DELETE                  ON app.projects, app.tasks, app.task_comments TO saas_app;
GRANT INSERT (key, name, description),
      UPDATE (key, name, description, archived_at)            ON app.projects      TO saas_app;
GRANT INSERT (project_id, title, description, status, priority, assignee_id, due_date),
      UPDATE (project_id, title, description, status, priority, assignee_id, due_date)
                                                                ON app.tasks         TO saas_app;
GRANT INSERT (task_id, body), UPDATE (body)                    ON app.task_comments TO saas_app;
GRANT SELECT                          ON app.audit_log          TO saas_app;
-- no grants at all on app.tenant_counters
-- saas_admin gets ALL on every table via ALTER DEFAULT PRIVILEGES (001).

-- saas_definer owns the privileged functions below and needs these to run them.
GRANT SELECT, INSERT                 ON app.tenants            TO saas_definer;
GRANT SELECT                         ON app.users              TO saas_definer;
GRANT SELECT, INSERT                 ON app.tenant_memberships TO saas_definer;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.tenant_invitations TO saas_definer;
GRANT SELECT, INSERT, UPDATE         ON app.tenant_counters    TO saas_definer;
GRANT INSERT                         ON app.audit_log          TO saas_definer;

-- ------------------------------------------------ SECURITY DEFINER helpers ---
-- Rules for every definer function (enforced by a test):
--   * owned by saas_definer (BYPASSRLS), so inside it the WHERE clause IS the
--     tenant boundary — keep them tiny and reviewed;
--   * search_path pinned, with pg_temp LAST so temp objects can't shadow ours;
--   * not executable by PUBLIC; granted explicitly.

-- Role of the current user in the current tenant; NULL if not a member or if
-- the tenant is suspended. Must bypass RLS: it is called from policies on
-- tenant_memberships itself, which would otherwise recurse.
CREATE FUNCTION app.current_member_role() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
  SELECT m.role
  FROM app.tenant_memberships m
  JOIN app.tenants t ON t.id = m.tenant_id
  WHERE m.tenant_id = app.current_tenant_id()
    AND m.user_id   = app.current_user_id()
    AND t.status    = 'active'
$$;

-- Tenant switcher: which tenants can the signed-in user open? Runs before any
-- tenant is selected, so it has to look across tenants — but only ever returns
-- the caller's own memberships.
CREATE FUNCTION app.my_tenants()
RETURNS TABLE (tenant_id uuid, slug text, name text, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
  SELECT t.id, t.slug, t.name, m.role
  FROM app.tenant_memberships m
  JOIN app.tenants t ON t.id = m.tenant_id
  WHERE m.user_id = app.current_user_id()
    AND t.status = 'active'
  ORDER BY t.name
$$;

-- Self-serve signup: creates a tenant and makes the current user its owner.
CREATE FUNCTION app.create_tenant(p_slug text, p_name text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
DECLARE
  v_user   uuid := app.current_user_id();
  v_tenant uuid;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'user context not set (app.user_id)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO app.tenants (slug, name) VALUES (p_slug, p_name) RETURNING id INTO v_tenant;
  INSERT INTO app.tenant_memberships (tenant_id, user_id, role) VALUES (v_tenant, v_user, 'owner');
  RETURN v_tenant;
END $$;

-- Invite someone by email. Returns the plaintext token ONCE (email it; don't
-- log it). 2 x 122 random bits from gen_random_uuid() (pg_strong_random).
-- Re-inviting the same address replaces the pending invitation.
CREATE FUNCTION app.create_invitation(p_email text, p_role text DEFAULT 'member') RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
DECLARE
  v_token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
BEGIN
  IF app.current_member_role() IS NULL OR app.current_member_role() NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION 'only tenant owners and admins can invite' USING ERRCODE = 'insufficient_privilege';
  END IF;
  DELETE FROM app.tenant_invitations
  WHERE tenant_id = app.current_tenant_id() AND lower(email) = lower(p_email) AND accepted_at IS NULL;
  INSERT INTO app.tenant_invitations (tenant_id, email, role, token_hash)
  VALUES (app.current_tenant_id(), p_email, p_role, sha256(convert_to(v_token, 'UTF8')));
  RETURN v_token;
END $$;

-- Redeem an invitation. The token must be valid, unexpired, unused, AND
-- addressed to the signed-in user's email (a forwarded/leaked link is useless
-- to anyone else). One generic error for every failure: no oracle.
CREATE FUNCTION app.accept_invitation(p_token text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
DECLARE
  v_user uuid := app.current_user_id();
  v_inv  app.tenant_invitations%ROWTYPE;
BEGIN
  SELECT i.* INTO v_inv
  FROM app.tenant_invitations i
  JOIN app.tenants t ON t.id = i.tenant_id AND t.status = 'active'
  WHERE i.token_hash = sha256(convert_to(coalesce(p_token, ''), 'UTF8'))
    AND i.accepted_at IS NULL
    AND i.expires_at > now()
    AND lower(i.email) = (SELECT lower(u.email) FROM app.users u WHERE u.id = v_user)
  FOR UPDATE OF i;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'invitation is invalid, expired, or addressed to someone else'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  INSERT INTO app.tenant_memberships (tenant_id, user_id, role)
  VALUES (v_inv.tenant_id, v_user, v_inv.role)
  ON CONFLICT (tenant_id, user_id) DO NOTHING;

  UPDATE app.tenant_invitations SET accepted_at = now()
  WHERE tenant_id = v_inv.tenant_id AND id = v_inv.id;
  RETURN v_inv.tenant_id;
END $$;

ALTER FUNCTION app.current_member_role()             OWNER TO saas_definer;
ALTER FUNCTION app.my_tenants()                      OWNER TO saas_definer;
ALTER FUNCTION app.create_tenant(text, text)         OWNER TO saas_definer;
ALTER FUNCTION app.create_invitation(text, text)     OWNER TO saas_definer;
ALTER FUNCTION app.accept_invitation(text)           OWNER TO saas_definer;

GRANT EXECUTE ON FUNCTION
  app.current_member_role(), app.my_tenants(), app.create_tenant(text, text),
  app.create_invitation(text, text), app.accept_invitation(text)
TO saas_app, saas_admin;

-- Offboarding / GDPR erasure. Admin tooling only (not granted to saas_app).
CREATE FUNCTION app.purge_tenant(p_tenant uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, app, pg_temp AS $$
BEGIN
  DELETE FROM app.tenants   WHERE id = p_tenant;   -- cascades to all tenant data
  DELETE FROM app.audit_log WHERE tenant_id = p_tenant;
END $$;
GRANT EXECUTE ON FUNCTION app.purge_tenant(uuid) TO saas_admin;

-- ---------------------------------------------------------- enable + force ---
-- FORCE makes the table owner subject to RLS too, so connecting as the owner
-- by mistake does not silently expose every tenant.
ALTER TABLE app.tenants            ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.users              ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.tenant_memberships ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.tenant_invitations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.projects           ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.tasks              ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.task_comments      ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
ALTER TABLE app.tenant_counters    ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;  -- no policies: definer only
ALTER TABLE app.audit_log          ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------- tenants ---
CREATE POLICY tenant_isolation ON app.tenants FOR ALL TO saas_app
  USING      (id = app.current_tenant_id())
  WITH CHECK (id = app.current_tenant_id());
CREATE POLICY member_only ON app.tenants AS RESTRICTIVE FOR ALL TO saas_app
  USING ((SELECT app.current_member_role()) IS NOT NULL);
CREATE POLICY admins_update ON app.tenants AS RESTRICTIVE FOR UPDATE TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin'));

-- ------------------------------------------------------------------ users ---
-- You can see yourself, plus people who share the current tenant.
CREATE POLICY visible_users ON app.users FOR SELECT TO saas_app
  USING (
    id = (SELECT app.current_user_id())
    OR EXISTS (SELECT 1 FROM app.tenant_memberships m WHERE m.user_id = users.id)  -- memberships are already RLS-scoped
  );
CREATE POLICY self_update ON app.users FOR UPDATE TO saas_app
  USING      (id = (SELECT app.current_user_id()))
  WITH CHECK (id = (SELECT app.current_user_id()));

-- ----------------------------------------------------- tenant_memberships ---
CREATE POLICY tenant_isolation ON app.tenant_memberships FOR ALL TO saas_app
  USING      (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY member_only ON app.tenant_memberships AS RESTRICTIVE FOR ALL TO saas_app
  USING ((SELECT app.current_member_role()) IS NOT NULL);
CREATE POLICY admins_update ON app.tenant_memberships AS RESTRICTIVE FOR UPDATE TO saas_app
  USING      ((SELECT app.current_member_role()) IN ('owner', 'admin') AND role <> 'owner')
  WITH CHECK (role <> 'owner');
CREATE POLICY admins_delete ON app.tenant_memberships AS RESTRICTIVE FOR DELETE TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin') AND role <> 'owner');

-- ----------------------------------------------------- tenant_invitations ---
CREATE POLICY tenant_isolation ON app.tenant_invitations FOR ALL TO saas_app
  USING      (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY admins_only ON app.tenant_invitations AS RESTRICTIVE FOR ALL TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin'));

-- ----------------------------------------------- projects / tasks / comments ---
CREATE POLICY tenant_isolation ON app.projects FOR ALL TO saas_app
  USING      (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY member_only ON app.projects AS RESTRICTIVE FOR ALL TO saas_app
  USING ((SELECT app.current_member_role()) IS NOT NULL);
CREATE POLICY writers_insert ON app.projects AS RESTRICTIVE FOR INSERT TO saas_app
  WITH CHECK ((SELECT app.current_member_role()) IN ('owner', 'admin', 'member'));
CREATE POLICY writers_update ON app.projects AS RESTRICTIVE FOR UPDATE TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin', 'member'));
CREATE POLICY admins_delete ON app.projects AS RESTRICTIVE FOR DELETE TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin'));

CREATE POLICY tenant_isolation ON app.tasks FOR ALL TO saas_app
  USING      (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY member_only ON app.tasks AS RESTRICTIVE FOR ALL TO saas_app
  USING ((SELECT app.current_member_role()) IS NOT NULL);
CREATE POLICY writers_insert ON app.tasks AS RESTRICTIVE FOR INSERT TO saas_app
  WITH CHECK ((SELECT app.current_member_role()) IN ('owner', 'admin', 'member'));
CREATE POLICY writers_update ON app.tasks AS RESTRICTIVE FOR UPDATE TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin', 'member'));
CREATE POLICY writers_delete ON app.tasks AS RESTRICTIVE FOR DELETE TO saas_app
  USING ((SELECT app.current_member_role()) IN ('owner', 'admin', 'member'));

CREATE POLICY tenant_isolation ON app.task_comments FOR ALL TO saas_app
  USING      (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY member_only ON app.task_comments AS RESTRICTIVE FOR ALL TO saas_app
  USING ((SELECT app.current_member_role()) IS NOT NULL);
CREATE POLICY writers_insert ON app.task_comments AS RESTRICTIVE FOR INSERT TO saas_app
  WITH CHECK ((SELECT app.current_member_role()) <> 'viewer'
              AND author_id = (SELECT app.current_user_id()));
-- Authors edit their own comments — unless they have since been made read-only.
CREATE POLICY author_update ON app.task_comments AS RESTRICTIVE FOR UPDATE TO saas_app
  USING      (author_id = (SELECT app.current_user_id())
              AND (SELECT app.current_member_role()) <> 'viewer')
  WITH CHECK (author_id = (SELECT app.current_user_id()));
CREATE POLICY author_or_admin_delete ON app.task_comments AS RESTRICTIVE FOR DELETE TO saas_app
  USING ((author_id = (SELECT app.current_user_id()) AND (SELECT app.current_member_role()) <> 'viewer')
         OR (SELECT app.current_member_role()) IN ('owner', 'admin'));

-- -------------------------------------------------------------- audit_log ---
CREATE POLICY tenant_admins_read ON app.audit_log FOR SELECT TO saas_app
  USING (tenant_id = app.current_tenant_id()
         AND (SELECT app.current_member_role()) IN ('owner', 'admin'));
