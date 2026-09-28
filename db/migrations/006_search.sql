-- =============================================================================
-- 006 — tenant-scoped full-text search that can actually use its index.
--
-- THE GOTCHA: under RLS, Postgres only pushes a user's WHERE clause into an
-- index scan if the operator's function is LEAKPROOF (otherwise it could leak
-- other tenants' values via errors/side effects before the policy filters
-- them). `@@` (ts_match_vq), LIKE/ILIKE (textlike), pg_trgm's % and most
-- jsonb operators are NOT leakproof. Result: with RLS on, the GIN index
-- (tenant_id, search) is only used for "tenant_id = ?"; every row of the
-- tenant is then fetched and rechecked. Fine for small tenants, linear in
-- tenant size for your biggest customers (see `npm run bench`).
--
-- THE FIX: a narrow SECURITY DEFINER function (owner bypasses RLS) that
-- applies the tenant + membership predicates itself, so both conditions become
-- index conditions. Keep functions like this tiny and reviewed: inside them,
-- the WHERE clause IS the security boundary.
-- =============================================================================

CREATE FUNCTION app.search_tasks(p_query text, p_limit int DEFAULT 50)
RETURNS SETOF app.tasks
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, app, pg_temp AS $$
  SELECT t.*
  FROM app.tasks t
  WHERE t.tenant_id = app.current_tenant_id()          -- tenant boundary (explicit: RLS is bypassed here)
    AND app.current_member_role() IS NOT NULL          -- caller must belong to the tenant
    AND t.search @@ websearch_to_tsquery('simple', p_query)
  ORDER BY ts_rank(t.search, websearch_to_tsquery('simple', p_query)) DESC, t.id DESC
  LIMIT least(greatest(p_limit, 1), 200)
$$;

GRANT SELECT ON app.tasks TO saas_definer;
ALTER FUNCTION app.search_tasks(text, int) OWNER TO saas_definer;
GRANT  EXECUTE ON FUNCTION app.search_tasks(text, int) TO saas_app;
