// Regression tests for issues found in the security review. Each test names
// the attack it prevents.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { appPool, adminPool, scoped, rows, exec, T, U, P, TASK } from './helpers.mjs';

after(() => Promise.all([appPool.end(), adminPool.end()]));

const as = (user, tenant = T.acme) => ({ tenant, user });
const admin = (sql, params) => scoped({}, (c) => c.query(sql, params), adminPool);

// ------------------------------------------------------------- integrity ---

test('members cannot forge system columns (number, created_by, completed_at, created_at)', async () => {
  for (const sql of [
    'UPDATE app.tasks SET number = 999 WHERE id = $1',
    'UPDATE app.tasks SET created_by = NULL WHERE id = $1',
    "UPDATE app.tasks SET completed_at = '2000-01-01' WHERE id = $1",
    "UPDATE app.tasks SET created_at = '2000-01-01' WHERE id = $1",
    'UPDATE app.tasks SET id = gen_random_uuid() WHERE id = $1',
  ]) {
    await assert.rejects(exec(as(U.bob), sql, [TASK.acmeLanding]), /permission denied/, sql);
  }
});

test('members cannot attribute new rows to someone else', async () => {
  await assert.rejects(
    exec(as(U.bob), "INSERT INTO app.projects (key, name, created_by) VALUES ('FAKE', 'x', $1)", [U.alice]),
    /permission denied/,
  );
  await assert.rejects(
    exec(as(U.bob), "INSERT INTO app.tasks (project_id, title, created_by) VALUES ($1, 'x', $2)", [P.acmeWeb, U.alice]),
    /permission denied/,
  );
});

// ------------------------------------------------------- membership / PII ---

test('admins cannot pull arbitrary users into their tenant (email disclosure / user-id oracle)', async () => {
  // Before the fix: an Acme admin could INSERT a membership for Dave (a Globex
  // user who never agreed to join) and then read Dave's email from app.users.
  await assert.rejects(
    exec(as(U.erin), "INSERT INTO app.tenant_memberships (user_id, role) VALUES ($1, 'viewer')", [U.dave]),
    /permission denied/,
  );
});

test('invitations: token-based, email-bound, single-use', async () => {
  await scoped(as(U.alice), async (c) => {
    // run a statement that must fail without aborting the surrounding transaction
    const mustFail = async (sql, params, pattern) => {
      await c.query('SAVEPOINT s');
      await assert.rejects(c.query(sql, params), pattern, sql);
      await c.query('ROLLBACK TO SAVEPOINT s');
    };
    const { rows: [{ token }] } = await c.query("SELECT app.create_invitation('dave@globex.test', 'member') AS token");
    assert.match(token, /^[0-9a-f]{64}$/);

    // admins can list pending invites but never see the token hash
    const inv = await c.query('SELECT email, role, accepted_at FROM app.tenant_invitations');
    assert.deepEqual(inv.rows, [{ email: 'dave@globex.test', role: 'member', accepted_at: null }]);
    await mustFail('SELECT token_hash FROM app.tenant_invitations', [], /permission denied/);

    // a different user holding the token cannot redeem it
    await c.query("SELECT set_config('app.tenant_id', '', true), set_config('app.user_id', $1, true)", [U.bob]);
    await mustFail('SELECT app.accept_invitation($1)', [token], /invalid/);

    // the invited user can, exactly once
    await c.query("SELECT set_config('app.user_id', $1, true)", [U.dave]);
    const { rows: [{ tenant }] } = await c.query('SELECT app.accept_invitation($1) AS tenant', [token]);
    assert.equal(tenant, T.acme);
    await mustFail('SELECT app.accept_invitation($1)', [token], /invalid/);

    const mine = await c.query('SELECT slug, role FROM app.my_tenants()');
    assert.deepEqual(mine.rows, [{ slug: 'acme', role: 'member' }, { slug: 'globex', role: 'owner' }]);
  });
});

test('invitations: members and viewers cannot invite; expired tokens are rejected', async () => {
  await assert.rejects(exec(as(U.bob), "SELECT app.create_invitation('x@y.test')"), /only tenant owners and admins/);
  await scoped(as(U.alice), async (c) => {
    const { rows: [{ token }] } = await c.query("SELECT app.create_invitation('dave@globex.test') AS token");
    await c.query('SET LOCAL ROLE admin_user');  // simulate time passing
    await c.query("UPDATE app.tenant_invitations SET expires_at = now() - interval '1 second'");
    await c.query('RESET ROLE');
    await c.query("SELECT set_config('app.user_id', $1, true)", [U.dave]);
    await assert.rejects(c.query('SELECT app.accept_invitation($1)', [token]), /invalid/);
  }, adminPool);
});

test('removing a member unassigns their tasks instead of failing or leaking', async () => {
  await scoped(as(U.erin), async (c) => {
    assert.equal((await c.query('DELETE FROM app.tenant_memberships WHERE user_id = $1', [U.bob])).rowCount, 1);
    const t = await c.query('SELECT assignee_id FROM app.tasks WHERE id = $1', [TASK.acmeLanding]);
    assert.equal(t.rows[0].assignee_id, null);
  });
});

test('demoted-to-viewer authors can no longer edit their comments', async () => {
  await scoped(as(U.erin), async (c) => {
    await c.query("UPDATE app.tenant_memberships SET role = 'viewer' WHERE user_id = $1", [U.bob]);
    await c.query("SELECT set_config('app.user_id', $1, true)", [U.bob]);
    const r = await c.query("UPDATE app.task_comments SET body = 'still here' WHERE author_id = $1", [U.bob]);
    assert.equal(r.rowCount, 0);
  });
});

// ---------------------------------------------------------- tenant state ---

test('suspended tenants are locked out (reads, writes, switcher, search)', async () => {
  // scoped() rolls back, so commit the suspension explicitly and restore it after.
  const setStatus = async (status) => {
    const c = await adminPool.connect();
    try { await c.query('UPDATE app.tenants SET status = $1 WHERE id = $2', [status, T.acme]); } finally { c.release(); }
  };
  await setStatus('suspended');
  try {
    assert.equal((await rows(as(U.alice), 'SELECT * FROM app.tasks')).length, 0);
    assert.equal((await rows(as(U.alice), "SELECT * FROM app.search_tasks('landing')")).length, 0);
    assert.deepEqual(await rows({ user: U.alice }, 'SELECT * FROM app.my_tenants()'), []);
    await assert.rejects(exec(as(U.alice), "INSERT INTO app.projects (key, name) VALUES ('NEW', 'x')"), /row-level security/);
  } finally {
    await setStatus('active');
  }
  assert.equal((await rows(as(U.alice), 'SELECT * FROM app.tasks')).length, 3, 'access restored on reactivation');
});

test('tenant settings changes are audited', async () => {
  await scoped(as(U.alice), async (c) => {
    await c.query(`UPDATE app.tenants SET settings = '{"sso": {"enforced": true}}'`);
    const log = await c.query("SELECT actor_id, new_data FROM app.audit_log WHERE table_name = 'tenants' AND actor_id = $1", [U.alice]);
    assert.equal(log.rowCount, 1);
    assert.equal(log.rows[0].actor_id, U.alice);
    assert.deepEqual(log.rows[0].new_data, { settings: { sso: { enforced: true } } });
  });
});

test('oversized payloads are rejected (tsvector/jsonb DoS)', async () => {
  await assert.rejects(
    exec(as(U.bob), "INSERT INTO app.tasks (project_id, title, description) VALUES ($1, 'big', repeat('x', 100001))", [P.acmeWeb]),
    /check constraint/,
  );
  await assert.rejects(
    exec(as(U.alice), "UPDATE app.tenants SET settings = jsonb_build_object('blob', repeat('x', 70000))"),
    /check constraint/,
  );
});

// ------------------------------------------------------ schema invariants ---
// Guards for FUTURE migrations: they fail the build when someone adds a table
// without RLS, a definer function without a pinned search_path, etc.

test('invariant: every table in app has RLS enabled AND forced', async () => {
  const { rows: bad } = await admin(`
    SELECT relname FROM pg_class
    WHERE relnamespace = 'app'::regnamespace AND relkind IN ('r', 'p')
      AND NOT (relrowsecurity AND relforcerowsecurity)`);
  assert.deepEqual(bad, []);
});

test('invariant: SECURITY DEFINER functions pin search_path and are not PUBLIC-executable', async () => {
  const { rows: bad } = await admin(`
    SELECT p.proname,
           NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search_path=%pg_temp') AS unpinned,
           has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec
    FROM pg_proc p
    WHERE p.pronamespace = 'app'::regnamespace AND p.prosecdef
      AND (has_function_privilege('public', p.oid, 'EXECUTE')
           OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search_path=%pg_temp'))`);
  assert.deepEqual(bad, []);
});

test('invariant: the app role owns nothing and cannot bypass RLS', async () => {
  const { rows: [r] } = await admin(`
    SELECT rolbypassrls, rolsuper,
           (SELECT count(*) FROM pg_class WHERE relowner = r.oid)::int AS owned
    FROM pg_roles r WHERE rolname = 'app_user'`);
  assert.deepEqual(r, { rolbypassrls: false, rolsuper: false, owned: 0 });
});

test('invariant: every foreign key has a supporting index (no seq scans on cascade)', async () => {
  const { rows: bad } = await admin(`
    SELECT c.conrelid::regclass::text AS tbl, c.conname
    FROM pg_constraint c
    WHERE c.contype = 'f' AND c.connamespace = 'app'::regnamespace
      AND NOT EXISTS (
        SELECT 1 FROM pg_index i
        WHERE i.indrelid = c.conrelid
          AND (i.indkey::int2[])[0:array_length(c.conkey, 1) - 1] @> c.conkey
          AND (i.indkey::int2[])[0:array_length(c.conkey, 1) - 1] <@ c.conkey)`);
  assert.deepEqual(bad, []);
});

test('app role has statement and idle-in-transaction timeouts', async () => {
  const r = await rows(as(U.alice), "SELECT current_setting('statement_timeout') AS st, current_setting('idle_in_transaction_session_timeout') AS idle");
  assert.notEqual(r[0].st, '0');
  assert.notEqual(r[0].idle, '0');
});
