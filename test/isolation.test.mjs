// Tenant isolation: the guarantees that matter most.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { appPool, adminPool, scoped, rows, exec, T, U, P, TASK } from './helpers.mjs';

after(() => Promise.all([appPool.end(), adminPool.end()]));

const acmeAlice = { tenant: T.acme, user: U.alice };
const globexDave = { tenant: T.globex, user: U.dave };

test('fails closed: no context means no rows', async () => {
  for (const table of ['tenants', 'users', 'tenant_memberships', 'projects', 'tasks', 'task_comments', 'audit_log']) {
    const r = await rows({}, `SELECT * FROM app.${table}`);
    assert.equal(r.length, 0, `app.${table} leaked ${r.length} rows without context`);
  }
});

test('fails closed: insert without tenant context is rejected', async () => {
  await assert.rejects(
    exec({ user: U.alice }, "INSERT INTO app.projects (key, name) VALUES ('NEW', 'x')"),
    /tenant context not set/,
  );
});

test('each tenant sees only its own rows', async () => {
  const acme = await rows(acmeAlice, 'SELECT tenant_id, key FROM app.projects ORDER BY key');
  assert.deepEqual(acme.map((r) => r.key), ['OPS', 'WEB']);
  assert.ok(acme.every((r) => r.tenant_id === T.acme));

  const globex = await rows(globexDave, 'SELECT title FROM app.tasks');
  assert.deepEqual(globex.map((r) => r.title), ['Secret prototype pricing model']);

  const tenants = await rows(acmeAlice, 'SELECT slug FROM app.tenants');
  assert.deepEqual(tenants.map((r) => r.slug), ['acme']);
});

test('guessing another tenant\'s id returns nothing and changes nothing', async () => {
  assert.equal((await rows(acmeAlice, 'SELECT * FROM app.tasks WHERE id = $1', [TASK.globexSecret])).length, 0);
  const upd = await exec(acmeAlice, "UPDATE app.tasks SET title = 'pwned' WHERE id = $1", [TASK.globexSecret]);
  assert.equal(upd.rowCount, 0);
  const del = await exec(acmeAlice, 'DELETE FROM app.projects WHERE id = $1', [P.globexRnd]);
  assert.equal(del.rowCount, 0);
});

test('forged tenant header: non-member sees nothing even with a valid tenant id', async () => {
  // Alice (acme only) claims to be acting in globex.
  const forged = { tenant: T.globex, user: U.alice };
  for (const table of ['tenants', 'tenant_memberships', 'projects', 'tasks', 'task_comments']) {
    assert.equal((await rows(forged, `SELECT * FROM app.${table}`)).length, 0, `app.${table} leaked`);
  }
  await assert.rejects(
    exec(forged, "INSERT INTO app.projects (key, name) VALUES ('HAX', 'x')"),
    /row-level security/,
  );
});

test('multi-tenant user sees exactly the tenant they are acting in', async () => {
  const inAcme = await rows({ tenant: T.acme, user: U.erin }, 'SELECT key FROM app.projects ORDER BY key');
  const inGlobex = await rows({ tenant: T.globex, user: U.erin }, 'SELECT key FROM app.projects ORDER BY key');
  assert.deepEqual(inAcme.map((r) => r.key), ['OPS', 'WEB']);
  assert.deepEqual(inGlobex.map((r) => r.key), ['RND']);
});

// Two layers stop these: tenant_id is not a writable column for the app
// (column grants -> permission denied), and RLS WITH CHECK behind that.
test('cannot insert a row into another tenant', async () => {
  await assert.rejects(
    exec(acmeAlice, "INSERT INTO app.projects (tenant_id, key, name) VALUES ($1, 'EVIL', 'x')", [T.globex]),
    /permission denied|row-level security/,
  );
});

test('cannot move an existing row to another tenant', async () => {
  await assert.rejects(
    exec(acmeAlice, 'UPDATE app.projects SET tenant_id = $1 WHERE id = $2', [T.globex, P.acmeWeb]),
    /permission denied|row-level security/,
  );
});

test('composite FK: a task cannot reference another tenant\'s project', async () => {
  // Even as a BYPASSRLS admin, the schema itself refuses the cross-tenant link.
  await assert.rejects(
    scoped({}, (c) => c.query(
      "INSERT INTO app.tasks (tenant_id, project_id, title) VALUES ($1, $2, 'cross-tenant')",
      [T.acme, P.globexRnd],
    ), adminPool),
    /violates foreign key constraint/,
  );
});

test('composite FK: cannot assign a task to a user outside the tenant', async () => {
  await assert.rejects(
    exec(acmeAlice, 'UPDATE app.tasks SET assignee_id = $1 WHERE id = $2', [U.dave, TASK.acmeLanding]),
    /violates foreign key constraint/,
  );
});

test('users: only co-members are visible', async () => {
  const visible = await rows(globexDave, 'SELECT display_name FROM app.users ORDER BY display_name');
  assert.deepEqual(visible.map((r) => r.display_name), ['Dave', 'Erin']);
});

test('context is transaction-scoped and never leaks to the next transaction', async () => {
  const client = await appPool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)", [T.acme, U.alice]);
    assert.equal((await client.query('SELECT * FROM app.projects')).rowCount, 2);
    await client.query('COMMIT');

    // Same physical connection, next "request" forgot to set context:
    const leaked = await client.query('SELECT * FROM app.projects');
    assert.equal(leaked.rowCount, 0);
    assert.equal((await client.query('SELECT app.current_tenant_id() AS t')).rows[0].t, null);
  } finally {
    client.release();
  }
});

test('the app role cannot switch RLS off', async () => {
  await assert.rejects(exec(acmeAlice, 'ALTER TABLE app.tasks DISABLE ROW LEVEL SECURITY'), /must be owner/);
  await assert.rejects(exec(acmeAlice, 'SET ROLE saas_admin'), /permission denied/);
  await assert.rejects(exec(acmeAlice, 'DROP POLICY tenant_isolation ON app.tasks'), /must be owner/);
  // row_security=off makes a query ERROR instead of silently filtering — never bypass.
  await assert.rejects(
    scoped(acmeAlice, async (c) => { await c.query('SET LOCAL row_security = off'); await c.query('SELECT * FROM app.tasks'); }),
    /row-level security/,
  );
});

test('the app role cannot read or write the counter table directly', async () => {
  await assert.rejects(exec(acmeAlice, 'SELECT * FROM app.tenant_counters'), /permission denied/);
});

test('admin role sees across tenants (for support tooling)', async () => {
  const r = await scoped({}, (c) => c.query('SELECT count(DISTINCT tenant_id)::int AS n FROM app.projects'), adminPool);
  assert.equal(r.rows[0].n, 2);
});
