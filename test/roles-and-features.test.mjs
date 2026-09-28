// In-tenant authorization (roles), onboarding helpers, numbering, audit trail.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { appPool, adminPool, scoped, rows, exec, T, U, P, TASK, COMMENT } from './helpers.mjs';

after(() => Promise.all([appPool.end(), adminPool.end()]));

const as = (user, tenant = T.acme) => ({ tenant, user });

test('viewer can read but not write', async () => {
  assert.equal((await rows(as(U.carol), 'SELECT * FROM app.tasks')).length, 3);
  await assert.rejects(
    exec(as(U.carol), "INSERT INTO app.tasks (project_id, title) VALUES ($1, 'x')", [P.acmeWeb]),
    /row-level security/,
  );
  const upd = await exec(as(U.carol), "UPDATE app.tasks SET status = 'done' WHERE id = $1", [TASK.acmeLanding]);
  assert.equal(upd.rowCount, 0);
});

test('member can create and edit, but only admins/owners delete projects', async () => {
  await scoped(as(U.bob), async (c) => {
    const ins = await c.query("INSERT INTO app.projects (key, name) VALUES ('MKT', 'Marketing') RETURNING tenant_id, created_by");
    assert.equal(ins.rows[0].tenant_id, T.acme, 'tenant_id filled from context');
    assert.equal(ins.rows[0].created_by, U.bob, 'created_by filled from context');
    const del = await c.query('DELETE FROM app.projects WHERE id = $1', [P.acmeOps]);
    assert.equal(del.rowCount, 0);
  });
  const del = await exec(as(U.erin), 'DELETE FROM app.projects WHERE id = $1', [P.acmeOps]);
  assert.equal(del.rowCount, 1);
});

test('comments: authors edit their own; admins may delete any', async () => {
  assert.equal((await exec(as(U.alice), "UPDATE app.task_comments SET body = 'edited' WHERE id = $1", [COMMENT.bobOnLanding])).rowCount, 0);
  assert.equal((await exec(as(U.bob), "UPDATE app.task_comments SET body = 'edited' WHERE id = $1", [COMMENT.bobOnLanding])).rowCount, 1);
  assert.equal((await exec(as(U.alice), 'DELETE FROM app.task_comments WHERE id = $1', [COMMENT.bobOnLanding])).rowCount, 1);
  await assert.rejects(
    exec(as(U.bob), "INSERT INTO app.task_comments (task_id, author_id, body) VALUES ($1, $2, 'spoof')", [TASK.acmeLanding, U.alice]),
    /permission denied|row-level security/,
    'cannot post as someone else',
  );
});

test('memberships: admins manage members but cannot touch or create owners', async () => {
  assert.equal((await exec(as(U.erin), "UPDATE app.tenant_memberships SET role = 'admin' WHERE user_id = $1", [U.bob])).rowCount, 1);
  assert.equal((await exec(as(U.erin), 'DELETE FROM app.tenant_memberships WHERE user_id = $1', [U.alice])).rowCount, 0);
  await assert.rejects(
    exec(as(U.erin), "UPDATE app.tenant_memberships SET role = 'owner' WHERE user_id = $1", [U.bob]),
    /row-level security/,
  );
  assert.equal((await exec(as(U.bob), "UPDATE app.tenant_memberships SET role = 'admin' WHERE user_id = $1", [U.carol])).rowCount, 0);
});

test('column privileges: plan/status are not user-editable', async () => {
  await assert.rejects(exec(as(U.alice), "UPDATE app.tenants SET plan = 'enterprise'"), /permission denied/);
  assert.equal((await exec(as(U.alice), "UPDATE app.tenants SET name = 'Acme Inc'")).rowCount, 1);
  assert.equal((await exec(as(U.bob), "UPDATE app.tenants SET name = 'Bob Corp'")).rowCount, 0, 'members cannot rename');
});

test('my_tenants(): tenant switcher returns only the caller\'s memberships', async () => {
  const erin = await rows({ user: U.erin }, 'SELECT slug, role FROM app.my_tenants()');
  assert.deepEqual(erin, [{ slug: 'acme', role: 'admin' }, { slug: 'globex', role: 'member' }]);
  const dave = await rows({ user: U.dave }, 'SELECT slug FROM app.my_tenants()');
  assert.deepEqual(dave.map((r) => r.slug), ['globex']);
  assert.equal((await rows({}, 'SELECT * FROM app.my_tenants()')).length, 0);
});

test('create_tenant(): signup creates a tenant owned by the caller', async () => {
  await scoped({ user: U.carol }, async (c) => {
    const { rows: [{ id }] } = await c.query("SELECT app.create_tenant('carols-shop', 'Carol''s Shop') AS id");
    await c.query("SELECT set_config('app.tenant_id', $1, true)", [id]);
    const m = await c.query('SELECT role FROM app.tenant_memberships WHERE user_id = $1', [U.carol]);
    assert.deepEqual(m.rows, [{ role: 'owner' }]);
    const p = await c.query("INSERT INTO app.projects (key, name) VALUES ('WEB', 'Same key as Acme is fine') RETURNING key");
    assert.equal(p.rowCount, 1, 'project keys are unique per tenant, not globally');
  });
});

test('task numbers are sequential per tenant', async () => {
  await scoped(as(U.bob), async (c) => {
    const a = await c.query("INSERT INTO app.tasks (project_id, title) VALUES ($1, 'a'), ($1, 'b') RETURNING number", [P.acmeWeb]);
    assert.deepEqual(a.rows.map((r) => Number(r.number)), [4, 5]);
  });
  await scoped(as(U.dave, T.globex), async (c) => {
    const g = await c.query("INSERT INTO app.tasks (project_id, title) VALUES ($1, 'g') RETURNING number", [P.globexRnd]);
    assert.equal(Number(g.rows[0].number), 2);
  });
});

test('completed_at follows status', async () => {
  await scoped(as(U.bob), async (c) => {
    const done = await c.query("UPDATE app.tasks SET status = 'done' WHERE id = $1 RETURNING completed_at", [TASK.acmeLanding]);
    assert.ok(done.rows[0].completed_at instanceof Date);
    const reopened = await c.query("UPDATE app.tasks SET status = 'todo' WHERE id = $1 RETURNING completed_at", [TASK.acmeLanding]);
    assert.equal(reopened.rows[0].completed_at, null);
  });
});

test('audit log: records actor + diff, admins-only, tamper-proof', async () => {
  await scoped(as(U.bob), async (c) => {
    await c.query("UPDATE app.tasks SET priority = 0 WHERE id = $1", [TASK.acmeLanding]);
    await c.query("SELECT set_config('app.user_id', $1, true)", [U.alice]);
    const log = await c.query(
      "SELECT actor_id, action, old_data, new_data FROM app.audit_log WHERE record_id = $1 AND action = 'UPDATE'",
      [TASK.acmeLanding],
    );
    assert.equal(log.rowCount, 1);
    assert.equal(log.rows[0].actor_id, U.bob);
    assert.deepEqual(log.rows[0].old_data, { priority: 1 });
    assert.deepEqual(log.rows[0].new_data, { priority: 0 });
  });
  assert.equal((await rows(as(U.bob), 'SELECT * FROM app.audit_log')).length, 0, 'members cannot read audit');
  assert.equal((await rows(as(U.dave, T.globex), 'SELECT DISTINCT tenant_id FROM app.audit_log'))[0].tenant_id, T.globex);
  await assert.rejects(exec(as(U.alice), 'DELETE FROM app.audit_log'), /permission denied/);
  await assert.rejects(
    exec(as(U.alice), "INSERT INTO app.audit_log (tenant_id, table_name, action) VALUES ($1, 'x', 'INSERT')", [T.acme]),
    /permission denied/,
  );
});

test('purge_tenant(): offboarding removes every row for that tenant only', async () => {
  await scoped({}, async (c) => {
    await c.query('SELECT app.purge_tenant($1)', [T.globex]);
    const left = await c.query(`
      SELECT (SELECT count(*) FROM app.tasks         WHERE tenant_id = $1)
           + (SELECT count(*) FROM app.projects      WHERE tenant_id = $1)
           + (SELECT count(*) FROM app.task_comments WHERE tenant_id = $1)
           + (SELECT count(*) FROM app.audit_log     WHERE tenant_id = $1) AS n,
             (SELECT count(*) FROM app.tasks         WHERE tenant_id = $2) AS acme_tasks`, [T.globex, T.acme]);
    assert.equal(Number(left.rows[0].n), 0);
    assert.equal(Number(left.rows[0].acme_tasks), 3);
  }, adminPool);
  await assert.rejects(exec(as(U.alice), 'SELECT app.purge_tenant($1)', [T.acme]), /permission denied/);
});

test('search_tasks(): tenant-scoped full-text search', async () => {
  const acme = await rows(as(U.bob), "SELECT title FROM app.search_tasks('landing page')");
  assert.deepEqual(acme.map((r) => r.title), ['Design new landing page']);
  // 'confidential' exists only in Globex — invisible from Acme, and to a forged header.
  assert.equal((await rows(as(U.bob), "SELECT * FROM app.search_tasks('confidential')")).length, 0);
  assert.equal((await rows(as(U.alice, T.globex), "SELECT * FROM app.search_tasks('confidential')")).length, 0);
  assert.equal((await rows({ user: U.alice }, "SELECT * FROM app.search_tasks('confidential')")).length, 0);
  assert.equal((await rows(as(U.dave, T.globex), "SELECT * FROM app.search_tasks('confidential')")).length, 1);
});
