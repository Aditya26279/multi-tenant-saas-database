// Walks through a request lifecycle the way a web app would use this schema.
// Run after `npm run db:reset` (or `npm run demo:embedded`).
import { createAppPool, withTenant, withUser } from '../src/db.mjs';

const pool = createAppPool();
const ERIN = '20000000-0000-7000-8000-000000000005'; // admin at Acme, member at Globex
const ALICE = '20000000-0000-7000-8000-000000000001'; // Acme only

// 1. After login: which workspaces can this user open? (no tenant chosen yet)
const tenants = await withUser(pool, ERIN, (db) => db.query('SELECT * FROM app.my_tenants()').then((r) => r.rows));
console.log('Erin can switch between:', tenants.map((t) => `${t.slug} (${t.role})`).join(', '));

// 2. Every request after that runs inside withTenant(). No tenant_id in any query.
const acme = tenants.find((t) => t.slug === 'acme').tenant_id;
const globex = tenants.find((t) => t.slug === 'globex').tenant_id;

await withTenant(pool, { tenantId: acme, userId: ERIN }, async (db) => {
  const { rows: projects } = await db.query('SELECT id, key, name FROM app.projects ORDER BY key');
  console.log('\n[acme] projects:', projects.map((p) => p.key).join(', '));

  const { rows: [task] } = await db.query(
    "INSERT INTO app.tasks (project_id, title, priority) VALUES ($1, 'Set up SSO for enterprise plan', 1) RETURNING number, tenant_id",
    [projects[0].id],
  );
  console.log(`[acme] created task #${task.number} (tenant_id filled in by the database: ${task.tenant_id === acme})`);

  const { rows: hits } = await db.query("SELECT number, title FROM app.search_tasks('sso')");
  console.log('[acme] search "sso":', hits.map((h) => `#${h.number} ${h.title}`));
});

await withTenant(pool, { tenantId: globex, userId: ERIN }, async (db) => {
  const { rows } = await db.query("SELECT number, title FROM app.search_tasks('sso')");
  console.log(`\n[globex] same user, same search, other tenant: ${rows.length} results`);
});

// 3. The classic multi-tenant bug: trusting a tenant id from the client.
//    Alice sends Globex's id in a header. The database checks membership.
await withTenant(pool, { tenantId: globex, userId: ALICE }, async (db) => {
  const { rowCount } = await db.query('SELECT * FROM app.tasks');
  console.log(`\n[forged] Alice with X-Tenant-Id=globex sees ${rowCount} tasks`);
});

// 4. A handler that forgets withTenant() gets nothing — it fails closed.
const { rowCount } = await pool.query('SELECT * FROM app.tasks');
console.log(`[no context] query outside withTenant() sees ${rowCount} tasks`);

await pool.end();
