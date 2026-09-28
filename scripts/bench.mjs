// Indexing benchmark: loads realistic volume, then runs the app's hot queries
// AS THE APP ROLE (so RLS is active) and reports the plan + timing.
//
//   BENCH_TENANTS=500 BENCH_TASKS=300000 node scripts/bench.mjs [--verbose]
//
// Data shape is deliberately skewed like real SaaS: one "whale" tenant holds
// ~20% of all tasks, the rest share the remainder; ~70% of tasks are closed.
import pg from 'pg';
import { config, assertDisposableDatabase } from '../src/config.mjs';

const TENANTS = Number(process.env.BENCH_TENANTS ?? 500);
const TASKS = Number(process.env.BENCH_TASKS ?? 300_000);
const verbose = process.argv.includes('--verbose');

const WORDS = ['invoice', 'onboarding', 'migration', 'api', 'billing', 'dashboard', 'export', 'report',
  'login', 'refactor', 'mobile', 'webhook', 'search', 'cache', 'email', 'pricing', 'audit', 'deploy',
  'bug', 'customer', 'import', 'settings', 'analytics', 'security', 'performance', 'sso', 'docs', 'test'];

async function load() {
  assertDisposableDatabase(config.migrationUrl, 'load benchmark data');
  const c = new pg.Client({ connectionString: config.migrationUrl });
  await c.connect();
  const t0 = performance.now();
  await c.query('BEGIN');
  // Bulk load: skip triggers/FK checks (data is generated consistent).
  await c.query('SET LOCAL session_replication_role = replica');
  // Remove a previous run. FK cascades do NOT fire under replica mode, so
  // every table is cleared explicitly (children first) to avoid orphans.
  await c.query(`CREATE TEMP TABLE old_bench ON COMMIT DROP AS SELECT id FROM app.tenants WHERE slug LIKE 'bench-%'`);
  for (const table of ['task_comments', 'tasks', 'projects', 'tenant_invitations', 'tenant_memberships', 'tenant_counters', 'audit_log']) {
    await c.query(`DELETE FROM app.${table} WHERE tenant_id IN (SELECT id FROM old_bench)`);
  }
  await c.query('DELETE FROM app.tenants WHERE id IN (SELECT id FROM old_bench)');
  await c.query(`DELETE FROM app.users WHERE email LIKE '%@bench.test'`);
  await c.query(`
    INSERT INTO app.tenants (slug, name, plan)
    SELECT 'bench-' || g, 'Bench tenant ' || g, (ARRAY['free','pro','enterprise'])[1 + g % 3]
    FROM generate_series(1, $1) g`, [TENANTS]);
  await c.query(`
    CREATE TEMP TABLE bt ON COMMIT DROP AS
    SELECT id, row_number() OVER (ORDER BY slug) AS n FROM app.tenants WHERE slug LIKE 'bench-%'`);
  // 5 users + 5 projects per tenant
  await c.query(`
    INSERT INTO app.users (email, display_name)
    SELECT 'u' || bt.n || '-' || k || '@bench.test', 'User ' || bt.n || '-' || k
    FROM bt, generate_series(1, 5) k`);
  await c.query(`
    INSERT INTO app.tenant_memberships (tenant_id, user_id, role)
    SELECT bt.id, u.id, CASE WHEN split_part(split_part(u.email, '-', 2), '@', 1) = '1' THEN 'owner' ELSE 'member' END
    FROM bt JOIN app.users u ON u.email LIKE 'u' || bt.n || '-%@bench.test'`);
  await c.query(`
    INSERT INTO app.projects (tenant_id, key, name)
    SELECT bt.id, 'P' || k, 'Project ' || k FROM bt, generate_series(1, 5) k`);
  // Tasks: tenant 1 is the whale (20%), the rest uniform.
  await c.query(`
    WITH members AS (
      SELECT tenant_id, array_agg(user_id) AS ids FROM app.tenant_memberships
      WHERE tenant_id IN (SELECT id FROM bt) GROUP BY tenant_id),
    projs AS (
      SELECT tenant_id, array_agg(id) AS ids FROM app.projects
      WHERE tenant_id IN (SELECT id FROM bt) GROUP BY tenant_id),
    raw AS (
      SELECT CASE WHEN random() < 0.2 THEN 1 ELSE 2 + floor(random() * ($2 - 1))::int END AS tn,
             $3::text[] AS w
      FROM generate_series(1, $1))
    INSERT INTO app.tasks (tenant_id, project_id, number, title, description, status, priority,
                           assignee_id, due_date, created_at)
    SELECT bt.id,
           p.ids[1 + floor(random() * 5)::int],
           row_number() OVER (PARTITION BY bt.id),
           initcap(raw.w[1 + floor(random() * 28)::int]) || ' ' || raw.w[1 + floor(random() * 28)::int] || ' ' || raw.w[1 + floor(random() * 28)::int],
           'Details about ' || raw.w[1 + floor(random() * 28)::int] || ' and ' || raw.w[1 + floor(random() * 28)::int],
           CASE WHEN r < 0.70 THEN 'done' WHEN r < 0.75 THEN 'cancelled' WHEN r < 0.90 THEN 'todo' ELSE 'in_progress' END,
           floor(random() * 5)::int,
           CASE WHEN random() < 0.9 THEN m.ids[1 + floor(random() * 5)::int] END,
           CASE WHEN random() < 0.6 THEN current_date + (floor(random() * 120)::int - 60) END,
           now() - random() * interval '2 years'
    FROM (SELECT raw.*, random() AS r FROM raw) raw
    JOIN bt ON bt.n = raw.tn
    JOIN members m ON m.tenant_id = bt.id
    JOIN projs p   ON p.tenant_id = bt.id`, [TASKS, TENANTS, WORDS]);
  await c.query(`
    INSERT INTO app.audit_log (tenant_id, occurred_at, table_name, record_id, action, new_data)
    SELECT tenant_id, created_at, 'tasks', id, 'INSERT', jsonb_build_object('title', title)
    FROM app.tasks WHERE tenant_id IN (SELECT id FROM bt)`);
  await c.query('COMMIT');
  await c.query('VACUUM ANALYZE app.tenants, app.users, app.tenant_memberships, app.projects, app.tasks, app.audit_log');

  const { rows: [whale] } = await c.query(`
    SELECT t.id AS tenant_id, m.user_id, (SELECT id FROM app.projects p WHERE p.tenant_id = t.id LIMIT 1) AS project_id,
           (SELECT count(*) FROM app.tasks x WHERE x.tenant_id = t.id)::int AS tasks
    FROM app.tenants t JOIN app.tenant_memberships m ON m.tenant_id = t.id AND m.role = 'owner'
    WHERE t.slug = 'bench-1'`);
  const { rows: [small] } = await c.query(`
    SELECT t.id AS tenant_id, m.user_id, (SELECT id FROM app.projects p WHERE p.tenant_id = t.id LIMIT 1) AS project_id,
           (SELECT count(*) FROM app.tasks x WHERE x.tenant_id = t.id)::int AS tasks
    FROM app.tenants t JOIN app.tenant_memberships m ON m.tenant_id = t.id AND m.role = 'owner'
    WHERE t.slug = 'bench-2'`);
  await c.end();
  console.log(`loaded ${TASKS.toLocaleString()} tasks across ${TENANTS} tenants in ${((performance.now() - t0) / 1000).toFixed(1)}s`);
  return { whale, small };
}

const QUERIES = [
  ['Board: project column', `SELECT id, number, title FROM app.tasks WHERE project_id = $1 AND status = 'todo' ORDER BY priority LIMIT 100`, (x) => [x.project_id]],
  ['My open tasks', `SELECT id, title, priority, due_date FROM app.tasks
     WHERE assignee_id = $1 AND status IN ('todo','in_progress') ORDER BY priority, due_date LIMIT 50`, (x) => [x.user_id]],
  ['Overdue dashboard', `SELECT count(*) FROM app.tasks
     WHERE status IN ('todo','in_progress') AND due_date < current_date`, () => []],
  ['Newest first (keyset page)', `SELECT id, title FROM app.tasks ORDER BY id DESC LIMIT 50`, () => []],
  ['Lookup by #number', `SELECT * FROM app.tasks WHERE number = 1234`, () => []],
  ['FTS: raw @@ under RLS', `SELECT id, title FROM app.tasks
     WHERE search @@ websearch_to_tsquery('simple', 'invoice webhook')
     ORDER BY ts_rank(search, websearch_to_tsquery('simple', 'invoice webhook')) DESC, id DESC LIMIT 50`, () => []],
  ['FTS: app.search_tasks()', `SELECT id, title FROM app.search_tasks('invoice webhook', 50)`, () => []],
  ['Audit feed', `SELECT * FROM app.audit_log ORDER BY occurred_at DESC LIMIT 50`, () => []],
];

async function explain(pool, label, ctx) {
  console.log(`\n=== ${label}: ${ctx.tasks.toLocaleString()} tasks (as app_user, RLS on) ===`);
  const client = await pool.connect();
  try {
    for (const [name, sql, params] of QUERIES) {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)", [ctx.tenant_id, ctx.user_id]);
      const { rows } = await client.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${sql}`, params(ctx));
      await client.query('ROLLBACK');
      const plan = rows[0]['QUERY PLAN'][0];
      const nodes = [];
      (function walk(n) {
        if (n['Index Name']) nodes.push(`${n['Node Type']} ${n['Index Name']}`);
        else if (n['Node Type'] === 'Seq Scan') nodes.push(`Seq Scan ${n['Relation Name']}`);
        else if (n['Node Type'] === 'Function Scan') nodes.push(`${n['Function Name']}() → GIN (tenant_id, search)`);
        (n.Plans ?? []).forEach(walk);
      })(plan.Plan);
      const scans = nodes.filter((s) => !s.includes('tenant_memberships_pkey')); // InitPlan: membership check
      const buffers = plan.Plan['Shared Hit Blocks'] + plan.Plan['Shared Read Blocks'];
      console.log(`${name.padEnd(28)} ${plan['Execution Time'].toFixed(2).padStart(8)} ms  ${String(buffers).padStart(6)} buf  ${scans.join(', ')}`);
      if (verbose) {
        const text = await client.query('BEGIN').then(() => client.query("SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)", [ctx.tenant_id, ctx.user_id]))
          .then(() => client.query(`EXPLAIN (ANALYZE, BUFFERS) ${sql}`, params(ctx)));
        await client.query('ROLLBACK');
        console.log(text.rows.map((r) => '    ' + r['QUERY PLAN']).join('\n'));
      }
    }
  } finally {
    client.release();
  }
}

const { whale, small } = await load();
const pool = new pg.Pool({ connectionString: config.appUrl, max: 1 });
await explain(pool, 'Whale tenant', whale);
await explain(pool, 'Typical tenant', small);
await pool.end();
