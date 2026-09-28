// Minimal, dependency-free migration runner.
//
//   node scripts/migrate.mjs            bootstrap + apply pending migrations
//   node scripts/migrate.mjs --reset    drop the app schema first (local DBs only)
//   node scripts/migrate.mjs --seed     load db/seed.sql afterwards
//
// Each migration runs in its own transaction as saas_owner, so every object
// it creates is owned by saas_owner (not by the superuser running this).
// Applied migrations are checksummed: editing one after it ran is an error —
// write a new migration instead.
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import pg from 'pg';
import { config, assertDisposableDatabase } from '../src/config.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const MIGRATION_LOCK = 72_100_001; // pg_advisory_lock key: one runner at a time

// Runtime limits for the app's login role. Set on the LOGIN role because
// role-level settings on group roles are not inherited.
const APP_ROLE_SETTINGS = {
  statement_timeout: '15s',
  lock_timeout: '5s',
  idle_in_transaction_session_timeout: '30s', // a crashed request can't hold locks/connections forever
};

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

async function ensureDatabase(url) {
  const dbName = decodeURIComponent(new URL(url).pathname.slice(1));
  const maint = new URL(url);
  maint.pathname = '/postgres';
  const client = new pg.Client({ connectionString: maint.toString() });
  await client.connect();
  try {
    const { rowCount } = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
    if (!rowCount) {
      await client.query(`CREATE DATABASE ${pg.escapeIdentifier(dbName)}`);
      console.log(`created database ${dbName}`);
    }
  } finally {
    await client.end();
  }
}

function loginRoleFromUrl(url) {
  const u = new URL(url);
  return { name: decodeURIComponent(u.username), password: decodeURIComponent(u.password) };
}

async function ensureLoginRole(client, { name, password }, { groupRole, bypassRls, settings = {} }) {
  if (!name || !password) throw new Error(`login role for ${groupRole} needs a username and password in its URL`);
  const { rows: [existing] } = await client.query(
    'SELECT rolsuper, rolname = current_user AS is_me FROM pg_roles WHERE rolname = $1', [name]);
  // Misconfiguration guard: pointing APP_DATABASE_URL at the superuser would
  // otherwise make us strip (or grant) attributes on the wrong account.
  if (existing?.rolsuper || existing?.is_me) {
    throw new Error(`refusing to manage "${name}" as the ${groupRole} login: it is a superuser or the migration user`);
  }
  const verb = existing ? 'ALTER' : 'CREATE';
  const attrs = `LOGIN ${bypassRls ? 'BYPASSRLS' : 'NOBYPASSRLS'} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION`;
  const { rows: [{ sql }] } = await client.query(
    `SELECT format('${verb} ROLE %I ${attrs} PASSWORD %L', $1::text, $2::text) AS sql`, [name, password]);
  await client.query(sql);
  await client.query(`GRANT ${groupRole} TO ${pg.escapeIdentifier(name)}`);
  for (const [key, value] of Object.entries(settings)) {
    await client.query(`ALTER ROLE ${pg.escapeIdentifier(name)} SET ${key} = ${pg.escapeLiteral(value)}`);
  }
}

async function main() {
  if (args.has('--reset')) assertDisposableDatabase(config.migrationUrl, 'reset the schema');

  const appRole = loginRoleFromUrl(config.appUrl);
  const adminRole = loginRoleFromUrl(config.adminUrl);
  if (appRole.name === adminRole.name) {
    throw new Error('APP_DATABASE_URL and ADMIN_DATABASE_URL must use different users (the admin role bypasses RLS)');
  }

  await ensureDatabase(config.migrationUrl);
  const client = new pg.Client({ connectionString: config.migrationUrl });
  await client.connect();
  client.on('notice', (n) => { if (n.severity !== 'NOTICE') console.log(n.message); });

  try {
    const { rows: [{ v }] } = await client.query("SELECT current_setting('server_version_num')::int AS v");
    if (v < 150000) throw new Error(`PostgreSQL 15+ required (ON DELETE SET NULL (col)); server is ${v}`);

    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK]);

    if (args.has('--reset')) {
      await client.query('DROP SCHEMA IF EXISTS app CASCADE; DROP TABLE IF EXISTS public.schema_migrations;');
      console.log('reset: dropped schema app');
    }

    await client.query(await readFile(path.join(root, 'db/bootstrap.sql'), 'utf8'));
    await ensureLoginRole(client, appRole, { groupRole: 'saas_app', bypassRls: false, settings: APP_ROLE_SETTINGS });
    await ensureLoginRole(client, adminRole, { groupRole: 'saas_admin', bypassRls: true });

    await client.query(`CREATE TABLE IF NOT EXISTS public.schema_migrations (
      version text PRIMARY KEY, checksum text, applied_at timestamptz NOT NULL DEFAULT now())`);
    await client.query('ALTER TABLE public.schema_migrations ADD COLUMN IF NOT EXISTS checksum text');
    const applied = new Map((await client.query('SELECT version, checksum FROM public.schema_migrations')).rows
      .map((r) => [r.version, r.checksum]));

    const dir = path.join(root, 'db/migrations');
    const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      const sql = await readFile(path.join(dir, file), 'utf8');
      const checksum = sha256(sql.replace(/\r\n/g, '\n'));
      if (applied.has(file)) {
        const recorded = applied.get(file);
        if (recorded && recorded !== checksum) {
          throw new Error(`${file} was modified after it was applied. Revert it and add a new migration instead.`);
        }
        continue;
      }
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL ROLE saas_owner');
        await client.query(sql);
        await client.query('RESET ROLE');
        await client.query('INSERT INTO public.schema_migrations (version, checksum) VALUES ($1, $2)', [file, checksum]);
        await client.query('COMMIT');
        console.log(`applied ${file}`);
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`${file}: ${err.message}`, { cause: err });
      }
    }

    if (args.has('--seed')) {
      await client.query('BEGIN');
      await client.query(await readFile(path.join(root, 'db/seed.sql'), 'utf8'));
      await client.query('COMMIT');
      console.log('seeded demo data');
    }
  } finally {
    await client.end(); // also releases the advisory lock
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
