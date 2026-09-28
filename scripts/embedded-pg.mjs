// Run a command against a throwaway PostgreSQL — no Docker or local install.
//
//   node scripts/embedded-pg.mjs                          start and keep running (Ctrl+C to stop)
//   node scripts/embedded-pg.mjs "npm test"               start, run, stop
//   node scripts/embedded-pg.mjs "npm run db:reset && npm run bench"
//
// Uses the `embedded-postgres` package (real PostgreSQL binaries).
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const { default: EmbeddedPostgres } = await import('embedded-postgres').catch(() => {
  console.error('embedded-postgres is not installed. Run `npm install` or use Docker (see README).');
  process.exit(1);
});

const port = Number(process.env.PGPORT ?? 54329);
const dataDir = await mkdtemp(path.join(os.tmpdir(), 'saas-pg-'));
const pgServer = new EmbeddedPostgres({
  databaseDir: dataDir,
  user: 'postgres',
  password: 'postgres',
  port,
  persistent: false,
  onLog: () => {},
});

try {
  await pgServer.initialise();
  await pgServer.start();
  console.log(`embedded PostgreSQL listening on localhost:${port}`);
} catch (error) {
  console.error("❌ Failed to start embedded PostgreSQL server:");
  console.error(error);
  // Ensure we clean up the temporary directory we created
  await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  process.exit(1);
}

// Set the URLs explicitly so a developer's .env (which may point at a real
// database) can never redirect `npm test` — and its --reset — elsewhere.
const base = `localhost:${port}/saas`;
const env = {
  ...process.env,
  PGHOST: 'localhost',
  PGPORT: String(port),
  MIGRATION_DATABASE_URL: `postgres://postgres:postgres@${base}`,
  APP_DATABASE_URL: `postgres://app_user:app_user_dev_pw@${base}`,
  ADMIN_DATABASE_URL: `postgres://admin_user:admin_user_dev_pw@${base}`,
};
const command = process.argv.slice(2).join(' ');

async function shutdown(code) {
  await pgServer.stop().catch(() => {});
  await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  process.exit(code);
}

if (!command) {
  console.log(`export PGHOST=localhost PGPORT=${port}   # then run npm scripts in another shell`);
  process.on('SIGINT', () => shutdown(0));
} else {
  const child = spawn(command, { stdio: 'inherit', shell: true, env });
  child.on('error', (err) => {
    console.error('Failed to start child process:', err?.message || err);
    shutdown(1);
  });
  child.on('exit', (code) => shutdown(code ?? 1));
}
