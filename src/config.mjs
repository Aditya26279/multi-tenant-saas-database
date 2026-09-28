// Connection settings. Three URLs = three privilege levels; never give the
// web tier anything but APP_DATABASE_URL.

// Load .env if present. Variables already set in the environment win.
try {
  process.loadEnvFile();
} catch {
  // no .env file — fine
}

const host = process.env.PGHOST ?? 'localhost';
const port = process.env.PGPORT ?? '5432';
const db = process.env.PGDATABASE ?? 'saas';

export const config = {
  // superuser / DBA: bootstrap + migrations only
  migrationUrl: process.env.MIGRATION_DATABASE_URL ?? `postgres://postgres:postgres@${host}:${port}/${db}`,
  // runtime application role (member of saas_app, RLS enforced)
  appUrl: process.env.APP_DATABASE_URL ?? `postgres://app_user:app_user_dev_pw@${host}:${port}/${db}`,
  // support / back-office role (member of saas_admin, bypasses RLS)
  adminUrl: process.env.ADMIN_DATABASE_URL ?? `postgres://admin_user:admin_user_dev_pw@${host}:${port}/${db}`,
};

/**
 * Guard for destructive dev tooling (--reset, bench data loads).
 * Only local databases qualify, unless ALLOW_DESTRUCTIVE_DB=1 is set
 * explicitly; NODE_ENV=production always refuses.
 */
export function assertDisposableDatabase(url, action) {
  const { hostname } = new URL(url);
  const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(hostname);
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`refusing to ${action}: NODE_ENV=production`);
  }
  if (!local && process.env.ALLOW_DESTRUCTIVE_DB !== '1') {
    throw new Error(
      `refusing to ${action} on ${hostname}: only local databases are allowed ` +
      '(set ALLOW_DESTRUCTIVE_DB=1 to override for a disposable remote database; never in production)',
    );
  }
}
