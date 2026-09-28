import pg from 'pg';
import { config } from '../src/config.mjs';

export const T = {
  acme: '10000000-0000-7000-8000-000000000001',
  globex: '10000000-0000-7000-8000-000000000002',
};
export const U = {
  alice: '20000000-0000-7000-8000-000000000001', // acme owner
  bob: '20000000-0000-7000-8000-000000000002', // acme member
  carol: '20000000-0000-7000-8000-000000000003', // acme viewer
  dave: '20000000-0000-7000-8000-000000000004', // globex owner
  erin: '20000000-0000-7000-8000-000000000005', // acme admin + globex member
};
export const P = {
  acmeWeb: '30000000-0000-7000-8000-000000000001',
  acmeOps: '30000000-0000-7000-8000-000000000002',
  globexRnd: '30000000-0000-7000-8000-000000000003',
};
export const TASK = {
  acmeLanding: '40000000-0000-7000-8000-000000000001',
  globexSecret: '40000000-0000-7000-8000-000000000004',
};
export const COMMENT = {
  bobOnLanding: '50000000-0000-7000-8000-000000000001',
};

export const appPool = new pg.Pool({ connectionString: config.appUrl, max: 2 });
export const adminPool = new pg.Pool({ connectionString: config.adminUrl, max: 1 });

/**
 * Run fn in a transaction with the given context and ALWAYS roll back,
 * so every test starts from the seeded state.
 */
export async function scoped(ctx, fn, pool = appPool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      "SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)",
      [ctx.tenant ?? '', ctx.user ?? ''],
    );
    return await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

export const rows = (ctx, sql, params) => scoped(ctx, (c) => c.query(sql, params).then((r) => r.rows));
export const exec = (ctx, sql, params) => scoped(ctx, (c) => c.query(sql, params));
