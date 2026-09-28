import pg from 'pg';
import { config } from './config.mjs';

export function createAppPool(options = {}) {
  return new pg.Pool({ connectionString: config.appUrl, max: 10, ...options });
}

/**
 * Run `fn` inside a transaction scoped to one tenant + user.
 *
 * This is the ONLY way application code should touch tenant data.
 *
 *  - Context is set with set_config(..., is_local = true): it dies with the
 *    transaction, so a pooled connection (or PgBouncer in transaction mode)
 *    can never carry tenant A's context into tenant B's request.
 *  - tenantId must come from something the server verified (session, signed
 *    JWT claim, subdomain lookup). The database re-checks membership anyway:
 *    a user who is not a member of tenantId sees zero rows.
 *
 * @template T
 * @param {pg.Pool} pool
 * @param {{ tenantId?: string | null, userId?: string | null }} ctx
 * @param {(client: pg.PoolClient) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withTenant(pool, { tenantId = null, userId = null }, fn) {
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query('BEGIN');
    await client.query(
      "SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)",
      [tenantId ?? '', userId ?? ''],
    );
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    // If even ROLLBACK fails, the connection's state is unknown (it may still
    // be inside this tenant's transaction): destroy it instead of pooling it.
    await client.query('ROLLBACK').catch(() => { broken = true; });
    throw err;
  } finally {
    client.release(broken);
  }
}

/** Pre-tenant calls (tenant switcher, signup): user context only. */
export function withUser(pool, userId, fn) {
  return withTenant(pool, { tenantId: null, userId }, fn);
}
