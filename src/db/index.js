import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/auth_db';

export const pool = new Pool({
  connectionString,
});

/**
 * Execute a query with the pool.
 * @param {string} text - SQL query text
 * @param {Array} [params] - Query parameters
 * @returns {Promise<pg.QueryResult>}
 */
export async function query(text, params) {
  return pool.query(text, params);
}

/**
 * Get a client from the pool with transaction helper.
 * @returns {Promise<pg.PoolClient>}
 */
export async function getClient() {
  return pool.connect();
}
