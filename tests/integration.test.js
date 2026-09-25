import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import { generateCode, getCurrentTimeWindow } from '../src/totp.js';
import { decrypt } from '../src/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const BASE_URL = 'http://localhost:3000';
const DB_URL = 'postgresql://postgres:postgres@localhost:5432/auth_db';
const MASTER_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
process.env.MASTER_ENCRYPTION_KEY = MASTER_KEY;

test('Core Requirement 1: docker-compose.yml structure', () => {
  const composePath = path.join(rootDir, 'docker-compose.yml');
  assert.ok(fs.existsSync(composePath), 'docker-compose.yml must exist at repository root');
  const content = fs.readFileSync(composePath, 'utf8');

  assert.ok(content.includes('db:'), 'docker-compose.yml must contain db service');
  assert.ok(content.includes('app:'), 'docker-compose.yml must contain app service');
  assert.ok(content.includes('healthcheck:'), 'docker-compose.yml must define healthchecks');
  assert.ok(content.includes('service_healthy'), 'app must wait for db to be healthy');
});

test('Core Requirement 2: .env.example verification', () => {
  const envExamplePath = path.join(rootDir, '.env.example');
  assert.ok(fs.existsSync(envExamplePath), '.env.example must exist at repository root');
  const content = fs.readFileSync(envExamplePath, 'utf8');

  assert.ok(content.includes('DATABASE_URL='), '.env.example must include DATABASE_URL');
  assert.ok(content.includes('JWT_SECRET='), '.env.example must include JWT_SECRET');
  assert.ok(content.includes('MASTER_ENCRYPTION_KEY='), '.env.example must include MASTER_ENCRYPTION_KEY');
});

test('Core Requirement 12: submission.json format', () => {
  const submissionPath = path.join(rootDir, 'submission.json');
  assert.ok(fs.existsSync(submissionPath), 'submission.json must exist at repository root');
  const data = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));

  assert.ok(data.testUser, 'testUser must be defined in submission.json');
  assert.ok(data.testUser.email, 'testUser.email must be defined');
  assert.ok(data.testUser.password, 'testUser.password must be defined');
  assert.ok(data.testUser.plaintextTotpSecret, 'testUser.plaintextTotpSecret must be defined');
});

test('Core Requirement 3: Database Schema & Users Table columns', async () => {
  const pool = new pg.Pool({ connectionString: DB_URL });
  try {
    const res = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'users'
      ORDER BY ordinal_position;
    `);

    assert.ok(res.rows.length >= 8, 'users table must have at least 8 columns');
    const columnMap = new Map(res.rows.map(r => [r.column_name, r]));

    const requiredColumns = [
      'id',
      'email',
      'password_hash',
      'totp_enabled',
      'totp_secret_encrypted',
      'totp_iv',
      'totp_tag',
      'last_totp_window'
    ];

    for (const col of requiredColumns) {
      assert.ok(columnMap.has(col), `Column '${col}' must exist in users table`);
    }

    // Assert totp_enabled is boolean
    assert.equal(columnMap.get('totp_enabled').data_type, 'boolean');
    // Assert last_totp_window is integer
    assert.equal(columnMap.get('last_totp_window').data_type, 'integer');
  } finally {
    await pool.end();
  }
});

test('End-to-End API Test Suite (Requirements 4, 5, 6, 7, 8, 9, 10, 11, 12)', async (t) => {
  const pool = new pg.Pool({ connectionString: DB_URL });

  // 1. Requirement 4: Register a new user
  const uniqueEmail = `user_${Date.now()}@example.com`;
  const password = 'Password123!';

  const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: uniqueEmail, password }),
  });

  assert.equal(regRes.status, 201, 'Registration should return 201 Created');
  const regData = await regRes.json();
  assert.ok(regData.id, 'Registered user should have an id');
  assert.equal(regData.email, uniqueEmail);

  // Verify in DB that password is not plaintext
  const dbUserRes = await pool.query('SELECT * FROM users WHERE email = $1', [uniqueEmail]);
  assert.equal(dbUserRes.rows.length, 1);
  const dbUser = dbUserRes.rows[0];
  assert.notEqual(dbUser.password_hash, password, 'Password must be hashed, not plaintext');
  assert.equal(dbUser.totp_enabled, false, 'totp_enabled must default to false');

  // 2. Requirement 5: Login without 2FA
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: uniqueEmail, password }),
  });
  assert.equal(loginRes.status, 200, 'Login should return 200 OK');
  const loginData = await loginRes.json();
  assert.ok(loginData.token, 'Non-2FA login should return full access token');
  assert.equal(loginData.requires_2fa, undefined);
  const fullAccessToken = loginData.token;

  // Invalid login check
  const badLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: uniqueEmail, password: 'WrongPassword' }),
  });
  assert.equal(badLoginRes.status, 401, 'Bad credentials should return 401 Unauthorized');

  // 3. Requirement 6 & 7: 2FA Setup & Encryption at Rest
  const setupRes = await fetch(`${BASE_URL}/api/auth/2fa/setup`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${fullAccessToken}`,
    },
  });
  assert.equal(setupRes.status, 200, '2FA setup should return 200 OK');
  const setupData = await setupRes.json();
  assert.ok(setupData.secret, 'Setup must return Base32 secret');
  assert.ok(setupData.uri.startsWith('otpauth://totp/'), 'Setup must return otpauth URI');

  // Verify in DB: Encryption at rest (Requirement 7)
  const dbUserAfterSetup = (await pool.query('SELECT * FROM users WHERE email = $1', [uniqueEmail])).rows[0];
  assert.equal(dbUserAfterSetup.totp_enabled, false, 'totp_enabled must remain false until verified');
  assert.ok(dbUserAfterSetup.totp_secret_encrypted, 'totp_secret_encrypted must be set');
  assert.ok(dbUserAfterSetup.totp_iv, 'totp_iv must be set');
  assert.ok(dbUserAfterSetup.totp_tag, 'totp_tag must be set');
  assert.notEqual(dbUserAfterSetup.totp_secret_encrypted, setupData.secret, 'Ciphertext must not match plaintext');
  assert.equal(dbUserAfterSetup.totp_secret_encrypted.includes(setupData.secret), false, 'Ciphertext must not contain plaintext');

  // Verify decrypted secret matches
  const decrypted = decrypt(dbUserAfterSetup.totp_iv, dbUserAfterSetup.totp_secret_encrypted, dbUserAfterSetup.totp_tag);
  assert.equal(decrypted, setupData.secret, 'Decrypted secret must match generated secret');

  // 4. Requirement 8: Verify 2FA to activate it
  const currentWindow = getCurrentTimeWindow(Date.now(), 30);
  const validCode = generateCode(setupData.secret, currentWindow);

  const verifyRes = await fetch(`${BASE_URL}/api/auth/2fa/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${fullAccessToken}`,
    },
    body: JSON.stringify({ code: validCode }),
  });
  assert.equal(verifyRes.status, 200, '2FA verify should return 200 OK');
  const verifyData = await verifyRes.json();
  assert.equal(verifyData.message, '2FA successfully enabled');

  // Verify in DB that totp_enabled is now true
  const dbUserAfterVerify = (await pool.query('SELECT * FROM users WHERE email = $1', [uniqueEmail])).rows[0];
  assert.equal(dbUserAfterVerify.totp_enabled, true, 'totp_enabled must now be true');

  // 5. Requirement 5 & 10: Login with 2FA enabled returns challenge_token only
  const login2FARes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: uniqueEmail, password }),
  });
  assert.equal(login2FARes.status, 200);
  const login2FAData = await login2FARes.json();
  assert.equal(login2FAData.requires_2fa, true, 'Must indicate 2FA is required');
  assert.ok(login2FAData.challenge_token, 'Must return challenge_token');
  assert.equal(login2FAData.token, undefined, 'Must NOT return full access token');

  const challengeToken = login2FAData.challenge_token;

  // Requirement 10: Strict enforcement - attempt to use challenge token on protected routes
  const bypassRes = await fetch(`${BASE_URL}/api/protected`, {
    headers: { 'Authorization': `Bearer ${challengeToken}` },
  });
  assert.ok([401, 403].includes(bypassRes.status), 'Challenge token must be rejected on protected routes');

  const bypassSetupRes = await fetch(`${BASE_URL}/api/auth/2fa/setup`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${challengeToken}` },
  });
  assert.ok([401, 403].includes(bypassSetupRes.status), 'Challenge token must be rejected on 2fa setup route');

  // 6. Requirement 9: Complete 2FA login with valid code
  // Generate code for next window if current was used in verify or use current
  const codeForLogin = generateCode(setupData.secret, currentWindow + 1);

  // Test invalid code first
  const invalidCodeRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_token: challengeToken, code: '000000' }),
  });
  assert.equal(invalidCodeRes.status, 401, 'Invalid TOTP code should return 401 Unauthorized');

  // Test valid code
  const valid2FALoginRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_token: challengeToken, code: codeForLogin }),
  });
  assert.equal(valid2FALoginRes.status, 200, 'Valid 2FA login must return 200 OK');
  const valid2FALoginData = await valid2FALoginRes.json();
  assert.ok(valid2FALoginData.token, 'Should return full access token');

  // 7. Requirement 11: Replay protection
  // Immediately resend identical request with same challenge_token and code
  const replayRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_token: challengeToken, code: codeForLogin }),
  });
  assert.equal(replayRes.status, 401, 'Replayed code must return 401 Unauthorized');

  // Verify in DB that last_totp_window matches the code's window
  const dbUserAfterLogin = (await pool.query('SELECT last_totp_window FROM users WHERE email = $1', [uniqueEmail])).rows[0];
  assert.equal(dbUserAfterLogin.last_totp_window, currentWindow + 1, 'last_totp_window must be updated in DB');

  // 8. Requirement 12: Seeded test user verification from submission.json
  const submission = JSON.parse(fs.readFileSync(path.join(rootDir, 'submission.json'), 'utf8'));
  const testUser = submission.testUser;

  // Login with seeded user credentials
  const seedLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testUser.email, password: testUser.password }),
  });
  assert.equal(seedLoginRes.status, 200, 'Seeded user login should return 200');
  const seedLoginData = await seedLoginRes.json();
  assert.equal(seedLoginData.requires_2fa, true, 'Seeded user must require 2FA');
  assert.ok(seedLoginData.challenge_token, 'Seeded user must receive challenge token');

  // Generate live code using testUser.plaintextTotpSecret
  const liveWindow = getCurrentTimeWindow(Date.now(), 30);
  const seedLiveCode = generateCode(testUser.plaintextTotpSecret, liveWindow);
  const seed2FALoginRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challenge_token: seedLoginData.challenge_token,
      code: seedLiveCode,
    }),
  });
  assert.equal(seed2FALoginRes.status, 200, 'Seeded user 2FA login must succeed with live TOTP code');
  const seedFinalData = await seed2FALoginRes.json();
  assert.ok(seedFinalData.token, 'Seeded user must receive full access token');

  // Check access to protected route with full token
  const protectedRes = await fetch(`${BASE_URL}/api/protected`, {
    headers: { 'Authorization': `Bearer ${seedFinalData.token}` },
  });
  assert.equal(protectedRes.status, 200, 'Full token should grant access to protected route');

  await pool.end();
});
