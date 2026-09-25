import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { generateCode, getCurrentTimeWindow } from '../src/totp.js';
import { decrypt } from '../src/crypto.js';

const BASE_URL = 'http://localhost:3000';
const DB_URL = 'postgresql://postgres:postgres@localhost:5432/auth_db';
const MASTER_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
process.env.MASTER_ENCRYPTION_KEY = MASTER_KEY;

test('System Architecture & State Machine Verification (Diagram 1 & Diagram 2)', async () => {
  const pool = new pg.Pool({ connectionString: DB_URL });

  try {
    const email = `state_test_${Date.now()}@example.com`;
    const password = 'TestPassword123!';

    // Step 0: Register and enable 2FA for state flow testing
    const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    assert.equal(regRes.status, 201);

    const initialLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const { token: setupToken } = await initialLoginRes.json();

    const setupRes = await fetch(`${BASE_URL}/api/auth/2fa/setup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${setupToken}`,
      },
    });
    const { secret } = await setupRes.json();

    // Verify critical constraint from Diagram 1: Base32 secret NEVER enters Storage Layer in plaintext
    const dbRow = (await pool.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    assert.notEqual(dbRow.totp_secret_encrypted, secret, 'Encrypted secret must not equal plaintext');
    assert.equal(dbRow.totp_secret_encrypted.includes(secret), false, 'Encrypted secret must not contain plaintext');
    assert.ok(dbRow.totp_iv, 'IV must be stored');
    assert.ok(dbRow.totp_tag, 'Auth tag must be stored');

    // Confirm that decrypting with Master Key reproduces the exact secret (Diagram 1 steps 5, 6, 7)
    const decryptedSecret = decrypt(dbRow.totp_iv, dbRow.totp_secret_encrypted, dbRow.totp_tag);
    assert.equal(decryptedSecret, secret, 'Decrypted secret must match original secret');

    // Enable 2FA
    const currentWindow = getCurrentTimeWindow(Date.now(), 30);
    const verifyCode = generateCode(secret, currentWindow);
    const verifyRes = await fetch(`${BASE_URL}/api/auth/2fa/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${setupToken}`,
      },
      body: JSON.stringify({ code: verifyCode }),
    });
    assert.equal(verifyRes.status, 200);

    // ==========================================
    // DIAGRAM 2: STATE MACHINE TRANSITION TESTS
    // ==========================================

    // Transition 1: Unauthenticated -> "Invalid Password (401)" -> Unauthenticated
    const invalidPwRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'WrongPassword!' }),
    });
    assert.equal(invalidPwRes.status, 401, 'Invalid password must return 401 Unauthorized');

    // Transition 2: Unauthenticated -> "Valid Password Submitted" -> ChallengePending
    const validLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    assert.equal(validLoginRes.status, 200);
    const loginData = await validLoginRes.json();
    assert.equal(loginData.requires_2fa, true, 'Must transition to ChallengePending');
    assert.ok(loginData.challenge_token, 'Must issue short-lived challenge token');
    const challengeToken = loginData.challenge_token;

    // Transition 3: ChallengePending -> "Challenge Token Expired" -> Unauthenticated (401)
    // Create an expired challenge token to verify state rejection
    const expiredChallengeToken = jwt.sign(
      { userId: dbRow.id, scope: '2fa_challenge' },
      process.env.JWT_SECRET || 'super-secret-jwt-key-for-2fa-auth-2025',
      { expiresIn: '-1s' } // Expired 1 second ago
    );
    const expiredRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: expiredChallengeToken,
        code: generateCode(secret, currentWindow + 1),
      }),
    });
    assert.equal(expiredRes.status, 401, 'Expired challenge token must return 401 Unauthorized');

    // Transition 4: ChallengePending -> Invalid Code -> 401 (Stays in ChallengePending)
    const invalidCodeRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: challengeToken,
        code: '999999',
      }),
    });
    assert.equal(invalidCodeRes.status, 401, 'Invalid code must return 401');

    // Transition 5: ChallengePending -> "Valid TOTP Code (200 OK)" -> Authenticated
    const validCode = generateCode(secret, currentWindow + 1);
    const valid2FARes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: challengeToken,
        code: validCode,
      }),
    });
    assert.equal(valid2FARes.status, 200, 'Valid TOTP code must return 200 OK');
    const { token: sessionToken } = await valid2FARes.json();
    assert.ok(sessionToken, 'Must issue full session token upon successful authentication');

    // Transition 6: ChallengePending -> "Replayed Code (401)" -> Rejection
    const replayRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: challengeToken,
        code: validCode,
      }),
    });
    assert.equal(replayRes.status, 401, 'Replayed TOTP code must return 401 Unauthorized');
  } finally {
    await pool.end();
  }
});
