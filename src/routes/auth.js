import express from 'express';
import bcrypt from 'bcryptjs';
import { query, getClient } from '../db/index.js';
import { encrypt, decrypt } from '../crypto.js';
import {
  generateSecret,
  verifyTotp,
  generateOtpAuthUri,
} from '../totp.js';
import {
  generateFullAccessToken,
  generateChallengeToken,
  verifyToken,
  requireFullAuth,
} from '../auth.js';

export const authRouter = express.Router();

/**
 * POST /api/auth/register
 * Registers a new user with hashed password.
 */
authRouter.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Check if email already exists
    const existing = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await query(
      `INSERT INTO users (email, password_hash, totp_enabled)
       VALUES ($1, $2, false)
       RETURNING id, email`,
      [email.toLowerCase().trim(), passwordHash]
    );

    const newUser = result.rows[0];
    return res.status(201).json({
      id: newUser.id,
      email: newUser.email,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/login
 * Validates credentials and branches response based on totp_enabled.
 */
authRouter.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const result = await query(
      'SELECT id, email, password_hash, totp_enabled FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // If 2FA is enabled, issue challenge token only
    if (user.totp_enabled) {
      const challengeToken = generateChallengeToken(user);
      return res.status(200).json({
        requires_2fa: true,
        challenge_token: challengeToken,
      });
    }

    // 2FA not enabled: issue full access token
    const token = generateFullAccessToken(user);
    return res.status(200).json({ token });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/2fa/setup
 * Generates Base32 secret and OTPAuth URI, encrypts secret at rest.
 */
authRouter.post('/2fa/setup', requireFullAuth, async (req, res, next) => {
  try {
    const userId = req.user.userId;

    // Fetch user email to populate URI
    const userRes = await query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userEmail = userRes.rows[0].email;

    // Generate fresh Base32 secret (20 bytes)
    const secret = generateSecret(20);

    // Encrypt secret with AES-256-GCM
    const encrypted = encrypt(secret);

    // Store encrypted secret parameters in database. totp_enabled remains false until verified.
    await query(
      `UPDATE users SET 
        totp_secret_encrypted = $1,
        totp_iv = $2,
        totp_tag = $3,
        totp_enabled = false
       WHERE id = $4`,
      [encrypted.ciphertext, encrypted.iv, encrypted.authTag, userId]
    );

    // Construct otpauth URI
    const uri = generateOtpAuthUri({
      secret,
      email: userEmail,
      issuer: 'YourAppName',
    });

    return res.status(200).json({
      secret,
      uri,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/2fa/verify
 * Confirms user has configured TOTP authenticator and enables 2FA.
 */
authRouter.post('/2fa/verify', requireFullAuth, async (req, res, next) => {
  try {
    const { code } = req.body || {};
    const userId = req.user.userId;

    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
      return res.status(400).json({ error: 'Valid 6-digit numeric TOTP code is required' });
    }

    const userRes = await query(
      'SELECT id, totp_secret_encrypted, totp_iv, totp_tag, totp_enabled FROM users WHERE id = $1',
      [userId]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRes.rows[0];
    if (!user.totp_secret_encrypted || !user.totp_iv || !user.totp_tag) {
      return res.status(400).json({ error: '2FA setup has not been initiated' });
    }

    // Decrypt the stored secret
    let plaintextSecret;
    try {
      plaintextSecret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);
    } catch (decryptErr) {
      return res.status(500).json({ error: 'Failed to decrypt TOTP secret' });
    }

    // Verify code with drift window
    const { valid, matchedWindow } = verifyTotp(plaintextSecret, code.trim(), { window: 1 });

    if (!valid) {
      return res.status(400).json({ error: 'Invalid TOTP code' });
    }

    // Enable 2FA and record matched window for replay prevention
    await query(
      'UPDATE users SET totp_enabled = true, last_totp_window = $1 WHERE id = $2',
      [matchedWindow, userId]
    );

    return res.status(200).json({
      message: '2FA successfully enabled',
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/2fa/login
 * Validates TOTP code against challenge token, checks replay, and issues full access token.
 */
authRouter.post('/2fa/login', async (req, res, next) => {
  const challengeToken =
    req.body?.challenge_token ||
    (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);
  const code = req.body?.code;

  if (!challengeToken) {
    return res.status(401).json({ error: 'Challenge token is required' });
  }

  if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    return res.status(401).json({ error: 'Valid 6-digit numeric TOTP code is required' });
  }

  let decoded;
  try {
    decoded = verifyToken(challengeToken);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired challenge token' });
  }

  if (decoded.scope !== '2fa_challenge' || !decoded.userId) {
    return res.status(401).json({ error: 'Invalid challenge token scope' });
  }

  const client = await getClient();
  try {
    await client.query('BEGIN');

    // Lock user row to eliminate race conditions for replay attacks
    const userRes = await client.query(
      'SELECT id, email, totp_enabled, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window FROM users WHERE id = $1 FOR UPDATE',
      [decoded.userId]
    );

    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'User not found' });
    }

    const user = userRes.rows[0];

    if (!user.totp_enabled || !user.totp_secret_encrypted) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: '2FA is not enabled for this user' });
    }

    // Decrypt the stored secret
    let plaintextSecret;
    try {
      plaintextSecret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);
    } catch (decryptErr) {
      await client.query('ROLLBACK');
      return res.status(500).json({ error: 'Failed to decrypt TOTP secret' });
    }

    // Verify TOTP code
    const { valid, matchedWindow } = verifyTotp(plaintextSecret, code.trim(), { window: 1 });

    if (!valid || matchedWindow === null) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Invalid TOTP code' });
    }

    // Enforce Replay Protection:
    // If matchedWindow <= last_totp_window, reject as replay attack
    if (user.last_totp_window !== null && matchedWindow <= user.last_totp_window) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Replay detected: TOTP code has already been used' });
    }

    // Update last_totp_window to matchedWindow
    await client.query(
      'UPDATE users SET last_totp_window = $1 WHERE id = $2',
      [matchedWindow, user.id]
    );

    await client.query('COMMIT');

    const token = generateFullAccessToken(user);
    return res.status(200).json({ token });
  } catch (err) {
    await client.query('ROLLBACK');
    next(err);
  } finally {
    client.release();
  }
});

/**
 * GET /api/auth/me (Protected resource)
 * Verifies that full access token is valid and rejects challenge tokens.
 */
authRouter.get('/me', requireFullAuth, (req, res) => {
  return res.status(200).json({
    user: {
      id: req.user.userId,
      email: req.user.email,
    },
  });
});
