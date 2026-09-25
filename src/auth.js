import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret-key-change-me';

/**
 * Generates a full access JWT for an authenticated user.
 * @param {object} user - User object containing id and email
 * @param {string} [expiresIn='1h']
 * @returns {string} JWT string
 */
export function generateFullAccessToken(user, expiresIn = '1h') {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      scope: 'full_access',
    },
    process.env.JWT_SECRET || JWT_SECRET,
    { expiresIn }
  );
}

/**
 * Generates a restricted, short-lived challenge token for 2FA pending state.
 * @param {object} user - User object containing id
 * @param {string} [expiresIn='5m']
 * @returns {string} JWT string
 */
export function generateChallengeToken(user, expiresIn = '5m') {
  return jwt.sign(
    {
      userId: user.id,
      scope: '2fa_challenge',
    },
    process.env.JWT_SECRET || JWT_SECRET,
    { expiresIn }
  );
}

/**
 * Verifies a JWT token with the secret.
 * @param {string} token 
 * @returns {object} Decoded payload
 */
export function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET || JWT_SECRET);
}

/**
 * Middleware ensuring the request contains a valid Full Access token.
 * Rejects challenge tokens, expired tokens, or missing tokens.
 */
export function requireFullAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header with Bearer token is required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = verifyToken(token);

    // Challenge tokens must never be allowed on protected routes
    if (decoded.scope === '2fa_challenge') {
      return res.status(403).json({ error: 'Forbidden: Challenge token cannot access protected resources' });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired access token' });
  }
}
