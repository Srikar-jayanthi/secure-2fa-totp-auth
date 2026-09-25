import crypto from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encodes a buffer to a Base32 string without padding.
 * @param {Buffer} buffer 
 * @returns {string}
 */
export function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodes a Base32 string into a Buffer.
 * Handles padding, whitespace, and case insensitivity.
 * @param {string} input 
 * @returns {Buffer}
 */
export function base32Decode(input) {
  const cleanInput = input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleanInput.length; i++) {
    const char = cleanInput[i];
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${char}`);
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generates a cryptographically secure random Base32 secret.
 * @param {number} lengthBytes - Default 20 bytes (160 bits, standard for TOTP SHA-1)
 * @returns {string} Base32 encoded secret
 */
export function generateSecret(lengthBytes = 20) {
  const randomBytes = crypto.randomBytes(lengthBytes);
  return base32Encode(randomBytes);
}

/**
 * Calculates the TOTP code for a specific time window.
 * 
 * @param {string} base32Secret 
 * @param {number} timeWindow - Epoch window integer (floor(epoch_seconds / period))
 * @param {number} digits - Default 6
 * @returns {string} 6-digit numeric string
 */
export function generateCode(base32Secret, timeWindow, digits = 6) {
  const secretBytes = base32Decode(base32Secret);

  // Time window as an 8-byte big-endian buffer
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigUInt64BE(BigInt(timeWindow));

  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', secretBytes).update(timeBuffer).digest();

  // Dynamic truncation (RFC 4226)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Gets the current time window for a given timestamp and period.
 * 
 * @param {number} timestampMs - Timestamp in milliseconds (defaults to Date.now())
 * @param {number} period - Time period in seconds (default 30)
 * @returns {number} Integer time window
 */
export function getCurrentTimeWindow(timestampMs = Date.now(), period = 30) {
  return Math.floor(timestampMs / 1000 / period);
}

/**
 * Securely compares two strings in constant time to prevent timing attacks.
 * 
 * @param {string} a 
 * @param {string} b 
 * @returns {boolean}
 */
export function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Verifies a user-provided TOTP code against a Base32 secret.
 * Checks clock drift (-driftWindow to +driftWindow, default 1: [-1, 0, 1]).
 * 
 * @param {string} base32Secret 
 * @param {string} userCode - User supplied 6-digit code
 * @param {object} options
 * @param {number} [options.window=1] - Number of time steps to check backward and forward
 * @param {number} [options.period=30] - Step size in seconds
 * @param {number} [options.timestampMs=Date.now()] - Current timestamp
 * @returns {{ valid: boolean, matchedWindow: number|null }}
 */
export function verifyTotp(base32Secret, userCode, options = {}) {
  const {
    window = 1,
    period = 30,
    timestampMs = Date.now(),
  } = options;

  if (typeof userCode !== 'string' || !/^\d{6}$/.test(userCode.trim())) {
    return { valid: false, matchedWindow: null };
  }

  const cleanCode = userCode.trim();
  const currentWindow = getCurrentTimeWindow(timestampMs, period);

  for (let offset = -window; offset <= window; offset++) {
    const checkWindow = currentWindow + offset;
    const expectedCode = generateCode(base32Secret, checkWindow);

    if (safeCompare(cleanCode, expectedCode)) {
      return {
        valid: true,
        matchedWindow: checkWindow,
      };
    }
  }

  return {
    valid: false,
    matchedWindow: null,
  };
}

/**
 * Constructs an otpauth:// URI for QR code generation and authenticator apps.
 * 
 * Format:
 * otpauth://totp/Issuer:user@example.com?secret=BASE32SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
 * 
 * @param {object} params
 * @param {string} params.secret - Base32 secret
 * @param {string} params.email - User email
 * @param {string} [params.issuer='Secure2FA'] - Service name
 * @param {number} [params.period=30]
 * @param {number} [params.digits=6]
 * @param {string} [params.algorithm='SHA1']
 * @returns {string} otpauth URI
 */
export function generateOtpAuthUri({
  secret,
  email,
  issuer = 'YourAppName',
  period = 30,
  digits = 6,
  algorithm = 'SHA1',
}) {
  return `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}&algorithm=${algorithm}&digits=${digits}&period=${period}`;
}
