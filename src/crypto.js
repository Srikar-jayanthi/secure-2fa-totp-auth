import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 12 bytes is the standard for AES-GCM

/**
 * Retrieves the 32-byte master key from the environment.
 * @returns {Buffer}
 */
export function getMasterKey() {
  const keyHex = process.env.MASTER_ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error('MASTER_ENCRYPTION_KEY environment variable is not set');
  }
  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error(`MASTER_ENCRYPTION_KEY must be a 32-byte (64 hex characters) hex string. Received ${keyBuffer.length} bytes.`);
  }
  return keyBuffer;
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Generates a fresh random 12-byte IV for every encryption call.
 * 
 * @param {string} plaintext - The secret string to encrypt (e.g. base32 TOTP secret).
 * @returns {{ iv: string, ciphertext: string, authTag: string }} Hex-encoded values.
 */
export function encrypt(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string');
  }

  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  return {
    iv: iv.toString('hex'),
    ciphertext,
    authTag,
  };
}

/**
 * Decrypts an AES-256-GCM encrypted payload.
 * Accepts either (iv, ciphertext, authTag) or an object { iv, ciphertext, authTag }.
 * 
 * @param {string|object} ivHexOrPayload - IV in hex, or payload object
 * @param {string} [ciphertextHex] - Ciphertext in hex
 * @param {string} [authTagHex] - Auth tag in hex
 * @returns {string} The decrypted plaintext string
 * @throws {Error} If authentication fails or tampering is detected
 */
export function decrypt(ivHexOrPayload, ciphertextHex, authTagHex) {
  let iv, ciphertext, authTag;

  if (typeof ivHexOrPayload === 'object' && ivHexOrPayload !== null) {
    iv = ivHexOrPayload.iv;
    ciphertext = ivHexOrPayload.ciphertext;
    authTag = ivHexOrPayload.authTag;
  } else {
    iv = ivHexOrPayload;
    ciphertext = ciphertextHex;
    authTag = authTagHex;
  }

  if (!iv || !ciphertext || !authTag) {
    throw new Error('Missing required encryption parameters: iv, ciphertext, and authTag are all required');
  }

  const masterKey = getMasterKey();
  const ivBuffer = Buffer.from(iv, 'hex');
  const authTagBuffer = Buffer.from(authTag, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, ivBuffer);
  decipher.setAuthTag(authTagBuffer);

  let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');

  return plaintext;
}
