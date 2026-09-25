import test from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt } from '../src/crypto.js';
import {
  base32Encode,
  base32Decode,
  generateSecret,
  generateCode,
  getCurrentTimeWindow,
  verifyTotp,
  generateOtpAuthUri,
  safeCompare,
} from '../src/totp.js';

// Set test environment variable
process.env.MASTER_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

test('AES-256-GCM Encryption and Decryption', () => {
  const secret = 'JBSWY3DPEHPK3PXP';
  const encrypted1 = encrypt(secret);

  assert.ok(encrypted1.iv, 'IV should exist');
  assert.ok(encrypted1.ciphertext, 'Ciphertext should exist');
  assert.ok(encrypted1.authTag, 'Auth tag should exist');
  assert.notEqual(encrypted1.ciphertext, secret, 'Ciphertext must not be plaintext');
  assert.equal(encrypted1.ciphertext.includes(secret), false, 'Ciphertext must not contain plaintext');

  // Verify unique IV on second encryption
  const encrypted2 = encrypt(secret);
  assert.notEqual(encrypted1.iv, encrypted2.iv, 'IV must be unique per encryption operation');

  // Successful decryption
  const decrypted1 = decrypt(encrypted1.iv, encrypted1.ciphertext, encrypted1.authTag);
  assert.equal(decrypted1, secret, 'Decrypted value should match original');

  // Successful decryption with object argument
  const decrypted2 = decrypt(encrypted2);
  assert.equal(decrypted2, secret);

  // Tampering detection (Auth tag failure)
  const tamperedCiphertext = (encrypted1.ciphertext.slice(0, -2) + (encrypted1.ciphertext.endsWith('00') ? '11' : '00'));
  assert.throws(() => {
    decrypt(encrypted1.iv, tamperedCiphertext, encrypted1.authTag);
  }, /auth/i, 'Tampered ciphertext should throw error');

  // Invalid tag detection
  const tamperedTag = (encrypted1.authTag.slice(0, -2) + (encrypted1.authTag.endsWith('00') ? '11' : '00'));
  assert.throws(() => {
    decrypt(encrypted1.iv, encrypted1.ciphertext, tamperedTag);
  }, /auth/i, 'Tampered auth tag should throw error');
});

test('Base32 encoding and decoding', () => {
  const testBuffer = Buffer.from('Hello, World!', 'utf8');
  const encoded = base32Encode(testBuffer);
  const decoded = base32Decode(encoded);
  assert.equal(decoded.toString('utf8'), 'Hello, World!');

  // Test RFC test vectors:
  // "foobar" -> "MZXW6YTBOI======"
  const foobar = Buffer.from('foobar');
  const foobarEncoded = base32Encode(foobar);
  assert.equal(foobarEncoded, 'MZXW6YTBOI');
  assert.equal(base32Decode('MZXW6YTBOI======').toString(), 'foobar');
  assert.equal(base32Decode('mzxw6ytboi').toString(), 'foobar'); // case insensitive
});

test('RFC 6238 TOTP generation and verification', () => {
  // RFC 6238 Appendix B test secret: "12345678901234567890" ASCII
  // Base32 for this is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  // Epoch time 59s: window = floor(59 / 30) = 1
  // RFC 6238 Table 1: T=59s, TOTP = 287082
  const code59 = generateCode(secret, 1);
  assert.equal(code59, '287082');

  // T=1111111109s: window = floor(1111111109 / 30) = 37037036
  // RFC 6238 Table 1: TOTP = 081804
  const code111 = generateCode(secret, 37037036);
  assert.equal(code111, '081804');

  // T=1111111111s: window = floor(1111111111 / 30) = 37037037
  // RFC 6238 Table 1: TOTP = 050471
  const code1111 = generateCode(secret, 37037037);
  assert.equal(code1111, '050471');

  // T=2000000000s: window = floor(2000000000 / 30) = 66666666
  // RFC 6238 Table 1: TOTP = 279037
  const code200 = generateCode(secret, 66666666);
  assert.equal(code200, '279037');
});

test('TOTP verification with clock drift', () => {
  const secret = generateSecret();
  const nowMs = 1700000000000;
  const currentWindow = getCurrentTimeWindow(nowMs, 30);

  const codeCurrent = generateCode(secret, currentWindow);
  const codePrev = generateCode(secret, currentWindow - 1);
  const codeNext = generateCode(secret, currentWindow + 1);
  const codeFar = generateCode(secret, currentWindow + 5);

  // Current window matches
  const resCurrent = verifyTotp(secret, codeCurrent, { timestampMs: nowMs, window: 1 });
  assert.equal(resCurrent.valid, true);
  assert.equal(resCurrent.matchedWindow, currentWindow);

  // Previous window matches
  const resPrev = verifyTotp(secret, codePrev, { timestampMs: nowMs, window: 1 });
  assert.equal(resPrev.valid, true);
  assert.equal(resPrev.matchedWindow, currentWindow - 1);

  // Next window matches
  const resNext = verifyTotp(secret, codeNext, { timestampMs: nowMs, window: 1 });
  assert.equal(resNext.valid, true);
  assert.equal(resNext.matchedWindow, currentWindow + 1);

  // Far window fails
  const resFar = verifyTotp(secret, codeFar, { timestampMs: nowMs, window: 1 });
  assert.equal(resFar.valid, false);
  assert.equal(resFar.matchedWindow, null);

  // Invalid code fails
  const resInvalid = verifyTotp(secret, '000000', { timestampMs: nowMs, window: 1 });
  // Unless by cosmic coincidence 000000 is the code
  if (codeCurrent !== '000000' && codePrev !== '000000' && codeNext !== '000000') {
    assert.equal(resInvalid.valid, false);
  }
});

test('OTPAuth URI generation', () => {
  const uri = generateOtpAuthUri({
    secret: 'JBSWY3DPEHPK3PXP',
    email: 'test@example.com',
    issuer: 'SecureApp',
  });

  assert.ok(uri.startsWith('otpauth://totp/'));
  assert.ok(uri.includes('secret=JBSWY3DPEHPK3PXP'));
  assert.ok(uri.includes('issuer=SecureApp'));
  assert.ok(uri.includes('algorithm=SHA1'));
  assert.ok(uri.includes('digits=6'));
  assert.ok(uri.includes('period=30'));
});
