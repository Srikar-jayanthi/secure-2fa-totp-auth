import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import { query } from './index.js';
import { encrypt } from '../crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function seedDatabase() {
  const submissionPath = path.resolve(__dirname, '../../submission.json');

  if (!fs.existsSync(submissionPath)) {
    console.warn(`submission.json not found at ${submissionPath}, skipping seeding.`);
    return;
  }

  const submissionData = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));
  const testUser = submissionData.testUser;

  if (!testUser || !testUser.email || !testUser.password || !testUser.plaintextTotpSecret) {
    console.warn('submission.json testUser is missing required fields.');
    return;
  }

  console.log(`Seeding test user: ${testUser.email}...`);

  const passwordHash = await bcrypt.hash(testUser.password, 10);
  const encryptedSecret = encrypt(testUser.plaintextTotpSecret);

  // Check if test user exists
  const existingRes = await query('SELECT id FROM users WHERE email = $1', [testUser.email]);

  if (existingRes.rows.length > 0) {
    await query(
      `UPDATE users SET 
        password_hash = $1,
        totp_enabled = true,
        totp_secret_encrypted = $2,
        totp_iv = $3,
        totp_tag = $4,
        last_totp_window = NULL
       WHERE email = $5`,
      [
        passwordHash,
        encryptedSecret.ciphertext,
        encryptedSecret.iv,
        encryptedSecret.authTag,
        testUser.email,
      ]
    );
    console.log(`Updated existing seeded user: ${testUser.email}`);
  } else {
    await query(
      `INSERT INTO users (
        email,
        password_hash,
        totp_enabled,
        totp_secret_encrypted,
        totp_iv,
        totp_tag,
        last_totp_window
      ) VALUES ($1, $2, true, $3, $4, $5, NULL)`,
      [
        testUser.email,
        passwordHash,
        encryptedSecret.ciphertext,
        encryptedSecret.iv,
        encryptedSecret.authTag,
      ]
    );
    console.log(`Successfully created seeded user: ${testUser.email}`);
  }
}

// If run directly from CLI
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Seeding failed:', err);
      process.exit(1);
    });
}
