#!/usr/bin/env node

/**
 * CLI TOTP Utility (oathtool equivalent)
 * 
 * Usage:
 *   node scripts/totp_tool.js
 *   node scripts/totp_tool.js <base32_secret>
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateCode, getCurrentTimeWindow } from '../src/totp.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let secret = process.argv[2];

if (!secret) {
  const submissionPath = path.resolve(__dirname, '../submission.json');
  if (fs.existsSync(submissionPath)) {
    const submission = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));
    secret = submission.testUser?.plaintextTotpSecret;
    console.log(`Using secret from submission.json (${submission.testUser?.email}): ${secret}`);
  }
}

if (!secret) {
  console.error('Usage: node scripts/totp_tool.js <BASE32_SECRET>');
  process.exit(1);
}

const nowMs = Date.now();
const currentWindow = getCurrentTimeWindow(nowMs, 30);
const remainingSeconds = 30 - (Math.floor(nowMs / 1000) % 30);
const code = generateCode(secret, currentWindow);

console.log(`Current Window : ${currentWindow}`);
console.log(`Current TOTP   : ${code} (expires in ${remainingSeconds}s)`);
