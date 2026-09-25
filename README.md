# Secure 2FA Login System with TOTP and Encrypted Credential Storage

A production-grade, highly secure authentication system featuring password hashing (bcrypt), Time-Based One-Time Passwords (TOTP RFC 6238), application-level symmetric encryption at rest using AES-256-GCM, multi-stage authentication state management, and stateful replay protection with atomic database concurrency control.

---

## System Architecture

```
+-----------------------------------------------------------------------------------+
|                                  Client / Evaluator                               |
+-----------------------------------------------------------------------------------+
                  |                                        ^
    1. Credentials / TOTP code               10. Session JWT / Error
                  v                                        |
+-----------------------------------------------------------------------------------+
|                             API Controller (Express.js)                           |
+-----------------------------------------------------------------------------------+
                  |                                        ^
          2. Route & Validate                     9. Issue JWT or 401
                  v                                        |
+-----------------------------------------------------------------------------------+
|                              Auth & State Manager                                 |
+-----------------------------------------------------------------------------------+
        |                         |                                    |
   3. Fetch user             5. Decrypt secret                    8. Validate TOTP
        v                         v                                    v
+----------------+       +------------------------+       +-------------------------+
| PostgreSQL DB  |       | Crypto (AES-256-GCM)   |       | TOTP Engine (RFC 6238)  |
| (users table)  | ----> | Decrypt with MASTER_KEY| ----> | Match code with drift   |
| Encrypted rest |       | Verify Auth Tag        |       | Window drift: [-1, 0, 1]|
+----------------+       +------------------------+       +-------------------------+
        |                                                              |
        +---------------- Replay Window Check & Update ----------------+
                           (T_match > last_totp_window)
```

---

## Multi-Stage Authentication State Flow

```
                      +-------------------+
                      |  Unauthenticated  |
                      +-------------------+
                                |
             +------------------+------------------+
             | Valid password                      | Valid password
             | (2FA disabled)                      | (2FA enabled)
             v                                     v
   +-------------------+                 +-------------------+
   |   Authenticated   |                 | ChallengePending  |<-------------+
   | (Full Access JWT) |                 | (Challenge Token) |              |
   +-------------------+                 +-------------------+              |
                                                   |                        |
                                                   | Submit TOTP code       |
                                                   v                        |
                                            +--------------+                |
                                            | Valid code & | No: Replay or  |
                                            |  T > last?   |---- Invalid ---+
                                            +--------------+     (401)
                                                   |
                                                   | Yes (200 OK)
                                                   v
                                         +-------------------+
                                         |   Authenticated   |
                                         | (Full Access JWT) |
                                         +-------------------+
```

---

## Core Security Features

1. **Symmetric Encryption at Rest (AES-256-GCM)**:
   - TOTP Base32 secrets are never stored in plaintext.
   - Encrypted with AES-256-GCM using a 32-byte `MASTER_ENCRYPTION_KEY`.
   - Every encryption operation generates a unique, cryptographically random 12-byte Initialization Vector (IV).
   - Authenticated encryption ensures confidentiality and integrity via an authentication tag (tamper-evident).

2. **RFC 6238 TOTP Engine**:
   - Implements standard HMAC-SHA1 dynamic truncation with 6 digits and 30-second time periods.
   - Clock drift tolerance: Evaluates current window ($T$), previous window ($T-1$), and next window ($T+1$).
   - Constant-time string comparison (`crypto.timingSafeEqual`) protects against timing side-channel attacks.

3. **Replay Protection**:
   - The exact matching time window $T_{match}$ that generated the valid code is captured.
   - If $T_{match} \le \text{last\_totp\_window}$, authentication is rejected with `401 Unauthorized` (Replay detected).
   - Atomic database transactions with row-level locking (`SELECT ... FOR UPDATE`) prevent race conditions.

4. **Strict Multi-Stage State Enforcement**:
   - When 2FA is enabled, `POST /api/auth/login` returns `{ requires_2fa: true, challenge_token }`.
   - Challenge tokens are short-lived JWTs scoped specifically to `2fa_challenge`.
   - Protected routes and 2FA setup reject challenge tokens with `401 Unauthorized` / `403 Forbidden`.

5. **Automated Seeding & Submission Compliance**:
   - Reads `submission.json` on startup.
   - Automatically migrates and seeds the pre-configured test user with `totp_enabled=true` and encrypted secret matching `plaintextTotpSecret`.

---

## Database Schema (`users` table)

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PRIMARY KEY DEFAULT gen_random_uuid()` | Unique user identifier |
| `email` | `VARCHAR(255)` | `UNIQUE, NOT NULL` | User login email |
| `password_hash` | `VARCHAR(255)` | `NOT NULL` | Bcrypt hashed password |
| `totp_enabled` | `BOOLEAN` | `DEFAULT false NOT NULL` | 2FA activation status |
| `totp_secret_encrypted`| `TEXT` | `NULLABLE` | AES-256-GCM encrypted Base32 secret |
| `totp_iv` | `TEXT` | `NULLABLE` | AES-GCM Initialization Vector (Hex) |
| `totp_tag` | `TEXT` | `NULLABLE` | AES-GCM Authentication Tag (Hex) |
| `last_totp_window` | `INTEGER` | `NULLABLE` | Replay protection epoch window counter |

---

## Environment Variables (`.env.example`)

```dotenv
# Database Connection URL
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_db

# Secret key for signing JSON Web Tokens
JWT_SECRET=super-secret-jwt-key-for-2fa-auth-2025

# 32-byte (256-bit) hex-encoded key for AES-256-GCM encryption
MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Server port and environment
PORT=3000
NODE_ENV=production
```

---

## Quick Start with Docker Compose

To start the database and API service:

```bash
docker compose up -d --build
```

### Healthcheck Verification

```bash
docker compose ps
```

Both `auth_db` and `auth_app` report status `healthy`.

---

## Running Automated Tests

Run the complete test suite (unit and integration tests covering all 12 core requirements):

```bash
npm test
```

---

## API Endpoints Reference

### 1. User Registration
- **Endpoint**: `POST /api/auth/register`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "strongPassword123"
  }
  ```
- **Response** (`201 Created`):
  ```json
  {
    "id": "c1f7b0a8-...",
    "email": "user@example.com"
  }
  ```

### 2. Primary Login
- **Endpoint**: `POST /api/auth/login`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "strongPassword123"
  }
  ```
- **Response (2FA Disabled)** (`200 OK`):
  ```json
  {
    "token": "<Full Access JWT>"
  }
  ```
- **Response (2FA Enabled)** (`200 OK`):
  ```json
  {
    "requires_2fa": true,
    "challenge_token": "<Challenge Token JWT>"
  }
  ```

### 3. TOTP Setup
- **Endpoint**: `POST /api/auth/2fa/setup`
- **Headers**: `Authorization: Bearer <Full Access Token>`
- **Response** (`200 OK`):
  ```json
  {
    "secret": "JBSWY3DPEHPK3PXP...",
    "uri": "otpauth://totp/Secure2FA:user%40example.com?secret=...&issuer=Secure2FA&algorithm=SHA1&digits=6&period=30"
  }
  ```

### 4. Verify & Enable 2FA
- **Endpoint**: `POST /api/auth/2fa/verify`
- **Headers**: `Authorization: Bearer <Full Access Token>`
- **Body**:
  ```json
  {
    "code": "123456"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "message": "2FA successfully enabled"
  }
  ```

### 5. Secondary Login (2FA Verification)
- **Endpoint**: `POST /api/auth/2fa/login`
- **Body**:
  ```json
  {
    "challenge_token": "<Challenge Token JWT>",
    "code": "123456"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "token": "<Full Access JWT>"
  }
  ```
- **Replay Attempt** (`401 Unauthorized`):
  ```json
  {
    "error": "Replay detected: TOTP code has already been used"
  }
  ```

### 6. Protected Resource
- **Endpoint**: `GET /api/protected`
- **Headers**: `Authorization: Bearer <Full Access Token>`
- **Response** (`200 OK`):
  ```json
  {
    "message": "Access granted to protected route",
    "user": {
      "id": "...",
      "email": "user@example.com"
    }
  }
  ```

### 7. Health Check
- **Endpoint**: `GET /health` or `GET /api/health`
- **Response** (`200 OK`):
  ```json
  {
    "status": "healthy"
  }
  ```
