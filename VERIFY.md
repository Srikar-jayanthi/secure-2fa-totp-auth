# Verification Checklist (VERIFY.md)

This checklist tracks the exact acceptance tests and named verification functions defined in the requirement walkthrough.

---

### Acceptance Checklist

- [x] **docker-compose-setup**
  - Function: `verify_docker_compose_setup(workspace)`
  - Status: PASS
  - Verified: `docker-compose.yml` defines `db` and `app`, health checks, dependency on `service_healthy`.

- [x] **env-example-file**
  - Function: `verify_env_example_file(workspace)`
  - Status: PASS
  - Verified: `.env.example` documents `DATABASE_URL`, `JWT_SECRET`, and `MASTER_ENCRYPTION_KEY`.

- [x] **db-schema-users**
  - Function: `verify_db_schema_users(workspace)`
  - Status: PASS
  - Verified: Table `users` contains all 8 required columns (`id`, `email`, `password_hash`, `totp_enabled`, `totp_secret_encrypted`, `totp_iv`, `totp_tag`, `last_totp_window`).

- [x] **api-register**
  - Function: `verify_api_register(workspace)`
  - Status: PASS
  - Verified: `POST /api/auth/register` creates user with bcrypt hash, returns `201 Created`.

- [x] **api-login-challenge**
  - Function: `verify_api_login_challenge(workspace)`
  - Status: PASS
  - Verified: `POST /api/auth/login` returns `{ token }` for non-2FA and `{ requires_2fa: true, challenge_token }` for 2FA. Rejects bad passwords with `401`.

- [x] **api-2fa-setup**
  - Function: `verify_api_2fa_setup(workspace)`
  - Status: PASS
  - Verified: `POST /api/auth/2fa/setup` generates secret and `otpauth://totp/` URI, stores encrypted payload, `totp_enabled=false`.

- [x] **encryption-at-rest**
  - Function: `verify_encryption_at_rest(workspace)`
  - Status: PASS
  - Verified: Secret is encrypted with AES-256-GCM. Plaintext Base32 secret never appears in database.

- [x] **api-2fa-verify**
  - Function: `verify_api_2fa_verify(workspace)`
  - Status: PASS
  - Verified: `POST /api/auth/2fa/verify` with valid code sets `totp_enabled = true`.

- [x] **api-2fa-login**
  - Function: `verify_api_2fa_login(workspace)`
  - Status: PASS
  - Verified: `POST /api/auth/2fa/login` with challenge token and code completes authentication, rejects replayed code with `401`.

---

### How to Run Verification

```bash
# Python Requirement Walkthrough verification:
python verify_requirements.py

# Complete Node.js Integration and Unit Test suite:
npm test

# Automated Evaluator verification:
python tests/verify_evaluator.py
```
