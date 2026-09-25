#!/usr/bin/env python3
"""
Python Automated Evaluator Script for Secure 2FA Login System.
Uses exclusively Python standard library (no external pip dependencies needed).
Verifies:
  - Service Health (/health)
  - 2FA Primary Login Challenge Flow (/api/auth/login)
  - Python-calculated Live RFC 6238 TOTP generation
  - Secondary Login (/api/auth/2fa/login)
  - Replay Attack Protection
  - Strict 2FA Enforcement (Protected Route authorization check)
"""

import sys
import os
import json
import time
import hmac
import hashlib
import struct
import base64
import urllib.request
import urllib.error

BASE_URL = os.environ.get("BASE_URL", "http://localhost:3000")

def make_request(path, method="GET", data=None, token=None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            resp_body = response.read().decode("utf-8")
            return status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(resp_body)
        except Exception:
            parsed = {"raw": resp_body}
        return e.code, parsed

def base32_decode(secret):
    clean = secret.strip().upper().replace("=", "")
    padding = "=" * ((8 - len(clean) % 8) % 8)
    return base64.b32decode(clean + padding)

def generate_totp(secret, time_window, digits=6):
    key = base32_decode(secret)
    msg = struct.pack(">Q", time_window)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)

def run_evaluator_checks():
    print(f"[*] Running Python verification against {BASE_URL}...")

    # 1. Health check
    status, body = make_request("/health")
    assert status == 200 and body.get("status") == "healthy", f"Healthcheck failed: {status}, {body}"
    print("  [OK] Health check passed (200 OK)")

    # 2. Read submission.json
    submission_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "submission.json")
    with open(submission_path, "r", encoding="utf-8") as f:
        sub = json.load(f)
    test_user = sub["testUser"]
    print(f"  [OK] Loaded submission.json test user: {test_user['email']}")

    # 3. Primary login with 2FA enabled
    status, login_res = make_request("/api/auth/login", method="POST", data={
        "email": test_user["email"],
        "password": test_user["password"]
    })
    assert status == 200, f"Login failed: {status}, {login_res}"
    assert login_res.get("requires_2fa") is True, f"Expected requires_2fa=True: {login_res}"
    assert "challenge_token" in login_res, "Expected challenge_token in response"
    assert "token" not in login_res, "Full access token must NOT be returned on challenge"
    challenge_token = login_res["challenge_token"]
    print("  [OK] Primary login branched correctly: requires_2fa=True with challenge_token")

    # 4. Strict Enforcement: Challenge token must be rejected on protected routes
    status, bypass_res = make_request("/api/protected", method="GET", token=challenge_token)
    assert status in (401, 403), f"Challenge token was not rejected on protected route: {status}"
    print(f"  [OK] Strict 2FA enforcement confirmed: challenge_token rejected on protected route ({status})")

    # 5. Generate live RFC 6238 TOTP code
    current_window = int(time.time() // 30)
    live_code = generate_totp(test_user["plaintextTotpSecret"], current_window)
    print(f"  [*] Generated live RFC 6238 TOTP code: {live_code} for window {current_window}")

    # 6. Secondary login with valid code
    status, totp_res = make_request("/api/auth/2fa/login", method="POST", data={
        "challenge_token": challenge_token,
        "code": live_code
    })
    # If the window was already consumed by an immediately preceding test run, wait for rollover
    if status == 401 and "Replay detected" in str(totp_res):
        sleep_sec = 31 - (int(time.time()) % 30)
        print(f"  [*] Window {current_window} already used in previous run; waiting {sleep_sec}s for next window...")
        time.sleep(sleep_sec)
        # Refresh challenge token
        _, login_res2 = make_request("/api/auth/login", method="POST", data={
            "email": test_user["email"],
            "password": test_user["password"]
        })
        challenge_token = login_res2["challenge_token"]
        current_window = int(time.time() // 30)
        live_code = generate_totp(test_user["plaintextTotpSecret"], current_window)
        status, totp_res = make_request("/api/auth/2fa/login", method="POST", data={
            "challenge_token": challenge_token,
            "code": live_code
        })

    assert status == 200, f"2FA login failed with valid code: {status}, {totp_res}"
    assert "token" in totp_res, "Expected full access token in 2FA response"
    session_token = totp_res["token"]
    print("  [OK] Secondary 2FA login succeeded (200 OK) and issued session token")

    # 7. Replay Protection: Reusing the exact same code immediately must fail
    status, replay_res = make_request("/api/auth/2fa/login", method="POST", data={
        "challenge_token": challenge_token,
        "code": live_code
    })
    assert status == 401, f"Replay was NOT blocked! Status: {status}, {replay_res}"
    print(f"  [OK] Replay attack blocked successfully: returned {status} Unauthorized")

    # 8. Access protected route with full session token
    status, prot_res = make_request("/api/protected", method="GET", token=session_token)
    assert status == 200, f"Session token failed to access protected route: {status}, {prot_res}"
    print("  [OK] Full session token successfully authorized protected resource access")

    print("\n[SUCCESS] All Python evaluator tests passed with 100% accuracy!")

if __name__ == "__main__":
    try:
        run_evaluator_checks()
    except Exception as e:
        print(f"\n[ERROR] Evaluation check failed: {e}", file=sys.stderr)
        sys.exit(1)
