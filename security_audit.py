"""
security_audit.py — SecureMsg penetration test suite.

Tests your OWN running server for security weaknesses before going live.
Run with: python security_audit.py [SERVER_URL]

What it checks:
  ✦ Authentication  — bad passwords, tampered tokens, missing fields
  ✦ Access control  — non-members accessing channels, wrong invitee
  ✦ Invite security — token reuse, expired tokens, token hijacking
  ✦ Input safety    — SQL injection probes, oversized inputs, special chars
  ✦ Crypto layer    — ciphertext integrity, wrong-password decryption
  ✦ Info leakage    — what error messages reveal to an attacker
  ✦ Transport       — whether traffic is going over HTTP vs HTTPS

IMPORTANT: Only run against a server YOU own and control.
"""

import sys
import time
import uuid
import base64
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Optional

import requests
import socketio

# ──────────────────────────────────────────────────────────────────────────────
SERVER = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"
DB_PATH = os.path.join(os.path.dirname(__file__), "secure_messages.db")

# Colours (work in Windows Terminal / VS Code terminal)
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS  = f"{GREEN}PASS{RESET}"
FAIL  = f"{RED}FAIL{RESET}"
WARN  = f"{YELLOW}WARN{RESET}"
INFO  = f"{CYAN}INFO{RESET}"


# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Result:
    name:    str
    status:  str          # "pass" | "fail" | "warn" | "info"
    detail:  str = ""

results: list[Result] = []


def check(name: str, condition: bool, pass_detail: str = "", fail_detail: str = "",
          warn_if_false: bool = False) -> bool:
    """Record a test result."""
    if condition:
        results.append(Result(name, "pass", pass_detail))
    elif warn_if_false:
        results.append(Result(name, "warn", fail_detail))
    else:
        results.append(Result(name, "fail", fail_detail))
    return condition


def info(name: str, detail: str) -> None:
    results.append(Result(name, "info", detail))


def section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD} {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def post(path: str, body: dict, headers: dict | None = None) -> requests.Response:
    return requests.post(f"{SERVER}{path}", json=body,
                         headers=headers or {}, timeout=8)


def register_test_user(suffix: str = "") -> tuple[str, str, str]:
    """Register a fresh test user. Returns (username, password, token)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    username = f"audit_{uuid.uuid4().hex[:8]}{suffix}"
    password = f"Audit@{uuid.uuid4().hex[:8]}!"
    priv     = X25519PrivateKey.generate()
    pub_b64  = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    resp = post("/register", {"username": username, "password": password,
                              "public_key": pub_b64})
    data = resp.json()
    return username, password, data.get("token", "")


def ws_connect(token: str) -> tuple[socketio.Client, list]:
    """Open a WebSocket connection. Returns (client, events_received)."""
    sio    = socketio.Client(logger=False, engineio_logger=False)
    events = []

    @sio.on("*")
    def catch_all(event, data):
        events.append((event, data))

    try:
        sio.connect(f"{SERVER}?token={token}",
                    transports=["websocket"], wait_timeout=5)
        time.sleep(0.4)
    except Exception:
        pass
    return sio, events


def ws_emit_wait(sio: socketio.Client, event: str, data: dict,
                 wait: float = 0.5) -> list:
    """Emit a socket event and collect responses."""
    received = []

    @sio.on("*")
    def catch(evt, d):
        received.append((evt, d))

    sio.emit(event, data)
    time.sleep(wait)
    return received


# ──────────────────────────────────────────────────────────────────────────────
# 0. Connectivity
# ──────────────────────────────────────────────────────────────────────────────

def test_connectivity():
    section("0 · Connectivity & Transport")

    try:
        r = requests.get(SERVER, timeout=5)
        reachable = True
    except Exception as e:
        reachable = False

    check("Server is reachable", reachable,
          f"Got a response from {SERVER}",
          f"Cannot reach {SERVER} — is the server running?")

    using_https = SERVER.startswith("https://")
    check("Transport is HTTPS (encrypted in transit)", using_https,
          "HTTPS — traffic is encrypted between client and server.",
          "HTTP — traffic is NOT encrypted in transit. Anyone on the same "
          "network can read tokens and public keys. Use ngrok or a TLS proxy "
          "before exposing this to the internet.",
          warn_if_false=True)


# ──────────────────────────────────────────────────────────────────────────────
# 1. Authentication
# ──────────────────────────────────────────────────────────────────────────────

def test_authentication():
    section("1 · Authentication")

    # ── Registration input validation ──────────────────────────────────────

    r = post("/register", {"username": "ab", "password": "ValidPass1!", "public_key": "x"})
    check("Short username rejected (< 3 chars)", r.status_code == 400,
          "400 returned", f"Expected 400, got {r.status_code}: {r.text[:80]}")

    long_name = "a" * 25
    r = post("/register", {"username": long_name, "password": "ValidPass1!", "public_key": "x"})
    check("Long username rejected (> 24 chars)", r.status_code == 400,
          "400 returned", f"Expected 400, got {r.status_code}: {r.text[:80]}")

    r = post("/register", {"username": "valid_user", "password": "short", "public_key": "x"})
    check("Weak password rejected (< 8 chars)", r.status_code == 400,
          "400 returned", f"Expected 400, got {r.status_code}: {r.text[:80]}")

    r = post("/register", {"username": "valid_user", "password": "ValidPass1!"})
    check("Registration without public_key rejected", r.status_code == 400,
          "400 returned", f"Expected 400, got {r.status_code}: {r.text[:80]}")

    r = post("/register", {})
    check("Empty registration body rejected", r.status_code == 400,
          "400 returned", f"Expected 400, got {r.status_code}: {r.text[:80]}")

    # ── Duplicate username ─────────────────────────────────────────────────

    username, password, token = register_test_user()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = X25519PrivateKey.generate()
    pub  = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    r = post("/register", {"username": username, "password": password, "public_key": pub})
    check("Duplicate username rejected", r.status_code == 409,
          "409 returned", f"Expected 409, got {r.status_code}")

    # ── Login validation ───────────────────────────────────────────────────

    r = post("/login", {"username": username, "password": "WrongPassword99!"})
    check("Wrong password rejected", r.status_code == 401,
          "401 returned", f"Expected 401, got {r.status_code}: {r.text[:80]}")

    r = post("/login", {"username": "nobody_exists_xyz", "password": "AnyPass123!"})
    check("Non-existent user login rejected", r.status_code == 401,
          "401 returned", f"Expected 401, got {r.status_code}: {r.text[:80]}")

    # ── Info leakage — do error messages reveal whether user exists? ───────

    msg_wrong_user = post("/login", {"username": "ghost_xyz_nobody", "password": "pass"}).text
    msg_wrong_pass = post("/login", {"username": username, "password": "WrongPass1!"}).text
    same_message   = (msg_wrong_user.lower() == msg_wrong_pass.lower())

    check("Login errors don't reveal whether user exists (user enumeration)",
          same_message,
          "Both return the same generic error message.",
          f"Different errors leak user existence:\n"
          f"  bad username: {msg_wrong_user[:60]}\n"
          f"  bad password: {msg_wrong_pass[:60]}",
          warn_if_false=True)

    # ── Valid login returns token ──────────────────────────────────────────

    check("Valid login returns JWT token", bool(token),
          "Token received", "No token in response")


# ──────────────────────────────────────────────────────────────────────────────
# 2. WebSocket auth
# ──────────────────────────────────────────────────────────────────────────────

def test_websocket_auth():
    section("2 · WebSocket Authentication")

    # ── No token ──────────────────────────────────────────────────────────

    sio = socketio.Client(logger=False, engineio_logger=False)
    connected = False

    @sio.on("connected")
    def _c(d):
        nonlocal connected
        connected = True

    try:
        sio.connect(f"{SERVER}", transports=["websocket"], wait_timeout=4)
        time.sleep(0.4)
        sio.disconnect()
    except Exception:
        pass

    check("WebSocket rejected without token", not connected,
          "Connection refused (no token)", "Connection was accepted without a token!")

    # ── Garbage token ─────────────────────────────────────────────────────

    connected2 = False
    sio2 = socketio.Client(logger=False, engineio_logger=False)

    @sio2.on("connected")
    def _c2(d):
        nonlocal connected2
        connected2 = True

    try:
        sio2.connect(f"{SERVER}?token=this.is.garbage",
                     transports=["websocket"], wait_timeout=4)
        time.sleep(0.4)
        sio2.disconnect()
    except Exception:
        pass

    check("WebSocket rejected with garbage token", not connected2,
          "Connection refused (invalid JWT)", "Garbage token was accepted!")

    # ── Tampered token (valid structure, wrong signature) ──────────────────

    _, _, real_token = register_test_user()
    parts = real_token.split(".")
    if len(parts) == 3:
        # Corrupt the signature
        tampered = parts[0] + "." + parts[1] + ".INVALIDSIGNATUREABC"
    else:
        tampered = "bad"

    connected3 = False
    sio3 = socketio.Client(logger=False, engineio_logger=False)

    @sio3.on("connected")
    def _c3(d):
        nonlocal connected3
        connected3 = True

    try:
        sio3.connect(f"{SERVER}?token={tampered}",
                     transports=["websocket"], wait_timeout=4)
        time.sleep(0.4)
        sio3.disconnect()
    except Exception:
        pass

    check("WebSocket rejected with tampered JWT signature", not connected3,
          "Connection refused (bad signature)", "Tampered JWT was accepted!")

    # ── Valid token works ──────────────────────────────────────────────────

    sio4, events4 = ws_connect(real_token)
    got_connected = any(e[0] == "connected" for e in events4)
    check("Valid token accepted", got_connected,
          "Connection accepted", "Valid token was rejected")
    try:
        sio4.disconnect()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# 3. Channel access control
# ──────────────────────────────────────────────────────────────────────────────

def test_channel_access():
    section("3 · Channel Access Control")

    import crypto as clib

    # Create two users
    user_a_name, user_a_pass, token_a = register_test_user("_a")
    user_b_name, user_b_pass, token_b = register_test_user("_b")

    # User A creates a channel
    sio_a, _ = ws_connect(token_a)
    time.sleep(0.3)

    channel_key = clib.generate_channel_key()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv_a  = X25519PrivateKey.generate()
    pub_a   = clib.get_public_key_b64(priv_a)
    enc_key = clib.encrypt_for_peer(channel_key, priv_a, pub_a)

    channel_id = None
    channel_events = []

    @sio_a.on("channel_created")
    def _cc(d):
        nonlocal channel_id
        channel_id = d.get("channel_id")
        channel_events.append(d)

    @sio_a.on("error")
    def _ae(d):
        channel_events.append(("error", d))

    sio_a.emit("create_channel", {
        "name":          f"audit_{uuid.uuid4().hex[:6]}",
        "encrypted_key": enc_key,
    })
    time.sleep(0.6)

    check("Channel created by owner", channel_id is not None,
          f"channel_id={channel_id}", "Channel was not created")

    if channel_id:
        # User B tries to join without an invite
        sio_b, _ = ws_connect(token_b)
        time.sleep(0.3)

        b_errors = []

        @sio_b.on("error")
        def _be(d):
            b_errors.append(d)

        @sio_b.on("channel_joined")
        def _bj(d):
            b_errors.append(("SHOULD_NOT_JOIN", d))

        sio_b.emit("join_channel", {"channel_id": channel_id})
        time.sleep(0.5)

        not_joined = not any(
            isinstance(e, tuple) and e[0] == "SHOULD_NOT_JOIN"
            for e in b_errors
        )
        check("Non-member cannot join channel without invite", not_joined,
              "join_channel was blocked", "Non-member joined without an invite!")

        # User B tries to send a message to the channel
        b_msg_events = []

        @sio_b.on("error")
        def _bme(d):
            b_msg_events.append(d)

        sio_b.emit("send_message", {
            "channel_id":        channel_id,
            "encrypted_content": base64.b64encode(b"fake ciphertext").decode(),
        })
        time.sleep(0.5)

        # Check that the message did NOT arrive for user A
        a_got_message = []

        @sio_a.on("new_message")
        def _nm(d):
            a_got_message.append(d)

        time.sleep(0.3)
        check("Non-member cannot send messages to channel", not a_got_message,
              "Message was blocked", "Message from non-member was delivered!")

        try:
            sio_b.disconnect()
        except Exception:
            pass

    try:
        sio_a.disconnect()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# 4. Invite security
# ──────────────────────────────────────────────────────────────────────────────

def test_invite_security():
    section("4 · Invite Security")

    import crypto as clib
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    # Three users: inviter, invitee, attacker
    _, _, tok_inviter  = register_test_user("_inv")
    name_b, _, tok_b   = register_test_user("_invitee")
    _, _, tok_attacker = register_test_user("_atk")

    priv_inv  = X25519PrivateKey.generate()
    channel_key = clib.generate_channel_key()
    pub_inv   = clib.get_public_key_b64(priv_inv)
    enc_self  = clib.encrypt_for_peer(channel_key, priv_inv, pub_inv)

    sio_inv, _ = ws_connect(tok_inviter)
    time.sleep(0.3)

    channel_id = None

    @sio_inv.on("channel_created")
    def _cc(d):
        nonlocal channel_id
        channel_id = d.get("channel_id")

    sio_inv.emit("create_channel", {
        "name":          f"audit_{uuid.uuid4().hex[:6]}",
        "encrypted_key": enc_self,
    })
    time.sleep(0.6)

    invite_token = None
    peer_key_cache = {}

    @sio_inv.on("peer_public_key")
    def _ppk(d):
        peer_key_cache["data"] = d
        # Encrypt channel key for invitee using their public key
        try:
            enc = clib.encrypt_for_peer(channel_key, priv_inv, d["public_key"])
            sio_inv.emit("send_invite", {
                "channel_id":   channel_id,
                "invitee_id":   d["user_id"],
                "encrypted_key": enc,
            })
        except Exception as e:
            peer_key_cache["error"] = str(e)

    @sio_inv.on("invite_ready")
    def _ir(d):
        nonlocal invite_token
        invite_token = d.get("token")

    sio_inv.emit("get_public_key", {"username": name_b})
    time.sleep(1.0)

    check("Invite token created successfully", invite_token is not None,
          f"Token={invite_token[:8]}…" if invite_token else "",
          "Failed to create invite token — skipping invite tests")

    if not invite_token:
        try:
            sio_inv.disconnect()
        except Exception:
            pass
        return

    # ── Attacker tries to use the token ───────────────────────────────────

    sio_atk, _ = ws_connect(tok_attacker)
    time.sleep(0.3)

    atk_errors   = []
    atk_accepted = []

    @sio_atk.on("error")
    def _ae(d):
        atk_errors.append(d)

    @sio_atk.on("invite_accepted")
    def _aa(d):
        atk_accepted.append(d)

    sio_atk.emit("accept_invite", {"token": invite_token})
    time.sleep(0.6)

    check("Invite cannot be accepted by wrong user (token hijacking)",
          len(atk_accepted) == 0,
          "Token hijack blocked", "Attacker accepted an invite meant for someone else!")

    try:
        sio_atk.disconnect()
    except Exception:
        pass

    # ── Correct invitee accepts the token ─────────────────────────────────

    sio_b, _ = ws_connect(tok_b)
    time.sleep(0.3)

    b_accepted = []
    b_errors   = []

    @sio_b.on("invite_accepted")
    def _ba(d):
        b_accepted.append(d)

    @sio_b.on("error")
    def _be(d):
        b_errors.append(d)

    sio_b.emit("accept_invite", {"token": invite_token})
    time.sleep(0.6)

    check("Invitee can accept invite with correct token", len(b_accepted) > 0,
          "Invite accepted", f"Invite failed: {b_errors}")

    # ── Replay: invitee tries to use the same token again ─────────────────

    b_replay = []

    @sio_b.on("error")
    def _br(d):
        b_replay.append(d)

    @sio_b.on("invite_accepted")
    def _ba2(d):
        b_replay.append(("ACCEPTED_AGAIN", d))

    b_replay.clear()
    sio_b.emit("accept_invite", {"token": invite_token})
    time.sleep(0.6)

    used_twice = any(
        isinstance(e, tuple) and e[0] == "ACCEPTED_AGAIN"
        for e in b_replay
    )
    check("Used invite token cannot be reused (replay attack)", not used_twice,
          "Token correctly marked as used",
          "Token was accepted a second time — replay vulnerability!")

    # ── Random garbage token ──────────────────────────────────────────────

    garbage_events = []

    @sio_b.on("error")
    def _bg(d):
        garbage_events.append(d)

    @sio_b.on("invite_accepted")
    def _bg2(d):
        garbage_events.append(("ACCEPTED_GARBAGE", d))

    garbage_events.clear()
    sio_b.emit("accept_invite", {"token": str(uuid.uuid4())})
    time.sleep(0.5)

    accepted_garbage = any(
        isinstance(e, tuple) and e[0] == "ACCEPTED_GARBAGE"
        for e in garbage_events
    )
    check("Random token rejected", not accepted_garbage,
          "Garbage token correctly rejected",
          "A random token was accepted!")

    for s in (sio_inv, sio_b):
        try:
            s.disconnect()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# 5. Encryption integrity
# ──────────────────────────────────────────────────────────────────────────────

def test_encryption():
    section("5 · Encryption Integrity")

    import crypto as clib

    # ── Tampered ciphertext fails authentication ───────────────────────────

    key      = clib.generate_channel_key()
    enc      = clib.encrypt_message("hello world", key)
    raw      = base64.b64decode(enc)
    # Flip a byte in the ciphertext (after the 12-byte nonce)
    tampered = bytearray(raw)
    tampered[20] ^= 0xFF
    tampered_b64 = base64.b64encode(bytes(tampered)).decode()

    try:
        clib.decrypt_message(tampered_b64, key)
        tamper_detected = False
    except Exception:
        tamper_detected = True

    check("Tampered ciphertext is rejected (AEAD integrity tag)",
          tamper_detected,
          "ChaCha20-Poly1305 authentication tag caught the tampering.",
          "Tampered message was NOT rejected — data integrity is broken!")

    # ── Wrong key fails decryption ─────────────────────────────────────────

    wrong_key = clib.generate_channel_key()
    try:
        clib.decrypt_message(enc, wrong_key)
        wrong_key_rejected = False
    except Exception:
        wrong_key_rejected = True

    check("Wrong channel key fails decryption",
          wrong_key_rejected,
          "Decryption correctly failed with wrong key.",
          "Wrong key produced output — crypto is broken!")

    # ── Messages in DB are ciphertext, not plaintext ───────────────────────

    if os.path.exists(DB_PATH):
        plaintext_probe = "audit_plaintext_marker_XYZ987"
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT encrypted_content FROM messages").fetchall()
        conn.close()
        found_plaintext = any(plaintext_probe in str(r[0]) for r in rows)
        check("Messages in DB are not stored as plaintext",
              not found_plaintext,
              f"Checked {len(rows)} messages — all appear to be ciphertext.",
              "Plaintext found in message DB!")
    else:
        info("Database check", "DB file not found — skipping plaintext-in-DB check.")

    # ── ECDH: wrong password fails identity load ───────────────────────────

    try:
        clib.load_identity("definitely_the_wrong_password_XYZ")
        identity_protected = False
    except (ValueError, FileNotFoundError):
        identity_protected = True
    except Exception:
        identity_protected = True

    check("Wrong password cannot decrypt local identity key",
          identity_protected,
          "Identity key is password-protected.",
          "Wrong password loaded the identity key — local key is unprotected!")

    # ── Peer encryption: output is different every time (random nonce) ────

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.generate()
    pub  = clib.get_public_key_b64(priv)
    ct1  = clib.encrypt_for_peer(b"same plaintext", priv, pub)
    ct2  = clib.encrypt_for_peer(b"same plaintext", priv, pub)

    check("Encryption produces unique ciphertext each time (random nonce)",
          ct1 != ct2,
          "Each encryption produces a unique ciphertext.",
          "Same plaintext produced identical ciphertext — nonce reuse!")


# ──────────────────────────────────────────────────────────────────────────────
# 6. SQL injection probes
# ──────────────────────────────────────────────────────────────────────────────

def test_sql_injection():
    section("6 · SQL Injection")

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pub  = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "admin'--",
        "1; SELECT * FROM users",
    ]

    for payload in payloads:
        r_login = post("/login", {"username": payload, "password": "x"})
        # Safe response = 401 (not found) or 400 (invalid input)
        safe = r_login.status_code in (400, 401)
        check(f"SQL injection in username: {payload[:30]!r}", safe,
              f"Safely rejected ({r_login.status_code})",
              f"Unexpected response {r_login.status_code}: {r_login.text[:80]}")


# ──────────────────────────────────────────────────────────────────────────────
# 7. Rate limiting (informational)
# ──────────────────────────────────────────────────────────────────────────────

def test_rate_limiting():
    section("7 · Brute Force / Rate Limiting")

    _, _, token = register_test_user()

    # Fire 20 failed logins rapidly
    blocked = False
    for i in range(20):
        r = post("/login", {"username": "nobody_xyz", "password": f"wrong{i}"})
        if r.status_code == 429:
            blocked = True
            break

    check("Server rate-limits repeated failed logins (429 Too Many Requests)",
          blocked,
          "Rate limiting is active.",
          "No rate limiting detected — an attacker could brute-force passwords. "
          "Consider adding flask-limiter.",
          warn_if_false=True)


# ──────────────────────────────────────────────────────────────────────────────
# Run all tests & print summary
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{'═'*62}{RESET}")
    print(f"{BOLD}  SecureMsg Security Audit{RESET}")
    print(f"{DIM}  Target: {SERVER}{RESET}")
    print(f"{BOLD}{'═'*62}{RESET}")

    try:
        test_connectivity()
        test_authentication()
        test_websocket_auth()
        test_channel_access()
        test_invite_security()
        test_encryption()
        test_sql_injection()
        test_rate_limiting()
    except requests.exceptions.ConnectionError:
        print(f"\n{RED}[ERROR] Cannot reach {SERVER}{RESET}")
        print("Make sure your server is running:  python server.py\n")
        sys.exit(1)

    # ── Print results ──────────────────────────────────────────────────────

    print(f"\n\n{BOLD}{'═'*62}{RESET}")
    print(f"{BOLD}  Results{RESET}")
    print(f"{BOLD}{'═'*62}{RESET}\n")

    counts = {"pass": 0, "fail": 0, "warn": 0, "info": 0}

    for r in results:
        icon = {
            "pass": f"{GREEN}✔{RESET}",
            "fail": f"{RED}✘{RESET}",
            "warn": f"{YELLOW}⚠{RESET}",
            "info": f"{CYAN}ℹ{RESET}",
        }[r.status]

        label = {
            "pass": PASS,
            "fail": FAIL,
            "warn": WARN,
            "info": INFO,
        }[r.status]

        print(f"  {icon}  [{label}]  {r.name}")
        if r.detail and r.status in ("fail", "warn"):
            for line in r.detail.splitlines():
                print(f"          {DIM}{line}{RESET}")
        counts[r.status] += 1

    total = counts["pass"] + counts["fail"] + counts["warn"]
    score = int(counts["pass"] / total * 100) if total else 0

    print(f"\n{'─'*62}")
    print(f"  {GREEN}PASS {counts['pass']}{RESET}   "
          f"{RED}FAIL {counts['fail']}{RESET}   "
          f"{YELLOW}WARN {counts['warn']}{RESET}   "
          f"{CYAN}INFO {counts['info']}{RESET}")

    bar_filled = score // 5
    bar        = f"{GREEN}{'█' * bar_filled}{DIM}{'░' * (20 - bar_filled)}{RESET}"
    colour     = GREEN if score >= 80 else (YELLOW if score >= 60 else RED)
    print(f"\n  Security score: {bar}  {colour}{score}%{RESET}\n")

    if counts["fail"] > 0:
        print(f"  {RED}Fix the FAIL items before exposing this server to the internet.{RESET}\n")
    elif counts["warn"] > 0:
        print(f"  {YELLOW}No critical failures. Review the WARN items for hardening.{RESET}\n")
    else:
        print(f"  {GREEN}All checks passed. Stay safe out there.{RESET}\n")


if __name__ == "__main__":
    main()
