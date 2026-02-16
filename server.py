"""
server.py — SecureMsg WebSocket server (Flask-SocketIO).

REST endpoints:  POST /register  POST /login
Socket events:   connect, disconnect, join_channel, send_message,
                 create_channel, request_invite, send_invite,
                 accept_invite, list_my_channels, get_public_key

Privacy notes:
  - No email, no phone number. Username + password only.
  - No IP addresses logged anywhere.
  - Server stores only ciphertext; it never sees plaintext messages.
  - Channel keys are encrypted client-side before reaching the server.
"""

import os
import uuid
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, emit

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    import secrets
    SECRET_KEY = secrets.token_hex(32)
    print(
        "[WARN] SECRET_KEY not set in .env — generated a random one for this session.\n"
        "       Set SECRET_KEY in .env to keep sessions valid across restarts."
    )

app.config["SECRET_KEY"] = SECRET_KEY

CORS(app, resources={r"/*": {"origins": os.environ.get("ALLOWED_ORIGINS", "*")}})

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
    async_mode="threading",
)

DB_PATH = os.environ.get("DB_PATH", "secure_messages.db")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                username    TEXT UNIQUE NOT NULL,
                pw_hash     TEXT NOT NULL,
                public_key  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                last_seen   TEXT
            );

            CREATE TABLE IF NOT EXISTS channels (
                id          TEXT PRIMARY KEY,
                name        TEXT UNIQUE NOT NULL,
                invite_only INTEGER NOT NULL DEFAULT 1,
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id  TEXT NOT NULL,
                user_id     TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'member',
                joined_at   TEXT NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY (channel_id) REFERENCES channels(id),
                FOREIGN KEY (user_id)    REFERENCES users(id)
            );

            -- Stores the channel key encrypted for each member individually.
            -- The server cannot decrypt this; only the intended user can.
            CREATE TABLE IF NOT EXISTS channel_keys (
                channel_id          TEXT NOT NULL,
                user_id             TEXT NOT NULL,
                encrypted_key       TEXT NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY (channel_id) REFERENCES channels(id),
                FOREIGN KEY (user_id)    REFERENCES users(id)
            );

            -- Single-use invite tokens. The encrypted_key is encrypted for the invitee.
            CREATE TABLE IF NOT EXISTS invites (
                token           TEXT PRIMARY KEY,
                channel_id      TEXT NOT NULL,
                created_by      TEXT NOT NULL,
                invitee_id      TEXT NOT NULL,
                encrypted_key   TEXT NOT NULL,
                inviter_pubkey  TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                used            INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (channel_id) REFERENCES channels(id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id                TEXT PRIMARY KEY,
                channel_id        TEXT NOT NULL,
                sender_id         TEXT NOT NULL,
                sender_name       TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                FOREIGN KEY (channel_id) REFERENCES channels(id),
                FOREIGN KEY (sender_id)  REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_channel
                ON messages (channel_id, created_at);
        """)


init_db()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_token(user_id: str, username: str) -> str:
    payload = {
        "uid": user_id,
        "usr": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


# sid → {user_id, username, public_key}
_online: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username   = (data.get("username") or "").strip()
    password   = data.get("password", "")
    public_key = data.get("public_key", "")

    if not username or not password or not public_key:
        return jsonify({"error": "username, password, and public_key required"}), 400
    if not (3 <= len(username) <= 24):
        return jsonify({"error": "username must be 3–24 characters"}), 400
    if not all(c.isalnum() or c in "_-" for c in username):
        return jsonify({"error": "username: only letters, digits, _ and - allowed"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    pw_hash  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id  = str(uuid.uuid4())

    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?)",
                (user_id, username, pw_hash, public_key, _now_iso(), None),
            )
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username taken"}), 409

    return jsonify({
        "token":    make_token(user_id, username),
        "user_id":  user_id,
        "username": username,
    })


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username   = (data.get("username") or "").strip()
    password   = data.get("password", "")
    public_key = data.get("public_key", "")

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

    if not row or not bcrypt.checkpw(password.encode(), row["pw_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    if public_key:
        with get_db() as db:
            db.execute(
                "UPDATE users SET public_key=?, last_seen=? WHERE id=?",
                (public_key, _now_iso(), row["id"]),
            )

    return jsonify({
        "token":    make_token(row["id"], row["username"]),
        "user_id":  row["id"],
        "username": row["username"],
    })


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def _user(sid: str) -> dict | None:
    return _online.get(sid)


def _is_member(db: sqlite3.Connection, channel_id: str, user_id: str) -> bool:
    return bool(db.execute(
        "SELECT 1 FROM channel_members WHERE channel_id=? AND user_id=?",
        (channel_id, user_id),
    ).fetchone())


# ---------------------------------------------------------------------------
# Socket lifecycle
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect(auth=None):
    # Token can arrive via auth dict (client.py) or query param (security_audit.py)
    token = ""
    if auth and isinstance(auth, dict):
        token = auth.get("token", "")
    if not token:
        token = request.args.get("token", "")
    payload = verify_token(token)
    if not payload:
        return False  # reject

    with get_db() as db:
        row = db.execute(
            "SELECT public_key FROM users WHERE id=?", (payload["uid"],)
        ).fetchone()
        if not row:
            return False
        db.execute(
            "UPDATE users SET last_seen=? WHERE id=?",
            (_now_iso(), payload["uid"]),
        )

    _online[request.sid] = {
        "user_id":    payload["uid"],
        "username":   payload["usr"],
        "public_key": row["public_key"],
    }
    emit("connected", {"username": payload["usr"]})


@socketio.on("disconnect")
def on_disconnect():
    user = _online.pop(request.sid, None)
    if not user:
        return
    with get_db() as db:
        memberships = db.execute(
            "SELECT channel_id FROM channel_members WHERE user_id=?",
            (user["user_id"],),
        ).fetchall()
    for m in memberships:
        emit("user_left", {"username": user["username"]},
             room=m["channel_id"], include_self=False)


# ---------------------------------------------------------------------------
# Channel operations
# ---------------------------------------------------------------------------

@socketio.on("create_channel")
def on_create_channel(data):
    user = _user(request.sid)
    if not user:
        return

    name = (data.get("name") or "").strip().lower().lstrip("#")
    encrypted_key = data.get("encrypted_key", "")   # channel key encrypted for creator

    if not name or not encrypted_key:
        emit("error", {"message": "channel name and encrypted_key required"})
        return

    channel_id = str(uuid.uuid4())
    now = _now_iso()

    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO channels VALUES (?,?,1,?,?)",
                (channel_id, name, user["user_id"], now),
            )
            db.execute(
                "INSERT INTO channel_members VALUES (?,?,'owner',?)",
                (channel_id, user["user_id"], now),
            )
            db.execute(
                "INSERT INTO channel_keys VALUES (?,?,?)",
                (channel_id, user["user_id"], encrypted_key),
            )
        except sqlite3.IntegrityError:
            emit("error", {"message": f"Channel #{name} already exists"})
            return

    emit("channel_created", {"channel_id": channel_id, "name": name})


@socketio.on("list_my_channels")
def on_list_my_channels():
    user = _user(request.sid)
    if not user:
        return
    with get_db() as db:
        rows = db.execute("""
            SELECT c.id, c.name
            FROM channels c
            JOIN channel_members cm ON c.id = cm.channel_id
            WHERE cm.user_id = ?
            ORDER BY c.name
        """, (user["user_id"],)).fetchall()
    emit("my_channels", {"channels": [dict(r) for r in rows]})


@socketio.on("join_channel")
def on_join_channel(data):
    user = _user(request.sid)
    if not user:
        return

    channel_id = data.get("channel_id", "")

    with get_db() as db:
        if not _is_member(db, channel_id, user["user_id"]):
            emit("error", {"message": "Not a member of this channel"})
            return

        channel = db.execute(
            "SELECT * FROM channels WHERE id=?", (channel_id,)
        ).fetchone()

        key_row = db.execute(
            "SELECT encrypted_key FROM channel_keys WHERE channel_id=? AND user_id=?",
            (channel_id, user["user_id"]),
        ).fetchone()

        # 50 most recent messages, oldest first
        msgs = db.execute("""
            SELECT id, sender_name, encrypted_content, created_at
            FROM messages
            WHERE channel_id=?
            ORDER BY created_at DESC
            LIMIT 50
        """, (channel_id,)).fetchall()

        # Online users in this channel
        online_in_channel = [
            u["username"]
            for u in _online.values()
            if _is_member(db, channel_id, u["user_id"])
        ]

    join_room(channel_id)
    emit("channel_joined", {
        "channel_id":    channel_id,
        "channel_name":  channel["name"],
        "encrypted_key": key_row["encrypted_key"] if key_row else None,
        "history":       [dict(m) for m in reversed(msgs)],
        "online_users":  online_in_channel,
    })
    emit("user_joined", {"username": user["username"]},
         room=channel_id, include_self=False)


@socketio.on("leave_channel")
def on_leave_channel(data):
    user = _user(request.sid)
    if not user:
        return
    channel_id = data.get("channel_id", "")
    leave_room(channel_id)
    emit("user_left", {"username": user["username"]},
         room=channel_id, include_self=False)


# ---------------------------------------------------------------------------
# Messaging
# ---------------------------------------------------------------------------

@socketio.on("send_message")
def on_send_message(data):
    user = _user(request.sid)
    if not user:
        return

    channel_id        = data.get("channel_id", "")
    encrypted_content = data.get("encrypted_content", "")

    if not channel_id or not encrypted_content:
        return

    with get_db() as db:
        if not _is_member(db, channel_id, user["user_id"]):
            emit("error", {"message": "Not a member"})
            return

        msg_id = str(uuid.uuid4())
        now    = _now_iso()
        db.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?)",
            (msg_id, channel_id, user["user_id"],
             user["username"], encrypted_content, now),
        )

    socketio.emit("new_message", {
        "id":                msg_id,
        "channel_id":        channel_id,
        "sender_name":       user["username"],
        "encrypted_content": encrypted_content,
        "created_at":        now,
    }, room=channel_id)


# ---------------------------------------------------------------------------
# Invite flow
# ---------------------------------------------------------------------------

@socketio.on("get_public_key")
def on_get_public_key(data):
    """Return a user's public key so the inviter can encrypt the channel key for them."""
    username = (data.get("username") or "").strip()
    with get_db() as db:
        row = db.execute(
            "SELECT id, public_key FROM users WHERE username=?", (username,)
        ).fetchone()
    if not row:
        emit("error", {"message": f"User '{username}' not found"})
        return
    emit("peer_public_key", {
        "username":   username,
        "user_id":    row["id"],
        "public_key": row["public_key"],
    })


@socketio.on("send_invite")
def on_send_invite(data):
    """
    Store an invite. The inviter has already encrypted the channel key for the invitee
    (client-side, using ECDH). The server just stores the opaque ciphertext.
    """
    user = _user(request.sid)
    if not user:
        return

    channel_id     = data.get("channel_id", "")
    invitee_id     = data.get("invitee_id", "")
    encrypted_key  = data.get("encrypted_key", "")   # channel key encrypted for invitee
    inviter_pubkey = user["public_key"]               # so invitee can do ECDH

    with get_db() as db:
        if not _is_member(db, channel_id, user["user_id"]):
            emit("error", {"message": "You are not in this channel"})
            return
        invitee = db.execute(
            "SELECT username FROM users WHERE id=?", (invitee_id,)
        ).fetchone()
        if not invitee:
            emit("error", {"message": "Invitee not found"})
            return

        token      = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()

        db.execute(
            "INSERT INTO invites VALUES (?,?,?,?,?,?,?,0)",
            (token, channel_id, user["user_id"],
             invitee_id, encrypted_key, inviter_pubkey, expires_at),
        )

    emit("invite_ready", {"token": token, "invitee": invitee["username"]})


@socketio.on("accept_invite")
def on_accept_invite(data):
    user  = _user(request.sid)
    if not user:
        return
    token = data.get("token", "")

    with get_db() as db:
        invite = db.execute(
            "SELECT * FROM invites WHERE token=? AND used=0", (token,)
        ).fetchone()

        if not invite:
            emit("error", {"message": "Invalid or already-used invite token"})
            return

        if invite["invitee_id"] != user["user_id"]:
            emit("error", {"message": "This invite is not for you"})
            return

        now = datetime.now(timezone.utc)
        if invite["expires_at"] < now.isoformat():
            emit("error", {"message": "Invite has expired"})
            return

        channel = db.execute(
            "SELECT name FROM channels WHERE id=?", (invite["channel_id"],)
        ).fetchone()

        joined_at = _now_iso()
        db.execute(
            "INSERT OR IGNORE INTO channel_members VALUES (?,?,'member',?)",
            (invite["channel_id"], user["user_id"], joined_at),
        )
        db.execute(
            "INSERT OR REPLACE INTO channel_keys VALUES (?,?,?)",
            (invite["channel_id"], user["user_id"], invite["encrypted_key"]),
        )
        db.execute("UPDATE invites SET used=1 WHERE token=?", (token,))

    emit("invite_accepted", {
        "channel_id":      invite["channel_id"],
        "channel_name":    channel["name"],
        "encrypted_key":   invite["encrypted_key"],
        "inviter_pubkey":  invite["inviter_pubkey"],
    })


if __name__ == "__main__":
    host  = os.environ.get("HOST", "0.0.0.0")
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    print(f"[SecureMsg] Server listening on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
