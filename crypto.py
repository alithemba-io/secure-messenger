"""
crypto.py — End-to-end encryption primitives.

Key design:
  - Each user has an X25519 keypair stored locally at ~/.securemsg/identity.json
    (private key encrypted with their login password via PBKDF2 + Fernet)
  - Channel keys are 32-byte random secrets stored locally at ~/.securemsg/channels.json
    (encrypted with the same password)
  - When inviting a user, the inviter encrypts the channel key using ECDH(inviter_priv, invitee_pub)
    + ChaCha20-Poly1305. The ciphertext travels through the server but the server never sees the key.
  - Messages are encrypted with ChaCha20-Poly1305 using the channel key.
    The server stores and relays only ciphertext.
"""

import os
import json
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.fernet import Fernet, InvalidToken

IDENTITY_DIR = Path.home() / ".securemsg"
IDENTITY_FILE = IDENTITY_DIR / "identity.json"
CHANNELS_FILE = IDENTITY_DIR / "channels.json"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pbkdf2_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _ecdh_key(my_private: X25519PrivateKey, their_public_b64: str) -> bytes:
    """Derive a 32-byte symmetric key from an X25519 key-exchange."""
    their_pub_bytes = base64.b64decode(their_public_b64)
    their_public = X25519PublicKey.from_public_bytes(their_pub_bytes)
    shared = my_private.exchange(their_public)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"securemsg-channel-key-v1",
    )
    return hkdf.derive(shared)


# ---------------------------------------------------------------------------
# Identity (keypair)
# ---------------------------------------------------------------------------

def identity_exists() -> bool:
    return IDENTITY_FILE.exists()


def generate_and_save_identity(password: str) -> str:
    """
    Generate a fresh X25519 keypair, encrypt the private key with *password*,
    persist to disk. Returns the base64-encoded public key (to register with server).
    """
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)

    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

    salt = os.urandom(16)
    fernet_key = _pbkdf2_fernet_key(password, salt)
    encrypted_private = Fernet(fernet_key).encrypt(private_bytes)

    IDENTITY_FILE.write_text(json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "encrypted_private": base64.b64encode(encrypted_private).decode(),
    }))

    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode()


def load_identity(password: str) -> X25519PrivateKey:
    """Decrypt and return the private key. Raises ValueError on wrong password."""
    data = json.loads(IDENTITY_FILE.read_text())
    salt = base64.b64decode(data["salt"])
    encrypted_private = base64.b64decode(data["encrypted_private"])

    fernet_key = _pbkdf2_fernet_key(password, salt)
    try:
        private_bytes = Fernet(fernet_key).decrypt(encrypted_private)
    except InvalidToken:
        raise ValueError("Wrong password or corrupted identity file.")
    return X25519PrivateKey.from_private_bytes(private_bytes)


def get_public_key_b64(private_key: X25519PrivateKey) -> str:
    pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode()


# ---------------------------------------------------------------------------
# Peer encryption (used for invite key exchange)
# ---------------------------------------------------------------------------

def encrypt_for_peer(
    data: bytes,
    my_private: X25519PrivateKey,
    their_public_b64: str,
) -> str:
    """Encrypt *data* for a peer using ECDH + ChaCha20-Poly1305. Returns base64."""
    sym_key = _ecdh_key(my_private, their_public_b64)
    aead = ChaCha20Poly1305(sym_key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_from_peer(
    encrypted_b64: str,
    my_private: X25519PrivateKey,
    their_public_b64: str,
) -> bytes:
    """Decrypt data from a peer. Raises cryptography.exceptions.InvalidTag on failure."""
    sym_key = _ecdh_key(my_private, their_public_b64)
    raw = base64.b64decode(encrypted_b64)
    nonce, ct = raw[:12], raw[12:]
    return ChaCha20Poly1305(sym_key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# Message encryption
# ---------------------------------------------------------------------------

def generate_channel_key() -> bytes:
    return os.urandom(32)


def encrypt_message(plaintext: str, channel_key: bytes) -> str:
    """Encrypt a chat message. Returns base64 ciphertext (nonce prepended)."""
    aead = ChaCha20Poly1305(channel_key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_message(encrypted_b64: str, channel_key: bytes) -> str:
    """Decrypt a chat message. Raises on failure."""
    raw = base64.b64decode(encrypted_b64)
    nonce, ct = raw[:12], raw[12:]
    return ChaCha20Poly1305(channel_key).decrypt(nonce, ct, None).decode("utf-8")


# ---------------------------------------------------------------------------
# Local channel-key store  (~/.securemsg/channels.json)
# ---------------------------------------------------------------------------

def _load_store(password: str) -> dict:
    if not CHANNELS_FILE.exists():
        return {}
    data = json.loads(CHANNELS_FILE.read_text())
    salt = base64.b64decode(data["salt"])
    fernet_key = _pbkdf2_fernet_key(password, salt)
    try:
        decrypted = Fernet(fernet_key).decrypt(base64.b64decode(data["blob"]))
        return json.loads(decrypted)
    except (InvalidToken, KeyError):
        return {}


def _save_store(store: dict, password: str) -> None:
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    fernet_key = _pbkdf2_fernet_key(password, salt)
    blob = Fernet(fernet_key).encrypt(json.dumps(store).encode())
    CHANNELS_FILE.write_text(json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "blob": base64.b64encode(blob).decode(),
    }))


def store_channel_key(channel_id: str, channel_key: bytes, password: str) -> None:
    store = _load_store(password)
    store[channel_id] = base64.b64encode(channel_key).decode()
    _save_store(store, password)


def get_channel_key(channel_id: str, password: str) -> bytes | None:
    store = _load_store(password)
    val = store.get(channel_id)
    return base64.b64decode(val) if val else None
