from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import sqlite3
from datetime import datetime
import os
import secrets
import bcrypt

class SecureMessagingApp:
    def __init__(self, db_name="secure_messages.db"):
        self.db_name = db_name
        self.setup_database()
        
    def setup_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table with salted password hashes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Messages table with encrypted content
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                recipient_id INTEGER,
                encrypted_content TEXT NOT NULL,
                iv TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user with securely hashed password"""
        try:
            # Generate salt and hash password
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode(), salt)
            
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash.decode(), salt.decode())
            )
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.IntegrityError:
            return False  # Username already exists
        
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user with username and password"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            stored_hash = result[0].encode()
            return bcrypt.checkpw(password.encode(), stored_hash)
        return False

    def send_message(self, sender: str, recipient: str, message: str) -> bool:
        """Send an encrypted message from sender to recipient"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            # Get user IDs
            cursor.execute("SELECT id FROM users WHERE username = ?", (sender,))
            sender_id = cursor.fetchone()[0]
            cursor.execute("SELECT id FROM users WHERE username = ?", (recipient,))
            recipient_id = cursor.fetchone()[0]
            
            # Generate encryption key and IV
            iv = os.urandom(16)
            key = Fernet.generate_key()
            f = Fernet(key)
            
            # Encrypt message
            encrypted_message = f.encrypt(message.encode())
            
            # Store encrypted message
            cursor.execute("""
                INSERT INTO messages (sender_id, recipient_id, encrypted_content, iv)
                VALUES (?, ?, ?, ?)
            """, (sender_id, recipient_id, encrypted_message.decode(), base64.b64encode(iv).decode()))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error sending message: {e}")
            return False

    def get_messages(self, username: str) -> list:
        """Retrieve messages for a user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT sender.username, messages.encrypted_content, messages.timestamp
            FROM messages
            JOIN users as recipient ON messages.recipient_id = recipient.id
            JOIN users as sender ON messages.sender_id = sender.id
            WHERE recipient.username = ?
            ORDER BY messages.timestamp DESC
        """, (username,))
        
        messages = cursor.fetchall()
        conn.close()
        
        return messages

    def delete_message(self, message_id: int, username: str) -> bool:
        """Delete a message (only if user is the recipient)"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM messages 
            WHERE id = ? AND recipient_id = (
                SELECT id FROM users WHERE username = ?
            )
        """, (message_id, username))
        
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return deleted