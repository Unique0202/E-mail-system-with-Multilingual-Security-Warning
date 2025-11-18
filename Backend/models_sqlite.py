"""
Database Models - SQLite Version for Executable
Save as: models_sqlite.py
"""

import sqlite3
from datetime import datetime
import json
import hashlib
import os
from pathlib import Path

class DatabaseManager:
    """SQLite database manager for standalone app"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            app_dir = Path.home() / '.secure_email_app'
            app_dir.mkdir(exist_ok=True)
            db_path = str(app_dir / 'email_app.db')
        
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                preferred_languages TEXT DEFAULT '["en", "hi"]',
                safe_score INTEGER DEFAULT 100,
                flags_received INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                is_locked INTEGER DEFAULT 0,
                email_verified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT,
                is_recovery INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Recovery codes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                is_used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Emails table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                body_path TEXT,
                size_bytes INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                is_flagged INTEGER DEFAULT 0,
                is_deleted INTEGER DEFAULT 0,
                is_spam INTEGER DEFAULT 0,
                security_score INTEGER DEFAULT 50,
                has_dangerous_links INTEGER DEFAULT 0,
                security_warnings TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                deleted_at TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)
        
        # Sender reputation table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sender_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT UNIQUE NOT NULL,
                safe_score INTEGER DEFAULT 50,
                total_flags INTEGER DEFAULT 0,
                badge_color TEXT DEFAULT 'yellow',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_flagged TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Flags table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_reputation_id INTEGER NOT NULL,
                flagger_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_reputation_id) REFERENCES sender_reputation(id),
                FOREIGN KEY (flagger_id) REFERENCES users(id),
                UNIQUE(sender_reputation_id, flagger_id)
            )
        """)
        
        # Link cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS link_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                is_safe INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                warnings TEXT,
                malicious_reports INTEGER DEFAULT 0,
                safe_reports INTEGER DEFAULT 0,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        
        # Security logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                user_id INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_recipient ON emails(recipient_id, sent_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_sender ON emails(sender_id, sent_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sender_reputation_email ON sender_reputation(sender_email)")
        
        conn.commit()
        conn.close()
        print("✓ SQLite database initialized")


class User:
    """User model"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def create(self, email: str, password_hash: str, totp_secret: str, preferred_languages: list) -> int:
        """Create new user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO users (email, password_hash, totp_secret, preferred_languages)
            VALUES (?, ?, ?, ?)
        """, (email, password_hash, totp_secret, json.dumps(preferred_languages)))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return user_id
    
    def get_by_email(self, email: str):
        """Get user by email"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            user_dict = dict(user)
            # Parse JSON fields
            if user_dict.get('preferred_languages'):
                user_dict['preferred_languages'] = json.loads(user_dict['preferred_languages'])
            return user_dict
        return None
    
    def get_by_id(self, user_id: int):
        """Get user by ID"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            user_dict = dict(user)
            # Parse JSON fields
            if user_dict.get('preferred_languages'):
                user_dict['preferred_languages'] = json.loads(user_dict['preferred_languages'])
            return user_dict
        return None
    
    def update_last_login(self, user_id: int):
        """Update last login timestamp"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE users SET last_login = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (user_id,))
        
        conn.commit()
        conn.close()
    
    def update_languages(self, user_id: int, languages: list):
        """Update preferred languages"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE users SET preferred_languages = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (json.dumps(languages), user_id))
        
        conn.commit()
        conn.close()


class Session:
    """Session model"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def create(self, session_token: str, user_id: int, ip_address: str, 
               user_agent: str, expires_at: datetime, is_recovery: bool = False) -> int:
        """Create new session"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO sessions (session_token, user_id, ip_address, user_agent, expires_at, is_recovery)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_token, user_id, ip_address, user_agent, expires_at.isoformat(), 1 if is_recovery else 0))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id
    
    def get_by_token(self, session_token: str):
        """Get session by token"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM sessions WHERE session_token = ?", (session_token,))
        session = cursor.fetchone()
        conn.close()
        
        if session:
            return dict(session)
        return None
    
    def delete(self, session_token: str):
        """Delete session"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
        
        conn.commit()
        conn.close()
    
    def update_activity(self, session_token: str):
        """Update last activity"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE sessions SET last_activity = CURRENT_TIMESTAMP
            WHERE session_token = ?
        """, (session_token,))
        
        conn.commit()
        conn.close()


class Email:
    """Email model"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def create(self, message_id: str, sender_id: int, recipient_id: int,
               subject: str, body_path: str, size_bytes: int) -> int:
        """Create new email"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO emails (message_id, sender_id, recipient_id, subject, body_path, size_bytes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (message_id, sender_id, recipient_id, subject, body_path, size_bytes))
        
        email_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return email_id
    
    def get_inbox(self, user_id: int, limit: int = 50):
        """Get inbox emails"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT e.*, u.email as sender_email
            FROM emails e
            JOIN users u ON e.sender_id = u.id
            WHERE e.recipient_id = ? AND e.is_deleted = 0
            ORDER BY e.sent_at DESC
            LIMIT ?
        """, (user_id, limit))
        
        emails = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return emails
    
    def get_sent(self, user_id: int, limit: int = 50):
        """Get sent emails"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT e.*, u.email as recipient_email
            FROM emails e
            JOIN users u ON e.recipient_id = u.id
            WHERE e.sender_id = ? AND e.is_deleted = 0
            ORDER BY e.sent_at DESC
            LIMIT ?
        """, (user_id, limit))
        
        emails = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return emails
    
    def get_by_message_id(self, message_id: str):
        """Get email by message ID"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT e.*, 
                   s.email as sender_email,
                   r.email as recipient_email
            FROM emails e
            JOIN users s ON e.sender_id = s.id
            JOIN users r ON e.recipient_id = r.id
            WHERE e.message_id = ?
        """, (message_id,))
        
        email = cursor.fetchone()
        conn.close()
        
        if email:
            return dict(email)
        return None
    
    def mark_read(self, message_id: str):
        """Mark email as read"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE emails 
            SET is_read = 1, read_at = CURRENT_TIMESTAMP
            WHERE message_id = ?
        """, (message_id,))
        
        conn.commit()
        conn.close()
    
    def delete(self, message_id: str):
        """Delete email (soft delete)"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE emails 
            SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP
            WHERE message_id = ?
        """, (message_id,))
        
        conn.commit()
        conn.close()


class SenderReputation:
    """Sender reputation model"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def get_or_create(self, sender_email: str):
        """Get or create sender reputation"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM sender_reputation WHERE sender_email = ?", (sender_email,))
        reputation = cursor.fetchone()
        
        if not reputation:
            cursor.execute("""
                INSERT INTO sender_reputation (sender_email)
                VALUES (?)
            """, (sender_email,))
            conn.commit()
            
            cursor.execute("SELECT * FROM sender_reputation WHERE sender_email = ?", (sender_email,))
            reputation = cursor.fetchone()
        
        conn.close()
        
        if reputation:
            return dict(reputation)
        return None
    
    def add_flag(self, sender_email: str, flagger_id: int, reason: str):
        """Add flag to sender"""
        reputation = self.get_or_create(sender_email)
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Check if already flagged
        cursor.execute("""
            SELECT id FROM flags 
            WHERE sender_reputation_id = ? AND flagger_id = ?
        """, (reputation['id'], flagger_id))
        
        if cursor.fetchone():
            conn.close()
            return False
        
        # Add flag
        cursor.execute("""
            INSERT INTO flags (sender_reputation_id, flagger_id, reason)
            VALUES (?, ?, ?)
        """, (reputation['id'], flagger_id, reason))
        
        # Update reputation
        new_score = max(0, reputation['safe_score'] - 10)
        new_flags = reputation['total_flags'] + 1
        
        if new_score >= 70:
            badge_color = 'green'
        elif new_score >= 40:
            badge_color = 'yellow'
        else:
            badge_color = 'red'
        
        cursor.execute("""
            UPDATE sender_reputation
            SET total_flags = ?, safe_score = ?, badge_color = ?,
                last_flagged = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_flags, new_score, badge_color, reputation['id']))
        
        conn.commit()
        conn.close()
        return True
