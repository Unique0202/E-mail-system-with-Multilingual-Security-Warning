"""
Database Models - ALL TABLES
Save as: models.py
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.postgresql import ARRAY, JSON
import hashlib

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=False)
    preferred_languages = db.Column(ARRAY(db.String(5)), default=['en', 'hi'])
    safe_score = db.Column(db.Integer, default=100)
    flags_received = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    is_locked = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    sessions = db.relationship('Session', back_populates='user', cascade='all, delete-orphan')
    recovery_codes = db.relationship('RecoveryCode', back_populates='user', cascade='all, delete-orphan')
    sent_emails = db.relationship('Email', foreign_keys='Email.sender_id', back_populates='sender')
    received_emails = db.relationship('Email', foreign_keys='Email.recipient_id', back_populates='recipient')
    flags_given = db.relationship('Flag', foreign_keys='Flag.flagger_id', back_populates='flagger')
    
    @property
    def mailbox_hash(self):
        return hashlib.sha256(self.email.encode()).hexdigest()[:16]


class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    is_recovery = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    user = db.relationship('User', back_populates='sessions')


class RecoveryCode(db.Model):
    __tablename__ = 'recovery_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)
    
    user = db.relationship('User', back_populates='recovery_codes')


class Email(db.Model):
    __tablename__ = 'emails'
    
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(500), nullable=False)
    body_path = db.Column(db.String(500))
    size_bytes = db.Column(db.Integer, default=0)
    is_read = db.Column(db.Boolean, default=False)
    is_flagged = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    is_spam = db.Column(db.Boolean, default=False)
    security_score = db.Column(db.Integer, default=50)
    has_dangerous_links = db.Column(db.Boolean, default=False)
    security_warnings = db.Column(JSON)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
    
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_emails')
    recipient = db.relationship('User', foreign_keys=[recipient_id], back_populates='received_emails')


class SenderReputation(db.Model):
    __tablename__ = 'sender_reputation'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    safe_score = db.Column(db.Integer, default=50)
    total_flags = db.Column(db.Integer, default=0)
    badge_color = db.Column(db.String(10), default='yellow')
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_flagged = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    flags = db.relationship('Flag', back_populates='sender_reputation', cascade='all, delete-orphan')
    
    def update_badge_color(self):
        if self.safe_score >= 70:
            self.badge_color = 'green'
        elif self.safe_score >= 40:
            self.badge_color = 'yellow'
        else:
            self.badge_color = 'red'


class Flag(db.Model):
    __tablename__ = 'flags'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_reputation_id = db.Column(db.Integer, db.ForeignKey('sender_reputation.id'), nullable=False)
    flagger_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reason = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender_reputation = db.relationship('SenderReputation', back_populates='flags')
    flagger = db.relationship('User', foreign_keys=[flagger_id], back_populates='flags_given')
    
    __table_args__ = (
        db.UniqueConstraint('sender_reputation_id', 'flagger_id', name='unique_flag_per_user'),
    )


class LinkCache(db.Model):
    __tablename__ = 'link_cache'
    
    id = db.Column(db.Integer, primary_key=True)
    url_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    is_safe = db.Column(db.Boolean, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    warnings = db.Column(JSON)
    malicious_reports = db.Column(db.Integer, default=0)
    safe_reports = db.Column(db.Integer, default=0)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)


class RateLimit(db.Model):
    __tablename__ = 'rate_limits'
    
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), nullable=False, index=True)
    request_type = db.Column(db.String(50), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        db.Index('idx_identifier_type_time', 'identifier', 'request_type', 'timestamp'),
    )


class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), default='info')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    details = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
        print("✓ Database tables created")


def create_indexes(app):
    with app.app_context():
        # Create additional indexes for performance
        db.session.execute("""
            CREATE INDEX IF NOT EXISTS idx_emails_recipient_sent 
            ON emails(recipient_id, sent_at DESC)
        """)
        db.session.execute("""
            CREATE INDEX IF NOT EXISTS idx_emails_sender_sent 
            ON emails(sender_id, sent_at DESC)
        """)
        db.session.execute("""
            CREATE INDEX IF NOT EXISTS idx_flags_sender 
            ON flags(sender_reputation_id, created_at DESC)
        """)
        db.session.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_token 
            ON sessions(session_token)
        """)
        db.session.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email 
            ON users(email)
        """)
        db.session.commit()
        print("✓ Database indexes created")