-- Enhanced Email Database Schema
-- Save this as database_schema.sql

-- Users table (already exists, adding new fields)
ALTER TABLE users ADD COLUMN spam_threshold INTEGER DEFAULT 5;
ALTER TABLE users ADD COLUMN auto_delete_spam INTEGER DEFAULT 1;
ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP;

-- Enhanced emails table with additional fields
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE,
    sender_email TEXT,
    recipient_email TEXT,
    subject TEXT,
    body TEXT,
    security_score INTEGER DEFAULT 50,
    has_dangerous_links INTEGER DEFAULT 0,
    security_warnings TEXT,
    sent_at TEXT,
    is_read INTEGER DEFAULT 0,
    is_spam INTEGER DEFAULT 0,
    is_flagged INTEGER DEFAULT 0,
    is_subscription INTEGER DEFAULT 0,
    folder TEXT DEFAULT 'inbox', -- inbox, sent, spam, trash
    is_deleted INTEGER DEFAULT 0,
    deleted_at TEXT,
    unsubscribe_token TEXT,
    subscription_source TEXT
);

-- Enhanced sender_reputation table
CREATE TABLE IF NOT EXISTS sender_reputation (
    email TEXT UNIQUE,
    safe_score INTEGER DEFAULT 50,
    total_flags INTEGER DEFAULT 0,
    total_spam_reports INTEGER DEFAULT 0,
    badge_color TEXT DEFAULT 'yellow',
    first_seen TEXT,
    last_flagged TEXT,
    is_whitelisted INTEGER DEFAULT 0,
    is_blacklisted INTEGER DEFAULT 0
);

-- Enhanced flags table
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_email TEXT,
    flagger_email TEXT,
    reason TEXT,
    severity TEXT DEFAULT 'medium', -- low, medium, high
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Spam reports table
CREATE TABLE IF NOT EXISTS spam_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_email TEXT,
    reporter_email TEXT,
    email_id INTEGER,
    reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id)
);

-- Subscriptions table
CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    sender_email TEXT,
    subscription_name TEXT,
    unsubscribe_token TEXT UNIQUE,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    unsubscribed_at TEXT
);

-- User folders table
CREATE TABLE IF NOT EXISTS user_folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    folder_name TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Email labels table
CREATE TABLE IF NOT EXISTS email_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    label_name TEXT,
    user_email TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email_id) REFERENCES emails(id)
);

-- Security logs table (already exists)
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT,
    severity TEXT,
    user_email TEXT,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);