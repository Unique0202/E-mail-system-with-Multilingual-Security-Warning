// Save this as databaseManager.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

class DatabaseManager {
    constructor(dbPath = null) {
        this.dbPath = dbPath || path.join(require('electron').app.getPath('userData'), 'secure_email.db');
        this.db = new sqlite3.Database(this.dbPath);
        this.initDatabase();
    }

    initDatabase() {
        // Run the enhanced schema
        const fs = require('fs');
        const schemaPath = path.join(__dirname, 'database_schema.sql');
        
        if (fs.existsSync(schemaPath)) {
            const schema = fs.readFileSync(schemaPath, 'utf8');
            this.db.exec(schema, (err) => {
                if (err) {
                    console.error('Error initializing database:', err);
                } else {
                    console.log('Database initialized successfully');
                }
            });
        } else {
            console.warn('Schema file not found, using default initialization');
            this.initDefaultTables();
        }
    }

    initDefaultTables() {
        // This would contain all the CREATE TABLE statements from above
        // For brevity, I'm including the key tables
        const tables = [
            `CREATE TABLE IF NOT EXISTS emails (
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
                folder TEXT DEFAULT 'inbox',
                is_deleted INTEGER DEFAULT 0,
                deleted_at TEXT,
                unsubscribe_token TEXT,
                subscription_source TEXT
            )`,
            
            `CREATE TABLE IF NOT EXISTS spam_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT,
                reporter_email TEXT,
                email_id INTEGER,
                reason TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            
            `CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                sender_email TEXT,
                subscription_name TEXT,
                unsubscribe_token TEXT UNIQUE,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                unsubscribed_at TEXT
            )`
        ];

        tables.forEach(tableSQL => {
            this.db.run(tableSQL);
        });
    }

    // Email Operations
    async saveEmail(emailData) {
        return new Promise((resolve, reject) => {
            const {
                message_id, sender_email, recipient_email, subject, body,
                security_score = 50, has_dangerous_links = 0, security_warnings = '[]',
                is_spam = 0, is_subscription = 0, folder = 'inbox', unsubscribe_token = null
            } = emailData;

            const sql = `INSERT INTO emails (
                message_id, sender_email, recipient_email, subject, body,
                security_score, has_dangerous_links, security_warnings,
                sent_at, is_spam, is_subscription, folder, unsubscribe_token
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?)`;

            this.db.run(sql, [
                message_id, sender_email, recipient_email, subject, body,
                security_score, has_dangerous_links, security_warnings,
                is_spam, is_subscription, folder, unsubscribe_token
            ], function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, message_id });
            });
        });
    }

    async getEmailsForUser(userEmail, folder = 'inbox', includeDeleted = false) {
        return new Promise((resolve, reject) => {
            let sql = `SELECT * FROM emails WHERE recipient_email = ? AND folder = ?`;
            let params = [userEmail, folder];

            if (!includeDeleted) {
                sql += ` AND is_deleted = 0`;
            }

            sql += ` ORDER BY sent_at DESC`;

            this.db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    async getSentEmails(userEmail) {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM emails WHERE sender_email = ? AND folder = 'sent' AND is_deleted = 0 ORDER BY sent_at DESC`;
            this.db.all(sql, [userEmail], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // Spam Management
    async markAsSpam(emailId, userEmail, reason = 'User reported') {
        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                // Update email
                this.db.run(
                    `UPDATE emails SET is_spam = 1, folder = 'spam' WHERE id = ? AND recipient_email = ?`,
                    [emailId, userEmail]
                );

                // Get sender email for reputation update
                this.db.get(
                    `SELECT sender_email FROM emails WHERE id = ?`,
                    [emailId],
                    (err, email) => {
                        if (email) {
                            // Update sender reputation
                            this.updateSenderReputation(email.sender_email, -10);
                            
                            // Log spam report
                            this.db.run(
                                `INSERT INTO spam_reports (sender_email, reporter_email, email_id, reason) VALUES (?, ?, ?, ?)`,
                                [email.sender_email, userEmail, emailId, reason]
                            );
                        }
                    }
                );

                resolve({ success: true });
            });
        });
    }

    async getSpamEmails(userEmail) {
        return this.getEmailsForUser(userEmail, 'spam');
    }

    // Subscription Management
    async addSubscription(userEmail, senderEmail, subscriptionName = null) {
        return new Promise((resolve, reject) => {
            const unsubscribeToken = crypto.randomBytes(32).toString('hex');
            const sql = `INSERT INTO subscriptions (user_email, sender_email, subscription_name, unsubscribe_token) VALUES (?, ?, ?, ?)`;
            
            this.db.run(sql, [userEmail, senderEmail, subscriptionName, unsubscribeToken], function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, unsubscribe_token: unsubscribeToken });
            });
        });
    }

    async unsubscribe(userEmail, unsubscribeToken) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE subscriptions SET is_active = 0, unsubscribed_at = datetime('now') WHERE user_email = ? AND unsubscribe_token = ?`;
            
            this.db.run(sql, [userEmail, unsubscribeToken], function(err) {
                if (err) reject(err);
                else resolve({ success: this.changes > 0 });
            });
        });
    }

    async getUserSubscriptions(userEmail, activeOnly = true) {
        return new Promise((resolve, reject) => {
            let sql = `SELECT * FROM subscriptions WHERE user_email = ?`;
            if (activeOnly) sql += ` AND is_active = 1`;
            sql += ` ORDER BY created_at DESC`;

            this.db.all(sql, [userEmail], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // Flagging System
    async flagEmail(emailId, userEmail, reason, severity = 'medium') {
        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                // Mark email as flagged
                this.db.run(
                    `UPDATE emails SET is_flagged = 1 WHERE id = ?`,
                    [emailId]
                );

                // Get sender email
                this.db.get(
                    `SELECT sender_email FROM emails WHERE id = ?`,
                    [emailId],
                    (err, email) => {
                        if (email) {
                            // Add to flags table
                            this.db.run(
                                `INSERT INTO flags (sender_email, flagger_email, reason, severity) VALUES (?, ?, ?, ?)`,
                                [email.sender_email, userEmail, reason, severity]
                            );

                            // Update sender reputation
                            const scoreChange = severity === 'high' ? -15 : severity === 'medium' ? -10 : -5;
                            this.updateSenderReputation(email.sender_email, scoreChange);
                        }
                    }
                );

                resolve({ success: true });
            });
        });
    }

    // Sender Reputation Management
    async updateSenderReputation(senderEmail, scoreChange) {
        return new Promise((resolve, reject) => {
            const sql = `INSERT OR REPLACE INTO sender_reputation 
                        (email, safe_score, total_flags, last_flagged) 
                        VALUES (?, 
                                COALESCE((SELECT safe_score FROM sender_reputation WHERE email = ?), 50) + ?, 
                                COALESCE((SELECT total_flags FROM sender_reputation WHERE email = ?), 0) + 1,
                                datetime('now'))`;

            this.db.run(sql, [senderEmail, senderEmail, scoreChange, senderEmail], function(err) {
                if (err) reject(err);
                else resolve({ success: true });
            });
        });
    }

    async getSenderReputation(senderEmail) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT * FROM sender_reputation WHERE email = ?`,
                [senderEmail],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row || { email: senderEmail, safe_score: 50, total_flags: 0, badge_color: 'yellow' });
                }
            );
        });
    }

    // Deletion and Cleanup
    async softDeleteEmail(emailId, userEmail) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE emails SET is_deleted = 1, deleted_at = datetime('now'), folder = 'trash' WHERE id = ? AND recipient_email = ?`;
            
            this.db.run(sql, [emailId, userEmail], function(err) {
                if (err) reject(err);
                else resolve({ success: this.changes > 0 });
            });
        });
    }

    async permanentDeleteEmail(emailId, userEmail) {
        return new Promise((resolve, reject) => {
            const sql = `DELETE FROM emails WHERE id = ? AND recipient_email = ?`;
            
            this.db.run(sql, [emailId, userEmail], function(err) {
                if (err) reject(err);
                else resolve({ success: this.changes > 0 });
            });
        });
    }

    async emptyTrash(userEmail) {
        return new Promise((resolve, reject) => {
            const sql = `DELETE FROM emails WHERE recipient_email = ? AND folder = 'trash'`;
            
            this.db.run(sql, [userEmail], function(err) {
                if (err) reject(err);
                else resolve({ success: true, deleted: this.changes });
            });
        });
    }

    // Security and Analysis
    async logSecurityEvent(eventType, severity, userEmail, details) {
        return new Promise((resolve, reject) => {
            const sql = `INSERT INTO security_logs (event_type, severity, user_email, details) VALUES (?, ?, ?, ?)`;
            
            this.db.run(sql, [eventType, severity, userEmail, JSON.stringify(details)], function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID });
            });
        });
    }

    async getSecurityReport(userEmail, limit = 100) {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM security_logs WHERE user_email = ? ORDER BY created_at DESC LIMIT ?`;
            
            this.db.all(sql, [userEmail, limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // Statistics
    async getUserStats(userEmail) {
        return new Promise((resolve, reject) => {
            const sql = `
                SELECT 
                    folder,
                    COUNT(*) as count,
                    SUM(is_read) as read_count,
                    SUM(is_flagged) as flagged_count,
                    SUM(is_spam) as spam_count
                FROM emails 
                WHERE recipient_email = ? AND is_deleted = 0
                GROUP BY folder
            `;
            
            this.db.all(sql, [userEmail], (err, rows) => {
                if (err) reject(err);
                else {
                    const stats = {
                        inbox: 0,
                        spam: 0,
                        sent: 0,
                        trash: 0,
                        read: 0,
                        flagged: 0
                    };

                    rows.forEach(row => {
                        stats[row.folder] = row.count;
                        if (row.folder === 'inbox') {
                            stats.read = row.read_count;
                            stats.flagged = row.flagged_count;
                        }
                    });

                    resolve(stats);
                }
            });
        });
    }

    close() {
        this.db.close();
    }
}

module.exports = DatabaseManager;