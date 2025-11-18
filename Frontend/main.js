const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

// Security imports
const {
    BufferOverflowProtection,
    SQLInjectionProtection,
    XSSProtection
} = require('./security/inputValidation');

const {
    SecurityWarningTranslations,
    EmailSecurityAnalyzer
} = require('./security/multilingualWarnings');

const { OpenSourceLinkVerifier } = require('./security/linkVerifier');

// --- Global State ---
let mainWindow;
let authenticatedUser = null;
let linkVerifier = new OpenSourceLinkVerifier();

// --- Database Setup ---
const dbPath = path.join(app.getPath('userData'), 'secure_email.db');
const db = new sqlite3.Database(dbPath);

function initDb() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash TEXT,
            totp_secret TEXT,
            preferred_languages TEXT,
            last_login TEXT,
            safe_score INTEGER DEFAULT 100,
            flags_received INTEGER DEFAULT 0
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS emails (
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
            is_read INTEGER DEFAULT 0
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS sender_reputation (
            email TEXT UNIQUE,
            safe_score INTEGER DEFAULT 50,
            total_flags INTEGER DEFAULT 0,
            badge_color TEXT DEFAULT 'yellow',
            first_seen TEXT,
            last_flagged TEXT
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT,
            flagger_email TEXT,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            severity TEXT,
            user_email TEXT,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )`);
    });
}

// --- Security Logging ---
function logSecurityEvent(eventType, severity, userEmail, details) {
    db.run(`INSERT INTO security_logs (event_type, severity, user_email, details) 
            VALUES (?, ?, ?, ?)`, 
            [eventType, severity, userEmail, JSON.stringify(details)]);
}

// --- Sender Reputation Management ---
function getOrCreateSenderReputation(senderEmail) {
    return new Promise((resolve) => {
        db.get(`SELECT * FROM sender_reputation WHERE email = ?`, [senderEmail], (err, row) => {
            if (err || !row) {
                // Create new reputation entry
                const now = new Date().toISOString();
                db.run(`INSERT INTO sender_reputation (email, first_seen) VALUES (?, ?)`, 
                      [senderEmail, now], function(err) {
                    if (err) {
                        resolve({ email: senderEmail, safe_score: 50, total_flags: 0, badge_color: 'yellow' });
                    } else {
                        resolve({ email: senderEmail, safe_score: 50, total_flags: 0, badge_color: 'yellow' });
                    }
                });
            } else {
                resolve(row);
            }
        });
    });
}

function updateSenderReputation(senderEmail, flaggerEmail, reason) {
    return new Promise((resolve) => {
        // Check if already flagged by this user
        db.get(`SELECT id FROM flags WHERE sender_email = ? AND flagger_email = ?`, 
              [senderEmail, flaggerEmail], (err, row) => {
            if (row) {
                resolve(false); // Already flagged
                return;
            }

            // Add flag
            db.run(`INSERT INTO flags (sender_email, flagger_email, reason) VALUES (?, ?, ?)`,
                  [senderEmail, flaggerEmail, reason], function(err) {
                if (err) {
                    resolve(false);
                    return;
                }

                // Update reputation
                db.get(`SELECT COUNT(*) as flag_count FROM flags WHERE sender_email = ?`, 
                      [senderEmail], (err, countRow) => {
                    const flagCount = countRow.flag_count;
                    let newScore = Math.max(0, 100 - (flagCount * 10));
                    let badgeColor = 'green';
                    
                    if (newScore < 40) badgeColor = 'red';
                    else if (newScore < 70) badgeColor = 'yellow';

                    const now = new Date().toISOString();
                    db.run(`INSERT OR REPLACE INTO sender_reputation 
                           (email, safe_score, total_flags, badge_color, last_flagged) 
                           VALUES (?, ?, ?, ?, ?)`,
                          [senderEmail, newScore, flagCount, badgeColor, now], function(err) {
                        resolve(!err);
                    });
                });
            });
        });
    });
}

// --- Window Management ---
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });

    mainWindow.loadFile('html/login.html');
}

app.whenReady().then(() => {
    initDb();
    createWindow();
});

// --- Page Navigation Handler ---
ipcMain.on('change-page', (event, page) => {
    if (page === 'dashboard' && authenticatedUser) {
        mainWindow.loadFile('html/dashboard.html');
    } else if (page === 'login') {
        authenticatedUser = null;
        mainWindow.loadFile('html/login.html');
    }
});

// --- API Handlers ---

// 1. Get Session
ipcMain.handle('get-current-user', () => authenticatedUser);

// 2. Login with Security Validation
ipcMain.handle('login', async (event, data) => {
    return new Promise((resolve) => {
        try {
            // Input validation
            const email = BufferOverflowProtection.validateEmail(data.email);
            const password = data.password; // Will be validated with bcrypt
            const totp = BufferOverflowProtection.validateTOTP(data.totp);

            db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
                if (err || !user) {
                    logSecurityEvent('login_failed', 'warning', email, { reason: 'user_not_found' });
                    return resolve({ success: false, error: "Invalid credentials" });
                }

                const match = await bcrypt.compare(password, user.password_hash);
                if (!match) {
                    logSecurityEvent('login_failed', 'warning', email, { reason: 'invalid_password' });
                    return resolve({ success: false, error: "Invalid credentials" });
                }

                const isValidTotp = authenticator.check(data.totp, user.totp_secret);
                if (!isValidTotp) {
                    logSecurityEvent('login_failed', 'warning', email, { reason: 'invalid_2fa' });
                    return resolve({ success: false, error: "Invalid 2FA Code" });
                }

                // SAVE SESSION
                authenticatedUser = { 
                    id: user.id, 
                    email: user.email, 
                    languages: JSON.parse(user.preferred_languages) 
                };

                // Update last login
                db.run(`UPDATE users SET last_login = ? WHERE id = ?`, 
                      [new Date().toISOString(), user.id]);

                logSecurityEvent('login_success', 'info', email, {});
                resolve({ success: true, user: authenticatedUser });
            });
        } catch (error) {
            logSecurityEvent('login_failed', 'warning', data.email, { reason: 'validation_error', error: error.message });
            resolve({ success: false, error: error.message });
        }
    });
});

// 3. Register with Security Validation
ipcMain.handle('register', async (event, data) => {
    try {
        // Input validation
        const email = BufferOverflowProtection.validateEmail(data.email);
        const password = BufferOverflowProtection.validatePassword(data.password);
        const langs = JSON.stringify([data.lang1, data.lang2]);

        const hash = await bcrypt.hash(password, 10);
        const secret = authenticator.generateSecret();

        return new Promise((resolve) => {
            db.run(`INSERT INTO users (email, password_hash, totp_secret, preferred_languages) VALUES (?, ?, ?, ?)`,
                [email, hash, secret, langs],
                async function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE constraint failed')) {
                            resolve({ success: false, error: "This email is already registered. Please login." });
                        } else {
                            resolve({ success: false, error: "Database Error: " + err.message });
                        }
                        return;
                    }
                    
                    const otpauth = authenticator.keyuri(email, 'SecureMail', secret);
                    const qrUrl = await QRCode.toDataURL(otpauth);
                    
                    logSecurityEvent('registration_success', 'info', email, {});
                    resolve({ success: true, qrCode: qrUrl });
                }
            );
        });
    } catch (error) {
        logSecurityEvent('registration_failed', 'warning', data.email, { reason: 'validation_error', error: error.message });
        return { success: false, error: error.message };
    }
});

// 4. Enhanced Email Functions with Security
ipcMain.handle('get-inbox', (event) => {
    if (!authenticatedUser) return [];
    return new Promise((resolve) => {
        db.all(`SELECT e.*, r.safe_score, r.badge_color FROM emails e 
                LEFT JOIN sender_reputation r ON e.sender_email = r.email
                WHERE recipient_email = ? ORDER BY sent_at DESC`, 
                [authenticatedUser.email], (err, rows) => {
            if (err) {
                resolve([]);
                return;
            }

            // Add security analysis to each email
            const enhancedRows = rows.map(row => {
                const reputation = {
                    safe_score: row.safe_score || 50,
                    total_flags: row.total_flags || 0
                };
                
                const securityAnalysis = EmailSecurityAnalyzer.analyzeEmail(
                    row, 
                    reputation, 
                    authenticatedUser.languages
                );

                return {
                    ...row,
                    security_analysis: securityAnalysis
                };
            });

            resolve(enhancedRows);
        });
    });
});

ipcMain.handle('get-sent', (event) => {
    if (!authenticatedUser) return [];
    return new Promise((resolve) => {
        db.all(`SELECT * FROM emails WHERE sender_email = ? ORDER BY sent_at DESC`, 
                [authenticatedUser.email], (err, rows) => resolve(rows || []));
    });
});

ipcMain.handle('send-email', async (event, data) => {
    if (!authenticatedUser) return { success: false, error: "Unauthorized" };

    try {
        // Security validation
        const toEmail = BufferOverflowProtection.validateEmail(data.to);
        const subject = BufferOverflowProtection.sanitizeText(data.subject, 500);
        let body = BufferOverflowProtection.sanitizeText(data.body, 50000);

        // XSS protection
        if (XSSProtection.detectXSS(body)) {
            throw new Error("Email contains dangerous content");
        }

        // Link verification
        const linkCheck = linkVerifier.verifyURL(body);
        let securityScore = 100;
        let securityWarnings = [];
        let hasDangerousLinks = 0;

        if (!linkCheck.is_safe) {
            securityScore -= 30;
            securityWarnings.push(linkCheck.warnings);
            hasDangerousLinks = 1;
        }

        // Get or create sender reputation for recipient
        await getOrCreateSenderReputation(authenticatedUser.email);

        const messageId = `${Date.now()}.${Math.random().toString(36).substr(2, 9)}`;
        
        return new Promise((resolve) => {
            db.run(`INSERT INTO emails (message_id, sender_email, recipient_email, subject, body, 
                    security_score, has_dangerous_links, security_warnings, sent_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [messageId, authenticatedUser.email, toEmail, subject, body, 
                 securityScore, hasDangerousLinks, JSON.stringify(securityWarnings), new Date().toISOString()], 
                (err) => {
                    if (err) {
                        logSecurityEvent('email_send_failed', 'error', authenticatedUser.email, { error: err.message });
                        resolve({ success: false, error: err.message });
                    } else {
                        logSecurityEvent('email_sent', 'info', authenticatedUser.email, { to: toEmail, messageId });
                        resolve({ success: true, messageId });
                    }
                }
            );
        });
    } catch (error) {
        logSecurityEvent('email_send_failed', 'error', authenticatedUser.email, { error: error.message });
        return { success: false, error: error.message };
    }
});

// 5. Security Features
ipcMain.handle('flag-sender', async (event, senderEmail, reason) => {
    if (!authenticatedUser) return { success: false, error: "Unauthorized" };

    try {
        const validatedEmail = BufferOverflowProtection.validateEmail(senderEmail);
        const validatedReason = BufferOverflowProtection.sanitizeText(reason, 200);

        const success = await updateSenderReputation(validatedEmail, authenticatedUser.email, validatedReason);
        
        if (success) {
            logSecurityEvent('sender_flagged', 'info', authenticatedUser.email, { sender: senderEmail, reason });
            return { success: true };
        } else {
            return { success: false, error: "Already flagged this sender" };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('verify-link', async (event, url) => {
    try {
        const result = linkVerifier.verifyURL(url);
        return { success: true, result };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('get-security-report', (event) => {
    if (!authenticatedUser) return { success: false, error: "Unauthorized" };

    return new Promise((resolve) => {
        db.all(`SELECT * FROM security_logs WHERE user_email = ? ORDER BY created_at DESC LIMIT 100`,
              [authenticatedUser.email], (err, rows) => {
            if (err) {
                resolve({ success: false, error: err.message });
            } else {
                resolve({ success: true, logs: rows });
            }
        });
    });
});