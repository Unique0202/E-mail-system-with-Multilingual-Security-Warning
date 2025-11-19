const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { spawn } = require('child_process');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const db = require('./data_manager');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Init DB
db.init();

// --- HELPER: Call Python ---
function scanEmailSecurity(emailData) {
    return new Promise((resolve) => {
        const python = spawn('python3', ['security_scanner.py']); // Use 'python' or 'python3'
        let output = '';

        python.stdin.write(JSON.stringify(emailData));
        python.stdin.end();

        python.stdout.on('data', (data) => output += data.toString());
        
        python.on('close', () => {
            try {
                resolve(JSON.parse(output));
            } catch {
                resolve({ safe_score: 50, badge_color: 'yellow', warnings: ['Scan failed'] });
            }
        });
    });
}

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password, lang1, lang2 } = req.body;
    const users = await db.read('users');

    if (users.find(u => u.email === email)) {
        return res.json({ success: false, error: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(email, 'SecureMail', secret);
    const qrCode = await QRCode.toDataURL(otpauth);

    const newUser = {
        id: Date.now(),
        email,
        password_hash: hash,
        totp_secret: secret,
        languages: [lang1, lang2]
    };

    users.push(newUser);
    await db.write('users', users);

    res.json({ success: true, qrCode });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password, totp } = req.body;
    const users = await db.read('users');
    const user = users.find(u => u.email === email);

    if (!user) return res.json({ success: false, error: "User not found" });

    const validPass = await bcrypt.compare(password, user.password_hash);
    if (!validPass) return res.json({ success: false, error: "Invalid credentials" });

    const validTotp = authenticator.check(totp, user.totp_secret);
    if (!validTotp) return res.json({ success: false, error: "Invalid 2FA Code" });

    res.json({ 
        success: true, 
        user: { id: user.id, email: user.email, languages: user.languages } 
    });
});

// --- EMAIL ROUTES ---
app.post('/api/email/send', async (req, res) => {
    const { to, subject, body, from } = req.body; // 'from' passed by client for now
    
    // 1. Security Scan (Python)
    const securityResult = await scanEmailSecurity({ subject, body });

    // 2. Save Email
    const emails = await db.read('emails');
    const newEmail = {
        id: Date.now(),
        sender_email: from,
        recipient_email: to,
        subject,
        body,
        sent_at: new Date().toISOString(),
        security_analysis: {
            badge: { color: securityResult.badge_color },
            safe_score: securityResult.safe_score,
            warnings: securityResult.warnings.map(w => ({ 
                severity: 'high', 
                title: { primary: 'Security Alert' }, 
                details: { primary: w } 
            }))
        }
    };

    emails.push(newEmail);
    await db.write('emails', emails);

    res.json({ success: true });
});

app.get('/api/email/inbox', async (req, res) => {
    const { email } = req.query;
    const all = await db.read('emails');
    const inbox = all.filter(e => e.recipient_email === email);
    res.json(inbox);
});

app.get('/api/email/sent', async (req, res) => {
    const { email } = req.query;
    const all = await db.read('emails');
    const sent = all.filter(e => e.sender_email === email);
    res.json(sent);
});

app.listen(3000, () => console.log('Server running on port 3000'));