import http.server
import socketserver
import json
import os
import re
import time
import threading
from urllib.parse import urlparse, parse_qs
import hashlib
import hmac
import base64

# --- CONFIGURATION ---
PORT = 3000
DATA_DIR = 'data'

# --- IN-MEMORY LOCKS FOR FILE SAFETY ---
file_locks = {
    'users': threading.Lock(),
    'emails': threading.Lock(),
    'reputation': threading.Lock(),
    'security_logs': threading.Lock()
}

# Predefined phishing links for detection
PHISHING_LINKS = [
    'bit.ly/free-money',
    'tinyurl.com/verify-account',
    'suspicious-bank.com',
    'login-secure-verify.com',
    'account-update-now.com',
    'free-gift-card.com',
    'urgent-action-required.net'
]

# --- DATABASE MANAGER ---
def init_db():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    for filename in ['users.json', 'emails.json', 'reputation.json', 'security_logs.json']:
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump([], f)

def db_read(collection):
    path = os.path.join(DATA_DIR, f"{collection}.json")
    with file_locks[collection]:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return []

def db_write(collection, data):
    path = os.path.join(DATA_DIR, f"{collection}.json")
    with file_locks[collection]:
        # Atomic write: write to temp then rename
        tmp_path = path + '.tmp'
        with open(tmp_path, 'w') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)

# --- SECURITY ENGINE (Phishing/Spam) ---
def analyze_email(subject, body, sender_email=None):
    score = 50
    warnings = []

    body_lower = body.lower()

    # 1. Keyword Analysis
    phishing_words = ['verify', 'account suspended', 'urgent', 'bank', 'password expiration', 'winner']
    for word in phishing_words:
        if word in body_lower:
            score += 15
            warnings.append({
                "severity": "high",
                "title": {"primary": "Suspicious Keyword", "secondary": ""},
                "details": {"primary": f"Suspicious keyword detected: '{word}'", "secondary": ""}
            })

    # 2. Link Analysis (Regex)
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    for url in urls:
        # Check for predefined phishing links
        for phish_link in PHISHING_LINKS:
            if phish_link in url.lower():
                score += 40
                warnings.append({
                    "severity": "high",
                    "title": {"primary": "Phishing Link Detected", "secondary": ""},
                    "details": {"primary": f"Known phishing link: {url}", "secondary": ""}
                })
                break

        if '@' in url:
            score += 30
            warnings.append({
                "severity": "high",
                "title": {"primary": "URL Obfuscation", "secondary": ""},
                "details": {"primary": "URL uses obfuscation (@ symbol)", "secondary": ""}
            })
        if len(url) > 100:
            score += 10
            warnings.append({
                "severity": "medium",
                "title": {"primary": "Long URL", "secondary": ""},
                "details": {"primary": "Unusually long URL detected", "secondary": ""}
            })
        if not url.startswith("https"):
            score += 20
            warnings.append({
                "severity": "medium",
                "title": {"primary": "Insecure Link", "secondary": ""},
                "details": {"primary": "Insecure HTTP link detected", "secondary": ""}
            })

    # 3. Check sender reputation
    if sender_email:
        reputation = db_read('reputation')
        sender_rep = next((r for r in reputation if r.get('sender_email') == sender_email), None)
        if sender_rep:
            if sender_rep.get('safe_score', 50) < 40:
                score += 20
                warnings.append({
                    "severity": "high",
                    "title": {"primary": "Suspicious Sender", "secondary": ""},
                    "details": {"primary": f"Sender has low reputation score: {sender_rep.get('safe_score')}", "secondary": ""}
                })
            elif sender_rep.get('safe_score', 50) >= 70:
                score -= 10
                warnings.append({
                    "severity": "low",
                    "title": {"primary": "Safe Sender", "secondary": ""},
                    "details": {"primary": "This sender has a good reputation", "secondary": ""}
                })

    # Determine Badge
    final_score = max(0, min(100, 100 - score))
    if final_score >= 70:
        badge = {
            "color": "green",
            "icon": "✓",
            "title_primary": "Safe",
            "title_secondary": "Verified Safe"
        }
    elif final_score >= 40:
        badge = {
            "color": "yellow",
            "icon": "⚠",
            "title_primary": "Caution",
            "title_secondary": "Exercise Caution"
        }
    else:
        badge = {
            "color": "red",
            "icon": "✗",
            "title_primary": "Dangerous",
            "title_secondary": "High Risk"
        }

    return {
        "safe_score": final_score,
        "badge": badge,
        "warnings": warnings
    }

# --- HTTP REQUEST HANDLER ---
class RequestHandler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') # CORS for Electron
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        raw_data = self.rfile.read(length)
        try:
            data = json.loads(raw_data)
        except:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
            return

        if self.path == '/api/auth/register':
            self.handle_register(data)
        elif self.path == '/api/auth/login':
            self.handle_login(data)
        elif self.path == '/api/email/send':
            self.handle_send_email(data)
        elif self.path == '/api/email/mark_spam':
            self.handle_mark_spam(data)
        elif self.path == '/api/email/delete':
            self.handle_delete_email(data)
        elif self.path == '/api/reputation/flag':
            self.handle_flag_sender(data)
        elif self.path == '/api/reputation/mark_safe':
            self.handle_mark_sender_safe(data)
        elif self.path == '/api/security/verify_link':
            self.handle_verify_link(data)
        elif self.path == '/api/unsubscribe':
            self.handle_unsubscribe(data)
        else:
            self._set_headers(404)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == '/api/email/inbox':
            self.handle_get_inbox(params)
        elif parsed_path.path == '/api/email/sent':
            self.handle_get_sent(params)
        elif parsed_path.path == '/api/email/spam':
            self.handle_get_spam(params)
        elif parsed_path.path == '/api/email/trash':
            self.handle_get_trash(params)
        elif parsed_path.path == '/api/email/stats':
            self.handle_get_stats(params)
        elif parsed_path.path == '/api/security/report':
            self.handle_get_security_report(params)
        elif parsed_path.path == '/api/subscriptions':
            self.handle_get_subscriptions(params)
        else:
            self._set_headers(404)

    # --- HANDLERS ---
    def handle_register(self, data):
        users = db_read('users')
        email = data.get('email')
        
        if any(u['email'] == email for u in users):
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False, "error": "Email exists"}).encode())
            return

        # Simple hashing
        pwd_hash = hashlib.sha256(data.get('password').encode()).hexdigest()
        
        # 1. Generate a random secret (Manual generation since no external libs)
        # A simple way to get a random base32-like string using standard libs
        random_bytes = os.urandom(10) 
        secret = base64.b32encode(random_bytes).decode('utf-8')

        new_user = {
            "id": int(time.time() * 1000),
            "email": email,
            "password": pwd_hash,
            "languages": [data.get('lang1'), data.get('lang2')],
            "totp_secret": secret
        }
        
        users.append(new_user)
        db_write('users', users)
        
        # 2. Construct the OTP Auth URL manually
        # Format: otpauth://totp/Label:Email?secret=SECRET&issuer=Label
        otpauth_url = f"otpauth://totp/SecureMail:{email}?secret={secret}&issuer=SecureMail"

        # 3. Send URL to client (Client will draw the QR code)
        self._set_headers(200)
        self.wfile.write(json.dumps({
            "success": True, 
            "otpauth_url": otpauth_url 
        }).encode())

    def handle_login(self, data):
        users = db_read('users')
        pwd_hash = hashlib.sha256(data.get('password').encode()).hexdigest()
        
        user = next((u for u in users if u['email'] == data['email'] and u['password'] == pwd_hash), None)
        
        if user:
            self._set_headers(200)
            self.wfile.write(json.dumps({
                "success": True, 
                "user": {"email": user['email'], "languages": user['languages']}
            }).encode())
        else:
            self._set_headers(401)
            self.wfile.write(json.dumps({"success": False, "error": "Invalid Credentials"}).encode())

    def handle_send_email(self, data):
        sender_email = data.get('from')
        security_result = analyze_email(data.get('subject', ''), data.get('body', ''), sender_email)

        new_email = {
            "id": int(time.time() * 1000),
            "sender_email": sender_email,
            "recipient_email": data.get('to'),
            "subject": data.get('subject'),
            "body": data.get('body'),
            "sent_at": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "folder": "inbox",
            "is_read": False,
            "security_analysis": {
                "badge": security_result['badge'],
                "safe_score": security_result['safe_score'],
                "warnings": security_result['warnings']
            }
        }

        emails = db_read('emails')
        emails.append(new_email)
        db_write('emails', emails)

        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True}).encode())

    def handle_get_inbox(self, params):
        email_addr = params.get('email', [None])[0]
        all_emails = db_read('emails')
        # Return emails where recipient matches and folder is inbox
        inbox = [e for e in all_emails if e.get('recipient_email') == email_addr and e.get('folder', 'inbox') == 'inbox']
        self._set_headers(200)
        self.wfile.write(json.dumps(inbox).encode())

    def handle_get_sent(self, params):
        email_addr = params.get('email', [None])[0]
        all_emails = db_read('emails')
        sent = [e for e in all_emails if e.get('sender_email') == email_addr]
        self._set_headers(200)
        self.wfile.write(json.dumps(sent).encode())

    def handle_get_spam(self, params):
        email_addr = params.get('email', [None])[0]
        all_emails = db_read('emails')
        spam = [e for e in all_emails if e.get('recipient_email') == email_addr and e.get('folder') == 'spam']
        self._set_headers(200)
        self.wfile.write(json.dumps(spam).encode())

    def handle_get_trash(self, params):
        email_addr = params.get('email', [None])[0]
        all_emails = db_read('emails')
        trash = [e for e in all_emails if e.get('recipient_email') == email_addr and e.get('folder') == 'trash']
        self._set_headers(200)
        self.wfile.write(json.dumps(trash).encode())

    def handle_mark_spam(self, data):
        email_id = data.get('email_id')
        emails = db_read('emails')

        for email in emails:
            if email.get('id') == email_id:
                email['folder'] = 'spam'
                break

        db_write('emails', emails)
        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True}).encode())

    def handle_delete_email(self, data):
        email_id = data.get('email_id')
        emails = db_read('emails')

        for email in emails:
            if email.get('id') == email_id:
                email['folder'] = 'trash'
                break

        db_write('emails', emails)
        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True}).encode())

    def handle_flag_sender(self, data):
        sender_email = data.get('sender_email')
        reason = data.get('reason')

        reputation = db_read('reputation')
        sender_rep = next((r for r in reputation if r.get('sender_email') == sender_email), None)

        if sender_rep:
            # Decrease safe score
            sender_rep['safe_score'] = max(0, sender_rep.get('safe_score', 50) - 10)
            sender_rep['total_flags'] = sender_rep.get('total_flags', 0) + 1
            if 'flag_reasons' not in sender_rep:
                sender_rep['flag_reasons'] = []
            sender_rep['flag_reasons'].append(reason)
        else:
            # Create new reputation entry
            reputation.append({
                "sender_email": sender_email,
                "safe_score": 40,  # Start lower since flagged
                "total_flags": 1,
                "flag_reasons": [reason],
                "marked_safe_count": 0
            })

        db_write('reputation', reputation)

        # Log security event
        logs = db_read('security_logs')
        logs.append({
            "id": int(time.time() * 1000),
            "event_type": "sender_flagged",
            "sender_email": sender_email,
            "created_at": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "severity": "high",
            "details": json.dumps({"reason": reason})
        })
        db_write('security_logs', logs)

        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True}).encode())

    def handle_mark_sender_safe(self, data):
        sender_email = data.get('sender_email')

        reputation = db_read('reputation')
        sender_rep = next((r for r in reputation if r.get('sender_email') == sender_email), None)

        if sender_rep:
            # Increase safe score
            sender_rep['safe_score'] = min(100, sender_rep.get('safe_score', 50) + 10)
            sender_rep['marked_safe_count'] = sender_rep.get('marked_safe_count', 0) + 1
        else:
            # Create new reputation entry with good score
            reputation.append({
                "sender_email": sender_email,
                "safe_score": 70,  # Start higher since marked safe
                "total_flags": 0,
                "flag_reasons": [],
                "marked_safe_count": 1
            })

        db_write('reputation', reputation)
        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True}).encode())

    def handle_get_stats(self, params):
        email_addr = params.get('email', [None])[0]
        all_emails = db_read('emails')

        inbox = [e for e in all_emails if e.get('recipient_email') == email_addr and e.get('folder', 'inbox') == 'inbox']
        read_count = len([e for e in inbox if e.get('is_read', False)])
        flagged = len([e for e in inbox if e.get('security_analysis', {}).get('badge', {}).get('color') == 'red'])

        stats = {
            "inbox": len(inbox),
            "read": read_count,
            "flagged": flagged
        }

        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True, "stats": stats}).encode())

    def handle_get_security_report(self, params):
        logs = db_read('security_logs')
        # Return last 50 logs
        recent_logs = sorted(logs, key=lambda x: x.get('created_at', ''), reverse=True)[:50]

        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True, "logs": recent_logs}).encode())

    def handle_verify_link(self, data):
        url = data.get('url', '')
        warnings = []
        risk_level = 'low'

        # Check for phishing links
        for phish_link in PHISHING_LINKS:
            if phish_link in url.lower():
                warnings.append("Known phishing link detected")
                risk_level = 'high'
                break

        # Check other suspicious patterns
        if '@' in url:
            warnings.append("URL contains @ symbol (potential obfuscation)")
            risk_level = 'high'
        if not url.startswith('https'):
            warnings.append("Insecure HTTP connection")
            if risk_level != 'high':
                risk_level = 'medium'
        if len(url) > 100:
            warnings.append("Unusually long URL")
            if risk_level == 'low':
                risk_level = 'medium'

        self._set_headers(200)
        self.wfile.write(json.dumps({
            "success": True,
            "result": {
                "risk_level": risk_level,
                "warnings": warnings
            }
        }).encode())

    def handle_get_subscriptions(self, params):
        # Placeholder - return empty list since no subscription system implemented
        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True, "subscriptions": []}).encode())

    def handle_unsubscribe(self, data):
        # Placeholder - return success
        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True}).encode())

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

if __name__ == '__main__':
    init_db()
    server = ThreadingHTTPServer(('0.0.0.0', PORT), RequestHandler)
    print(f"Starting pure Python server on port {PORT}")
    server.serve_forever()