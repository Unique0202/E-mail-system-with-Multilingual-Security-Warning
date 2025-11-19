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
    'reputation': threading.Lock()
}

# --- DATABASE MANAGER ---
def init_db():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    for filename in ['users.json', 'emails.json', 'reputation.json']:
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
def analyze_email(subject, body):
    score = 50
    warnings = []
    
    body_lower = body.lower()
    
    # 1. Keyword Analysis
    phishing_words = ['verify', 'account suspended', 'urgent', 'bank', 'password expiration', 'winner']
    for word in phishing_words:
        if word in body_lower:
            score += 15
            warnings.append(f"Suspicious keyword detected: '{word}'")

    # 2. Link Analysis (Regex)
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    for url in urls:
        if '@' in url:
            score += 30
            warnings.append("URL uses obfuscation (@ symbol)")
        if len(url) > 100:
            score += 10
            warnings.append("Unusually long URL detected")
        if not url.startswith("https"):
            score += 20
            warnings.append("Insecure HTTP link detected")

    # Determine Badge
    badge = 'green'
    if score > 80: badge = 'red'
    elif score > 60: badge = 'yellow'

    return {
        "safe_score": max(0, 100 - score),
        "badge_color": badge,
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
        else:
            self._set_headers(404)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        if parsed_path.path == '/api/email/inbox':
            self.handle_get_inbox(params)
        elif parsed_path.path == '/api/email/sent':
            self.handle_get_sent(params)
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

        # Simple hashing (In production, use a library, but avoiding dependencies here)
        # We use standard lib hashlib
        pwd_hash = hashlib.sha256(data.get('password').encode()).hexdigest()
        
        new_user = {
            "id": int(time.time() * 1000),
            "email": email,
            "password": pwd_hash,
            "languages": [data.get('lang1'), data.get('lang2')],
            "totp_secret": "MOCK_SECRET" # Without 'otplib', we simulate 2FA secret generation
        }
        
        users.append(new_user)
        db_write('users', users)
        
        # Return success (QR code generation happens on client to save server deps)
        self._set_headers(200)
        self.wfile.write(json.dumps({"success": True, "mock_secret": "MOCK_SECRET"}).encode())

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
        security_result = analyze_email(data.get('subject', ''), data.get('body', ''))
        
        new_email = {
            "id": int(time.time() * 1000),
            "sender_email": data.get('from'),
            "recipient_email": data.get('to'),
            "subject": data.get('subject'),
            "body": data.get('body'),
            "sent_at": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "security_analysis": {
                "badge": {"color": security_result['badge_color']},
                "safe_score": security_result['safe_score'],
                "warnings": [{"severity": "high", "details": {"primary": w}} for w in security_result['warnings']]
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
        # Return emails where recipient matches
        inbox = [e for e in all_emails if e.get('recipient_email') == email_addr]
        self._set_headers(200)
        self.wfile.write(json.dumps(inbox).encode())

    def handle_get_sent(self, params):
        email_addr = params.get('email', [None])[0]
        all_emails = db_read('emails')
        sent = [e for e in all_emails if e.get('sender_email') == email_addr]
        self._set_headers(200)
        self.wfile.write(json.dumps(sent).encode())

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

if __name__ == '__main__':
    init_db()
    server = ThreadingHTTPServer(('0.0.0.0', PORT), RequestHandler)
    print(f"Starting pure Python server on port {PORT}")
    server.serve_forever()