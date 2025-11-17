"""
Secure Multilingual Email System - Main Application
Complete implementation with all features
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import os
from dotenv import load_dotenv
import logging
from datetime import datetime, timedelta
import secrets
import hashlib
import pyotp
import bcrypt
import qrcode
from io import BytesIO

# Import database models
from models import (
    db, init_db, create_indexes,
    User, Session, RecoveryCode, Email, 
    SenderReputation, Flag, LinkCache, 
    RateLimit, SecurityLog
)

# Import security modules
from buffer_overflow_protection import (
    BufferOverflowProtection,
    SQLInjectionProtection,
    XSSProtection,
    validate_request
)
from opensource_link_verifier import OpenSourceLinkVerifier
from email_server_core import EmailClient, EmailStorage
from multilingual_warnings import (
    SecurityWarningTranslations,
    SecurityBadge,
    EmailSecurityAnalyzer,
    SenderFlaggingSystem
)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_urlsafe(64))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://emailapp:password@localhost/secure_email_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Request limits
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Email storage path
app.config['MAILDATA_PATH'] = os.getenv('MAILDATA_PATH', '/opt/secure-email-app/maildata')

# CORS
CORS(app, 
     origins=os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(','),
     supports_credentials=True)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute"],
    storage_uri=os.getenv('REDIS_URL', "redis://localhost:6379")
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize database
init_db(app)

# Initialize systems
link_verifier = OpenSourceLinkVerifier()
email_client = EmailClient()


# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

@app.before_request
def check_request_size():
    """Check request size"""
    if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
        logger.warning(f"Request too large from {get_remote_address()}")
        return jsonify({'error': 'Request too large'}), 413


@app.after_request
def add_security_headers(response):
    """Add security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers.pop('Server', None)
    return response


def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No authorization token'}), 401
        
        session_token = auth_header[7:]
        
        # Verify session from database
        session = Session.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Check expiration
        if session.expires_at and datetime.utcnow() > session.expires_at:
            db.session.delete(session)
            db.session.commit()
            return jsonify({'error': 'Session expired'}), 401
        
        # Check IP address (session hijacking detection)
        if session.ip_address != get_remote_address():
            log_security_event('session_hijacking_attempt', {
                'session_id': session.id,
                'original_ip': session.ip_address,
                'request_ip': get_remote_address()
            }, session.user_id)
            return jsonify({'error': 'Session security violation'}), 401
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        # Add user to request context
        request.user = session.user
        request.session = session
        
        return f(*args, **kwargs)
    
    return decorated_function


def log_security_event(event_type: str, details: dict, user_id: int = None, severity: str = 'warning'):
    """Log security event to database"""
    try:
        log = SecurityLog(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent'),
            details=details
        )
        db.session.add(log)
        db.session.commit()
        logger.warning(f"SECURITY: {event_type} - {details}")
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per hour")
@validate_request({
    'email': {
        'type': str,
        'required': True,
        'max_length': 254,
        'validator': BufferOverflowProtection.validate_email
    },
    'password': {
        'type': str,
        'required': True,
        'max_length': 128,
        'validator': BufferOverflowProtection.validate_password
    },
    'preferred_languages': {
        'type': list,
        'required': True,
        'max_size': 2
    }
})
def register():
    """Register new user"""
    try:
        data = request.validated_data
        
        # Check if email exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Validate languages
        valid_langs = ['en', 'hi', 'bn', 'te', 'mr', 'ta', 'gu', 'kn', 'ml', 'pa', 'or', 'as', 'es', 'fr', 'de']
        if len(data['preferred_languages']) != 2:
            return jsonify({'error': 'Please select exactly 2 languages'}), 400
        
        for lang in data['preferred_languages']:
            if lang not in valid_langs:
                return jsonify({'error': f'Invalid language: {lang}'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
        
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        # Create user
        user = User(
            email=data['email'],
            password_hash=password_hash,
            totp_secret=totp_secret,
            preferred_languages=data['preferred_languages']
        )
        db.session.add(user)
        db.session.flush()
        
        # Generate recovery codes
        recovery_codes = []
        for _ in range(10):
            code = secrets.token_hex(8)
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            recovery_code = RecoveryCode(
                user_id=user.id,
                code_hash=code_hash
            )
            db.session.add(recovery_code)
            recovery_codes.append(code)
        
        # Create sender reputation entry
        reputation = SenderReputation(sender_email=data['email'])
        db.session.add(reputation)
        
        db.session.commit()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=data['email'],
            issuer_name='SecureMailSystem'
        )
        
        logger.info(f"User registered: {data['email']}")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'totp_uri': totp_uri,
            'recovery_codes': recovery_codes
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/qr-code', methods=['POST'])
@limiter.limit("10 per hour")
def generate_qr():
    """Generate QR code image for TOTP"""
    try:
        data = request.get_json()
        totp_uri = data.get('totp_uri')
        
        if not totp_uri:
            return jsonify({'error': 'TOTP URI required'}), 400
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        return send_file(img_io, mimetype='image/png')
        
    except Exception as e:
        logger.error(f"QR code generation error: {e}")
        return jsonify({'error': 'Failed to generate QR code'}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per 15 minutes")
@validate_request({
    'email': {
        'type': str,
        'required': True,
        'max_length': 254,
        'validator': BufferOverflowProtection.validate_email
    },
    'password': {
        'type': str,
        'required': True,
        'max_length': 128
    },
    'totp_code': {
        'type': str,
        'required': True,
        'max_length': 6,
        'validator': BufferOverflowProtection.validate_totp
    }
})
def login():
    """Login with 2FA"""
    try:
        data = request.validated_data
        ip_address = get_remote_address()
        
        # Find user
        user = User.query.filter_by(email=data['email']).first()
        
        if not user:
            log_security_event('failed_login', {'email': data['email'], 'reason': 'user_not_found'})
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if locked
        if user.is_locked:
            return jsonify({'error': 'Account locked'}), 403
        
        # Verify password
        if not bcrypt.checkpw(data['password'].encode(), user.password_hash.encode()):
            log_security_event('failed_login', {'email': data['email'], 'reason': 'wrong_password'}, user.id)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify TOTP
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(data['totp_code'], valid_window=1):
            log_security_event('failed_login', {'email': data['email'], 'reason': 'wrong_totp'}, user.id)
            return jsonify({'error': 'Invalid 2FA code'}), 401
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        session = Session(
            session_token=session_token,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=request.headers.get('User-Agent'),
            expires_at=datetime.utcnow() + timedelta(seconds=3600)
        )
        db.session.add(session)
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"Successful login: {data['email']}")
        
        return jsonify({
            'success': True,
            'session_token': session_token,
            'user': {
                'email': user.email,
                'preferred_languages': user.preferred_languages
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    """Logout"""
    try:
        db.session.delete(request.session)
        db.session.commit()
        
        logger.info(f"User logged out: {request.user.email}")
        return jsonify({'success': True}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@app.route('/api/recover', methods=['POST'])
@limiter.limit("3 per hour")
@validate_request({
    'email': {
        'type': str,
        'required': True,
        'max_length': 254,
        'validator': BufferOverflowProtection.validate_email
    },
    'recovery_code': {
        'type': str,
        'required': True,
        'max_length': 32
    }
})
def recover_account():
    """Account recovery"""
    try:
        data = request.validated_data
        
        user = User.query.filter_by(email=data['email']).first()
        if not user:
            return jsonify({'error': 'Invalid recovery code'}), 401
        
        # Hash provided code
        code_hash = hashlib.sha256(data['recovery_code'].encode()).hexdigest()
        
        # Find matching unused code
        recovery_code = RecoveryCode.query.filter_by(
            user_id=user.id,
            code_hash=code_hash,
            is_used=False
        ).first()
        
        if not recovery_code:
            log_security_event('failed_recovery', {'email': data['email']}, user.id)
            return jsonify({'error': 'Invalid recovery code'}), 401
        
        # Mark code as used
        recovery_code.is_used = True
        recovery_code.used_at = datetime.utcnow()
        
        # Create temporary session
        session_token = secrets.token_urlsafe(32)
        session = Session(
            session_token=session_token,
            user_id=user.id,
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent'),
            is_recovery=True,
            expires_at=datetime.utcnow() + timedelta(minutes=15)  # Shorter timeout
        )
        db.session.add(session)
        db.session.commit()
        
        logger.info(f"Account recovery successful: {data['email']}")
        
        return jsonify({
            'success': True,
            'session_token': session_token,
            'message': 'Recovery successful. Please reset your 2FA.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Recovery error: {e}")
        return jsonify({'error': 'Recovery failed'}), 500


# ============================================================================
# EMAIL ENDPOINTS (From app_email_endpoints.py)
# ============================================================================

@app.route('/api/email/send', methods=['POST'])
@require_auth
@limiter.limit("30 per minute")
@validate_request({
    'to': {
        'type': str,
        'required': True,
        'max_length': 254,
        'validator': BufferOverflowProtection.validate_email
    },
    'subject': {
        'type': str,
        'required': True,
        'max_length': 500
    },
    'body': {
        'type': str,
        'required': True,
        'max_length': 50000
    }
})
def send_email():
    """Send email"""
    try:
        data = request.validated_data
        
        # Sanitize
        subject = BufferOverflowProtection.sanitize_text(data['subject'], 500)
        body = BufferOverflowProtection.sanitize_text(data['body'], 50000)
        
        # XSS check
        if XSSProtection.detect_xss(body):
            return jsonify({'error': 'Email contains dangerous content'}), 400
        
        # Find recipient
        recipient = User.query.filter_by(email=data['to']).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Send via email client
        result = email_client.send_email(
            from_address=request.user.email,
            to_address=data['to'],
            subject=subject,
            body=body,
            preferred_languages=request.user.preferred_languages
        )
        
        if result['success']:
            # Store in database
            email = Email(
                message_id=result['message_id'],
                sender_id=request.user.id,
                recipient_id=recipient.id,
                subject=subject,
                size_bytes=len(body),
                body_path=f"maildata/{recipient.mailbox_hash}/new/{result['message_id']}.eml"
            )
            db.session.add(email)
            db.session.commit()
            
            logger.info(f"Email sent: {request.user.email} -> {data['to']}")
            return jsonify(result), 200
        else:
            return jsonify(result), 500
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Send email error: {e}")
        return jsonify({'error': 'Failed to send email'}), 500


@app.route('/api/email/inbox', methods=['GET'])
@require_auth
@limiter.limit("60 per minute")
def get_inbox():
    """Get inbox with security analysis"""
    try:
        limit = request.args.get('limit', 50, type=int)
        if limit > 100:
            limit = 100
        
        # Get emails from database
        emails = Email.query.filter_by(
            recipient_id=request.user.id,
            is_deleted=False
        ).order_by(Email.sent_at.desc()).limit(limit).all()
        
        email_list = []
        for email in emails:
            # Get sender reputation
            sender_reputation = SenderReputation.query.filter_by(
                sender_email=email.sender.email
            ).first()
            
            if not sender_reputation:
                sender_reputation = SenderReputation(sender_email=email.sender.email)
                db.session.add(sender_reputation)
                db.session.flush()
            
            # Security analysis
            security_analysis = EmailSecurityAnalyzer.analyze_email(
                {
                    'from': email.sender.email,
                    'subject': email.subject,
                    'body': ''  # Load from file if needed
                },
                {
                    'safe_score': sender_reputation.safe_score,
                    'total_flags': sender_reputation.total_flags
                },
                request.user.preferred_languages
            )
            
            email_data = {
                'message_id': email.message_id,
                'from': email.sender.email,
                'subject': email.subject,
                'preview': email.subject[:100],
                'date': email.sent_at.isoformat(),
                'is_read': email.is_read,
                'size': email.size_bytes,
                'security': security_analysis
            }
            email_list.append(email_data)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'emails': email_list,
            'count': len(email_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Get inbox error: {e}")
        return jsonify({'error': 'Failed to get inbox'}), 500


@app.route('/api/email/sent', methods=['GET'])
@require_auth
@limiter.limit("60 per minute")
def get_sent():
    """Get sent emails"""
    try:
        limit = request.args.get('limit', 50, type=int)
        if limit > 100:
            limit = 100
        
        emails = Email.query.filter_by(
            sender_id=request.user.id,
            is_deleted=False
        ).order_by(Email.sent_at.desc()).limit(limit).all()
        
        email_list = []
        for email in emails:
            email_data = {
                'message_id': email.message_id,
                'to': email.recipient.email,
                'subject': email.subject,
                'date': email.sent_at.isoformat(),
                'size': email.size_bytes
            }
            email_list.append(email_data)
        
        return jsonify({
            'success': True,
            'emails': email_list,
            'count': len(email_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Get sent error: {e}")
        return jsonify({'error': 'Failed to get sent emails'}), 500


@app.route('/api/email/<message_id>', methods=['GET'])
@require_auth
@limiter.limit("100 per minute")
def get_email(message_id):
    """Get specific email"""
    try:
        message_id = BufferOverflowProtection.sanitize_text(message_id, 64)
        
        # Find email
        email = Email.query.filter_by(message_id=message_id).first()
        
        if not email:
            return jsonify({'error': 'Email not found'}), 404
        
        # Check permission
        if email.recipient_id != request.user.id and email.sender_id != request.user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Load full body from filesystem
        try:
            body = email_client.get_message(request.user.email, message_id)
            if not body:
                body = {'body': 'Email body not available'}
        except:
            body = {'body': 'Error loading email'}
        
        # Get sender reputation
        sender_reputation = SenderReputation.query.filter_by(
            sender_email=email.sender.email
        ).first()
        
        # Security analysis
        security_analysis = EmailSecurityAnalyzer.analyze_email(
            {
                'from': email.sender.email,
                'subject': email.subject,
                'body': body.get('body', '')
            },
            {
                'safe_score': sender_reputation.safe_score if sender_reputation else 50,
                'total_flags': sender_reputation.total_flags if sender_reputation else 0
            },
            request.user.preferred_languages
        )
        
        # Mark as read
        if email.recipient_id == request.user.id and not email.is_read:
            email.is_read = True
            email.read_at = datetime.utcnow()
            db.session.commit()
        
        email_data = {
            'message_id': email.message_id,
            'from': email.sender.email,
            'to': email.recipient.email,
            'subject': email.subject,
            'body': body.get('body', ''),
            'date': email.sent_at.isoformat(),
            'is_read': email.is_read,
            'security': security_analysis
        }
        
        return jsonify({
            'success': True,
            'email': email_data
        }), 200
        
    except Exception as e:
        logger.error(f"Get email error: {e}")
        return jsonify({'error': 'Failed to get email'}), 500


@app.route('/api/email/<message_id>', methods=['DELETE'])
@require_auth
@limiter.limit("30 per minute")
def delete_email(message_id):
    """Delete email"""
    try:
        message_id = BufferOverflowProtection.sanitize_text(message_id, 64)
        
        email = Email.query.filter_by(message_id=message_id).first()
        
        if not email:
            return jsonify({'error': 'Email not found'}), 404
        
        # Check permission
        if email.recipient_id != request.user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Soft delete
        email.is_deleted = True
        email.deleted_at = datetime.utcnow()
        db.session.commit()
        
        # Move file
        email_client.delete_message(request.user.email, message_id)
        
        logger.info(f"Email deleted: {message_id} by {request.user.email}")
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete email error: {e}")
        return jsonify({'error': 'Failed to delete email'}), 500


@app.route('/api/email/search', methods=['GET'])
@require_auth
@limiter.limit("30 per minute")
def search_emails():
    """Search emails"""
    try:
        query = request.args.get('q', '')
        query = BufferOverflowProtection.sanitize_text(query, 200)
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        # Search in database
        emails = Email.query.filter(
            Email.recipient_id == request.user.id,
            Email.is_deleted == False,
            db.or_(
                Email.subject.ilike(f'%{query}%'),
                Email.sender.has(User.email.ilike(f'%{query}%'))
            )
        ).order_by(Email.sent_at.desc()).limit(50).all()
        
        results = []
        for email in emails:
            results.append({
                'message_id': email.message_id,
                'from': email.sender.email,
                'subject': email.subject,
                'date': email.sent_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        }), 200
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({'error': 'Search failed'}), 500


@app.route('/api/email/stats', methods=['GET'])
@require_auth
@limiter.limit("60 per minute")
def get_mailbox_stats():
    """Get mailbox statistics"""
    try:
        inbox_total = Email.query.filter_by(
            recipient_id=request.user.id,
            is_deleted=False
        ).count()
        
        inbox_unread = Email.query.filter_by(
            recipient_id=request.user.id,
            is_deleted=False,
            is_read=False
        ).count()
        
        sent_total = Email.query.filter_by(
            sender_id=request.user.id,
            is_deleted=False
        ).count()
        
        return jsonify({
            'success': True,
            'stats': {
                'inbox_total': inbox_total,
                'inbox_unread': inbox_unread,
                'sent_total': sent_total
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        return jsonify({'error': 'Failed to get stats'}), 500


# ============================================================================
# SENDER REPUTATION & FLAGGING ENDPOINTS
# ============================================================================

@app.route('/api/sender/<sender_email>', methods=['GET'])
@require_auth
def get_sender_info(sender_email):
    """Get sender reputation"""
    try:
        sender_email = BufferOverflowProtection.validate_email(sender_email)
        
        reputation = SenderReputation.query.filter_by(sender_email=sender_email).first()
        
        if not reputation:
            reputation = SenderReputation(sender_email=sender_email)
            db.session.add(reputation)
            db.session.commit()
        
        # Get badge
        badge = SecurityBadge.get_badge_with_translations(
            reputation.safe_score,
            reputation.total_flags,
            request.user.preferred_languages
        )
        
        # Get flag reasons
        flags = Flag.query.filter_by(sender_reputation_id=reputation.id).all()
        flag_reasons = {}
        for flag in flags:
            flag_reasons[flag.reason] = flag_reasons.get(flag.reason, 0) + 1
        
        return jsonify({
            'email': sender_email,
            'safe_score': reputation.safe_score,
            'total_flags': reputation.total_flags,
            'badge': badge,
            'flag_reasons': flag_reasons,
            'first_seen': reputation.first_seen.isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Get sender info error: {e}")
        return jsonify({'error': 'Failed to get sender info'}), 500


@app.route('/api/flag-sender', methods=['POST'])
@require_auth
@limiter.limit("10 per hour")
@validate_request({
    'sender_email': {
        'type': str,
        'required': True,
        'max_length': 254,
        'validator': BufferOverflowProtection.validate_email
    },
    'reason': {
        'type': str,
        'required': True,
        'max_length': 50
    }
})
def flag_sender():
    """Flag a sender"""
    try:
        data = request.validated_data
        
        valid_reasons = ['phishing', 'spam', 'malware', 'impersonation', 'scam', 'other']
        if data['reason'] not in valid_reasons:
            return jsonify({'error': 'Invalid flag reason'}), 400
        
        # Get or create sender reputation
        reputation = SenderReputation.query.filter_by(sender_email=data['sender_email']).first()
        
        if not reputation:
            reputation = SenderReputation(sender_email=data['sender_email'])
            db.session.add(reputation)
            db.session.flush()
        
        # Check if already flagged by this user
        existing_flag = Flag.query.filter_by(
            sender_reputation_id=reputation.id,
            flagger_id=request.user.id
        ).first()
        
        if existing_flag:
            return jsonify({'error': 'Already flagged by you'}), 400
        
        # Create flag
        flag = Flag(
            sender_reputation_id=reputation.id,
            flagger_id=request.user.id,
            reason=data['reason']
        )
        db.session.add(flag)
        
        # Update reputation
        reputation.total_flags += 1
        reputation.safe_score = max(0, reputation.safe_score - 10)
        reputation.last_flagged = datetime.utcnow()
        reputation.update_badge_color()
        
        db.session.commit()
        
        # Get multilingual flag report
        flag_report = SenderFlaggingSystem.create_flag_report(
            data['sender_email'],
            data['reason'],
            request.user.preferred_languages
        )
        
        logger.info(f"Sender flagged: {data['sender_email']} by {request.user.email} for {data['reason']}")
        
        return jsonify({
            'success': True,
            'flag_report': flag_report
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Flag sender error: {e}")
        return jsonify({'error': 'Failed to flag sender'}), 500


@app.route('/api/flag-reasons', methods=['GET'])
@require_auth
def get_flag_reasons():
    """Get flag reasons in user's languages"""
    try:
        reasons = SenderFlaggingSystem.get_flag_reasons(request.user.preferred_languages)
        
        return jsonify({
            'success': True,
            'reasons': reasons,
            'languages': request.user.preferred_languages
        }), 200
        
    except Exception as e:
        logger.error(f"Get flag reasons error: {e}")
        return jsonify({'error': 'Failed to get flag reasons'}), 500


# ============================================================================
# LINK VERIFICATION ENDPOINTS
# ============================================================================

@app.route('/api/verify-link', methods=['POST'])
@require_auth
@limiter.limit("30 per minute")
@validate_request({
    'url': {
        'type': str,
        'required': True,
        'max_length': 2048,
        'validator': BufferOverflowProtection.validate_url
    }
})
def verify_link():
    """Verify link safety"""
    try:
        data = request.validated_data
        
        # Check XSS
        if XSSProtection.detect_xss(data['url']):
            return jsonify({'error': 'URL contains dangerous content'}), 400
        
        # Check cache
        url_hash = hashlib.sha256(data['url'].encode()).hexdigest()
        cached = LinkCache.query.filter_by(url_hash=url_hash).first()
        
        if cached and cached.expires_at and datetime.utcnow() < cached.expires_at:
            result = {
                'url': data['url'],
                'is_safe': cached.is_safe,
                'risk_level': cached.risk_level,
                'risk_score': cached.risk_score,
                'warnings': cached.warnings,
                'cached': True
            }
        else:
            # Verify link
            result = link_verifier.verify_url(data['url'])
            
            # Cache result
            if cached:
                cached.is_safe = result['is_safe']
                cached.risk_level = result['risk_level']
                cached.risk_score = result['risk_score']
                cached.warnings = result['warnings']
                cached.expires_at = datetime.utcnow() + timedelta(hours=1)
            else:
                cached = LinkCache(
                    url_hash=url_hash,
                    url=data['url'],
                    is_safe=result['is_safe'],
                    risk_level=result['risk_level'],
                    risk_score=result['risk_score'],
                    warnings=result['warnings'],
                    expires_at=datetime.utcnow() + timedelta(hours=1)
                )
                db.session.add(cached)
            
            db.session.commit()
        
        logger.info(f"Link verified: {data['url'][:50]}... - Safe: {result['is_safe']}")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Link verification error: {e}")
        return jsonify({'error': 'Verification failed'}), 500


# ============================================================================
# USER PROFILE ENDPOINTS
# ============================================================================

@app.route('/api/profile', methods=['GET'])
@require_auth
def get_profile():
    """Get user profile"""
    try:
        return jsonify({
            'email': request.user.email,
            'preferred_languages': request.user.preferred_languages,
            'safe_score': request.user.safe_score,
            'flags_received': request.user.flags_received,
            'created_at': request.user.created_at.isoformat(),
            'last_login': request.user.last_login.isoformat() if request.user.last_login else None
        }), 200
        
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({'error': 'Failed to get profile'}), 500


@app.route('/api/profile/languages', methods=['PUT'])
@require_auth
@limiter.limit("10 per hour")
@validate_request({
    'preferred_languages': {
        'type': list,
        'required': True,
        'max_size': 2
    }
})
def update_languages():
    """Update preferred languages"""
    try:
        data = request.validated_data
        
        valid_langs = ['en', 'hi', 'bn', 'te', 'mr', 'ta', 'gu', 'kn', 'ml', 'pa', 'or', 'as', 'es', 'fr', 'de']
        
        if len(data['preferred_languages']) != 2:
            return jsonify({'error': 'Please select exactly 2 languages'}), 400
        
        for lang in data['preferred_languages']:
            if lang not in valid_langs:
                return jsonify({'error': f'Invalid language: {lang}'}), 400
        
        request.user.preferred_languages = data['preferred_languages']
        db.session.commit()
        
        logger.info(f"Languages updated: {request.user.email}")
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update languages error: {e}")
        return jsonify({'error': 'Failed to update languages'}), 500


# ============================================================================
# APPLICATION STARTUP
# ============================================================================

if __name__ == '__main__':
    # Create necessary directories and files
    os.makedirs('logs', exist_ok=True)
    os.makedirs(app.config['MAILDATA_PATH'], exist_ok=True)
    
    # Create blacklist file if it doesn't exist
    blacklist_file = 'phishing_blacklist.txt'
    if not os.path.exists(blacklist_file):
        with open(blacklist_file, 'w') as f:
            f.write("# Phishing Domain Blacklist\n")
            f.write("bit.ly\n")
            f.write("tinyurl.com\n")
            f.write("goo.gl\n")
    
    # Create database indexes
    with app.app_context():
        create_indexes(app)
    
    # Start the application
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )