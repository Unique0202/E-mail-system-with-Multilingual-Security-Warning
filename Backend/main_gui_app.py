"""
Secure Multilingual Email System - Desktop GUI Application
Save as: main_gui_app.py

Run with: python main_gui_app.py
Build executable: pyinstaller --onefile --windowed main_gui_app.py
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import secrets
import hashlib
import pyotp
import bcrypt
import qrcode
from io import BytesIO

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QTabWidget, QMessageBox, QDialog, QComboBox, QSplitter, QScrollArea,
    QFrame, QGridLayout
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QPixmap, QImage, QFont

# Import local modules
from models_sqlite import DatabaseManager, User, Session, Email, SenderReputation
from buffer_overflow_protection import BufferOverflowProtection, XSSProtection
from email_server_core import EmailClient
from multilingual_warnings import (
    SecurityWarningTranslations,
    SecurityBadge,
    EmailSecurityAnalyzer
)
from opensource_link_verifier import OpenSourceLinkVerifier


class LoginWindow(QDialog):
    """Login/Registration Dialog"""
    
    def __init__(self, db_manager, user_model):
        super().__init__()
        self.db_manager = db_manager
        self.user_model = user_model
        self.current_user = None
        self.session_token = None
        
        self.setWindowTitle("Secure Email System - Login")
        self.setGeometry(0, 0, 715, 1467)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Secure Multilingual Email System")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 20px;")
        layout.addWidget(title)
        
        # Tab widget for Login/Register
        self.tabs = QTabWidget()
        
        # Login tab
        login_tab = QWidget()
        login_layout = QVBoxLayout()
        
        login_layout.addWidget(QLabel("Email:"))
        self.login_email = QLineEdit()
        self.login_email.setPlaceholderText("your.email@example.com")
        login_layout.addWidget(self.login_email)
        
        login_layout.addWidget(QLabel("Password:"))
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        login_layout.addWidget(self.login_password)
        
        login_layout.addWidget(QLabel("2FA Code:"))
        self.login_totp = QLineEdit()
        self.login_totp.setPlaceholderText("6-digit code")
        self.login_totp.setMaxLength(6)
        login_layout.addWidget(self.login_totp)
        
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.handle_login)
        login_layout.addWidget(login_btn)
        
        login_layout.addStretch()
        login_tab.setLayout(login_layout)
        
        # Register tab
        register_tab = QWidget()
        register_layout = QVBoxLayout()
        
        register_layout.addWidget(QLabel("Email:"))
        self.register_email = QLineEdit()
        self.register_email.setPlaceholderText("your.email@example.com")
        register_layout.addWidget(self.register_email)
        
        register_layout.addWidget(QLabel("Password (min 12 chars):"))
        self.register_password = QLineEdit()
        self.register_password.setEchoMode(QLineEdit.Password)
        register_layout.addWidget(self.register_password)
        
        register_layout.addWidget(QLabel("Confirm Password:"))
        self.register_password2 = QLineEdit()
        self.register_password2.setEchoMode(QLineEdit.Password)
        register_layout.addWidget(self.register_password2)
        
        register_layout.addWidget(QLabel("Primary Language:"))
        self.lang1 = QComboBox()
        self.lang1.addItems(['en', 'hi', 'bn', 'te', 'mr', 'ta', 'gu', 'kn', 'ml', 'pa', 'or', 'as'])
        register_layout.addWidget(self.lang1)
        
        register_layout.addWidget(QLabel("Secondary Language:"))
        self.lang2 = QComboBox()
        self.lang2.addItems(['hi', 'en', 'bn', 'te', 'mr', 'ta', 'gu', 'kn', 'ml', 'pa', 'or', 'as'])
        register_layout.addWidget(self.lang2)
        
        register_btn = QPushButton("Register")
        register_btn.clicked.connect(self.handle_register)
        register_layout.addWidget(register_btn)
        
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        register_layout.addWidget(self.qr_label)
        
        self.recovery_codes_text = QTextEdit()
        self.recovery_codes_text.setReadOnly(True)
        self.recovery_codes_text.setMaximumHeight(100)
        register_layout.addWidget(self.recovery_codes_text)
        
        register_layout.addStretch()
        register_tab.setLayout(register_layout)
        
        self.tabs.addTab(login_tab, "Login")
        self.tabs.addTab(register_tab, "Register")
        
        layout.addWidget(self.tabs)
        self.setLayout(layout)
    
    def handle_login(self):
        """Handle login"""
        try:
            email = BufferOverflowProtection.validate_email(self.login_email.text())
            password = self.login_password.text()
            totp_code = BufferOverflowProtection.validate_totp(self.login_totp.text())
            
            # Get user
            user = self.user_model.get_by_email(email)
            if not user:
                QMessageBox.warning(self, "Error", "Invalid credentials")
                return
            
            # Verify password
            if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
                QMessageBox.warning(self, "Error", "Invalid credentials")
                return
            
            # Verify TOTP
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code, valid_window=1):
                QMessageBox.warning(self, "Error", "Invalid 2FA code")
                return
            
            # Create session
            self.session_token = secrets.token_urlsafe(32)
            session_model = Session(self.db_manager)
            session_model.create(
                self.session_token,
                user['id'],
                '127.0.0.1',
                'Desktop App',
                datetime.utcnow() + timedelta(hours=8),
                False
            )
            
            # Update last login
            self.user_model.update_last_login(user['id'])
            
            self.current_user = user
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")
    
    def handle_register(self):
        """Handle registration"""
        try:
            email = BufferOverflowProtection.validate_email(self.register_email.text())
            password = self.register_password.text()
            password2 = self.register_password2.text()
            
            if password != password2:
                QMessageBox.warning(self, "Error", "Passwords don't match")
                return
            
            BufferOverflowProtection.validate_password(password)
            
            # Check if exists
            if self.user_model.get_by_email(email):
                QMessageBox.warning(self, "Error", "Email already registered")
                return
            
            # Create user
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            totp_secret = pyotp.random_base32()
            languages = [self.lang1.currentText(), self.lang2.currentText()]
            
            user_id = self.user_model.create(email, password_hash, totp_secret, languages)
            
            # Generate QR code
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email,
                issuer_name='SecureMailSystem'
            )
            
            qr = qrcode.QRCode(version=1, box_size=5, border=2)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to QPixmap
            img_byte_arr = BytesIO()
            img.save(img_byte_arr, format='PNG')
            img_byte_arr.seek(0)
            
            qimage = QImage.fromData(img_byte_arr.read())
            pixmap = QPixmap.fromImage(qimage)
            self.qr_label.setPixmap(pixmap.scaled(200, 200, Qt.KeepAspectRatio))
            
            # # Generate recovery codes
            # recovery_codes = []
            # for _ in range(10):
            #     code = secrets.token_hex(8)
            #     recovery_codes.append(code)
                
            #     # Store in database
            #     code_hash = hashlib.sha256(code.encode()).hexdigest()
            #     conn = self.db_manager.get_connection()
            #     cursor = conn.cursor()
            #     cursor.execute("""
            #         INSERT INTO recovery_codes (user_id, code_hash)
            #         VALUES (?, ?)
            #     """, (user_id, code_hash))
            #     conn.commit()
            #     conn.close()
            
            # self.recovery_codes_text.setText(
            #     "SAVE THESE RECOVERY CODES:\n\n" + "\n".join(recovery_codes)
            # )
            
            QMessageBox.information(
                self,
                "Success",
                "Registration successful!\n\n"
                "1. Scan the QR code with your authenticator app\n"
                "2. Save your recovery codes\n"
                "3. Go to Login tab"
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Registration failed: {str(e)}")


class EmailViewerDialog(QDialog):
    """Email viewer dialog"""
    
    def __init__(self, email_data, parent=None):
        super().__init__(parent)
        self.email_data = email_data
        
        self.setWindowTitle("Email")
        self.setFixedSize(800, 600)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header_layout = QGridLayout()
        
        header_layout.addWidget(QLabel("<b>From:</b>"), 0, 0)
        header_layout.addWidget(QLabel(self.email_data.get('sender_email', 'Unknown')), 0, 1)
        
        header_layout.addWidget(QLabel("<b>To:</b>"), 1, 0)
        header_layout.addWidget(QLabel(self.email_data.get('recipient_email', 'Unknown')), 1, 1)
        
        header_layout.addWidget(QLabel("<b>Subject:</b>"), 2, 0)
        header_layout.addWidget(QLabel(self.email_data.get('subject', '')), 2, 1)
        
        header_layout.addWidget(QLabel("<b>Date:</b>"), 3, 0)
        header_layout.addWidget(QLabel(self.email_data.get('sent_at', '')), 3, 1)
        
        layout.addLayout(header_layout)
        
        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(line)
        
        # Body
        body_text = QTextEdit()
        body_text.setReadOnly(True)
        body_text.setText(self.email_data.get('body', 'Email body not available'))
        layout.addWidget(body_text)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        
        self.setLayout(layout)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, db_manager, current_user, session_token):
        super().__init__()
        self.db_manager = db_manager
        self.current_user = current_user
        self.session_token = session_token
        
        self.email_client = EmailClient()
        self.link_verifier = OpenSourceLinkVerifier()
        
        self.setWindowTitle(f"Secure Email - {current_user['email']}")
        self.setGeometry(0, 0, 1400, 1600)
        
        self.init_ui()
        self.load_inbox()
    
    def init_ui(self):
        """Initialize UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout()
        
        # Left sidebar
        sidebar = QVBoxLayout()
        
        compose_btn = QPushButton("✉ Compose")
        compose_btn.clicked.connect(self.show_compose_dialog)
        sidebar.addWidget(compose_btn)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_inbox)
        sidebar.addWidget(refresh_btn)
        
        sidebar.addWidget(QLabel("<b>Folders:</b>"))
        
        inbox_btn = QPushButton("📥 Inbox")
        inbox_btn.clicked.connect(self.load_inbox)
        sidebar.addWidget(inbox_btn)
        
        sent_btn = QPushButton("📤 Sent")
        sent_btn.clicked.connect(self.load_sent)
        sidebar.addWidget(sent_btn)
        
        sidebar.addStretch()
        
        logout_btn = QPushButton("🚪 Logout")
        logout_btn.clicked.connect(self.logout)
        sidebar.addWidget(logout_btn)
        
        # Email list
        self.email_list = QListWidget()
        self.email_list.itemDoubleClicked.connect(self.open_email)
        
        # Splitter
        splitter = QSplitter(Qt.Horizontal)
        
        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar)
        sidebar_widget.setMaximumWidth(200)
        
        splitter.addWidget(sidebar_widget)
        splitter.addWidget(self.email_list)
        
        main_layout.addWidget(splitter)
        
        central_widget.setLayout(main_layout)
    
    def load_inbox(self):
        """Load inbox emails"""
        try:
            email_model = Email(self.db_manager)
            emails = email_model.get_inbox(self.current_user['id'], 50)
            
            self.email_list.clear()
            
            for email in emails:
                # Get sender reputation
                rep_model = SenderReputation(self.db_manager)
                reputation = rep_model.get_or_create(email['sender_email'])
                
                # Create list item
                item_text = f"{'[UNREAD] ' if not email['is_read'] else ''}"
                item_text += f"From: {email['sender_email']}\n"
                item_text += f"Subject: {email['subject']}\n"
                item_text += f"Score: {reputation['safe_score']} | Flags: {reputation['total_flags']}"
                
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, email)
                
                # Color code by security
                if reputation['badge_color'] == 'green':
                    item.setBackground(Qt.lightGray)
                elif reputation['badge_color'] == 'yellow':
                    item.setBackground(Qt.yellow)
                elif reputation['badge_color'] == 'red':
                    item.setBackground(Qt.red)
                
                self.email_list.addItem(item)
            
            self.statusBar().showMessage(f"Loaded {len(emails)} emails")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load inbox: {str(e)}")
    
    def load_sent(self):
        """Load sent emails"""
        try:
            email_model = Email(self.db_manager)
            emails = email_model.get_sent(self.current_user['id'], 50)
            
            self.email_list.clear()
            
            for email in emails:
                item_text = f"To: {email['recipient_email']}\n"
                item_text += f"Subject: {email['subject']}"
                
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, email)
                self.email_list.addItem(item)
            
            self.statusBar().showMessage(f"Loaded {len(emails)} sent emails")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load sent: {str(e)}")
    
    def open_email(self, item):
        """Open email in viewer"""
        email_data = item.data(Qt.UserRole)
        
        # Load full email body
        try:
            full_email = self.email_client.get_message(
                self.current_user['email'],
                email_data['message_id']
            )
            
            if full_email:
                email_data['body'] = full_email.get('body', 'Email body not available')
            else:
                email_data['body'] = 'Email body not available'
            
            # Mark as read
            email_model = Email(self.db_manager)
            email_model.mark_read(email_data['message_id'])
            
            # Show viewer
            dialog = EmailViewerDialog(email_data, self)
            dialog.exec_()
            
            # Refresh list
            self.load_inbox()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open email: {str(e)}")
    
    def show_compose_dialog(self):
        """Show compose email dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Compose Email")
        dialog.setFixedSize(600, 500)
        
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("To:"))
        to_email = QLineEdit()
        layout.addWidget(to_email)
        
        layout.addWidget(QLabel("Subject:"))
        subject = QLineEdit()
        layout.addWidget(subject)
        
        layout.addWidget(QLabel("Body:"))
        body = QTextEdit()
        layout.addWidget(body)
        
        send_btn = QPushButton("Send")
        
        def send_email():
            try:
                to = BufferOverflowProtection.validate_email(to_email.text())
                subj = BufferOverflowProtection.sanitize_text(subject.text(), 500)
                body_text = BufferOverflowProtection.sanitize_text(body.toPlainText(), 50000)
                
                # Check XSS
                if XSSProtection.detect_xss(body_text):
                    QMessageBox.warning(dialog, "Error", "Email contains dangerous content")
                    return
                
                # Get recipient
                user_model = User(self.db_manager)
                recipient = user_model.get_by_email(to)
                
                if not recipient:
                    QMessageBox.warning(dialog, "Error", "Recipient not found")
                    return
                
                # Send email
                result = self.email_client.send_email(
                    self.current_user['email'],
                    to,
                    subj,
                    body_text,
                    self.current_user['preferred_languages']
                )
                
                if result['success']:
                    # Store in database
                    email_model = Email(self.db_manager)
                    email_model.create(
                        result['message_id'],
                        self.current_user['id'],
                        recipient['id'],
                        subj,
                        f"maildata/{recipient['id']}/new/{result['message_id']}.eml",
                        len(body_text)
                    )
                    
                    QMessageBox.information(dialog, "Success", "Email sent successfully")
                    dialog.accept()
                    self.load_inbox()
                else:
                    QMessageBox.critical(dialog, "Error", f"Failed to send: {result.get('error', 'Unknown error')}")
                
            except Exception as e:
                QMessageBox.critical(dialog, "Error", f"Failed to send email: {str(e)}")
        
        send_btn.clicked.connect(send_email)
        layout.addWidget(send_btn)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def logout(self):
        """Logout"""
        session_model = Session(self.db_manager)
        session_model.delete(self.session_token)
        
        QMessageBox.information(self, "Logout", "Logged out successfully")
        self.close()
        QApplication.quit()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Initialize database
    db_manager = DatabaseManager()
    user_model = User(db_manager)
    
    # Show login window
    login_window = LoginWindow(db_manager, user_model)
    
    if login_window.exec_() == QDialog.Accepted:
        # Show main window
        main_window = MainWindow(
            db_manager,
            login_window.current_user,
            login_window.session_token
        )
        main_window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
