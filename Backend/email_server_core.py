"""
Email Server Core - SMTP/IMAP Implementation
Save as: email_server_core.py
Handles email sending, receiving, and storage
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging
from pathlib import Path
import time

logger = logging.getLogger(__name__)


class EmailStorage:
    """Store emails on filesystem (Maildir format)"""
    
    def __init__(self, base_path: str = None):
        if base_path is None:
            # Use user's home directory instead of hardcoded path
            app_dir = Path.home() / '.secure_email_app' / 'maildata'
            app_dir.mkdir(parents=True, exist_ok=True)
            base_path = str(app_dir)
    
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    
    def _get_user_mailbox(self, email_address: str) -> Path:
        """Get user's mailbox directory"""
        email_hash = hashlib.sha256(email_address.encode()).hexdigest()[:16]
        user_dir = self.base_path / email_hash
        
        (user_dir / 'new').mkdir(parents=True, exist_ok=True)
        (user_dir / 'cur').mkdir(parents=True, exist_ok=True)
        (user_dir / 'tmp').mkdir(parents=True, exist_ok=True)
        (user_dir / 'sent').mkdir(parents=True, exist_ok=True)
        (user_dir / 'drafts').mkdir(parents=True, exist_ok=True)
        (user_dir / 'trash').mkdir(parents=True, exist_ok=True)
        
        return user_dir
    
    def store_email(self, recipient: str, email_data: Dict) -> str:
        """Store email in recipient's mailbox"""
        mailbox = self._get_user_mailbox(recipient)
        
        timestamp = int(time.time() * 1000)
        message_id = f"{timestamp}.{hashlib.md5(recipient.encode()).hexdigest()[:8]}"
        
        metadata = {
            'message_id': message_id,
            'from': email_data['from'],
            'to': email_data['to'],
            'subject': email_data['subject'],
            'date': datetime.now().isoformat(),
            'size': len(email_data['body']),
            'flags': ['\\Recent'],
            'uid': message_id,
        }
        
        email_file = mailbox / 'new' / f"{message_id}.eml"
        
        with open(email_file, 'w', encoding='utf-8') as f:
            f.write(f"From: {email_data['from']}\n")
            f.write(f"To: {email_data['to']}\n")
            f.write(f"Subject: {email_data['subject']}\n")
            f.write(f"Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}\n")
            f.write(f"Message-ID: <{message_id}@securemail.local>\n")
            f.write(f"Content-Type: text/plain; charset=utf-8\n")
            f.write("\n")
            f.write(email_data['body'])
        
        metadata_file = mailbox / 'new' / f"{message_id}.meta"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f)
        
        logger.info(f"Email stored: {message_id} for {recipient}")
        return message_id
    
    def get_emails(self, email_address: str, folder: str = 'new', limit: int = 50) -> List[Dict]:
        """Retrieve emails from user's mailbox"""
        mailbox = self._get_user_mailbox(email_address)
        folder_path = mailbox / folder
        
        if not folder_path.exists():
            return []
        
        emails = []
        
        email_files = sorted(folder_path.glob('*.eml'), 
                           key=lambda x: x.stat().st_mtime, 
                           reverse=True)[:limit]
        
        for email_file in email_files:
            metadata_file = email_file.with_suffix('.meta')
            
            try:
                if metadata_file.exists():
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                else:
                    metadata = self._parse_email_file(email_file)
                
                with open(email_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                parts = content.split('\n\n', 1)
                body = parts[1] if len(parts) > 1 else ''
                
                metadata['body'] = body
                metadata['preview'] = body[:200] + '...' if len(body) > 200 else body
                
                emails.append(metadata)
                
            except Exception as e:
                logger.error(f"Error reading email {email_file}: {e}")
                continue
        
        return emails
    
    def move_email(self, email_address: str, message_id: str, 
                  from_folder: str, to_folder: str) -> bool:
        """Move email between folders"""
        mailbox = self._get_user_mailbox(email_address)
        
        source = mailbox / from_folder / f"{message_id}.eml"
        source_meta = mailbox / from_folder / f"{message_id}.meta"
        
        dest = mailbox / to_folder / f"{message_id}.eml"
        dest_meta = mailbox / to_folder / f"{message_id}.meta"
        
        try:
            if source.exists():
                source.rename(dest)
            if source_meta.exists():
                source_meta.rename(dest_meta)
            return True
        except Exception as e:
            logger.error(f"Error moving email: {e}")
            return False
    
    def delete_email(self, email_address: str, message_id: str, folder: str = 'cur') -> bool:
        """Delete email (move to trash)"""
        return self.move_email(email_address, message_id, folder, 'trash')
    
    def _parse_email_file(self, email_file: Path) -> Dict:
        """Parse email file to extract metadata"""
        metadata = {}
        
        with open(email_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key in ['from', 'to', 'subject', 'date', 'message-id']:
                    metadata[key] = value
        
        return metadata


class SMTPServer:
    """SMTP server for sending emails"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 2525, storage: EmailStorage = None):
        self.host = host
        self.port = port
        self.storage = storage or EmailStorage()
    
    def send_email(self, from_address: str, to_address: str, 
                   subject: str, body: str, 
                   preferred_languages: List[str] = None) -> Dict:
        """Send email (internal delivery)"""
        try:
            email_data = {
                'from': from_address,
                'to': to_address,
                'subject': subject,
                'body': body,
                'timestamp': datetime.now().isoformat(),
                'languages': preferred_languages or ['en']
            }
            
            if self._is_local_user(to_address):
                message_id = self.storage.store_email(to_address, email_data)
                
                logger.info(f"Email delivered locally: {from_address} -> {to_address}")
                
                return {
                    'success': True,
                    'message_id': message_id,
                    'status': 'delivered',
                    'delivery_type': 'local'
                }
            else:
                return {
                    'success': True,
                    'message_id': 'queued',
                    'status': 'queued',
                    'delivery_type': 'external'
                }
        
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _is_local_user(self, email_address: str) -> bool:
        """Check if email address is for a local user"""
        return True  # All users are local in this system
    
    def save_to_sent(self, from_address: str, email_data: Dict) -> str:
        """Save sent email to sender's 'sent' folder"""
        mailbox = self.storage._get_user_mailbox(from_address)
        
        timestamp = int(time.time() * 1000)
        message_id = f"sent.{timestamp}.{hashlib.md5(from_address.encode()).hexdigest()[:8]}"
        
        email_file = mailbox / 'sent' / f"{message_id}.eml"
        
        with open(email_file, 'w', encoding='utf-8') as f:
            f.write(f"From: {email_data['from']}\n")
            f.write(f"To: {email_data['to']}\n")
            f.write(f"Subject: {email_data['subject']}\n")
            f.write(f"Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}\n")
            f.write(f"Message-ID: <{message_id}@securemail.local>\n")
            f.write("\n")
            f.write(email_data['body'])
        
        return message_id


class IMAPServer:
    """IMAP server for retrieving emails"""
    
    def __init__(self, storage: EmailStorage = None):
        self.storage = storage or EmailStorage()
    
    def list_folders(self, email_address: str) -> List[str]:
        """List available folders for user"""
        return ['INBOX', 'Sent', 'Drafts', 'Trash']
    
    def select_folder(self, email_address: str, folder: str) -> Dict:
        """Select a folder and return info"""
        folder_map = {
            'INBOX': ['new', 'cur'],
            'Sent': ['sent'],
            'Drafts': ['drafts'],
            'Trash': ['trash']
        }
        
        folders = folder_map.get(folder, ['new'])
        
        total_messages = 0
        recent_messages = 0
        
        mailbox = self.storage._get_user_mailbox(email_address)
        
        for f in folders:
            folder_path = mailbox / f
            if folder_path.exists():
                messages = list(folder_path.glob('*.eml'))
                total_messages += len(messages)
                
                if f == 'new':
                    recent_messages = len(messages)
        
        return {
            'folder': folder,
            'exists': total_messages,
            'recent': recent_messages,
            'unseen': recent_messages,
            'flags': ['\\Seen', '\\Answered', '\\Flagged', '\\Deleted', '\\Draft']
        }
    
    def fetch_messages(self, email_address: str, folder: str = 'INBOX', limit: int = 50) -> List[Dict]:
        """Fetch messages from folder"""
        folder_map = {
            'INBOX': 'new',
            'Sent': 'sent',
            'Drafts': 'drafts',
            'Trash': 'trash'
        }
        
        storage_folder = folder_map.get(folder, 'new')
        messages = self.storage.get_emails(email_address, storage_folder, limit)
        
        if folder == 'INBOX':
            cur_messages = self.storage.get_emails(email_address, 'cur', limit)
            messages.extend(cur_messages)
        
        return messages
    
    def mark_as_read(self, email_address: str, message_id: str) -> bool:
        """Mark message as read"""
        return self.storage.move_email(email_address, message_id, 'new', 'cur')
    
    def search(self, email_address: str, criteria: Dict) -> List[Dict]:
        """Search messages based on criteria"""
        all_messages = self.fetch_messages(email_address, 'INBOX', limit=1000)
        
        results = []
        
        for message in all_messages:
            match = True
            
            for key, value in criteria.items():
                if key in message:
                    if value.lower() not in str(message[key]).lower():
                        match = False
                        break
            
            if match:
                results.append(message)
        
        return results


class EmailClient:
    """High-level email client interface"""
    
    def __init__(self):
        self.storage = EmailStorage()
        self.smtp = SMTPServer(storage=self.storage)
        self.imap = IMAPServer(storage=self.storage)
    
    def send_email(self, from_address: str, to_address: str, 
                   subject: str, body: str, 
                   preferred_languages: List[str] = None) -> Dict:
        """Send an email"""
        result = self.smtp.send_email(
            from_address, to_address, subject, body, preferred_languages
        )
        
        if result['success']:
            email_data = {
                'from': from_address,
                'to': to_address,
                'subject': subject,
                'body': body
            }
            self.smtp.save_to_sent(from_address, email_data)
        
        return result
    
    def get_inbox(self, email_address: str, limit: int = 50) -> List[Dict]:
        """Get inbox messages"""
        return self.imap.fetch_messages(email_address, 'INBOX', limit)
    
    def get_sent(self, email_address: str, limit: int = 50) -> List[Dict]:
        """Get sent messages"""
        return self.imap.fetch_messages(email_address, 'Sent', limit)
    
    def get_message(self, email_address: str, message_id: str) -> Optional[Dict]:
        """Get specific message by ID"""
        messages = self.get_inbox(email_address, limit=1000)
        
        for message in messages:
            if message.get('message_id') == message_id:
                return message
        
        return None
    
    def mark_read(self, email_address: str, message_id: str) -> bool:
        """Mark message as read"""
        return self.imap.mark_as_read(email_address, message_id)
    
    def delete_message(self, email_address: str, message_id: str) -> bool:
        """Delete message"""
        success = self.storage.delete_email(email_address, message_id, 'new')
        if not success:
            success = self.storage.delete_email(email_address, message_id, 'cur')
        return success
    
    def search_emails(self, email_address: str, query: str) -> List[Dict]:
        """Search emails by query string"""
        criteria = {}
        
        if 'from:' in query:
            criteria['from'] = query.split('from:')[1].split()[0]
        if 'subject:' in query:
            criteria['subject'] = query.split('subject:')[1].split()[0]
        
        if not criteria:
            all_messages = self.get_inbox(email_address, limit=1000)
            results = []
            
            for message in all_messages:
                if (query.lower() in message.get('subject', '').lower() or
                    query.lower() in message.get('body', '').lower()):
                    results.append(message)
            
            return results
        
        return self.imap.search(email_address, criteria)
    
    def get_mailbox_stats(self, email_address: str) -> Dict:
        """Get mailbox statistics"""
        inbox = self.imap.select_folder(email_address, 'INBOX')
        sent = self.imap.select_folder(email_address, 'Sent')
        
        return {
            'inbox_total': inbox['exists'],
            'inbox_unread': inbox['unseen'],
            'sent_total': sent['exists'],
        }
