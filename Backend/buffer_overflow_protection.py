"""
Buffer Overflow Protection and Input Validation
Save as: buffer_overflow_protection.py
ALL VULNERABILITY CHECKS
"""

import re
from typing import Any, Dict
from functools import wraps
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)


class BufferOverflowProtection:
    """Buffer overflow protection for all inputs"""
    
    MAX_EMAIL_LENGTH = 254
    MAX_PASSWORD_LENGTH = 128
    MAX_TOTP_LENGTH = 6
    MAX_URL_LENGTH = 2048
    MAX_NAME_LENGTH = 100
    MAX_TEXT_LENGTH = 1000
    MAX_REASON_LENGTH = 200
    MAX_JSON_SIZE = 1048576
    MAX_ARRAY_SIZE = 100
    
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    URL_PATTERN = re.compile(r'^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?$')
    TOTP_PATTERN = re.compile(r'^\d{6}$')
    
    @staticmethod
    def validate_string_length(value: str, max_length: int, field_name: str = "Field") -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
        
        byte_length = len(value.encode('utf-8'))
        if byte_length > max_length:
            raise ValueError(f"{field_name} exceeds maximum length of {max_length} bytes")
        
        if '\x00' in value:
            raise ValueError(f"{field_name} contains null bytes")
        
        return value
    
    @staticmethod
    def validate_email(email: str) -> str:
        email = BufferOverflowProtection.validate_string_length(
            email, 
            BufferOverflowProtection.MAX_EMAIL_LENGTH,
            "Email"
        )
        
        email = email.strip()
        
        if not BufferOverflowProtection.EMAIL_PATTERN.match(email):
            raise ValueError("Invalid email format")
        
        local, domain = email.split('@')
        if len(local) > 64:
            raise ValueError("Email local part too long")
        if len(domain) > 255:
            raise ValueError("Email domain too long")
        
        return email.lower()
    
    @staticmethod
    def validate_password(password: str) -> str:
        password = BufferOverflowProtection.validate_string_length(
            password,
            BufferOverflowProtection.MAX_PASSWORD_LENGTH,
            "Password"
        )
        
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            raise ValueError("Password must contain uppercase, lowercase, digit, and special character")
        
        return password
    
    @staticmethod
    def validate_totp(totp: str) -> str:
        totp = BufferOverflowProtection.validate_string_length(
            totp,
            BufferOverflowProtection.MAX_TOTP_LENGTH,
            "TOTP code"
        )
        
        totp = totp.strip()
        
        if not BufferOverflowProtection.TOTP_PATTERN.match(totp):
            raise ValueError("TOTP must be 6 digits")
        
        return totp
    
    @staticmethod
    def validate_url(url: str) -> str:
        url = BufferOverflowProtection.validate_string_length(
            url,
            BufferOverflowProtection.MAX_URL_LENGTH,
            "URL"
        )
        
        url = url.strip()
        
        if not BufferOverflowProtection.URL_PATTERN.match(url):
            raise ValueError("Invalid URL format")
        
        url_lower = url.lower()
        
        dangerous_protocols = ['file://', 'ftp://', 'javascript:', 'data:']
        if any(url_lower.startswith(proto) for proto in dangerous_protocols):
            raise ValueError("Unsupported URL protocol")
        
        return url
    
    @staticmethod
    def validate_array(arr: list, max_size: int = MAX_ARRAY_SIZE, field_name: str = "Array") -> list:
        if not isinstance(arr, list):
            raise ValueError(f"{field_name} must be an array")
        
        if len(arr) > max_size:
            raise ValueError(f"{field_name} exceeds maximum size of {max_size}")
        
        return arr
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
        text = BufferOverflowProtection.validate_string_length(
            text, max_length, "Text"
        )
        
        text = ''.join(
            char for char in text 
            if char in '\n\t' or (ord(char) >= 32 and ord(char) != 127)
        )
        
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        
        return text


class SQLInjectionProtection:
    """SQL injection protection"""
    
    DANGEROUS_PATTERNS = [
        r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)",
        r"(\bEXEC\b|\bEXECUTE\b|\bCOMMENT\b|\b--\b|\b;)",
        r"(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)",
        r"('|\"|`)",
    ]
    
    @staticmethod
    def detect_sql_injection(value: str) -> bool:
        if not isinstance(value, str):
            return False
        
        value_upper = value.upper()
        
        for pattern in SQLInjectionProtection.DANGEROUS_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {value[:50]}")
                return True
        
        return False
    
    @staticmethod
    def sanitize_for_sql(value: str) -> str:
        if SQLInjectionProtection.detect_sql_injection(value):
            raise ValueError("Input contains potentially dangerous SQL patterns")
        
        value = value.replace("'", "''")
        value = value.replace("\\", "\\\\")
        value = value.replace("\x00", "")
        
        return value


class XSSProtection:
    """XSS protection"""
    
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'onclick\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
    ]
    
    @staticmethod
    def detect_xss(value: str) -> bool:
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        
        for pattern in XSSProtection.DANGEROUS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                logger.warning(f"Potential XSS detected: {value[:50]}")
                return True
        
        return False
    
    @staticmethod
    def sanitize_html(value: str) -> str:
        if XSSProtection.detect_xss(value):
            raise ValueError("Input contains potentially dangerous HTML/JavaScript")
        
        value = re.sub(r'<[^>]+>', '', value)
        
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
        }
        
        for char, entity in replacements.items():
            value = value.replace(char, entity)
        
        return value


class CommandInjectionProtection:
    """Command injection protection"""
    
    DANGEROUS_CHARS = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '\n', '\r']
    
    @staticmethod
    def detect_command_injection(value: str) -> bool:
        if not isinstance(value, str):
            return False
        
        for char in CommandInjectionProtection.DANGEROUS_CHARS:
            if char in value:
                logger.warning(f"Potential command injection detected: {value[:50]}")
                return True
        
        return False
    
    @staticmethod
    def sanitize_for_shell(value: str) -> str:
        if CommandInjectionProtection.detect_command_injection(value):
            raise ValueError("Input contains potentially dangerous shell characters")
        
        for char in CommandInjectionProtection.DANGEROUS_CHARS:
            value = value.replace(char, '')
        
        return value


class PathTraversalProtection:
    """Path traversal protection"""
    
    @staticmethod
    def detect_path_traversal(value: str) -> bool:
        if not isinstance(value, str):
            return False
        
        dangerous_patterns = [
            '../', '..\\', '%2e%2e/', '%2e%2e\\', '..%2f', '..%5c',
        ]
        
        value_lower = value.lower()
        
        for pattern in dangerous_patterns:
            if pattern in value_lower:
                logger.warning(f"Potential path traversal detected: {value[:50]}")
                return True
        
        return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        if PathTraversalProtection.detect_path_traversal(filename):
            raise ValueError("Filename contains path traversal patterns")
        
        filename = filename.replace('/', '').replace('\\', '')
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        if filename.startswith('.'):
            filename = filename[1:]
        
        return filename


class IntegerOverflowProtection:
    """Integer overflow protection"""
    
    INT32_MIN = -2147483648
    INT32_MAX = 2147483647
    UINT32_MAX = 4294967295
    
    @staticmethod
    def validate_integer(value: Any, min_val: int = INT32_MIN, 
                        max_val: int = INT32_MAX, 
                        field_name: str = "Integer") -> int:
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"{field_name} must be a valid integer")
        
        if int_value < min_val or int_value > max_val:
            raise ValueError(f"{field_name} must be between {min_val} and {max_val}")
        
        return int_value
    
    @staticmethod
    def safe_addition(a: int, b: int) -> int:
        result = a + b
        if a > 0 and b > 0 and result < 0:
            raise OverflowError("Integer addition overflow")
        if a < 0 and b < 0 and result > 0:
            raise OverflowError("Integer addition underflow")
        return result
    
    @staticmethod
    def safe_multiplication(a: int, b: int) -> int:
        result = a * b
        if a != 0 and result // a != b:
            raise OverflowError("Integer multiplication overflow")
        return result


def validate_request(schema: Dict[str, Dict[str, Any]]):
    """Request validation decorator"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({'error': 'No data provided'}), 400
                
                json_size = len(request.get_data())
                if json_size > BufferOverflowProtection.MAX_JSON_SIZE:
                    return jsonify({'error': 'Request too large'}), 413
                
                validated_data = {}
                
                for field, rules in schema.items():
                    value = data.get(field)
                    
                    if rules.get('required', False) and value is None:
                        return jsonify({'error': f'Missing required field: {field}'}), 400
                    
                    if value is None:
                        continue
                    
                    expected_type = rules.get('type')
                    if expected_type and not isinstance(value, expected_type):
                        return jsonify({'error': f'{field} must be of type {expected_type.__name__}'}), 400
                    
                    if isinstance(value, str) and 'max_length' in rules:
                        try:
                            value = BufferOverflowProtection.validate_string_length(
                                value, rules['max_length'], field
                            )
                        except ValueError as e:
                            return jsonify({'error': str(e)}), 400
                    
                    if isinstance(value, list) and 'max_size' in rules:
                        try:
                            value = BufferOverflowProtection.validate_array(
                                value, rules['max_size'], field
                            )
                        except ValueError as e:
                            return jsonify({'error': str(e)}), 400
                    
                    if 'validator' in rules:
                        try:
                            value = rules['validator'](value)
                        except ValueError as e:
                            return jsonify({'error': f'{field}: {str(e)}'}), 400
                    
                    validated_data[field] = value
                
                request.validated_data = validated_data
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Request validation error: {e}")
                return jsonify({'error': 'Invalid request data'}), 400
        
        return wrapper
    return decorator
