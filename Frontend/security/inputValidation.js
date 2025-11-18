/**
 * Buffer Overflow Protection and Input Validation
 * Equivalent of buffer_overflow_protection.py
 */

class BufferOverflowProtection {
    static MAX_EMAIL_LENGTH = 254;
    static MAX_PASSWORD_LENGTH = 128;
    static MAX_TOTP_LENGTH = 6;
    static MAX_URL_LENGTH = 2048;
    static MAX_NAME_LENGTH = 100;
    static MAX_TEXT_LENGTH = 1000;
    static MAX_REASON_LENGTH = 200;
    static MAX_JSON_SIZE = 1048576;
    static MAX_ARRAY_SIZE = 100;

    static EMAIL_PATTERN = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    static URL_PATTERN = /^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:\/[^\s]*)?$/;
    static TOTP_PATTERN = /^\d{6}$/;

    static validateStringLength(value, maxLength, fieldName = "Field") {
        if (typeof value !== 'string') {
            throw new Error(`${fieldName} must be a string`);
        }

        const byteLength = Buffer.byteLength(value, 'utf8');
        if (byteLength > maxLength) {
            throw new Error(`${fieldName} exceeds maximum length of ${maxLength} bytes`);
        }

        if (value.includes('\x00')) {
            throw new Error(`${fieldName} contains null bytes`);
        }

        return value;
    }

    static validateEmail(email) {
        email = this.validateStringLength(email, this.MAX_EMAIL_LENGTH, "Email");
        email = email.trim();

        if (!this.EMAIL_PATTERN.test(email)) {
            throw new Error("Invalid email format");
        }

        const [local, domain] = email.split('@');
        if (local.length > 64) {
            throw new Error("Email local part too long");
        }
        if (domain.length > 255) {
            throw new Error("Email domain too long");
        }

        return email.toLowerCase();
    }

    static validatePassword(password) {
        password = this.validateStringLength(password, this.MAX_PASSWORD_LENGTH, "Password");

        if (password.length < 12) {
            throw new Error("Password must be at least 12 characters");
        }

        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasDigit = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (!(hasUpper && hasLower && hasDigit && hasSpecial)) {
            throw new Error("Password must contain uppercase, lowercase, digit, and special character");
        }

        return password;
    }

    static validateTOTP(totp) {
        totp = this.validateStringLength(totp, this.MAX_TOTP_LENGTH, "TOTP code");
        totp = totp.trim();

        if (!this.TOTP_PATTERN.test(totp)) {
            throw new Error("TOTP must be 6 digits");
        }

        return totp;
    }

    static validateArray(arr, maxSize = this.MAX_ARRAY_SIZE, fieldName = "Array") {
        if (!Array.isArray(arr)) {
            throw new Error(`${fieldName} must be an array`);
        }

        if (arr.length > maxSize) {
            throw new Error(`${fieldName} exceeds maximum size of ${maxSize}`);
        }

        return arr;
    }

    static sanitizeText(text, maxLength = this.MAX_TEXT_LENGTH) {
        text = this.validateStringLength(text, maxLength, "Text");

        // Remove dangerous characters, keep only safe ones
        text = text.split('')
            .filter(char => {
                const code = char.charCodeAt(0);
                return char === '\n' || char === '\t' || (code >= 32 && code !== 127);
            })
            .join('');

        // Normalize whitespace
        text = text.replace(/\s+/g, ' ').trim();

        return text;
    }
}

class SQLInjectionProtection {
    static DANGEROUS_PATTERNS = [
        /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)/i,
        /(\bEXEC\b|\bEXECUTE\b|\bCOMMENT\b|\b--\b|;)/i,
        /(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)/i,
        /('|"|`)/,
    ];

    static detectSQLInjection(value) {
        if (typeof value !== 'string') return false;

        for (const pattern of this.DANGEROUS_PATTERNS) {
            if (pattern.test(value)) {
                console.warn(`Potential SQL injection detected: ${value.substring(0, 50)}`);
                return true;
            }
        }

        return false;
    }

    static sanitizeForSQL(value) {
        if (this.detectSQLInjection(value)) {
            throw new Error("Input contains potentially dangerous SQL patterns");
        }

        return value.replace(/'/g, "''")
                   .replace(/\\/g, "\\\\")
                   .replace(/\x00/g, "");
    }
}

class XSSProtection {
    static DANGEROUS_PATTERNS = [
        /<script[^>]*>.*?<\/script>/gi,
        /javascript:/gi,
        /onerror\s*=/gi,
        /onload\s*=/gi,
        /onclick\s*=/gi,
        /<iframe[^>]*>/gi,
        /<object[^>]*>/gi,
        /<embed[^>]*>/gi,
    ];

    static detectXSS(value) {
        if (typeof value !== 'string') return false;

        for (const pattern of this.DANGEROUS_PATTERNS) {
            if (pattern.test(value)) {
                console.warn(`Potential XSS detected: ${value.substring(0, 50)}`);
                return true;
            }
        }

        return false;
    }

    static sanitizeHTML(value) {
        if (this.detectXSS(value)) {
            throw new Error("Input contains potentially dangerous HTML/JavaScript");
        }

        // Remove HTML tags
        value = value.replace(/<[^>]+>/g, '');

        // Escape dangerous characters
        const replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
        };

        for (const [char, entity] of Object.entries(replacements)) {
            value = value.replace(new RegExp(char, 'g'), entity);
        }

        return value;
    }
}

class CommandInjectionProtection {
    static DANGEROUS_CHARS = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '\n', '\r'];

    static detectCommandInjection(value) {
        if (typeof value !== 'string') return false;

        for (const char of this.DANGEROUS_CHARS) {
            if (value.includes(char)) {
                console.warn(`Potential command injection detected: ${value.substring(0, 50)}`);
                return true;
            }
        }

        return false;
    }

    static sanitizeForShell(value) {
        if (this.detectCommandInjection(value)) {
            throw new Error("Input contains potentially dangerous shell characters");
        }

        let sanitized = value;
        for (const char of this.DANGEROUS_CHARS) {
            sanitized = sanitized.split(char).join('');
        }

        return sanitized;
    }
}

class PathTraversalProtection {
    static detectPathTraversal(value) {
        if (typeof value !== 'string') return false;

        const dangerousPatterns = [
            '../', '..\\', '%2e%2e/', '%2e%2e\\', '..%2f', '..%5c',
        ];

        const valueLower = value.toLowerCase();

        for (const pattern of dangerousPatterns) {
            if (valueLower.includes(pattern)) {
                console.warn(`Potential path traversal detected: ${value.substring(0, 50)}`);
                return true;
            }
        }

        return false;
    }

    static sanitizeFilename(filename) {
        if (this.detectPathTraversal(filename)) {
            throw new Error("Filename contains path traversal patterns");
        }

        let sanitized = filename.replace(/\//g, '').replace(/\\/g, '');
        sanitized = sanitized.replace(/[^a-zA-Z0-9._-]/g, '');

        if (sanitized.startsWith('.')) {
            sanitized = sanitized.substring(1);
        }

        return sanitized;
    }
}

class IntegerOverflowProtection {
    static INT32_MIN = -2147483648;
    static INT32_MAX = 2147483647;
    static UINT32_MAX = 4294967295;

    static validateInteger(value, minVal = this.INT32_MIN, maxVal = this.INT32_MAX, fieldName = "Integer") {
        const intValue = parseInt(value, 10);
        
        if (isNaN(intValue)) {
            throw new Error(`${fieldName} must be a valid integer`);
        }

        if (intValue < minVal || intValue > maxVal) {
            throw new Error(`${fieldName} must be between ${minVal} and ${maxVal}`);
        }

        return intValue;
    }

    static safeAddition(a, b) {
        const result = a + b;
        if (a > 0 && b > 0 && result < 0) {
            throw new Error("Integer addition overflow");
        }
        if (a < 0 && b < 0 && result > 0) {
            throw new Error("Integer addition underflow");
        }
        return result;
    }

    static safeMultiplication(a, b) {
        const result = a * b;
        if (a !== 0 && Math.floor(result / a) !== b) {
            throw new Error("Integer multiplication overflow");
        }
        return result;
    }
}

module.exports = {
    BufferOverflowProtection,
    SQLInjectionProtection,
    XSSProtection,
    CommandInjectionProtection,
    PathTraversalProtection,
    IntegerOverflowProtection
};