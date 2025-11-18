"""
Build script for creating standalone executable
Run: python build_executable.py
"""

import PyInstaller.__main__
import os
import shutil
from pathlib import Path

def build_executable():
    """Build standalone executable"""
    
    print("=" * 60)
    print("Building Secure Email System Executable")
    print("=" * 60)
    
    # Create necessary directories
    os.makedirs('build_temp', exist_ok=True)
    os.makedirs('dist', exist_ok=True)
    
    # PyInstaller arguments
    args = [
        'main_gui_app.py',                    # Main script
        '--name=SecureEmailSystem',           # Executable name
        '--onefile',                          # Single file
        '--windowed',                         # No console (GUI only)
        '--icon=app_icon.ico',               # App icon (if available)
        
        # Add data files
        '--add-data=buffer_overflow_protection.py:.',
        '--add-data=email_server_core.py:.',
        '--add-data=multilingual_warnings.py:.',
        '--add-data=opensource_link_verifier.py:.',
        '--add-data=models_sqlite.py:.',
        '--add-data=phishing_blacklist.txt:.',
        
        # Hidden imports
        '--hidden-import=PyQt5',
        '--hidden-import=PyQt5.QtCore',
        '--hidden-import=PyQt5.QtWidgets',
        '--hidden-import=PyQt5.QtGui',
        '--hidden-import=bcrypt',
        '--hidden-import=pyotp',
        '--hidden-import=qrcode',
        '--hidden-import=PIL',
        
        # Build options
        '--clean',
        '--noconfirm',
        f'--distpath=dist',
        f'--workpath=build_temp',
        f'--specpath=build_temp',
        
        # Optimization
        '--optimize=2',
    ]
    
    print("\nRunning PyInstaller...")
    PyInstaller.__main__.run(args)
    
    print("\n" + "=" * 60)
    print("Build Complete!")
    print(f"Executable location: {os.path.abspath('dist/SecureEmailSystem.exe')}")
    print("=" * 60)
    
    # Create README for distribution
    readme_content = """
# Secure Email System - Standalone Application

## Installation
1. Extract all files to a folder
2. Run SecureEmailSystem.exe

## Features
- End-to-end secure email system
- 2FA authentication with TOTP
- Multilingual support (15+ languages)
- Sender reputation scoring
- Link verification
- Phishing detection
- Offline operation (no external services required)

## Data Storage
- Database: ~/.secure_email_app/email_app.db
- Email files: ~/.secure_email_app/maildata/

## First Time Setup
1. Click "Register" tab
2. Enter email and password (min 12 chars)
3. Select two preferred languages
4. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
5. Save recovery codes in a safe place
6. Login with email, password, and 2FA code

## Security Features
- All data stored locally
- No external API dependencies
- Military-grade encryption
- Real-time phishing detection
- Community-driven sender reputation

## Support
For issues or questions, check the documentation in the docs/ folder.

## Version
1.0.0
    """
    
    with open('dist/README.txt', 'w') as f:
        f.write(readme_content)
    
    print("\nREADME.txt created in dist folder")
    
    # Copy blacklist file
    if os.path.exists('phishing_blacklist.txt'):
        shutil.copy('phishing_blacklist.txt', 'dist/phishing_blacklist.txt')
        print("Phishing blacklist copied to dist folder")
    
    print("\n✓ Build complete! Check the 'dist' folder.")


if __name__ == '__main__':
    build_executable()
