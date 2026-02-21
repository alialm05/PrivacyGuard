"""
zipper.py
Handles AES-256 encryption of files into password-protected ZIP archives.
"""

import os
import pyzipper


def encrypt_to_zip(filepath, password):
    """
    Encrypt a file into a password-protected AES-256 ZIP next to the original.
    Returns the path to the ZIP file on success, or None on failure.
    """
    zip_path = filepath + ".encrypted.zip"
    try:
        with pyzipper.AESZipFile(zip_path, 'w',
                                  compression=pyzipper.ZIP_DEFLATED,
                                  encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode())
            zf.write(filepath, os.path.basename(filepath))
        print(f"  [OK] Encrypted ZIP created: {zip_path}")
        return zip_path
    except Exception as e:
        print(f"  [!] Encryption failed: {e}")
        return None


def delete_file(filepath):
    """Delete a file and return True on success, False on failure."""
    try:
        os.remove(filepath)
        print(f"  [OK] Original file deleted: {filepath}")
        return True
    except Exception as e:
        print(f"  [!] Could not delete file: {e}")
        return False