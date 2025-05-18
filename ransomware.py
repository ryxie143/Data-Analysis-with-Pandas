import pathlib
import os
import secrets
import base64
import getpass
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(size=16):
    """Generate cryptographically secure salt for key derivation"""
    return secrets.token_bytes(size)

def derive_key(salt, password):
    """Derive encryption key from password using Scrypt"""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    """Load salt from salt.salt file"""
    return open("salt.salt", "rb").read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Generate encryption key from password"""
    if load_existing_salt:
        salt = load_salt()
    elif save_salt:
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    """Encrypt a file using Fernet symmetric encryption"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    """Decrypt a file using Fernet symmetric encryption"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
        with open(filename, "wb") as file:
            file.write(decrypted_data)
        return True
    except cryptography.fernet.InvalidToken:
        print(f"[!] Failed to decrypt {filename} - incorrect password")
        return False

def encrypt_folder(foldername, key):
    """Recursively encrypt all files in a folder"""
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            encrypt(child, key)
        elif child.is_dir():
            encrypt_folder(child, key)

def decrypt_folder(foldername, key):
    """Recursively decrypt all files in a folder"""
    success = 0
    failures = 0
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            if decrypt(child, key):
                success += 1
            else:
                failures += 1
        elif child.is_dir():
            sub_success, sub_failures = decrypt_folder(child, key)
            success += sub_success
            failures += sub_failures
    return success, failures

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="File Encryption Tool (Educational)")
    parser.add_argument("path", help="File or folder path to encrypt/decrypt")
    parser.add_argument("-s", "--salt-size", type=int, 
                      help="Size of salt to generate (default: 16)")
    parser.add_argument("-e", "--encrypt", action="store_true",
                      help="Encrypt the target")
    parser.add_argument("-d", "--decrypt", action="store_true",
                      help="Decrypt the target")
    
    args = parser.parse_args()
    
    if not (args.encrypt or args.decrypt):
        parser.error("Please specify -e (encrypt) or -d (decrypt)")
    
    if args.encrypt:
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords don't match!")
            exit(1)
    else:
        password = getpass.getpass("Enter decryption password: ")
    
    key = generate_key(
        password,
        salt_size=args.salt_size if args.salt_size else 16,
        load_existing_salt=args.decrypt,
        save_salt=args.encrypt
    )
    
    if args.encrypt:
        if os.path.isfile(args.path):
            encrypt(args.path, key)
            print("[+] File encrypted successfully")
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
            print("[+] Folder encrypted successfully")
    else:
        if os.path.isfile(args.path):
            if decrypt(args.path, key):
                print("[+] File decrypted successfully")
            else:
                print("[!] Decryption failed")
        elif os.path.isdir(args.path):
            success, failures = decrypt_folder(args.path, key)
            print(f"[+] Decryption complete: {success} successful, {failures} failed")
